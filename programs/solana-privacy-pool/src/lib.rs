//! Solana Privacy Pool – Anchor program.
//!
//! One global concurrent Merkle tree stores note commitments.
//! - Deposits append commitments to the tree.
//! - Swaps (private) tombstone the input leaf and append a fresh output leaf.
//! - Withdrawals verify Groth16 proofs and pay out from shared AMM vaults.
//!
//! Canonical two-layer commitment format:
//!   Layer 1 – noteHash  = keccak256(nullifier ‖ secret)
//!   Layer 2 – commitment = keccak256(noteHash ‖ amountLE8 ‖ assetIdLE4)
//!             (or sharesLE8 ‖ poolIdLE4 for LP notes)

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer as TokenTransfer};
use bincode::Options;
use groth16_solana::groth16::Groth16Verifier;
use solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState};

// --- Modules ---
mod constants;
mod contexts;
mod errors;
mod pmm;
mod poseidon_merkle_tree;
mod state;
mod types;
mod utils;
mod verifying_key;
mod verifying_key_deposit_asset_bind;
mod verifying_key_deposit_liquidity_bind;
mod verifying_key_liquidity;
mod verifying_key_swap;

// --- Re-exports ---
use constants::*;
use contexts::*;
pub use errors::PrivacyError;
use state::*;
use types::*;
use utils::*;
use verifying_key::VERIFYINGKEY;
use verifying_key_deposit_asset_bind::VERIFYINGKEY_DEPOSIT_ASSET_BIND;
use verifying_key_deposit_liquidity_bind::VERIFYINGKEY_DEPOSIT_LIQUIDITY_BIND;
use verifying_key_liquidity::VERIFYINGKEY_LIQUIDITY;
use verifying_key_swap::VERIFYINGKEY_SWAP;

// v2 Poseidon shielded path.
use light_hasher::{Hasher, Poseidon};

declare_id!("p1VaCyyfzodMni1tSYhvUFd3MyGB6sb6NRFWPixXD54");

// =============================================================================
//  Program
// =============================================================================

#[program]
pub mod solana_privacy_pool {
    use super::*;

    // =========================================================================
    //  Admin / Governance
    // =========================================================================

    /// Create the singleton AMM config account (PDA seed `[b"amm"]`).
    ///
    /// Only the program upgrade authority may call this.
    pub fn create_amm(ctx: Context<CreateAmm>, tee_authority: Pubkey) -> Result<()> {
        // Verify the caller is the program's upgrade authority.
        require!(
            ctx.accounts.program.owner == &bpf_loader_upgradeable::id(),
            PrivacyError::InvalidProgramData
        );
        let (expected_pd, _) = Pubkey::find_program_address(
            &[ctx.accounts.program.key().as_ref()],
            &bpf_loader_upgradeable::id(),
        );
        require_keys_eq!(
            ctx.accounts.program_data.key(),
            expected_pd,
            PrivacyError::InvalidProgramData
        );
        require!(
            ctx.accounts.program_data.owner == &bpf_loader_upgradeable::id(),
            PrivacyError::InvalidProgramData
        );
        let data = ctx.accounts.program_data.try_borrow_data()?;
        let loader_state: UpgradeableLoaderState = bincode::options()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(256)
            .deserialize(&data)
            .map_err(|_| PrivacyError::InvalidProgramData)?;
        match loader_state {
            UpgradeableLoaderState::ProgramData {
                upgrade_authority_address: Some(ua),
                ..
            } => {
                require_keys_eq!(ua, ctx.accounts.upgrade_authority.key(), PrivacyError::UnauthorizedUpgradeAuthority);
            }
            _ => return err!(PrivacyError::InvalidProgramData),
        }

        let amm = &mut ctx.accounts.amm;
        amm.admin = ctx.accounts.upgrade_authority.key();
        amm.tee_authority = tee_authority;
        amm.merkle_tree = ctx.accounts.merkle_tree.key();
        amm.total_deposits = 0;
        amm.paused = false;

        msg!("AMM created. TEE: {} | Tree: {}", tee_authority, amm.merkle_tree);
        Ok(())
    }

    /// Initialize the global Registry PDA (call once after `create_amm`).
    pub fn initialize_registry(ctx: Context<InitializeRegistry>) -> Result<()> {
        let reg = &mut ctx.accounts.registry;
        reg.is_initialized = true;
        reg.assets = Vec::new();
        reg.mints_by_asset_id = Vec::new();
        reg.pools = Vec::new();
        reg.pools_by_id = Vec::new();
        reg.bump = ctx.bumps.registry;
        Ok(())
    }

    /// Initialize the v2 Poseidon commitment tree (call once; admin-gated).
    ///
    /// Validates the tree config up front (audit findings #2/#3): `height` must
    /// index into the hasher's zero-bytes table and stay below the 64-bit shift
    /// limit, and the root-history size must fit the ring buffer — so a
    /// misconfigured deploy is impossible. Then seeds the empty tree.
    pub fn init_poseidon_tree(ctx: Context<InitPoseidonTree>) -> Result<()> {
        let mut tree = ctx.accounts.merkle_tree.load_init()?;

        // Bound checks before touching the tree (prevents the panics the audit
        // flagged on a bad `height` / `root_history_size`).
        let zero_len = <Poseidon as Hasher>::zero_bytes().len();
        require!(
            (MERKLE_TREE_HEIGHT as usize) < zero_len,
            PrivacyError::InvalidTreeConfig
        );
        require!(MERKLE_TREE_HEIGHT < 64, PrivacyError::InvalidTreeConfig);
        require!(
            (1..=tree.root_history.len()).contains(&ROOT_HISTORY_SIZE),
            PrivacyError::InvalidTreeConfig
        );

        tree.height = MERKLE_TREE_HEIGHT;
        tree.root_history_size = ROOT_HISTORY_SIZE as u8;
        tree.authority = ctx.accounts.amm.key();
        tree.bump = ctx.bumps.merkle_tree;

        crate::poseidon_merkle_tree::MerkleTree::initialize::<Poseidon>(&mut tree)?;
        Ok(())
    }

    /// Admin: zero one leaf of the legacy keccak SPL tree. Call once per
    /// non-empty leaf (Merkle proof nodes in `remaining_accounts`) before
    /// `admin_close_keccak_tree`. Reuses SPL `replace_leaf` (writes a zero leaf).
    pub fn admin_vacuum_keccak_leaf<'info>(
        ctx: Context<'_, '_, '_, 'info, AdminVacuumKeccakLeaf<'info>>,
        root: [u8; 32],
        previous_leaf: [u8; 32],
        index: u32,
    ) -> Result<()> {
        let bump = ctx.bumps.amm;
        let seeds: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];
        let mut all_infos = ctx.accounts.to_account_infos();
        all_infos.extend_from_slice(ctx.remaining_accounts);
        cpi_spl_replace_leaf(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.amm.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &root,
            &previous_leaf,
            index,
            ctx.remaining_accounts,
            &all_infos,
            seeds,
        )?;
        Ok(())
    }

    /// Admin: close the (already-zeroed) legacy keccak SPL tree, reclaiming its
    /// rent lamports to `rent_recipient`. Signed by the AMM PDA.
    pub fn admin_close_keccak_tree(ctx: Context<AdminCloseKeccakTree>) -> Result<()> {
        let bump = ctx.bumps.amm;
        let seeds: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];
        cpi_spl_close_empty_tree(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.amm.to_account_info(),
            &ctx.accounts.rent_recipient.to_account_info(),
            seeds,
        )?;
        msg!("Legacy keccak tree closed; rent -> {}", ctx.accounts.rent_recipient.key());
        Ok(())
    }

    /// Toggle the global emergency pause flag.
    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        ctx.accounts.amm.paused = paused;
        msg!("Paused = {}", paused);
        Ok(())
    }

    /// Rotate protocol admin (governance key rotation).
    pub fn rotate_admin(ctx: Context<RotateAdmin>, new_admin: Pubkey) -> Result<()> {
        require!(new_admin != Pubkey::default(), PrivacyError::InvalidAdmin);
        require!(ctx.accounts.registry.is_initialized, PrivacyError::RegistryNotInitialized);
        ctx.accounts.amm.admin = new_admin;
        msg!("Admin rotated to {}", new_admin);
        Ok(())
    }

    /// Rotate the TEE authority with full borrow cleanup for one pool.
    ///
    /// 1. Recall all borrowed tokens from old TEE ATAs → vault (AMM PDA delegate)
    /// 2. Zero the borrow ledger, restore pool reserves
    /// 3. Set `amm.tee_authority` to the new TEE
    /// 4. Approve `u64::MAX` delegate on new TEE ATAs
    ///
    /// Old TEE does NOT need to sign — the AMM PDA delegate handles recall.
    pub fn rotate_tee_with_borrow_cleanup(ctx: Context<RotateTeeWithBorrowCleanup>) -> Result<()> {
        let new_tee = ctx.accounts.new_tee_authority.key();
        require!(new_tee != Pubkey::default(), PrivacyError::InvalidTEEAuthority);
        require!(new_tee != ctx.accounts.amm.tee_authority, PrivacyError::InvalidTEEAuthority);

        let borrowed_a = ctx.accounts.borrow_ledger.borrowed_a;
        let borrowed_b = ctx.accounts.borrow_ledger.borrowed_b;

        let bump = ctx.bumps.amm;
        let signer: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];

        // 1) Recall principal from old TEE ATAs → vault.
        // If old TEE is insolvent, recall what is available and rotate anyway.
        let available_a = ctx.accounts.old_tee_ata_a.amount;
        let available_b = ctx.accounts.old_tee_ata_b.amount;
        let recalled_a = core::cmp::min(borrowed_a, available_a);
        let recalled_b = core::cmp::min(borrowed_b, available_b);
        let bad_debt_a = borrowed_a.saturating_sub(recalled_a);
        let bad_debt_b = borrowed_b.saturating_sub(recalled_b);

        if recalled_a > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.old_tee_ata_a.to_account_info(),
                        to: ctx.accounts.vault_a.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                recalled_a,
            ).map_err(|_| PrivacyError::RecallFailed)?;
        }
        if recalled_b > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.old_tee_ata_b.to_account_info(),
                        to: ctx.accounts.vault_b.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                recalled_b,
            ).map_err(|_| PrivacyError::RecallFailed)?;
        }

        // 2) Zero ledger, restore reserves.
        ctx.accounts.pool.reserve_a = ctx.accounts.pool
            .reserve_a
            .saturating_add(recalled_a);
        ctx.accounts.pool.reserve_b = ctx.accounts.pool
            .reserve_b
            .saturating_add(recalled_b);

        ctx.accounts.borrow_ledger.borrowed_a = 0;
        ctx.accounts.borrow_ledger.borrowed_b = 0;

        // 3) Rotate authority.
        ctx.accounts.amm.tee_authority = new_tee;

        // 4) Grant delegate on new TEE ATAs.
        token::approve(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Approve {
                    to: ctx.accounts.new_tee_ata_a.to_account_info(),
                    delegate: ctx.accounts.amm.to_account_info(),
                    authority: ctx.accounts.new_tee_authority.to_account_info(),
                },
            ),
            u64::MAX,
        )?;
        token::approve(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Approve {
                    to: ctx.accounts.new_tee_ata_b.to_account_info(),
                    delegate: ctx.accounts.amm.to_account_info(),
                    authority: ctx.accounts.new_tee_authority.to_account_info(),
                },
            ),
            u64::MAX,
        )?;

        msg!(
            "TEE rotated to {} with borrow cleanup (bad_debt a={}, b={})",
            new_tee,
            bad_debt_a,
            bad_debt_b
        );
        Ok(())
    }

    // =========================================================================
    //  Pool Creation & Configuration
    // =========================================================================

    /// Create a trading pair pool.
    ///
    /// Admin-only. Initializes the `Pool` PDA, shared AMM vault ATAs, and
    /// registers the mints + pool in the global `Registry`.
    pub fn create_pool(ctx: Context<CreatePool>) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        let mint_a = ctx.accounts.mint_a.key();
        let mint_b = ctx.accounts.mint_b.key();
        let pool_key = ctx.accounts.pool.key();

        // Ensure registry has capacity for new entries.
        let reg_view: &Registry = &ctx.accounts.registry;
        let new_assets = [mint_a, mint_b]
            .iter()
            .filter(|m| registry_asset_id_for_mint(reg_view, **m).is_none())
            .count();
        let new_pools = if registry_pool_id_for_pool(reg_view, pool_key).is_none() { 1 } else { 0 };

        require!(
            reg_view.assets.len() + new_assets <= Registry::MAX_ASSETS
                && reg_view.pools.len() + new_pools <= Registry::MAX_POOLS,
            PrivacyError::RegistryFull
        );

        let required_len = Registry::required_len(
            reg_view.assets.len() + new_assets,
            reg_view.mints_by_asset_id.len() + new_assets,
            reg_view.pools.len() + new_pools,
            reg_view.pools_by_id.len() + new_pools,
        );
        ensure_registry_capacity(
            &ctx.accounts.registry.to_account_info(),
            &ctx.accounts.admin.to_account_info(),
            &ctx.accounts.system_program.to_account_info(),
            required_len,
        )?;

        let reg = &mut ctx.accounts.registry;
        let _asset_id_a = registry_get_or_alloc_asset_id(reg, mint_a)?;
        let _asset_id_b = registry_get_or_alloc_asset_id(reg, mint_b)?;

        let pool = &mut ctx.accounts.pool;
        pool.amm = ctx.accounts.amm.key();
        pool.mint_a = mint_a;
        pool.mint_b = mint_b;
        pool.vault_a = ctx.accounts.amm_vault_a.key();
        pool.vault_b = ctx.accounts.amm_vault_b.key();
        pool.total_shares = 0;
        pool.reserve_a = 0;
        pool.reserve_b = 0;
        pool.bump = ctx.bumps.pool;
        // Oracle / PMM fields — defaults; configure via `configure_pool`.
        pool.oracle_a = Pubkey::default();
        pool.oracle_b = Pubkey::default();
        pool.dec_a = ctx.accounts.mint_a.decimals;
        pool.dec_b = ctx.accounts.mint_b.decimals;
        pool.fee_bps = 0;
        pool.pmm = PmmConfig::default();

        let _pool_id = registry_alloc_and_register_pool(reg, pool_key)?;
        Ok(())
    }

    /// Configure pool oracle feeds, fee, and PMM policy. Admin-only.
    ///
    /// Must be called before `execute_zk_swap` can succeed for this pool.
    pub fn configure_pool(
        ctx: Context<ConfigurePool>,
        oracle_a: Pubkey,
        oracle_b: Pubkey,
        fee_bps: u16,
        pmm_config: PmmConfig,
    ) -> Result<()> {
        require!(
            oracle_a != Pubkey::default() && oracle_b != Pubkey::default(),
            PrivacyError::InvalidOracleAccount
        );
        require!(
            pmm_config.max_spread_bps > 0 && pmm_config.max_spread_bps <= 10_000,
            PrivacyError::InvalidPmmConfig
        );
        require!(pmm_config.max_skew_bps <= 10_000, PrivacyError::InvalidPmmConfig);
        require!(pmm_config.max_oracle_age_secs > 0, PrivacyError::InvalidPmmConfig);

        let pool = &mut ctx.accounts.pool;
        pool.oracle_a = oracle_a;
        pool.oracle_b = oracle_b;
        pool.dec_a = ctx.accounts.mint_a.decimals;
        pool.dec_b = ctx.accounts.mint_b.decimals;
        pool.fee_bps = fee_bps;
        pool.pmm = pmm_config;

        msg!(
            "Pool configured: oracle_a={}, oracle_b={}, fee_bps={}, max_spread={}, max_skew={}, oracle_age={}s",
            oracle_a, oracle_b, fee_bps,
            pmm_config.max_spread_bps, pmm_config.max_skew_bps, pmm_config.max_oracle_age_secs,
        );
        Ok(())
    }

    // =========================================================================
    //  Deposits
    // =========================================================================

    /// Shield a single asset into the tree (deposit).
    ///
    /// Transfers tokens into the AMM vault and appends the provided `commitment`
    /// to the global Merkle tree. A Groth16 proof binds (commitment, amount, assetId).
    pub fn deposit(
        ctx: Context<Deposit>,
        proof: Groth16Proof,
        amount: u64,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        require!(amount > 0, PrivacyError::ZeroDepositAmount);
        require!(commitment != [0u8; 32], PrivacyError::InvalidCommitment);
        require!(ctx.accounts.registry.is_initialized, PrivacyError::RegistryNotInitialized);
        require!(ctx.accounts.user_source.amount >= amount, PrivacyError::InsufficientUserBalance);

        // 0) Verify Groth16 proof — binds (amount, asset_id, commitment).
        let asset_id = registry_asset_id_for_mint(&ctx.accounts.registry, ctx.accounts.mint.key())
            .ok_or(PrivacyError::AssetNotRegistered)?;

        let mut amount_be = [0u8; 32];
        amount_be[24..].copy_from_slice(&amount.to_be_bytes());
        let mut asset_be = [0u8; 32];
        asset_be[28..].copy_from_slice(&asset_id.to_be_bytes());

        // Public inputs match deposit_poseidon.circom: [amount, assetId, commitment].
        let public_inputs: [[u8; 32]; 3] = [amount_be, asset_be, commitment];
        if VERIFYINGKEY_DEPOSIT_ASSET_BIND.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<3>::new(
            &proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY_DEPOSIT_ASSET_BIND,
        ).map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 1) Transfer tokens: User -> AMM vault.
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TokenTransfer {
                    from: ctx.accounts.user_source.to_account_info(),
                    to: ctx.accounts.amm_vault.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                },
            ),
            amount,
        )?;

        // 2) Append commitment to the Poseidon tree (leaf_index = next_index).
        let leaf_index = poseidon_append(&ctx.accounts.merkle_tree, &commitment)?;
        ctx.accounts.amm.total_deposits = ctx
            .accounts
            .amm
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        emit!(DepositEvent { commitment, leaf_index, amount_a: amount, amount_b: 0, encrypted_note });
        Ok(())
    }

    /// Deposit liquidity into a pool and mint a private LP note.
    ///
    /// Permissionless. Computes shares on-chain from virtual reserves.
    pub fn deposit_liquidity(
        ctx: Context<DepositLiquidity>,
        proof: Groth16Proof,
        amount_a: u64,
        amount_b: u64,
        expected_shares: u64,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        require!(amount_a > 0 && amount_b > 0, PrivacyError::InvalidLiquidityDeposit);

        let reserve_a_before = ctx.accounts.pool.reserve_a;
        let reserve_b_before = ctx.accounts.pool.reserve_b;
        let total_before = ctx.accounts.pool.total_shares;
        let effective_a = (reserve_a_before as u128)
            .checked_add(ctx.accounts.borrow_ledger.borrowed_a as u128)
            .ok_or(PrivacyError::MathOverflow)?;
        let effective_b = (reserve_b_before as u128)
            .checked_add(ctx.accounts.borrow_ledger.borrowed_b as u128)
            .ok_or(PrivacyError::MathOverflow)?;

        // 0) Verify Groth16 proof — binds (commitment, shares, pool_id).
        let pool_id = registry_pool_id_for_pool(&ctx.accounts.registry, ctx.accounts.pool.key())
            .ok_or(PrivacyError::PoolNotRegistered)?;

        let mut shares_be = [0u8; 32];
        shares_be[24..].copy_from_slice(&expected_shares.to_be_bytes());
        let mut pool_be = [0u8; 32];
        pool_be[28..].copy_from_slice(&pool_id.to_be_bytes());

        // Public inputs match deposit_liquidity_poseidon.circom: [shares, poolId, commitment].
        let public_inputs: [[u8; 32]; 3] = [shares_be, pool_be, commitment];
        if VERIFYINGKEY_DEPOSIT_LIQUIDITY_BIND.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<3>::new(
            &proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY_DEPOSIT_LIQUIDITY_BIND,
        ).map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 1) Transfer tokens A & B into pool vaults.
        if amount_a > 0 {
            token::transfer(
                CpiContext::new(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.user_account_a.to_account_info(),
                    to: ctx.accounts.amm_vault_a.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                }),
                amount_a,
            )?;
        }
        if amount_b > 0 {
            token::transfer(
                CpiContext::new(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.user_account_b.to_account_info(),
                    to: ctx.accounts.amm_vault_b.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                }),
                amount_b,
            )?;
        }

        // 2) Append LP note to the Poseidon tree (leaf_index = next_index).
        let leaf_index = poseidon_append(&ctx.accounts.merkle_tree, &commitment)?;
        ctx.accounts.amm.total_deposits = ctx
            .accounts
            .amm
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        // 4) Mint shares.
        let pool = &mut ctx.accounts.pool;
        let minted_shares: u64 = if total_before == 0 {
            let prod = (amount_a as u128)
                .checked_mul(amount_b as u128)
                .ok_or(PrivacyError::MathOverflow)?;
            let root = integer_sqrt_u128(prod);
            require!(root <= (u64::MAX as u128), PrivacyError::MathOverflow);
            root as u64
        } else {
            require!(effective_a > 0 && effective_b > 0, PrivacyError::InvalidReserves);

            // Enforce correct ratio (±1 rounding tolerance).
            let ra = effective_a;
            let rb = effective_b;
            let aa = amount_a as u128;
            let ab = amount_b as u128;
            let ideal_b_floor = aa.checked_mul(rb).ok_or(PrivacyError::MathOverflow)? / ra;
            let ideal_b_ceil = aa
                .checked_mul(rb).ok_or(PrivacyError::MathOverflow)?
                .checked_add(ra.saturating_sub(1)).ok_or(PrivacyError::MathOverflow)?
                / ra;
            require!(ab >= ideal_b_floor && ab <= ideal_b_ceil, PrivacyError::InvalidLiquidityRatio);

            let share_a = (amount_a as u128)
                .checked_mul(total_before as u128).ok_or(PrivacyError::MathOverflow)?
                / effective_a;
            let share_b = (amount_b as u128)
                .checked_mul(total_before as u128).ok_or(PrivacyError::MathOverflow)?
                / effective_b;
            let m = core::cmp::min(share_a, share_b);
            require!(m <= (u64::MAX as u128), PrivacyError::MathOverflow);
            m as u64
        };

        require!(minted_shares > 0, PrivacyError::ZeroShares);
        require!(minted_shares == expected_shares, PrivacyError::SharesMismatch);
        pool.reserve_a = pool.reserve_a.checked_add(amount_a).ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool.reserve_b.checked_add(amount_b).ok_or(PrivacyError::MathOverflow)?;
        pool.total_shares = pool.total_shares.checked_add(minted_shares).ok_or(PrivacyError::MathOverflow)?;

        emit!(DepositEvent { commitment, leaf_index, amount_a, amount_b, encrypted_note });
        Ok(())
    }

    // =========================================================================
    //  Withdrawals
    // =========================================================================

    /// Withdraw (unshield) a single asset – private note -> public token.
    pub fn withdraw(
        ctx: Context<Withdraw>,
        proof: Groth16Proof,
        root: [u8; 32],
        leaf_index: u32,
        amount: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;

        let asset_id = registry_asset_id_for_mint(&ctx.accounts.registry, ctx.accounts.mint_output.key())
            .ok_or(PrivacyError::AssetNotRegistered)?;

        // 1) Validate Merkle root against the Poseidon tree's root history.
        require_poseidon_root(&ctx.accounts.merkle_tree, &root)?;

        // 2) Verify Groth16 proof (7 public inputs).
        let rec_bytes = ctx.accounts.recipient.key().to_bytes();
        let mut fee_be = [0u8; 32];
        fee_be[24..].copy_from_slice(&relayer_fee.to_be_bytes());
        let mut amount_be = [0u8; 32];
        amount_be[24..].copy_from_slice(&amount.to_be_bytes());
        let mut asset_be = [0u8; 32];
        asset_be[28..].copy_from_slice(&asset_id.to_be_bytes());
        let mut leaf_be = [0u8; 32];
        leaf_be[28..].copy_from_slice(&leaf_index.to_be_bytes());

        // Public inputs match withdraw_poseidon.circom:
        // [root, recipientHi, recipientLo, relayerFee, amount, assetId, leafIndex].
        let public_inputs: [[u8; 32]; 7] = [
            root,
            to_field_element(&rec_bytes[0..16]),
            to_field_element(&rec_bytes[16..32]),
            fee_be,
            amount_be,
            asset_be,
            leaf_be,
        ];
        if VERIFYINGKEY.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<7>::new(
            &proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY,
        ).map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 3) Nullify (mark spent).
        validate_and_mark_spent(&mut ctx.accounts.spent_shard, leaf_index)?;

        // 4) Transfer: AMM vault -> recipient + relayer fee.
        let bump = ctx.bumps.amm;
        let signer: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];

        let payout_amount = amount.checked_sub(relayer_fee).ok_or(PrivacyError::FeeExceedsAmount)?;
        if payout_amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.amm_vault.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                    authority: ctx.accounts.amm.to_account_info(),
                }, signer),
                payout_amount,
            )?;
        }
        if relayer_fee > 0 {
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.amm_vault.to_account_info(),
                    to: ctx.accounts.relayer_fee_account.to_account_info(),
                    authority: ctx.accounts.amm.to_account_info(),
                }, signer),
                relayer_fee,
            )?;
        }

        msg!("Withdrawal ok");
        Ok(())
    }

    /// Withdraw liquidity – private LP note -> public tokens (both mints).
    ///
    /// `borrow_ledger` is always required to prevent omission-based underpayment.
    /// `tee_ata_a` / `tee_ata_b` are still optional and only required when the
    /// computed recall from TEE is non-zero.
    pub fn withdraw_liquidity(
        ctx: Context<WithdrawLiquidity>,
        proof: Groth16Proof,
        root: [u8; 32],
        leaf_index: u32,
        shares: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        require!(relayer_fee == 0, PrivacyError::TokenRelayerFeeNotSupported);

        let pool_id = registry_pool_id_for_pool(&ctx.accounts.registry, ctx.accounts.pool.key())
            .ok_or(PrivacyError::PoolNotRegistered)?;

        // Validate recipient accounts.
        let recipient_owner = ctx.accounts.recipient_account_a.owner;
        require!(ctx.accounts.recipient_account_b.owner == recipient_owner, PrivacyError::InvalidRecipientOwner);
        require!(ctx.accounts.recipient_account_a.mint == ctx.accounts.mint_a.key(), PrivacyError::InvalidRecipientMint);
        require!(ctx.accounts.recipient_account_b.mint == ctx.accounts.mint_b.key(), PrivacyError::InvalidRecipientMint);

        // 1) Validate Merkle root against the Poseidon tree's root history.
        require_poseidon_root(&ctx.accounts.merkle_tree, &root)?;

        // 2) Verify Groth16 proof (7 public inputs).
        let rec_bytes = recipient_owner.to_bytes();
        let mut fee_be = [0u8; 32];
        fee_be[24..].copy_from_slice(&relayer_fee.to_be_bytes());
        let mut shares_be = [0u8; 32];
        shares_be[24..].copy_from_slice(&shares.to_be_bytes());
        let mut pool_be = [0u8; 32];
        pool_be[28..].copy_from_slice(&pool_id.to_be_bytes());
        let mut leaf_be = [0u8; 32];
        leaf_be[28..].copy_from_slice(&leaf_index.to_be_bytes());

        // Public inputs match withdraw_liquidity_poseidon.circom:
        // [root, recipientHi, recipientLo, relayerFee, shares, poolId, leafIndex].
        let public_inputs: [[u8; 32]; 7] = [
            root,
            to_field_element(&rec_bytes[0..16]),
            to_field_element(&rec_bytes[16..32]),
            fee_be,
            shares_be,
            pool_be,
            leaf_be,
        ];
        if VERIFYINGKEY_LIQUIDITY.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<7>::new(
            &proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY_LIQUIDITY,
        ).map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 3) Nullify (mark spent).
        validate_and_mark_spent(&mut ctx.accounts.spent_shard, leaf_index)?;

        // 4) Compute payout from shares + effective reserves.
        let total_shares = ctx.accounts.pool.total_shares;
        require!(total_shares > 0, PrivacyError::ZeroTotalShares);
        require!(shares > 0, PrivacyError::ZeroShares);
        require!(shares <= total_shares, PrivacyError::SharesExceedTotal);

        let reserve_a = ctx.accounts.pool.reserve_a;
        let reserve_b = ctx.accounts.pool.reserve_b;
        require!(
            reserve_a <= ctx.accounts.amm_vault_a.amount
                && reserve_b <= ctx.accounts.amm_vault_b.amount,
            PrivacyError::InsufficientPoolBalance
        );

        let borrowed_a = ctx.accounts.borrow_ledger.borrowed_a;
        let borrowed_b = ctx.accounts.borrow_ledger.borrowed_b;

        let ts = total_shares as u128;

        let from_vault_a: u64 = u64::try_from(
            (shares as u128).checked_mul(reserve_a as u128).ok_or(PrivacyError::MathOverflow)? / ts,
        ).map_err(|_| PrivacyError::MathOverflow)?;
        let from_vault_b: u64 = u64::try_from(
            (shares as u128).checked_mul(reserve_b as u128).ok_or(PrivacyError::MathOverflow)? / ts,
        ).map_err(|_| PrivacyError::MathOverflow)?;

        let from_tee_a: u64 = u64::try_from(
            (shares as u128).checked_mul(borrowed_a as u128).ok_or(PrivacyError::MathOverflow)? / ts,
        ).map_err(|_| PrivacyError::MathOverflow)?;
        let from_tee_b: u64 = u64::try_from(
            (shares as u128).checked_mul(borrowed_b as u128).ok_or(PrivacyError::MathOverflow)? / ts,
        ).map_err(|_| PrivacyError::MathOverflow)?;

        // 5) Transfer from vault (AMM PDA signs).
        let bump = ctx.bumps.amm;
        let signer: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];

        if from_vault_a > 0 {
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.amm_vault_a.to_account_info(),
                    to: ctx.accounts.recipient_account_a.to_account_info(),
                    authority: ctx.accounts.amm.to_account_info(),
                }, signer),
                from_vault_a,
            )?;
        }
        if from_vault_b > 0 {
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.amm_vault_b.to_account_info(),
                    to: ctx.accounts.recipient_account_b.to_account_info(),
                    authority: ctx.accounts.amm.to_account_info(),
                }, signer),
                from_vault_b,
            )?;
        }

        // 6) Recall from TEE via max delegate (AMM PDA signs as delegate).
        if from_tee_a > 0 || from_tee_b > 0 {
            let tee_ata_a = ctx.accounts.tee_ata_a.as_ref().ok_or(PrivacyError::RecallFailed)?;
            let tee_ata_b = ctx.accounts.tee_ata_b.as_ref().ok_or(PrivacyError::RecallFailed)?;

            if from_tee_a > 0 {
                token::transfer(
                    CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                        from: tee_ata_a.to_account_info(),
                        to: ctx.accounts.recipient_account_a.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    }, signer),
                    from_tee_a,
                ).map_err(|_| PrivacyError::RecallFailed)?;
            }
            if from_tee_b > 0 {
                token::transfer(
                    CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                        from: tee_ata_b.to_account_info(),
                        to: ctx.accounts.recipient_account_b.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    }, signer),
                    from_tee_b,
                ).map_err(|_| PrivacyError::RecallFailed)?;
            }
        }

        // 7) Burn shares + update reserves + borrowed.
        let ledger = &mut ctx.accounts.borrow_ledger;
        ledger.borrowed_a = ledger.borrowed_a.checked_sub(from_tee_a).ok_or(PrivacyError::MathOverflow)?;
        ledger.borrowed_b = ledger.borrowed_b.checked_sub(from_tee_b).ok_or(PrivacyError::MathOverflow)?;

        let pool = &mut ctx.accounts.pool;
        pool.reserve_a = pool.reserve_a.checked_sub(from_vault_a).ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool.reserve_b.checked_sub(from_vault_b).ok_or(PrivacyError::MathOverflow)?;
        pool.total_shares = pool.total_shares.checked_sub(shares).ok_or(PrivacyError::SharesExceedTotal)?;

        msg!("LP withdrawal ok");
        Ok(())
    }

    // =========================================================================
    //  Swaps
    // =========================================================================

    /// RFQ swap (legacy TEE path) – tombstone input leaf, append output leaf.
    pub fn execute_rfq_swap_append<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteRfqSwapAppend<'info>>,
        swap: RfqSwapUpdate,
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.config)?;
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        // Validate leaf not already spent (don't mark yet — wait until append).
        let (byte_i, mask) = validate_not_spent(&ctx.accounts.spent_shard, swap.index)?;

        // Validate the referenced root is known. TEE-trusted path: no membership
        // proof, and the input leaf is not tombstoned — the spent bitmap is the
        // double-spend guard.
        require_poseidon_root(&ctx.accounts.merkle_tree, &swap.root)?;

        // 1) Append the TEE-provided output leaf to the Poseidon tree.
        let output_leaf_index = poseidon_append(&ctx.accounts.merkle_tree, &swap.new_leaf)?;

        // 2) Mark input leaf spent.
        ctx.accounts.spent_shard.bits[byte_i] |= mask;

        // 4) Update pool reserves using checked deltas (not blind overwrite).
        //    This preserves compatibility with existing RFQ payloads while
        //    avoiding direct state rewrites.
        let pool = &mut ctx.accounts.pool;
        let prev_a = pool.reserve_a;
        let prev_b = pool.reserve_b;
        let next_a = swap.new_reserve_a;
        let next_b = swap.new_reserve_b;

        // Basic pool sanity: keep both virtual reserves non-zero.
        require!(next_a > 0 && next_b > 0, PrivacyError::InvalidReserves);

        // RFQ swap should move inventory in opposite directions (or be exact no-op).
        let a_up = next_a >= prev_a;
        let b_up = next_b >= prev_b;
        let is_noop = next_a == prev_a && next_b == prev_b;
        require!(is_noop || (a_up != b_up), PrivacyError::InvalidReserves);

        pool.reserve_a = if next_a >= prev_a {
            let delta = next_a.checked_sub(prev_a).ok_or(PrivacyError::MathOverflow)?;
            prev_a.checked_add(delta).ok_or(PrivacyError::MathOverflow)?
        } else {
            let delta = prev_a.checked_sub(next_a).ok_or(PrivacyError::MathOverflow)?;
            prev_a.checked_sub(delta).ok_or(PrivacyError::MathOverflow)?
        };
        pool.reserve_b = if next_b >= prev_b {
            let delta = next_b.checked_sub(prev_b).ok_or(PrivacyError::MathOverflow)?;
            prev_b.checked_add(delta).ok_or(PrivacyError::MathOverflow)?
        } else {
            let delta = prev_b.checked_sub(next_b).ok_or(PrivacyError::MathOverflow)?;
            prev_b.checked_sub(delta).ok_or(PrivacyError::MathOverflow)?
        };
        require!(
            pool.reserve_a <= ctx.accounts.amm_vault_a.amount
                && pool.reserve_b <= ctx.accounts.amm_vault_b.amount,
            PrivacyError::InsufficientPoolBalance
        );

        // 5) Update deposit counter (leaf index captured at append above).
        ctx.accounts.config.total_deposits = ctx
            .accounts
            .config
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        emit!(SwapAppendEvent {
            pool: ctx.accounts.pool.key(),
            input_commitment: swap.previous_leaf,
            input_leaf_index: swap.index,
            output_commitment: swap.new_leaf,
            output_leaf_index,
            encrypted_note,
        });
        msg!("Swap ok");
        Ok(())
    }

    /// Permissionless ZK swap (Path C) – on-chain PMM pricing via Pyth oracles.
    ///
    /// No TEE signature required. Anyone can submit this instruction.
    pub fn execute_zk_swap<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteZkSwap<'info>>,
        proof: Groth16Proof,
        params: ZkSwapParams,
        amount_in: u64,
        asset_id_in: u32,
        asset_id_out: u32,
        min_amount_out: u64,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.config)?;
        require!(params.encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        require!(amount_in > 0, PrivacyError::ZeroDepositAmount);
        require!(min_amount_out > 0, PrivacyError::ZeroDepositAmount);
        require!(
            ctx.remaining_accounts.len() <= SPL_TREE_MAX_DEPTH,
            PrivacyError::TooManyMerkleProofAccounts
        );

        let pool = &ctx.accounts.pool;

        // --- Validate oracles are configured ---
        require!(
            pool.oracle_a != Pubkey::default() && pool.oracle_b != Pubkey::default(),
            PrivacyError::InvalidOracleAccount
        );
        // Address checks are enforced by Anchor constraints in ExecuteZkSwap.

        // --- Validate asset_ids via registry ---
        let registry = &ctx.accounts.registry;
        let reg_asset_a = registry_asset_id_for_mint(registry, pool.mint_a)
            .ok_or(PrivacyError::AssetNotRegistered)?;
        let reg_asset_b = registry_asset_id_for_mint(registry, pool.mint_b)
            .ok_or(PrivacyError::AssetNotRegistered)?;

        let is_a_to_b = if asset_id_in == reg_asset_a && asset_id_out == reg_asset_b {
            true
        } else if asset_id_in == reg_asset_b && asset_id_out == reg_asset_a {
            false
        } else {
            return err!(PrivacyError::InvalidAssetId);
        };

        let (reserve_in, reserve_out, dec_in, dec_out) = if is_a_to_b {
            (pool.reserve_a, pool.reserve_b, pool.dec_a, pool.dec_b)
        } else {
            (pool.reserve_b, pool.reserve_a, pool.dec_b, pool.dec_a)
        };

        // --- Validate leaf not spent ---
        let (byte_i, mask) = validate_not_spent(&ctx.accounts.spent_shard, params.input_leaf_index)?;

        // --- Validate Merkle root against the Poseidon tree's root history ---
        require_poseidon_root(&ctx.accounts.merkle_tree, &params.root)?;

        // --- Verify Groth16 proof (swap_poseidon circuit, 7 public inputs).
        //     Membership is now proven IN-CIRCUIT (root + leafIndex are public),
        //     so the input commitment is recomputed inside the proof, not passed. ---
        let mut amount_in_be = [0u8; 32];
        amount_in_be[24..].copy_from_slice(&amount_in.to_be_bytes());
        let mut asset_in_be = [0u8; 32];
        asset_in_be[28..].copy_from_slice(&asset_id_in.to_be_bytes());
        let mut asset_out_be = [0u8; 32];
        asset_out_be[28..].copy_from_slice(&asset_id_out.to_be_bytes());
        let mut min_out_be = [0u8; 32];
        min_out_be[24..].copy_from_slice(&min_amount_out.to_be_bytes());
        let mut leaf_be = [0u8; 32];
        leaf_be[28..].copy_from_slice(&params.input_leaf_index.to_be_bytes());

        // Public inputs match swap_poseidon.circom:
        // [root, amountIn, assetIdIn, leafIndex, noteHashOut, assetIdOut, minAmountOut].
        let public_inputs: [[u8; 32]; 7] = [
            params.root,
            amount_in_be,
            asset_in_be,
            leaf_be,
            params.note_hash_out,
            asset_out_be,
            min_out_be,
        ];
        if VERIFYINGKEY_SWAP.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<7>::new(
            &proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY_SWAP,
        ).map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // --- Read Pyth oracle prices (PriceUpdateV2, deserialized by Anchor) ---
        let pyth_a = pmm::from_pyth_update(&ctx.accounts.oracle_a);
        let pyth_b = pmm::from_pyth_update(&ctx.accounts.oracle_b);

        // Enforce staleness.
        let clock = Clock::get()?;
        let now = clock.unix_timestamp;
        let max_age = pool.pmm.max_oracle_age_secs as i64;
        require!(
            now.saturating_sub(pyth_a.timestamp) <= max_age
                && now.saturating_sub(pyth_b.timestamp) <= max_age,
            PrivacyError::OracleStale
        );

        let (oracle_in, oracle_out) = if is_a_to_b { (&pyth_a, &pyth_b) } else { (&pyth_b, &pyth_a) };

        // --- Compute PMM amount_out ---
        let amount_out = pmm::compute_swap_amount_out(
            &pool.pmm, amount_in, reserve_in, reserve_out,
            dec_in, dec_out, pool.fee_bps as u64,
            oracle_in, oracle_out, is_a_to_b, now,
            pool.reserve_a, pool.reserve_b,
            pool.dec_a, pool.dec_b,
            pyth_a.price, pyth_a.expo,
            pyth_b.price, pyth_b.expo,
        ).ok_or(PrivacyError::InvalidOracleAccount)?;

        require!(amount_out >= min_amount_out, PrivacyError::SlippageExceeded);
        require!(amount_out > 0, PrivacyError::ZeroSwapOutput);

        // --- Compute output commitment on-chain. MUST match swap_poseidon's
        //     Commitment: Poseidon(noteHashOut, amountOut, assetIdOut, KIND_ASSET) ---
        let output_commitment =
            poseidon_commitment(&params.note_hash_out, amount_out, asset_id_out, KIND_ASSET)?;

        // --- 1) Append the output leaf to the Poseidon tree. The input leaf is
        //     NOT tombstoned; the spent bitmap is the double-spend guard. ---
        let output_leaf_index = poseidon_append(&ctx.accounts.merkle_tree, &output_commitment)?;

        // --- 2) Mark input leaf as spent ---
        ctx.accounts.spent_shard.bits[byte_i] |= mask;

        // --- 4) Update pool reserves ---
        let pool = &mut ctx.accounts.pool;
        if is_a_to_b {
            pool.reserve_a = pool.reserve_a.checked_add(amount_in).ok_or(PrivacyError::MathOverflow)?;
            pool.reserve_b = pool.reserve_b.checked_sub(amount_out).ok_or(PrivacyError::InsufficientPoolBalance)?;
        } else {
            pool.reserve_b = pool.reserve_b.checked_add(amount_in).ok_or(PrivacyError::MathOverflow)?;
            pool.reserve_a = pool.reserve_a.checked_sub(amount_out).ok_or(PrivacyError::InsufficientPoolBalance)?;
        }
        require!(
            pool.reserve_a <= ctx.accounts.amm_vault_a.amount
                && pool.reserve_b <= ctx.accounts.amm_vault_b.amount,
            PrivacyError::InsufficientPoolBalance
        );

        // --- 5) Update deposit counter (leaf index captured at append above) ---
        ctx.accounts.config.total_deposits = ctx
            .accounts
            .config
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        emit!(ZkSwapEvent {
            pool: ctx.accounts.pool.key(),
            input_commitment: params.input_commitment,
            input_leaf_index: params.input_leaf_index,
            output_commitment,
            output_leaf_index,
            amount_in, amount_out,
            asset_id_in, asset_id_out,
            encrypted_note: params.encrypted_note,
        });

        msg!("ZK swap ok");
        Ok(())
    }

    // =========================================================================
    //  Borrow / Repay (TEE liquidity borrowing)
    // =========================================================================

    /// Initialize a per-pool borrow ledger. Admin-only.
    ///
    /// `max_borrow_bps` sets the borrow cap (hard-capped at 8 000 = 80%).
    pub fn init_borrow_ledger(ctx: Context<InitBorrowLedger>, max_borrow_bps: u16) -> Result<()> {
        require!(
            max_borrow_bps <= BorrowLedger::MAX_BPS,
            PrivacyError::BorrowCapExceeded
        );

        let ledger = &mut ctx.accounts.borrow_ledger;
        ledger.pool = ctx.accounts.pool.key();
        ledger.borrowed_a = 0;
        ledger.borrowed_b = 0;
        ledger.max_borrow_bps = max_borrow_bps;
        ledger.bump = ctx.bumps.borrow_ledger;

        msg!("Borrow ledger initialized: pool={}, max_bps={}", ledger.pool, max_borrow_bps);
        Ok(())
    }

    /// Borrow tokens from pool vaults into the TEE wallet.
    ///
    /// On first borrow sets the program (AMM PDA) as `u64::MAX` delegate
    /// on both TEE ATAs so the program can always recall tokens for LP
    /// withdrawals.
    pub fn borrow_from_pool(ctx: Context<Borrow>, amount_a: u64, amount_b: u64) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        require!(amount_a > 0 || amount_b > 0, PrivacyError::NoOpBorrowRepay);

        let pool = &ctx.accounts.pool;
        let ledger = &ctx.accounts.borrow_ledger;
        let max_bps = ledger.max_borrow_bps as u128;

        if amount_a > 0 {
            let effective = (pool.reserve_a as u128)
                .checked_add(ledger.borrowed_a as u128)
                .ok_or(PrivacyError::MathOverflow)?;
            let new_borrowed = (ledger.borrowed_a as u128)
                .checked_add(amount_a as u128)
                .ok_or(PrivacyError::MathOverflow)?;
            require!(
                new_borrowed <= effective.checked_mul(max_bps).ok_or(PrivacyError::MathOverflow)? / 10_000,
                PrivacyError::BorrowCapExceeded
            );
        }
        if amount_b > 0 {
            let effective = (pool.reserve_b as u128)
                .checked_add(ledger.borrowed_b as u128)
                .ok_or(PrivacyError::MathOverflow)?;
            let new_borrowed = (ledger.borrowed_b as u128)
                .checked_add(amount_b as u128)
                .ok_or(PrivacyError::MathOverflow)?;
            require!(
                new_borrowed <= effective.checked_mul(max_bps).ok_or(PrivacyError::MathOverflow)? / 10_000,
                PrivacyError::BorrowCapExceeded
            );
        }

        let first_borrow = ledger.borrowed_a == 0 && ledger.borrowed_b == 0;

        let bump = ctx.bumps.amm;
        let signer: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];

        if amount_a > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.vault_a.to_account_info(),
                        to: ctx.accounts.tee_ata_a.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                amount_a,
            )?;
        }
        if amount_b > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.vault_b.to_account_info(),
                        to: ctx.accounts.tee_ata_b.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                amount_b,
            )?;
        }

        if first_borrow {
            token::approve(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Approve {
                        to: ctx.accounts.tee_ata_a.to_account_info(),
                        delegate: ctx.accounts.amm.to_account_info(),
                        authority: ctx.accounts.tee_authority.to_account_info(),
                    },
                ),
                u64::MAX,
            )?;
            token::approve(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Approve {
                        to: ctx.accounts.tee_ata_b.to_account_info(),
                        delegate: ctx.accounts.amm.to_account_info(),
                        authority: ctx.accounts.tee_authority.to_account_info(),
                    },
                ),
                u64::MAX,
            )?;
        }

        let pool = &mut ctx.accounts.pool;
        pool.reserve_a = pool.reserve_a.checked_sub(amount_a).ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool.reserve_b.checked_sub(amount_b).ok_or(PrivacyError::MathOverflow)?;

        let ledger = &mut ctx.accounts.borrow_ledger;
        ledger.borrowed_a = ledger.borrowed_a.checked_add(amount_a).ok_or(PrivacyError::MathOverflow)?;
        ledger.borrowed_b = ledger.borrowed_b.checked_add(amount_b).ok_or(PrivacyError::MathOverflow)?;

        ctx.accounts.vault_a.reload()?;
        ctx.accounts.vault_b.reload()?;
        require!(
            pool.reserve_a <= ctx.accounts.vault_a.amount
                && pool.reserve_b <= ctx.accounts.vault_b.amount,
            PrivacyError::InsufficientPoolBalance
        );

        msg!("borrow ok");
        Ok(())
    }

    /// Repay borrowed tokens from TEE wallet back to pool vaults.
    ///
    /// Principal-only: `amount_x <= ledger.borrowed_x`. TEE keeps profits.
    pub fn repay_to_pool(ctx: Context<Repay>, amount_a: u64, amount_b: u64) -> Result<()> {
        require!(amount_a > 0 || amount_b > 0, PrivacyError::NoOpBorrowRepay);

        let ledger = &ctx.accounts.borrow_ledger;
        require!(amount_a <= ledger.borrowed_a, PrivacyError::NothingToRepay);
        require!(amount_b <= ledger.borrowed_b, PrivacyError::NothingToRepay);

        if amount_a > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.tee_ata_a.to_account_info(),
                        to: ctx.accounts.vault_a.to_account_info(),
                        authority: ctx.accounts.tee_authority.to_account_info(),
                    },
                ),
                amount_a,
            )?;
        }
        if amount_b > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.tee_ata_b.to_account_info(),
                        to: ctx.accounts.vault_b.to_account_info(),
                        authority: ctx.accounts.tee_authority.to_account_info(),
                    },
                ),
                amount_b,
            )?;
        }

        let pool = &mut ctx.accounts.pool;
        pool.reserve_a = pool.reserve_a.checked_add(amount_a).ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool.reserve_b.checked_add(amount_b).ok_or(PrivacyError::MathOverflow)?;

        let ledger = &mut ctx.accounts.borrow_ledger;
        ledger.borrowed_a = ledger.borrowed_a.checked_sub(amount_a).ok_or(PrivacyError::MathOverflow)?;
        ledger.borrowed_b = ledger.borrowed_b.checked_sub(amount_b).ok_or(PrivacyError::MathOverflow)?;

        msg!("repay ok");
        Ok(())
    }


    /// Update max borrow cap on a borrow ledger. Admin-only.
    ///
    /// Allows governance to keep borrow disabled (`0`) at deploy time and
    /// enable later without redeploy.
    pub fn set_max_borrow_bps(ctx: Context<SetMaxBorrowBps>, new_max_borrow_bps: u16) -> Result<()> {
        require!(
            new_max_borrow_bps <= BorrowLedger::MAX_BPS,
            PrivacyError::BorrowCapExceeded
        );

        ctx.accounts.borrow_ledger.max_borrow_bps = new_max_borrow_bps;

        msg!("Max borrow cap updated to {} bps", new_max_borrow_bps);
        Ok(())
    }

}

// =============================================================================
//  Tests
// =============================================================================

#[cfg(test)]
mod tests {
    // -- Helpers replicating on-chain math for isolated testing ----------------

    /// Mirrors the withdrawal split math from `withdraw_liquidity`.
    fn compute_withdrawal(
        shares: u64,
        total_shares: u64,
        reserve_a: u64,
        reserve_b: u64,
        borrowed_a: u64,
        borrowed_b: u64,
    ) -> (u64, u64, u64, u64) {
        let ts = total_shares as u128;
        let from_vault_a = ((shares as u128) * (reserve_a as u128) / ts) as u64;
        let from_vault_b = ((shares as u128) * (reserve_b as u128) / ts) as u64;
        let from_tee_a = ((shares as u128) * (borrowed_a as u128) / ts) as u64;
        let from_tee_b = ((shares as u128) * (borrowed_b as u128) / ts) as u64;
        (from_vault_a, from_vault_b, from_tee_a, from_tee_b)
    }

    /// Mirrors the borrow cap check from `borrow_from_pool`.
    fn borrow_allowed(
        reserve: u64,
        already_borrowed: u64,
        new_amount: u64,
        max_borrow_bps: u16,
    ) -> bool {
        let effective = (reserve as u128) + (already_borrowed as u128);
        let new_borrowed = (already_borrowed as u128) + (new_amount as u128);
        new_borrowed <= effective * (max_borrow_bps as u128) / 10_000
    }

    // -- Withdrawal math tests ------------------------------------------------

    #[test]
    fn withdraw_no_borrows() {
        let (fv_a, fv_b, ft_a, ft_b) =
            compute_withdrawal(100, 1_000, 5_000_000, 10_000_000, 0, 0);
        assert_eq!(fv_a, 500_000);
        assert_eq!(fv_b, 1_000_000);
        assert_eq!(ft_a, 0);
        assert_eq!(ft_b, 0);
    }

    #[test]
    fn withdraw_full_shares_no_borrows() {
        let (fv_a, fv_b, ft_a, ft_b) =
            compute_withdrawal(1_000, 1_000, 5_000_000, 10_000_000, 0, 0);
        assert_eq!(fv_a, 5_000_000);
        assert_eq!(fv_b, 10_000_000);
        assert_eq!(ft_a, 0);
        assert_eq!(ft_b, 0);
    }

    #[test]
    fn withdraw_with_50pct_borrow() {
        // reserve=500, borrowed=500 → effective=1000 per side.
        // 50% of shares → 250 from vault, 250 from TEE.
        let (fv_a, fv_b, ft_a, ft_b) =
            compute_withdrawal(500, 1_000, 500, 500, 500, 500);
        assert_eq!(fv_a, 250);
        assert_eq!(fv_b, 250);
        assert_eq!(ft_a, 250);
        assert_eq!(ft_b, 250);
        assert_eq!(fv_a + ft_a, 500); // total payout = effective * shares / total
        assert_eq!(fv_b + ft_b, 500);
    }

    #[test]
    fn withdraw_full_shares_with_borrows() {
        let (fv_a, fv_b, ft_a, ft_b) =
            compute_withdrawal(1_000, 1_000, 3_000, 7_000, 2_000, 3_000);
        assert_eq!(fv_a, 3_000);
        assert_eq!(fv_b, 7_000);
        assert_eq!(ft_a, 2_000);
        assert_eq!(ft_b, 3_000);
    }

    #[test]
    fn withdraw_single_sided_borrow() {
        // Only side A has borrows.
        let (fv_a, fv_b, ft_a, ft_b) =
            compute_withdrawal(100, 1_000, 8_000, 10_000, 2_000, 0);
        assert_eq!(fv_a, 800);
        assert_eq!(fv_b, 1_000);
        assert_eq!(ft_a, 200);
        assert_eq!(ft_b, 0);
        // Total payout on A = 800 + 200 = 1000 = 10% of effective(10_000).
        assert_eq!(fv_a + ft_a, 1_000);
    }

    #[test]
    fn withdraw_rounding_floors_to_zero() {
        // 1 share out of 3 with reserve=1: 1*1/3 = 0 (floor).
        let (fv_a, _, ft_a, _) = compute_withdrawal(1, 3, 1, 0, 1, 0);
        assert_eq!(fv_a, 0);
        assert_eq!(ft_a, 0);
    }

    #[test]
    fn withdraw_rounding_odd_division() {
        // 1 share out of 3 with reserve=10: 10/3 = 3 (floor).
        let (fv_a, _, ft_a, _) = compute_withdrawal(1, 3, 10, 0, 5, 0);
        assert_eq!(fv_a, 3);
        assert_eq!(ft_a, 1);
    }

    #[test]
    fn withdraw_rounding_always_floors() {
        // 333 shares out of 1000 with reserve=1000: 333*1000/1000 = 333.
        // borrowed=999: 333*999/1000 = 332 (floor).
        let (fv_a, _, ft_a, _) = compute_withdrawal(333, 1_000, 1_000, 0, 999, 0);
        assert_eq!(fv_a, 333);
        assert_eq!(ft_a, 332);
    }

    #[test]
    fn withdraw_dust_amounts() {
        let (fv_a, fv_b, ft_a, ft_b) = compute_withdrawal(1, 1_000_000, 1, 1, 1, 1);
        assert_eq!(fv_a, 0);
        assert_eq!(fv_b, 0);
        assert_eq!(ft_a, 0);
        assert_eq!(ft_b, 0);
    }

    #[test]
    fn withdraw_large_reserves_no_overflow() {
        let max = u64::MAX / 2;
        let (fv_a, _, ft_a, _) = compute_withdrawal(1, 2, max, 0, max, 0);
        // 1 * max / 2 = max/2 (u128 intermediate avoids overflow).
        assert_eq!(fv_a, max / 2);
        assert_eq!(ft_a, max / 2);
    }

    #[test]
    fn withdraw_max_u64_shares_and_reserves() {
        // shares = total_shares = 1 (single LP), reserves at near-max.
        let r = u64::MAX - 1;
        let b = 1u64;
        let (fv_a, _, ft_a, _) = compute_withdrawal(1, 1, r, 0, b, 0);
        assert_eq!(fv_a, r);
        assert_eq!(ft_a, b);
    }

    #[test]
    fn withdraw_lp_value_preserved_across_borrow() {
        // Before borrow: reserve=1000, borrowed=0, shares=100.
        // LP value per share = 1000/100 = 10.
        // After borrow 400: reserve=600, borrowed=400, shares=100.
        // LP effective per share = (600+400)/100 = 10. Same.
        let (fv_a, _, ft_a, _) = compute_withdrawal(10, 100, 600, 0, 400, 0);
        assert_eq!(fv_a + ft_a, 100); // 10 shares × 10 value = 100
    }

    #[test]
    fn withdraw_multiple_lps_fair_split() {
        // Two LPs with 500 shares each, total=1000.
        // reserve=3000, borrowed=2000.
        let (fv1, _, ft1, _) = compute_withdrawal(500, 1_000, 3_000, 0, 2_000, 0);
        let (fv2, _, ft2, _) = compute_withdrawal(500, 1_000, 3_000, 0, 2_000, 0);
        assert_eq!(fv1, fv2);
        assert_eq!(ft1, ft2);
        assert_eq!(fv1 + ft1, 2_500); // 50% of effective 5000
    }

    #[test]
    fn withdraw_sequential_preserves_proportions() {
        // LP1 withdraws 200/1000, then LP2 withdraws 200/800 of remaining.
        let total = 1_000u64;
        let reserve = 6_000u64;
        let borrowed = 4_000u64;

        // LP1 withdraws.
        let (fv1, _, ft1, _) = compute_withdrawal(200, total, reserve, 0, borrowed, 0);
        assert_eq!(fv1, 1_200);
        assert_eq!(ft1, 800);

        // State after LP1.
        let total2 = total - 200;
        let reserve2 = reserve - fv1;
        let borrowed2 = borrowed - ft1;

        // LP2 withdraws same shares from updated state.
        let (fv2, _, ft2, _) = compute_withdrawal(200, total2, reserve2, 0, borrowed2, 0);
        // Effective per share unchanged: (4800+3200)/800 = 10.
        assert_eq!(fv2 + ft2, 2_000); // 200/800 * 8000 = 2000
    }

    // -- Borrow cap tests -----------------------------------------------------

    #[test]
    fn borrow_cap_at_zero() {
        assert!(!borrow_allowed(1_000, 0, 1, 0));
    }

    #[test]
    fn borrow_cap_50pct_exact_limit() {
        // effective=1000, cap=50%. Max borrowed = 500.
        assert!(borrow_allowed(1_000, 0, 500, 5_000));
        assert!(!borrow_allowed(1_000, 0, 501, 5_000));
    }

    #[test]
    fn borrow_cap_50pct_incremental() {
        // Already borrowed 200, reserve=800, effective=1000.
        // Cap = 500. Can borrow 300 more.
        assert!(borrow_allowed(800, 200, 300, 5_000));
        assert!(!borrow_allowed(800, 200, 301, 5_000));
    }

    #[test]
    fn borrow_cap_effective_grows_with_borrows() {
        // At 50% cap: borrowed <= effective * 0.5.
        // reserve=500, borrowed=500 → effective=1000, cap=500. Exactly at limit.
        assert!(borrow_allowed(500, 500, 0, 5_000));
        assert!(!borrow_allowed(500, 500, 1, 5_000));
    }

    #[test]
    fn borrow_cap_low_bps() {
        // 10% cap (1000 bps). effective=1000. Max borrowed = 100.
        assert!(borrow_allowed(1_000, 0, 100, 1_000));
        assert!(!borrow_allowed(1_000, 0, 101, 1_000));
    }

    #[test]
    fn borrow_cap_large_reserves() {
        let reserve = 1_000_000_000_000u64; // 1T
        assert!(borrow_allowed(reserve, 0, reserve / 2, 5_000));
        assert!(!borrow_allowed(reserve, 0, reserve / 2 + 1, 5_000));
    }

    // -- Repay validation tests -----------------------------------------------

    #[test]
    fn repay_exact_balance() {
        let borrowed = 500u64;
        let repay = 500u64;
        assert!(repay <= borrowed);
    }

    #[test]
    fn repay_partial() {
        let borrowed = 500u64;
        let repay = 200u64;
        assert!(repay <= borrowed);
        assert_eq!(borrowed - repay, 300);
    }

    #[test]
    fn repay_exceeds_borrowed() {
        let borrowed = 500u64;
        let repay = 501u64;
        assert!(repay > borrowed);
    }

    // -- State update invariants ----------------------------------------------

    #[test]
    fn state_after_borrow() {
        let reserve = 10_000u64;
        let borrowed = 0u64;
        let amount = 4_000u64;

        let new_reserve = reserve - amount;
        let new_borrowed = borrowed + amount;

        assert_eq!(new_reserve, 6_000);
        assert_eq!(new_borrowed, 4_000);
        // Effective unchanged.
        assert_eq!(new_reserve + new_borrowed, reserve + borrowed);
    }

    #[test]
    fn state_after_repay() {
        let reserve = 6_000u64;
        let borrowed = 4_000u64;
        let amount = 2_000u64;

        let new_reserve = reserve + amount;
        let new_borrowed = borrowed - amount;

        assert_eq!(new_reserve, 8_000);
        assert_eq!(new_borrowed, 2_000);
        assert_eq!(new_reserve + new_borrowed, reserve + borrowed);
    }

    #[test]
    fn state_after_withdrawal_with_borrows() {
        let total_shares = 1_000u64;
        let reserve = 6_000u64;
        let borrowed = 4_000u64;
        let shares = 100u64;

        let (from_vault, _, from_tee, _) =
            compute_withdrawal(shares, total_shares, reserve, 0, borrowed, 0);

        let new_reserve = reserve - from_vault;
        let new_borrowed = borrowed - from_tee;
        let new_total = total_shares - shares;

        // Effective per share should remain constant (floor rounding aside).
        let eff_before = (reserve + borrowed) as u128 * 10_000 / total_shares as u128;
        let eff_after = (new_reserve + new_borrowed) as u128 * 10_000 / new_total as u128;
        // Allow ±1 for rounding.
        assert!((eff_before as i128 - eff_after as i128).unsigned_abs() <= 1);
    }

    #[test]
    fn effective_per_share_stable_through_borrow_cycle() {
        let total_shares = 1_000u64;
        let initial_reserve = 10_000u64;

        // Before borrow.
        let eff0 = initial_reserve as u128 * 10_000 / total_shares as u128;

        // After borrow 3000.
        let reserve1 = initial_reserve - 3_000;
        let borrowed1 = 3_000u64;
        let eff1 = (reserve1 + borrowed1) as u128 * 10_000 / total_shares as u128;
        assert_eq!(eff0, eff1);

        // After repay 1000.
        let reserve2 = reserve1 + 1_000;
        let borrowed2 = borrowed1 - 1_000;
        let eff2 = (reserve2 + borrowed2) as u128 * 10_000 / total_shares as u128;
        assert_eq!(eff0, eff2);

        // After withdrawal of 100 shares.
        let (fv, _, ft, _) = compute_withdrawal(100, total_shares, reserve2, 0, borrowed2, 0);
        let reserve3 = reserve2 - fv;
        let borrowed3 = borrowed2 - ft;
        let total3 = total_shares - 100;
        let eff3 = (reserve3 + borrowed3) as u128 * 10_000 / total3 as u128;
        assert!((eff0 as i128 - eff3 as i128).unsigned_abs() <= 1);
    }

    // -- Gap coverage: floor division safety ----------------------------------

    #[test]
    fn floor_split_never_exceeds_effective_payout() {
        // For all tested cases: from_vault + from_tee <= shares * effective / total_shares.
        let cases: Vec<(u64, u64, u64, u64)> = vec![
            (333, 1_000, 7_777, 2_223),
            (1, 3, 10, 5),
            (999, 1_000, 1, 999_999),
            (17, 31, 12_345, 67_890),
            (1, 1_000_000, 999_999, 1),
        ];
        for (shares, total, reserve, borrowed) in cases {
            let ts = total as u128;
            let effective = (reserve as u128) + (borrowed as u128);
            let effective_payout = ((shares as u128) * effective / ts) as u64;
            let (fv, _, ft, _) = compute_withdrawal(shares, total, reserve, 0, borrowed, 0);
            assert!(
                fv + ft <= effective_payout,
                "fv({fv}) + ft({ft}) > eff({effective_payout}) for shares={shares} total={total} res={reserve} bor={borrowed}"
            );
        }
    }

    // -- Gap coverage: zero reserve (everything borrowed to cap) ---------------

    #[test]
    fn withdraw_zero_reserve_all_from_tee() {
        // reserve=0, borrowed=1000 (extreme case: vault empty).
        let (fv_a, _, ft_a, _) = compute_withdrawal(500, 1_000, 0, 0, 1_000, 0);
        assert_eq!(fv_a, 0);
        assert_eq!(ft_a, 500);
    }

    #[test]
    fn withdraw_near_zero_reserve() {
        // reserve=1, borrowed=999 (almost all borrowed).
        let (fv_a, _, ft_a, _) = compute_withdrawal(100, 1_000, 1, 0, 999, 0);
        assert_eq!(fv_a, 0); // 100*1/1000 = 0 (floor)
        assert_eq!(ft_a, 99); // 100*999/1000 = 99 (floor)
    }

    // -- Gap coverage: full drain by all LPs ----------------------------------

    #[test]
    fn full_drain_no_negative_dust() {
        let mut total_shares = 1_000u64;
        let mut reserve = 7_777u64;
        let mut borrowed = 3_333u64;

        // 10 LPs each with 100 shares withdraw sequentially.
        for _ in 0..10 {
            let (fv, _, ft, _) =
                compute_withdrawal(100, total_shares, reserve, 0, borrowed, 0);
            assert!(fv <= reserve, "from_vault exceeds reserve");
            assert!(ft <= borrowed, "from_tee exceeds borrowed");
            reserve -= fv;
            borrowed -= ft;
            total_shares -= 100;
        }
        assert_eq!(total_shares, 0);
        // Dust must be non-negative (can't go below zero).
        // Small dust is expected from floor rounding.
        assert!(reserve <= 9, "reserve dust too large: {reserve}");
        assert!(borrowed <= 9, "borrowed dust too large: {borrowed}");
    }

    #[test]
    fn full_drain_unequal_shares() {
        let mut total_shares = 1_000u64;
        let mut reserve = 10_000u64;
        let mut borrowed = 5_000u64;

        let withdrawals = [100, 250, 50, 300, 200, 100];
        for shares in withdrawals {
            let (fv, _, ft, _) =
                compute_withdrawal(shares, total_shares, reserve, 0, borrowed, 0);
            assert!(fv <= reserve);
            assert!(ft <= borrowed);
            reserve -= fv;
            borrowed -= ft;
            total_shares -= shares;
        }
        assert_eq!(total_shares, 0);
        assert!(reserve <= 5, "reserve dust: {reserve}");
        assert!(borrowed <= 5, "borrowed dust: {borrowed}");
    }

    // -- Gap coverage: borrow cap rounding ------------------------------------

    #[test]
    fn borrow_cap_odd_effective_rounding() {
        // effective=999, cap=50%. 999*5000/10000 = 499 (floor).
        assert!(borrow_allowed(999, 0, 499, 5_000));
        assert!(!borrow_allowed(999, 0, 500, 5_000));
    }

    #[test]
    fn borrow_cap_one_lamport_boundary() {
        // effective=1, cap=50%. 1*5000/10000 = 0 (floor). Can't borrow anything.
        assert!(!borrow_allowed(1, 0, 1, 5_000));
        // effective=2, cap=50%. 2*5000/10000 = 1.
        assert!(borrow_allowed(2, 0, 1, 5_000));
        assert!(!borrow_allowed(2, 0, 2, 5_000));
    }

    // -- Gap coverage: borrow → partial repay → re-borrow ---------------------

    #[test]
    fn borrow_repay_reborrow_cap_consistent() {
        let initial_reserve = 10_000u64;
        let max_bps = 5_000u16;

        // Borrow 5000 (50% of effective 10000).
        let borrow1 = 5_000u64;
        assert!(borrow_allowed(initial_reserve, 0, borrow1, max_bps));
        let reserve1 = initial_reserve - borrow1;
        let borrowed1 = borrow1;

        // Repay 2000.
        let repay = 2_000u64;
        let reserve2 = reserve1 + repay;
        let borrowed2 = borrowed1 - repay;
        // effective unchanged: 10000.

        // Re-borrow: can borrow up to 5000 total → 2000 more.
        assert!(borrow_allowed(reserve2, borrowed2, 2_000, max_bps));
        assert!(!borrow_allowed(reserve2, borrowed2, 2_001, max_bps));
    }

    #[test]
    fn borrow_full_repay_full_reborrow() {
        let reserve = 10_000u64;
        let max_bps = 5_000u16;

        // Borrow max.
        assert!(borrow_allowed(reserve, 0, 5_000, max_bps));
        let r1 = reserve - 5_000;
        let b1 = 5_000u64;

        // Full repay.
        let r2 = r1 + 5_000;
        let b2 = b1 - 5_000;
        assert_eq!(r2, reserve);
        assert_eq!(b2, 0);

        // Re-borrow max again.
        assert!(borrow_allowed(r2, b2, 5_000, max_bps));
    }

    // -- Gap coverage: near-u64::MAX on both sides ----------------------------

    #[test]
    fn withdraw_both_sides_near_max() {
        let big = u64::MAX / 4;
        let (fv_a, fv_b, ft_a, ft_b) = compute_withdrawal(1, 2, big, big, big, big);
        assert_eq!(fv_a, big / 2);
        assert_eq!(fv_b, big / 2);
        assert_eq!(ft_a, big / 2);
        assert_eq!(ft_b, big / 2);
    }

    #[test]
    fn withdraw_u128_multiplication_ceiling() {
        // shares=u64::MAX, total=u64::MAX, reserve=u64::MAX.
        // Result: u64::MAX * u64::MAX / u64::MAX = u64::MAX. No overflow in u128.
        let m = u64::MAX;
        let (fv_a, _, ft_a, _) = compute_withdrawal(m, m, m, 0, m, 0);
        assert_eq!(fv_a, m);
        assert_eq!(ft_a, m);
    }

    #[test]
    fn withdraw_large_shares_small_total() {
        // shares close to total, large reserves + borrows.
        let total = 1_000_000u64;
        let shares = 999_999u64;
        let reserve = u64::MAX / 8;
        let borrowed = u64::MAX / 8;
        let (fv, _, ft, _) = compute_withdrawal(shares, total, reserve, 0, borrowed, 0);
        // Should be very close to reserve/borrowed (off by ~reserve/1M).
        let expected_fv = ((shares as u128) * (reserve as u128) / (total as u128)) as u64;
        assert_eq!(fv, expected_fv);
        let expected_ft = ((shares as u128) * (borrowed as u128) / (total as u128)) as u64;
        assert_eq!(ft, expected_ft);
    }
}
