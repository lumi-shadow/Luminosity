//! Solana Privacy Pool – Anchor program.
//!
//! One global concurrent Merkle tree stores note commitments.
//! - Deposits append commitments to the tree.
//! - Swaps tombstone the input leaf and append a fresh output leaf.
//! - Withdrawals verify Groth16 proofs and pay out from shared AMM vaults.
//!
//! Canonical two-layer commitment format (V2):
//!   Layer 1 – noteHash  = keccak256(nullifier ‖ secret)
//!   Layer 2 – commitment = keccak256(noteHash ‖ amountLE8 ‖ assetIdLE4)
//!             (or sharesLE8 ‖ poolIdLE4 for LP notes)

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer as TokenTransfer};
use bincode::Options;
use groth16_solana::groth16::Groth16Verifier;
use solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState};
use spl_concurrent_merkle_tree::concurrent_merkle_tree::ConcurrentMerkleTree;

// --- Modules ---
mod constants;
mod contexts;
mod errors;
mod pmm;
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

declare_id!("p1VaCyyfzodMni1tSYhvUFd3MyGB6sb6NRFWPixXD54");

// =============================================================================
//  Helpers (private, used only by instruction handlers)
// =============================================================================

/// Big-endian 32-byte field element from a byte slice.
fn to_field_element(slice: &[u8]) -> [u8; 32] {
    let mut elem = [0u8; 32];
    elem[32 - slice.len()..].copy_from_slice(slice);
    elem
}

/// Validate a Merkle root against the SPL tree changelog buffer.
fn require_valid_root(merkle_tree: &AccountInfo, root: &[u8; 32]) -> Result<()> {
    let data = merkle_tree.try_borrow_data()?;
    let tree_end = SPL_TREE_DATA_OFFSET
        + std::mem::size_of::<ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>>();
    if data.len() < tree_end {
        return err!(PrivacyError::TreeDeserializationFailed);
    }
    let tree = bytemuck::try_from_bytes::<
        ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
    >(&data[SPL_TREE_DATA_OFFSET..tree_end])
    .map_err(|_| PrivacyError::TreeDeserializationFailed)?;

    require!(
        tree.change_logs.iter().any(|e| e.root == *root),
        PrivacyError::InvalidMerkleRoot
    );
    Ok(())
}

/// Read the latest output leaf index after an append, and increment `total_deposits`.
fn post_append_update(
    merkle_tree: &AccountInfo,
    amm: &mut Amm,
) -> Result<u64> {
    let leaf_index = amm.total_deposits;
    amm.total_deposits = amm
        .total_deposits
        .checked_add(1)
        .ok_or(PrivacyError::MathOverflow)?;
    // Read the new root to keep the SPL tree changelog consistent; the root is not
    // persisted separately—root acceptance relies on the SPL tree changelog itself.
    let _new_root = {
        let data = merkle_tree.try_borrow_data()?;
        let tree_end = SPL_TREE_DATA_OFFSET
            + std::mem::size_of::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >();
        if data.len() < tree_end {
            return err!(PrivacyError::TreeDeserializationFailed);
        }
        let tree = bytemuck::try_from_bytes::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >(&data[SPL_TREE_DATA_OFFSET..tree_end])
        .map_err(|_| PrivacyError::TreeDeserializationFailed)?;
        let seq = tree.active_index;
        let idx = if seq > 0 { (seq - 1) as usize % 64 } else { 63 };
        tree.change_logs[idx].root
    };
    Ok(leaf_index)
}

/// Build + invoke the SPL Compression `Append` CPI.
fn cpi_spl_append<'a>(
    compression_program: &AccountInfo<'a>,
    merkle_tree: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    noop: &AccountInfo<'a>,
    commitment: &[u8; 32],
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = SPL_APPEND_DISCRIMINATOR.to_vec();
    data.extend_from_slice(commitment);
    let ix = solana_program::instruction::Instruction {
        program_id: compression_program.key(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new(merkle_tree.key(), false),
            solana_program::instruction::AccountMeta::new_readonly(authority.key(), true),
            solana_program::instruction::AccountMeta::new_readonly(noop.key(), false),
        ],
        data,
    };
    solana_program::program::invoke_signed(
        &ix,
        &[
            compression_program.clone(),
            merkle_tree.clone(),
            authority.clone(),
            noop.clone(),
        ],
        signer_seeds,
    )?;
    Ok(())
}

/// Build + invoke the SPL Compression `replace_leaf` CPI (tombstone).
fn cpi_spl_replace_leaf<'a>(
    compression_program: &AccountInfo<'a>,
    merkle_tree: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    noop: &AccountInfo<'a>,
    root: &[u8; 32],
    previous_leaf: &[u8; 32],
    index: u32,
    proof_accounts: &[AccountInfo<'a>],
    all_infos: &[AccountInfo<'a>],
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(8 + 32 + 32 + 32 + 4);
    data.extend_from_slice(&SPL_REPLACE_LEAF_DISCRIMINATOR);
    data.extend_from_slice(root);
    data.extend_from_slice(previous_leaf);
    data.extend_from_slice(&[0u8; 32]); // tombstone leaf
    data.extend_from_slice(&index.to_le_bytes());

    let mut metas = vec![
        solana_program::instruction::AccountMeta::new(merkle_tree.key(), false),
        solana_program::instruction::AccountMeta::new_readonly(authority.key(), true),
        solana_program::instruction::AccountMeta::new_readonly(noop.key(), false),
    ];
    for acc in proof_accounts {
        metas.push(solana_program::instruction::AccountMeta::new_readonly(
            acc.key(),
            false,
        ));
    }

    let ix = solana_program::instruction::Instruction {
        program_id: compression_program.key(),
        accounts: metas,
        data,
    };
    solana_program::program::invoke_signed(&ix, all_infos, signer_seeds)?;
    Ok(())
}

/// Validate + mark a leaf as spent in the bitmap shard. Returns (byte_index, mask).
fn validate_and_mark_spent(
    shard: &mut SpentBitmapShard,
    leaf_index: u32,
) -> Result<()> {
    require_leaf_index_in_range(leaf_index)?;
    let shard_index: u32 = leaf_index / SPENT_BITMAP_SHARD_BITS;
    let max_shard = max_spent_shard_index_u32()?;
    require!(shard_index <= max_shard, PrivacyError::ShardIndexOutOfRange);

    let bit_in_shard = leaf_index % SPENT_BITMAP_SHARD_BITS;
    let byte_i = (bit_in_shard / 8) as usize;
    let mask = 1u8 << (bit_in_shard % 8);
    require!(byte_i < SPENT_BITMAP_SHARD_BYTES, PrivacyError::MathOverflow);
    require!((shard.bits[byte_i] & mask) == 0, PrivacyError::AlreadySpent);
    shard.bits[byte_i] |= mask;
    Ok(())
}

/// Same as above but only checks (does NOT set the bit). For two-phase patterns where
/// the CPI must succeed before marking spent.
fn validate_not_spent(
    shard: &SpentBitmapShard,
    leaf_index: u32,
) -> Result<(usize, u8)> {
    require_leaf_index_in_range(leaf_index)?;
    let shard_index: u32 = leaf_index / SPENT_BITMAP_SHARD_BITS;
    let max_shard = max_spent_shard_index_u32()?;
    require!(shard_index <= max_shard, PrivacyError::ShardIndexOutOfRange);

    let bit_in_shard = leaf_index % SPENT_BITMAP_SHARD_BITS;
    let byte_i = (bit_in_shard / 8) as usize;
    let mask = 1u8 << (bit_in_shard % 8);
    require!(byte_i < SPENT_BITMAP_SHARD_BYTES, PrivacyError::MathOverflow);
    require!((shard.bits[byte_i] & mask) == 0, PrivacyError::AlreadySpent);
    Ok((byte_i, mask))
}

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

    /// Rotate the TEE / relayer authority key.
    pub fn rotate_tee_authority(ctx: Context<RotateTeeAuthority>, new_tee_authority: Pubkey) -> Result<()> {
        require!(new_tee_authority != Pubkey::default(), PrivacyError::InvalidTEEAuthority);
        ctx.accounts.amm.tee_authority = new_tee_authority;
        msg!("TEE authority rotated to {}", new_tee_authority);
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
        // V2 fields — defaults; configure via `configure_pool`.
        pool.oracle_a = Pubkey::default();
        pool.oracle_b = Pubkey::default();
        pool.dec_a = ctx.accounts.mint_a.decimals;
        pool.dec_b = ctx.accounts.mint_b.decimals;
        pool.fee_bps = 0;
        pool.pmm = PmmConfig::default();

        let _pool_id = registry_alloc_and_register_pool(reg, pool_key)?;
        Ok(())
    }

    /// Configure pool V2 fields (oracle feeds, fee, PMM policy). Admin-only.
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
        let max_leaves = max_tree_leaves_u64()?;
        require!(ctx.accounts.amm.total_deposits < max_leaves, PrivacyError::TreeFull);
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        require!(amount > 0, PrivacyError::ZeroDepositAmount);
        require!(commitment != [0u8; 32], PrivacyError::InvalidCommitment);
        require!(ctx.accounts.registry.is_initialized, PrivacyError::RegistryNotInitialized);
        require!(
            ctx.accounts.merkle_tree.owner == &contexts::SplCompression::id(),
            PrivacyError::InvalidTreeOwner
        );
        require!(ctx.accounts.user_source.amount >= amount, PrivacyError::InsufficientUserBalance);

        // 0) Verify Groth16 proof — binds (commitment, amount, asset_id).
        let asset_id = registry_asset_id_for_mint(&ctx.accounts.registry, ctx.accounts.mint.key())
            .ok_or(PrivacyError::AssetNotRegistered)?;

        let mut amount_be = [0u8; 32];
        amount_be[24..].copy_from_slice(&amount.to_be_bytes());
        let mut asset_be = [0u8; 32];
        asset_be[28..].copy_from_slice(&asset_id.to_be_bytes());

        let public_inputs: [[u8; 32]; 4] = [
            to_field_element(&commitment[0..16]),
            to_field_element(&commitment[16..32]),
            amount_be,
            asset_be,
        ];
        if VERIFYINGKEY_DEPOSIT_ASSET_BIND.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<4>::new(
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

        // 2) Append commitment to the tree.
        let bump = ctx.bumps.amm;
        let seeds: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];
        cpi_spl_append(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.amm.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &commitment,
            seeds,
        )?;

        // 3) Update deposit counter.
        let leaf_index = post_append_update(
            &ctx.accounts.merkle_tree.to_account_info(),
            &mut ctx.accounts.amm,
        )?;

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

        // 0) Verify Groth16 proof — binds (commitment, shares, pool_id).
        let pool_id = registry_pool_id_for_pool(&ctx.accounts.registry, ctx.accounts.pool.key())
            .ok_or(PrivacyError::PoolNotRegistered)?;

        let mut shares_be = [0u8; 32];
        shares_be[24..].copy_from_slice(&expected_shares.to_be_bytes());
        let mut pool_be = [0u8; 32];
        pool_be[28..].copy_from_slice(&pool_id.to_be_bytes());

        let public_inputs: [[u8; 32]; 4] = [
            to_field_element(&commitment[0..16]),
            to_field_element(&commitment[16..32]),
            shares_be,
            pool_be,
        ];
        if VERIFYINGKEY_DEPOSIT_LIQUIDITY_BIND.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<4>::new(
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

        // 2) Append LP note to the tree.
        let bump = ctx.bumps.amm;
        let seeds: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];
        cpi_spl_append(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.amm.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &commitment,
            seeds,
        )?;

        // 3) Update deposit counter.
        let leaf_index = post_append_update(
            &ctx.accounts.merkle_tree.to_account_info(),
            &mut ctx.accounts.amm,
        )?;

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
            require!(reserve_a_before > 0 && reserve_b_before > 0, PrivacyError::InvalidReserves);

            // Enforce correct ratio (±1 rounding tolerance).
            let ra = reserve_a_before as u128;
            let rb = reserve_b_before as u128;
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
                / (reserve_a_before as u128);
            let share_b = (amount_b as u128)
                .checked_mul(total_before as u128).ok_or(PrivacyError::MathOverflow)?
                / (reserve_b_before as u128);
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

        // 1) Validate Merkle root.
        require_valid_root(&ctx.accounts.merkle_tree.to_account_info(), &root)?;

        // 2) Verify Groth16 proof (8 public inputs).
        let rec_bytes = ctx.accounts.recipient.key().to_bytes();
        let mut fee_be = [0u8; 32];
        fee_be[24..].copy_from_slice(&relayer_fee.to_be_bytes());
        let mut amount_be = [0u8; 32];
        amount_be[24..].copy_from_slice(&amount.to_be_bytes());
        let mut asset_be = [0u8; 32];
        asset_be[28..].copy_from_slice(&asset_id.to_be_bytes());
        let mut leaf_be = [0u8; 32];
        leaf_be[28..].copy_from_slice(&leaf_index.to_be_bytes());

        let public_inputs: [[u8; 32]; 8] = [
            to_field_element(&root[0..16]),
            to_field_element(&root[16..32]),
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
        let mut verifier = Groth16Verifier::<8>::new(
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

        // 1) Validate Merkle root.
        require_valid_root(&ctx.accounts.merkle_tree.to_account_info(), &root)?;

        // 2) Verify Groth16 proof (8 public inputs).
        let rec_bytes = recipient_owner.to_bytes();
        let mut fee_be = [0u8; 32];
        fee_be[24..].copy_from_slice(&relayer_fee.to_be_bytes());
        let mut shares_be = [0u8; 32];
        shares_be[24..].copy_from_slice(&shares.to_be_bytes());
        let mut pool_be = [0u8; 32];
        pool_be[28..].copy_from_slice(&pool_id.to_be_bytes());
        let mut leaf_be = [0u8; 32];
        leaf_be[28..].copy_from_slice(&leaf_index.to_be_bytes());

        let public_inputs: [[u8; 32]; 8] = [
            to_field_element(&root[0..16]),
            to_field_element(&root[16..32]),
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
        let mut verifier = Groth16Verifier::<8>::new(
            &proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY_LIQUIDITY,
        ).map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 3) Nullify (mark spent).
        validate_and_mark_spent(&mut ctx.accounts.spent_shard, leaf_index)?;

        // 4) Compute payout from shares + virtual reserves.
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

        let amount_a: u64 = u64::try_from(
            (shares as u128).checked_mul(reserve_a as u128).ok_or(PrivacyError::MathOverflow)? / (total_shares as u128),
        ).map_err(|_| PrivacyError::MathOverflow)?;
        let amount_b: u64 = u64::try_from(
            (shares as u128).checked_mul(reserve_b as u128).ok_or(PrivacyError::MathOverflow)? / (total_shares as u128),
        ).map_err(|_| PrivacyError::MathOverflow)?;

        // 5) Transfer out.
        let bump = ctx.bumps.amm;
        let signer: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];

        if amount_a > 0 {
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.amm_vault_a.to_account_info(),
                    to: ctx.accounts.recipient_account_a.to_account_info(),
                    authority: ctx.accounts.amm.to_account_info(),
                }, signer),
                amount_a,
            )?;
        }
        if amount_b > 0 {
            token::transfer(
                CpiContext::new_with_signer(ctx.accounts.token_program.to_account_info(), TokenTransfer {
                    from: ctx.accounts.amm_vault_b.to_account_info(),
                    to: ctx.accounts.recipient_account_b.to_account_info(),
                    authority: ctx.accounts.amm.to_account_info(),
                }, signer),
                amount_b,
            )?;
        }

        // 6) Burn shares + update reserves.
        let pool = &mut ctx.accounts.pool;
        pool.reserve_a = pool.reserve_a.checked_sub(amount_a).ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool.reserve_b.checked_sub(amount_b).ok_or(PrivacyError::MathOverflow)?;
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
        require!(
            ctx.remaining_accounts.len() <= SPL_TREE_MAX_DEPTH,
            PrivacyError::TooManyMerkleProofAccounts
        );

        // Validate leaf not already spent (don't mark yet — wait for CPI success).
        let (byte_i, mask) = validate_not_spent(&ctx.accounts.spent_shard, swap.index)?;

        // Validate Merkle root.
        require_valid_root(&ctx.accounts.merkle_tree.to_account_info(), &swap.root)?;

        // 1) Tombstone the input leaf.
        let bump = ctx.bumps.config;
        let seeds: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];
        let mut all_infos = ctx.accounts.to_account_infos();
        all_infos.extend_from_slice(ctx.remaining_accounts);

        cpi_spl_replace_leaf(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.config.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &swap.root,
            &swap.previous_leaf,
            swap.index,
            ctx.remaining_accounts,
            &all_infos,
            seeds,
        )?;

        // 2) Append the output leaf.
        cpi_spl_append(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.config.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &swap.new_leaf,
            seeds,
        )?;

        // 3) Mark spent (only after both CPIs succeeded).
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

        // 5) Update deposit counter.
        let output_leaf_index = post_append_update(
            &ctx.accounts.merkle_tree.to_account_info(),
            &mut ctx.accounts.config,
        )?;

        emit!(SwapAppendEvent {
            pool: ctx.accounts.pool.key(),
            input_commitment: swap.previous_leaf,
            input_leaf_index: swap.index,
            output_commitment: swap.new_leaf,
            output_leaf_index,
            new_reserve_a: swap.new_reserve_a,
            new_reserve_b: swap.new_reserve_b,
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

        // --- Validate Merkle root ---
        require_valid_root(&ctx.accounts.merkle_tree.to_account_info(), &params.root)?;

        // --- Verify Groth16 proof (swap_zk circuit, 8 public inputs) ---
        let mut amount_in_be = [0u8; 32];
        amount_in_be[24..].copy_from_slice(&amount_in.to_be_bytes());
        let mut asset_in_be = [0u8; 32];
        asset_in_be[28..].copy_from_slice(&asset_id_in.to_be_bytes());
        let mut asset_out_be = [0u8; 32];
        asset_out_be[28..].copy_from_slice(&asset_id_out.to_be_bytes());
        let mut min_out_be = [0u8; 32];
        min_out_be[24..].copy_from_slice(&min_amount_out.to_be_bytes());

        let public_inputs: [[u8; 32]; 8] = [
            to_field_element(&params.input_commitment[0..16]),
            to_field_element(&params.input_commitment[16..32]),
            amount_in_be,
            asset_in_be,
            to_field_element(&params.note_hash_out[0..16]),
            to_field_element(&params.note_hash_out[16..32]),
            asset_out_be,
            min_out_be,
        ];
        if VERIFYINGKEY_SWAP.vk_ic.len() != public_inputs.len() + 1 {
            return err!(PrivacyError::InvalidVerifyingKey);
        }
        let mut verifier = Groth16Verifier::<8>::new(
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

        // --- Compute output commitment (Layer 2) on-chain ---
        let mut preimage = [0u8; 44];
        preimage[0..32].copy_from_slice(&params.note_hash_out);
        preimage[32..40].copy_from_slice(&amount_out.to_le_bytes());
        preimage[40..44].copy_from_slice(&asset_id_out.to_le_bytes());
        let output_commitment = solana_program::keccak::hashv(&[&preimage]).0;

        // --- 1) Tombstone the input leaf ---
        let bump = ctx.bumps.config;
        let seeds: &[&[&[u8]]] = &[&[b"amm".as_ref(), &[bump]]];
        let mut all_infos = ctx.accounts.to_account_infos();
        all_infos.extend_from_slice(ctx.remaining_accounts);

        cpi_spl_replace_leaf(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.config.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &params.root,
            &params.input_commitment,
            params.input_leaf_index,
            ctx.remaining_accounts,
            &all_infos,
            seeds,
        )?;

        // --- 2) Append the output leaf ---
        cpi_spl_append(
            &ctx.accounts.compression_program.to_account_info(),
            &ctx.accounts.merkle_tree.to_account_info(),
            &ctx.accounts.config.to_account_info(),
            &ctx.accounts.noop.to_account_info(),
            &output_commitment,
            seeds,
        )?;

        // --- 3) Mark input leaf as spent ---
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

        // --- 5) Update deposit counter ---
        let output_leaf_index = post_append_update(
            &ctx.accounts.merkle_tree.to_account_info(),
            &mut ctx.accounts.config,
        )?;

        emit!(ZkSwapEvent {
            pool: ctx.accounts.pool.key(),
            input_commitment: params.input_commitment,
            input_leaf_index: params.input_leaf_index,
            output_commitment,
            output_leaf_index,
            amount_in, amount_out,
            asset_id_in, asset_id_out,
            new_reserve_a: ctx.accounts.pool.reserve_a,
            new_reserve_b: ctx.accounts.pool.reserve_b,
            encrypted_note: params.encrypted_note,
        });

        msg!("ZK swap ok");
        Ok(())
    }

    // =========================================================================
    //  Migration
    // =========================================================================

    /// Migrate a V1 Pool account to V2 (adds oracle / PMM fields). Admin-only.
    ///
    /// Safe to call repeatedly (idempotent).
    pub fn migrate_pool_v2(ctx: Context<MigratePoolV2>) -> Result<()> {
        let pool_info = &ctx.accounts.pool;
        let current_len = pool_info.data_len();
        let target_len = Pool::LEN;

        if current_len >= target_len {
            msg!("Pool already at V2 size ({} bytes), skipping", current_len);
            return Ok(());
        }

        // Validate discriminator + AMM key + mint keys manually (V1-sized account).
        {
            let data = pool_info.try_borrow_data()?;
            let expected_disc = <Pool as anchor_lang::Discriminator>::DISCRIMINATOR;
            require!(&data[..8] == expected_disc, PrivacyError::InvalidPoolAmm);

            let amm_bytes: [u8; 32] = data[8..40].try_into().map_err(|_| PrivacyError::MathOverflow)?;
            require!(Pubkey::from(amm_bytes) == ctx.accounts.amm.key(), PrivacyError::InvalidPoolAmm);

            // SECURITY: validate that the caller-supplied mints match the pool's stored mints.
            let mint_a_bytes: [u8; 32] = data[40..72].try_into().map_err(|_| PrivacyError::MathOverflow)?;
            let mint_b_bytes: [u8; 32] = data[72..104].try_into().map_err(|_| PrivacyError::MathOverflow)?;
            require!(
                Pubkey::from(mint_a_bytes) == ctx.accounts.mint_a.key(),
                PrivacyError::InvalidPoolMints
            );
            require!(
                Pubkey::from(mint_b_bytes) == ctx.accounts.mint_b.key(),
                PrivacyError::InvalidPoolMints
            );
        }

        // Top up rent for the larger account.
        let rent = Rent::get()?;
        let new_min = rent.minimum_balance(target_len);
        let current_lamports = pool_info.lamports();
        if current_lamports < new_min {
            let delta = new_min.saturating_sub(current_lamports);
            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.admin.to_account_info(),
                        to: pool_info.to_account_info(),
                    },
                ),
                delta,
            )?;
        }

        pool_info.resize(target_len)?;

        // Write V2 default fields into the newly allocated tail.
        {
            let mut data = pool_info.try_borrow_mut_data()?;
            let defaults = PmmConfig::default();
            let zero_pk = [0u8; 32];

            let mut off = current_len;
            data[off..off + 32].copy_from_slice(&zero_pk); off += 32;     // oracle_a
            data[off..off + 32].copy_from_slice(&zero_pk); off += 32;     // oracle_b
            data[off] = ctx.accounts.mint_a.decimals;       off += 1;     // dec_a
            data[off] = ctx.accounts.mint_b.decimals;       off += 1;     // dec_b
            data[off..off + 2].copy_from_slice(&0u16.to_le_bytes()); off += 2; // fee_bps
            // PmmConfig (9 × u16 = 18 bytes, borsh LE)
            data[off..off + 2].copy_from_slice(&defaults.size_spread_mult_bps.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.conf_spread_mult_bps.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.stale_spread_bps_per_sec.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.max_spread_bps.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&(defaults.skew_k_bps as u16).to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.max_skew_bps.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.skew_small_div_bps.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.cpmm_cap_min_size_bps.to_le_bytes()); off += 2;
            data[off..off + 2].copy_from_slice(&defaults.max_oracle_age_secs.to_le_bytes());
        }

        msg!("Pool migrated from V1 ({} bytes) to V2 ({} bytes)", current_len, target_len);
        Ok(())
    }
}
