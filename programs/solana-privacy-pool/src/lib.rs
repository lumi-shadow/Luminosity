use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::{self, AssociatedToken},
    token::{self, Mint, Token, TokenAccount, Transfer as TokenTransfer},
};
use bincode::Options;
use solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState};
use groth16_solana::groth16::Groth16Verifier;
use spl_concurrent_merkle_tree::concurrent_merkle_tree::ConcurrentMerkleTree;
mod verifying_key;
use verifying_key::VERIFYINGKEY;
mod verifying_key_liquidity;
use verifying_key_liquidity::VERIFYINGKEY_LIQUIDITY;
mod verifying_key_deposit_asset_bind;
use verifying_key_deposit_asset_bind::VERIFYINGKEY_DEPOSIT_ASSET_BIND;
mod verifying_key_deposit_liquidity_bind;
use verifying_key_deposit_liquidity_bind::VERIFYINGKEY_DEPOSIT_LIQUIDITY_BIND;
mod constants;
use constants::*;
mod state;
use state::{Amm, DepositEvent, Pool, Registry, SpentBitmapShard, SwapAppendEvent};
mod types;
use types::{Groth16Proof, RfqSwapUpdate};

declare_id!("p1VaCyyfzodMni1tSYhvUFd3MyGB6sb6NRFWPixXD54");

// -----------------------------------------------------------------------------
// Protocol overview (high-level)
// -----------------------------------------------------------------------------
// - One global concurrent Merkle tree stores note commitments (32 bytes).
// - Deposits append commitments to the tree.
// - Swaps "spend" one commitment by replacing the input leaf, and mint a new commitment
//   by appending an output leaf.
// - Withdrawals are gated by Groth16 proofs that show the prover knows the note secrets.
//
// Asset routing / lookup:
// - Public withdrawals are bound to an `asset_id` so the program can pick the correct AMM vault ATA.
// - A single PDA `Registry` stores mint<->asset_id and pool<->pool_id mappings.
//
// Canonical leaf formats (expected by circuits / off-chain prover):
// - Withdraw (single-asset): keccak256(nullifier || secret || amountLE8 || assetIdLE4)
// - Withdraw liquidity (LP): keccak256(nullifier || secret || sharesLE8 || poolIdLE4)
//
// Security model:
// - The program cannot verify commitment preimages (it does not know nullifier/secret).
// - It enforces routing/authorization and verifies Groth16 proofs at withdraw time.

mod utils;
use utils::{
    ensure_registry_capacity, integer_sqrt_u128, max_spent_shard_index_u32,
    max_tree_leaves_u64, registry_alloc_and_register_pool, registry_asset_id_for_mint,
    registry_get_or_alloc_asset_id, registry_mint_is_registered, registry_pool_id_for_pool,
    registry_pool_is_registered, require_leaf_index_in_range, require_not_paused,
};

#[program]
pub mod solana_privacy_pool {
    use super::*;

    /// Create the single-instance AMM config account.
    ///
    /// The AMM account address is a PDA derived from the static seed `[b"amm"]`,
    /// so there can only be **one** AMM config for this program ID.
    pub fn create_amm(ctx: Context<CreateAmm>, tee_authority: Pubkey) -> Result<()> {
        // Invariant: the Merkle tree must be owned by the SPL Account Compression program.
        // If this is wrong, all tree CPIs will fail.
        require!(
            ctx.accounts.merkle_tree.owner == &SplCompression::id(),
            PrivacyError::InvalidTreeOwner
        );

        // Hard gate: only the program upgrade authority may initialize the singleton AMM PDA.
        {
            // Ensure this program is actually upgradeable (owned by the upgradeable loader).
            // If it's deployed as non-upgradeable, there is no ProgramData account to validate.
            require!(
                ctx.accounts.program.owner == &bpf_loader_upgradeable::id(),
                PrivacyError::InvalidProgramData
            );

            let (expected_program_data, _bump) = Pubkey::find_program_address(
                &[ctx.accounts.program.key().as_ref()],
                &bpf_loader_upgradeable::id(),
            );
            require_keys_eq!(
                ctx.accounts.program_data.key(),
                expected_program_data,
                PrivacyError::InvalidProgramData
            );
            require!(
                ctx.accounts.program_data.owner == &bpf_loader_upgradeable::id(),
                PrivacyError::InvalidProgramData
            );

            let data = ctx.accounts.program_data.try_borrow_data()?;
            // ProgramData is serialized with bincode (fixed-int encoding).
            let state: UpgradeableLoaderState = bincode::options()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(256)
                .deserialize(&data)
                .map_err(|_| PrivacyError::InvalidProgramData)?;
            match state {
                UpgradeableLoaderState::ProgramData {
                    upgrade_authority_address: Some(ua),
                    ..
                } => {
                    require_keys_eq!(
                        ua,
                        ctx.accounts.upgrade_authority.key(),
                        PrivacyError::UnauthorizedUpgradeAuthority
                    );
                }
                _ => return err!(PrivacyError::InvalidProgramData),
            }
        }

        let amm = &mut ctx.accounts.amm;
        // Set the AMM admin to the program upgrade authority.
        amm.admin = ctx.accounts.upgrade_authority.key();
        amm.tee_authority = tee_authority;
        amm.merkle_tree = ctx.accounts.merkle_tree.key();
        amm.total_deposits = 0;
        amm.paused = false;

        msg!(
            "AMM Created. TEE: {:?} | Merkle Tree: {:?}",
            tee_authority,
            amm.merkle_tree
        );
        Ok(())
    }

    /// Create a trading pair pool (e.g. SOL/USDC).
    ///
    /// - **Admin-only (for now)**.
    /// - Initializes the pair `Pool` PDA.
    /// - Creates (if needed) shared AMM vault ATAs for `mint_a` and `mint_b` (authority = AMM PDA).
    /// - Registers `mint_a`/`mint_b` (auto-allocated `asset_id`s) and the pool (auto-allocated `pool_id`)
    ///   in the global `Registry` PDA.
    ///
    /// This does **not** touch the Merkle tree.
    pub fn create_pool(ctx: Context<CreatePool>) -> Result<()> {
        // Ensure the registry account is large enough to serialize any new entries we append.
        // This avoids large one-shot allocations (which Solana rejects) while keeping lookups simple.
        let mint_a = ctx.accounts.mint_a.key();
        let mint_b = ctx.accounts.mint_b.key();
        let pool_key = ctx.accounts.pool.key();

        let reg_view: &Registry = &ctx.accounts.registry;
        let mut new_assets = 0usize;
        if registry_asset_id_for_mint(reg_view, mint_a).is_none() {
            new_assets += 1;
        }
        if registry_asset_id_for_mint(reg_view, mint_b).is_none() {
            new_assets += 1;
        }

        let new_pools = if registry_pool_id_for_pool(reg_view, pool_key).is_none() {
            1usize
        } else {
            0usize
        };

        // Hard caps: prevent unbounded registry growth (compute + realloc risk).
        // This makes the registry growth bounded and predictable for initial deployments.
        require!(
            reg_view.assets.len().saturating_add(new_assets) <= Registry::MAX_ASSETS
                && reg_view.pools.len().saturating_add(new_pools) <= Registry::MAX_POOLS,
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
        // Registry: mint <-> asset_id mappings (auto-allocated; no user input).
        let _asset_id_a = registry_get_or_alloc_asset_id(reg, mint_a)?;
        let _asset_id_b = registry_get_or_alloc_asset_id(reg, mint_b)?;

        let pool = &mut ctx.accounts.pool;
        pool.amm = ctx.accounts.amm.key();
        pool.mint_a = ctx.accounts.mint_a.key();
        pool.mint_b = ctx.accounts.mint_b.key();
        // Store canonical shared AMM vaults (ATAs for each mint, authority = AMM PDA).
        pool.vault_a = ctx.accounts.amm_vault_a.key();
        pool.vault_b = ctx.accounts.amm_vault_b.key();
        pool.total_shares = 0;
        pool.reserve_a = 0;
        pool.reserve_b = 0;
        pool.bump = ctx.bumps.pool;

        // Registry: pool <-> pool_id mapping (auto-allocated; no user input).
        let _pool_id = registry_alloc_and_register_pool(reg, ctx.accounts.pool.key())?;

        Ok(())
    }

    /// Toggle the global emergency pause flag.
    ///
    /// When paused, user-facing instructions (deposit/withdraw/swap/liquidity) are rejected.
    pub fn set_paused(ctx: Context<SetPaused>, paused: bool) -> Result<()> {
        let amm = &mut ctx.accounts.amm;
        amm.paused = paused;
        msg!("Paused = {}", amm.paused);
        Ok(())
    }

    /// Rotate protocol admin (used for governance key rotation).
    pub fn rotate_admin(ctx: Context<RotateAdmin>, new_admin: Pubkey) -> Result<()> {
        require!(new_admin != Pubkey::default(), PrivacyError::InvalidAdmin);
        require!(ctx.accounts.registry.is_initialized, PrivacyError::RegistryNotInitialized);
        ctx.accounts.amm.admin = new_admin;
        msg!("Admin rotated to {}", new_admin);
        Ok(())
    }

    /// Rotate the TEE/relayer authority key.
    ///
    /// This controls who can authorize RFQ swap updates (TEE writer).
    pub fn rotate_tee_authority(
        ctx: Context<RotateTeeAuthority>,
        new_tee_authority: Pubkey,
    ) -> Result<()> {
        require!(
            new_tee_authority != Pubkey::default(),
            PrivacyError::InvalidTEEAuthority
        );
        ctx.accounts.amm.tee_authority = new_tee_authority;
        msg!("TEE authority rotated to {}", new_tee_authority);
        Ok(())
    }

    /// Execute an RFQ swap by tombstoning the input leaf and appending the output leaf.
    ///
    /// This is the first step towards "append-only notes" so that we can later move spent tracking
    /// from per-nullifier PDAs to a spent-by-index bitmap (cheap).
    ///
    /// Implementation:
    /// - `replace_leaf(root, previous_leaf, ZERO_LEAF, index)` to remove the spent commitment from
    ///   the live tree (reduces liability scanning noise; still rely on nullifier PDAs for spend)
    /// - `Append(output_commitment)` to mint the new output note at a fresh leaf index
    ///
    /// The caller must provide the Merkle proof nodes for the `replace_leaf` as `remaining_accounts`.
    pub fn execute_rfq_swap_append<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteRfqSwapAppend<'info>>,
        swap: RfqSwapUpdate,
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.config)?;
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);

        // Bound proof node accounts to prevent pathological account injection/compute usage.
        // (If the tree has a canopy, fewer proof nodes may be required; we only enforce an upper bound.)
        require!(
            ctx.remaining_accounts.len() <= (SPL_TREE_MAX_DEPTH as usize),
            PrivacyError::TooManyMerkleProofAccounts
        );

        // Validate leaf index + spent status, but only *mark* spent after the tree CPI succeeds.
        // This avoids a DoS where a failing CPI would permanently mark the leaf as spent.
        let input_leaf_index: u32 = swap.index;
        require_leaf_index_in_range(input_leaf_index)?;
        let shard_index: u32 = input_leaf_index / SPENT_BITMAP_SHARD_BITS;
        let max_shard = max_spent_shard_index_u32()?;
        require!(
            shard_index <= max_shard,
            PrivacyError::ShardIndexOutOfRange
        );
        let bit_in_shard: u32 = input_leaf_index % SPENT_BITMAP_SHARD_BITS;
        let byte_i: usize = (bit_in_shard / 8) as usize;
        let mask: u8 = 1u8 << (bit_in_shard % 8);
        require!(byte_i < SPENT_BITMAP_SHARD_BYTES, PrivacyError::MathOverflow);
        {
            let shard = &ctx.accounts.spent_shard;
            let already = (shard.bits[byte_i] & mask) != 0;
            require!(!already, PrivacyError::AlreadySpent);
        }

        // Reject stale/unknown roots early (same acceptance model as withdraw: SPL tree changelog).
        {
            let data = ctx.accounts.merkle_tree.try_borrow_data()?;
            let tree_struct_size = std::mem::size_of::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >();
            let tree_start = SPL_TREE_DATA_OFFSET;
            let tree_end = tree_start + tree_struct_size;
            if data.len() < tree_end {
                return err!(PrivacyError::TreeDeserializationFailed);
            }
            let tree_data = &data[tree_start..tree_end];
            let tree = bytemuck::try_from_bytes::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >(tree_data)
            .map_err(|_| PrivacyError::TreeDeserializationFailed)?;
            let is_valid_root = tree.change_logs.iter().any(|e| e.root == swap.root);
            require!(is_valid_root, PrivacyError::InvalidMerkleRoot);
        }

        // 1) Tombstone the input leaf with SPL Compression `replace_leaf`.
        // data layout: discriminator(8) || root(32) || previous_leaf(32) || new_leaf(32) || index(u32 LE)
        let mut ix_data = Vec::with_capacity(8 + 32 + 32 + 32 + 4);
        ix_data.extend_from_slice(&SPL_REPLACE_LEAF_DISCRIMINATOR);
        ix_data.extend_from_slice(&swap.root);
        ix_data.extend_from_slice(&swap.previous_leaf);
        ix_data.extend_from_slice(&[0u8; 32]); // tombstone leaf (all zeros)
        ix_data.extend_from_slice(&swap.index.to_le_bytes());

        let mut metas = vec![
            solana_program::instruction::AccountMeta::new(ctx.accounts.merkle_tree.key(), false),
            solana_program::instruction::AccountMeta::new_readonly(ctx.accounts.config.key(), true),
            solana_program::instruction::AccountMeta::new_readonly(ctx.accounts.noop.key(), false),
        ];
        for acc in ctx.remaining_accounts.iter() {
            metas.push(solana_program::instruction::AccountMeta::new_readonly(
                acc.key(),
                false,
            ));
        }

        let replace_ix = solana_program::instruction::Instruction {
            program_id: ctx.accounts.compression_program.key(),
            accounts: metas,
            data: ix_data,
        };

        let mut infos = ctx.accounts.to_account_infos();
        infos.extend_from_slice(ctx.remaining_accounts);

        let bump = ctx.bumps.config;
        let seeds = &[b"amm".as_ref(), &[bump]];
        let signer = &[&seeds[..]];
        solana_program::program::invoke_signed(&replace_ix, &infos, signer)?;

        // 2) Append the output leaf with SPL Compression `Append`.
        let mut append_data = SPL_APPEND_DISCRIMINATOR.to_vec();
        append_data.extend_from_slice(&swap.new_leaf);
        let append_ix = solana_program::instruction::Instruction {
            program_id: ctx.accounts.compression_program.key(),
            accounts: vec![
                solana_program::instruction::AccountMeta::new(ctx.accounts.merkle_tree.key(), false),
                solana_program::instruction::AccountMeta::new_readonly(ctx.accounts.config.key(), true),
                solana_program::instruction::AccountMeta::new_readonly(ctx.accounts.noop.key(), false),
            ],
            data: append_data,
        };
        solana_program::program::invoke_signed(
            &append_ix,
            &[
                ctx.accounts.compression_program.to_account_info(),
                ctx.accounts.merkle_tree.to_account_info(),
                ctx.accounts.config.to_account_info(),
                ctx.accounts.noop.to_account_info(),
            ],
            signer,
        )?;

        // Mark the input leaf as spent only after the tree ops succeeded.
        {
            let shard = &mut ctx.accounts.spent_shard;
            shard.bits[byte_i] |= mask;
        }

        // 3) Update pool virtual reserves to reflect this swap (TEE is the writer).
        let pool = &mut ctx.accounts.pool;
        pool.reserve_a = swap.new_reserve_a;
        pool.reserve_b = swap.new_reserve_b;

        // Solvency guard: never allow virtual reserves to exceed actual vault balances.
        require!(
            pool.reserve_a <= ctx.accounts.amm_vault_a.amount
                && pool.reserve_b <= ctx.accounts.amm_vault_b.amount,
            PrivacyError::InsufficientPoolBalance
        );

        // 4) Update AMM deposit counter (because we appended one new leaf).
        let data = ctx.accounts.merkle_tree.try_borrow_data()?;
        let tree_struct_size = std::mem::size_of::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >();
        let tree_start = SPL_TREE_DATA_OFFSET;
        let tree_end = tree_start + tree_struct_size;
        if data.len() < tree_end {
            return err!(PrivacyError::TreeDeserializationFailed);
        }
        let tree_data = &data[tree_start..tree_end];
        let tree = bytemuck::try_from_bytes::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >(tree_data)
        .map_err(|_| PrivacyError::TreeDeserializationFailed)?;

        let seq = tree.active_index;
        let active_idx = if seq > 0 { (seq - 1) as usize % 64 } else { 63 };
        let new_root = tree.change_logs[active_idx].root;

        // Output leaf index = next global leaf index (before incrementing).
        let amm = &mut ctx.accounts.config;
        let output_leaf_index = amm.total_deposits;
        // Root acceptance relies on the SPL tree changelog (not a program-maintained ring buffer).
        let _ = new_root; // root is still emitted implicitly via tree state; keep variable for potential debugging.
        amm.total_deposits = amm
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

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

        msg!(
            "Luminary Swap (append): input index {} tombstoned; output appended at index {}",
            swap.index,
            output_leaf_index
        );
        Ok(())
    }

    /// DEPOSIT (Pre-Swap): Shield ONE asset into the Tree.
    ///
    /// - Transfers tokens into the AMM vault ATA for the deposit mint.
    /// - Appends the provided `commitment` to the global Merkle tree.
    ///
    /// The commitment must match the withdraw circuit's canonical leaf format for this asset:
    /// `keccak256(nullifier || secret || amountLE8 || assetIdLE4)` (computed off-chain).
    pub fn deposit(
        ctx: Context<Deposit>,
        proof: Groth16Proof,
        amount: u64,
        commitment: [u8; 32],
        encrypted_note: Vec<u8>,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        // Fail early with a clear protocol error if the global tree is full.
        // This also bounds `amm.total_deposits` so the derived leaf_index always fits the tree.
        let max_leaves = max_tree_leaves_u64()?;
        require!(
            ctx.accounts.amm.total_deposits < max_leaves,
            PrivacyError::TreeFull
        );
        // --- Strict argument + account validation (fail fast with clear protocol errors) ---
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        require!(amount > 0, PrivacyError::ZeroDepositAmount);
        require!(commitment != [0u8; 32], PrivacyError::InvalidCommitment);
        require!(
            ctx.accounts.registry.is_initialized,
            PrivacyError::RegistryNotInitialized
        );
        // Tree account must be the real SPL compression-owned tree (not a spoofed account at the same address).
        require!(
            ctx.accounts.merkle_tree.owner == &SplCompression::id(),
            PrivacyError::InvalidTreeOwner
        );
        // User must have enough balance; otherwise the token CPI will fail anyway, but this gives a clearer error.
        require!(
            ctx.accounts.user_source.amount >= amount,
            PrivacyError::InsufficientUserBalance
        );

        // 0) Verify ZK Proof (Groth16) — binds (amount, asset_id) to commitment.
        // Public Inputs (4): [commitmentHi, commitmentLo, amountVal, assetId]
        let asset_id = registry_asset_id_for_mint(&ctx.accounts.registry, ctx.accounts.mint.key())
            .ok_or(PrivacyError::AssetNotRegistered)?;

        let to_field_element = |slice: &[u8]| -> [u8; 32] {
            let mut element = [0u8; 32];
            let start = 32 - slice.len();
            element[start..].copy_from_slice(slice);
            element
        };

        // Public inputs are encoded as big-endian field elements (u256 BE),
        // where the actual u64/u32 values are placed in the *least significant* bytes.
        // This must match the circuit's public input interpretation.
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
            &proof.a,
            &proof.b,
            &proof.c,
            &public_inputs,
            &VERIFYINGKEY_DEPOSIT_ASSET_BIND,
        )
        .map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 1. Transfer Token from User -> Pool Vault
        // This supports any SPL token. For SOL, user should use WSOL.
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

        // 2. Append Note to Global Tree
        let mut ix_data = SPL_APPEND_DISCRIMINATOR.to_vec();
        ix_data.extend_from_slice(&commitment);
        let append_ix = solana_program::instruction::Instruction {
            program_id: ctx.accounts.compression_program.key(),
            accounts: vec![
                solana_program::instruction::AccountMeta::new(
                    ctx.accounts.merkle_tree.key(),
                    false,
                ),
                solana_program::instruction::AccountMeta::new_readonly(
                    ctx.accounts.amm.key(),
                    true,
                ),
                solana_program::instruction::AccountMeta::new_readonly(
                    ctx.accounts.noop.key(),
                    false,
                ),
            ],
            data: ix_data,
        };
        let bump = ctx.bumps.amm;
        let seeds = &[b"amm".as_ref(), &[bump]];
        let signer = &[&seeds[..]];
        solana_program::program::invoke_signed(
            &append_ix,
            &[
                ctx.accounts.compression_program.to_account_info(),
                ctx.accounts.merkle_tree.to_account_info(),
                ctx.accounts.amm.to_account_info(),
                ctx.accounts.noop.to_account_info(),
            ],
            signer,
        )?;

        // 3. Update Global Root History
        let data = ctx.accounts.merkle_tree.try_borrow_data()?;

        let tree_struct_size = std::mem::size_of::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >();
        let tree_start = SPL_TREE_DATA_OFFSET;
        let tree_end = tree_start + tree_struct_size;

        if data.len() < tree_end {
            return err!(PrivacyError::TreeDeserializationFailed);
        }
        let tree_data = &data[tree_start..tree_end];
        let tree = bytemuck::try_from_bytes::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >(tree_data)
        .map_err(|_| PrivacyError::TreeDeserializationFailed)?;
        
        let seq = tree.active_index;
        let active_idx = if seq > 0 { (seq - 1) as usize % 64 } else { 63 };
        let new_root = tree.change_logs[active_idx].root;

        // 4. Update deposit counter & emit event
        let amm = &mut ctx.accounts.amm;

        // Capture the leaf index before incrementing the counter.
        let leaf_index = amm.total_deposits;

        // Root acceptance relies on the SPL tree changelog (not a program-maintained ring buffer).
        let _ = new_root;

        // Increment the counter
        amm.total_deposits = amm
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        emit!(DepositEvent {
            commitment,
            leaf_index,
            amount_a: amount,
            amount_b: 0,
            encrypted_note,
        });

        msg!(
            "Shielded Asset. Amount: {}. Leaf Index: {}",
            amount,
            leaf_index
        );
        Ok(())
    }

    /// WITHDRAW (Unshielding): Private Note -> Public Token.
    ///
    /// This verifies a Groth16 proof with public inputs including `asset_id`, so the program can:
    /// - validate that `asset_id` resolves to `mint_output` via the `Registry`
    /// - pay out from the correct AMM vault ATA (authority = AMM PDA)
    ///
    /// Notes:
    /// - Proof verification will only work when `verifying_key.rs` matches the currently compiled circuit.
    pub fn withdraw(
        ctx: Context<Withdraw>,
        // ZK Proof Data
        proof: Groth16Proof,
        root: [u8; 32],
        leaf_index: u32,
        // Public Inputs
        amount: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        require_leaf_index_in_range(leaf_index)?;
        {
            let shard_index: u32 = leaf_index / SPENT_BITMAP_SHARD_BITS;
            let max_shard = max_spent_shard_index_u32()?;
            require!(
                shard_index <= max_shard,
                PrivacyError::ShardIndexOutOfRange
            );
        }
        // Derive asset_id from (mint_output -> registry) to avoid user-supplied IDs.
        let asset_id =
            registry_asset_id_for_mint(&ctx.accounts.registry, ctx.accounts.mint_output.key())
                .ok_or(PrivacyError::AssetNotRegistered)?;
        // 1) Verify Merkle root (SPL tree changelog buffer)
        {
            let _amm = &ctx.accounts.amm;
            let merkle_tree_account = &ctx.accounts.merkle_tree;
            let data = merkle_tree_account.try_borrow_data()?;

            let tree_struct_size = std::mem::size_of::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >();
            let tree_start = SPL_TREE_DATA_OFFSET;
            let tree_end = tree_start + tree_struct_size;
            if data.len() < tree_end {
                return err!(PrivacyError::TreeDeserializationFailed);
            }
            let tree_data = &data[tree_start..tree_end];
            let tree = bytemuck::try_from_bytes::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >(tree_data)
            .map_err(|_| PrivacyError::TreeDeserializationFailed)?;

            // Accept only roots present in the SPL tree changelog buffer.
            // This buffer size is configured at tree init (`maxBufferSize`, currently 1024 in scripts/init_mainnet.ts).
            let is_valid_root = tree.change_logs.iter().any(|e| e.root == root);
            require!(is_valid_root, PrivacyError::InvalidMerkleRoot);
        }

        // 2. Verify ZK Proof (Groth16)
        // Public Inputs (8): [rootHi, rootLo, recipientHi, recipientLo, relayerFee, amountVal, assetId, leafIndex]
        let to_field_element = |slice: &[u8]| -> [u8; 32] {
            let mut element = [0u8; 32];
            let start = 32 - slice.len();
            element[start..].copy_from_slice(slice);
            element
        };

        let rec_bytes = ctx.accounts.recipient.key().to_bytes(); // recipient token account pubkey

        // Public inputs are encoded as big-endian field elements (u256 BE),
        // where the actual u64/u32 values are placed in the *least significant* bytes.
        // This must match the circuit's public input interpretation.
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

        let mut verifier =
            Groth16Verifier::<8>::new(&proof.a, &proof.b, &proof.c, &public_inputs, &VERIFYINGKEY)
        .map_err(|_| PrivacyError::InvalidProof)?;

        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 3) Bitmap nullification (spent-by-index) for withdrawals.
        {
            let bit_in_shard: u32 = leaf_index % SPENT_BITMAP_SHARD_BITS;
            let byte_i: usize = (bit_in_shard / 8) as usize;
            let mask: u8 = 1u8 << (bit_in_shard % 8);
            require!(byte_i < SPENT_BITMAP_SHARD_BYTES, PrivacyError::MathOverflow);
            let shard = &mut ctx.accounts.spent_shard;
            let already = (shard.bits[byte_i] & mask) != 0;
            require!(!already, PrivacyError::AlreadySpent);
            shard.bits[byte_i] |= mask;
        }

        // 4. Transfer Logic (Pool -> Recipient)
        // We need the seeds to sign for the AMM PDA (shared vault per mint).
        let bump = ctx.bumps.amm;
        let amm_seeds = &[b"amm".as_ref(), &[bump]];
        let signer = &[&amm_seeds[..]];

        let payout_amount = amount
            .checked_sub(relayer_fee)
            .ok_or(PrivacyError::FeeExceedsAmount)?;

        if payout_amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.amm_vault.to_account_info(),
                        to: ctx.accounts.recipient.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                payout_amount,
            )?;
        }

        // Handle Relayer Fee (if any): pay the relayer from the same AMM vault.
        if relayer_fee > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.amm_vault.to_account_info(),
                        to: ctx.accounts.relayer_fee_account.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                relayer_fee,
            )?;
        }

        msg!("Withdrawal Successful. Amount: {}", payout_amount);
        Ok(())
    }

    // WITHDRAW LIQUIDITY (Private Note -> Public Tokens)
    //
    // Share-based LP note withdrawal:
    // - The liquidity circuit binds `shares` + `pool_id` into the note commitment.
    // - The program derives `(amount_a, amount_b)` from the pool's virtual reserves
    //   (`pool.reserve_a`, `pool.reserve_b`) and `pool.total_shares`.
    //
    // Notes:
    // - Proof verification will only work when `verifying_key_liquidity.rs` matches the currently compiled circuit.
    pub fn withdraw_liquidity(
        ctx: Context<WithdrawLiquidity>,
        // ZK Proof Inputs
        proof: Groth16Proof,
        root: [u8; 32],
        leaf_index: u32,
        // Public Inputs
        shares: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        require_not_paused(&ctx.accounts.amm)?;
        require_leaf_index_in_range(leaf_index)?;
        {
            let shard_index: u32 = leaf_index / SPENT_BITMAP_SHARD_BITS;
            let max_shard = max_spent_shard_index_u32()?;
            require!(
                shard_index <= max_shard,
                PrivacyError::ShardIndexOutOfRange
            );
        }
        // Derive pool_id from (pool -> registry) to avoid user-supplied IDs.
        let pool_id = registry_pool_id_for_pool(&ctx.accounts.registry, ctx.accounts.pool.key())
            .ok_or(PrivacyError::PoolNotRegistered)?;
        // Share-based liquidity note:
        // - `shares` is the note's claim on this pool.
        // - Actual amounts paid out are computed from `pool.reserve_a/b` and `pool.total_shares`.
        //
        // Notes:
        // - Safety depends on the **liquidity circuit + VK** binding `shares` to `pool_id`.
        // - Proof verification will only work when `verifying_key_liquidity.rs` matches the currently compiled circuit.
        require!(relayer_fee == 0, PrivacyError::TokenRelayerFeeNotSupported);

        // Recipient wallet is the TokenAccount owner (must match across A/B).
        let recipient_owner = ctx.accounts.recipient_account_a.owner;
        require!(
            ctx.accounts.recipient_account_b.owner == recipient_owner,
            PrivacyError::InvalidRecipientOwner
        );
        require!(
            ctx.accounts.recipient_account_a.mint == ctx.accounts.mint_a.key(),
            PrivacyError::InvalidRecipientMint
        );
        require!(
            ctx.accounts.recipient_account_b.mint == ctx.accounts.mint_b.key(),
            PrivacyError::InvalidRecipientMint
        );

        // 1) Verify Merkle root (SPL tree changelog buffer)
        {
            let _amm = &ctx.accounts.amm;
            let merkle_tree_account = &ctx.accounts.merkle_tree;
            let data = merkle_tree_account.try_borrow_data()?;

            let tree_struct_size = std::mem::size_of::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >();
            let tree_start = SPL_TREE_DATA_OFFSET;
            let tree_end = tree_start + tree_struct_size;
            if data.len() < tree_end {
                return err!(PrivacyError::TreeDeserializationFailed);
            }
            let tree_data = &data[tree_start..tree_end];
            let tree = bytemuck::try_from_bytes::<
                ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
            >(tree_data)
            .map_err(|_| PrivacyError::TreeDeserializationFailed)?;

            let is_valid_root = tree.change_logs.iter().any(|e| e.root == root);
            require!(is_valid_root, PrivacyError::InvalidMerkleRoot);
        }

        // 2) Verify ZK Proof (Groth16) — liquidity circuit (shares + pool_id bound).
        let to_field_element = |slice: &[u8]| -> [u8; 32] {
            let mut element = [0u8; 32];
            let start = 32 - slice.len();
            element[start..].copy_from_slice(slice);
            element
        };

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
            &proof.a,
            &proof.b,
            &proof.c,
            &public_inputs,
            &VERIFYINGKEY_LIQUIDITY,
        )
        .map_err(|_| PrivacyError::InvalidProof)?;

        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // Bitmap nullification (spent-by-index) for LP withdrawals.
        {
            require_leaf_index_in_range(leaf_index)?;
            let bit_in_shard: u32 = leaf_index % SPENT_BITMAP_SHARD_BITS;
            let byte_i: usize = (bit_in_shard / 8) as usize;
            let mask: u8 = 1u8 << (bit_in_shard % 8);
            require!(byte_i < SPENT_BITMAP_SHARD_BYTES, PrivacyError::MathOverflow);
            let shard = &mut ctx.accounts.spent_shard;
            let already = (shard.bits[byte_i] & mask) != 0;
            require!(!already, PrivacyError::AlreadySpent);
            shard.bits[byte_i] |= mask;
        }

        // 3) Compute amounts from shares + pool virtual reserves, then transfer and burn.
        let total_shares = ctx.accounts.pool.total_shares;
        require!(total_shares > 0, PrivacyError::ZeroTotalShares);
        require!(shares > 0, PrivacyError::ZeroShares);
        require!(shares <= total_shares, PrivacyError::SharesExceedTotal);

        let reserve_a = ctx.accounts.pool.reserve_a;
        let reserve_b = ctx.accounts.pool.reserve_b;

        // Solvency guard (on-chain): never allow virtual reserves to exceed actual vault balances.
        // This gives a clear protocol error instead of failing later inside the token program.
        require!(
            reserve_a <= ctx.accounts.amm_vault_a.amount
                && reserve_b <= ctx.accounts.amm_vault_b.amount,
            PrivacyError::InsufficientPoolBalance
        );

        let amount_a_u128 = (shares as u128)
            .checked_mul(reserve_a as u128)
            .ok_or(PrivacyError::MathOverflow)?
            / (total_shares as u128);
        let amount_b_u128 = (shares as u128)
            .checked_mul(reserve_b as u128)
            .ok_or(PrivacyError::MathOverflow)?
            / (total_shares as u128);
        let amount_a: u64 = u64::try_from(amount_a_u128).map_err(|_| PrivacyError::MathOverflow)?;
        let amount_b: u64 = u64::try_from(amount_b_u128).map_err(|_| PrivacyError::MathOverflow)?;

        // 3) TRANSFER ASSETS OUT (Shared AMM Vault -> Recipient)
        let bump = ctx.bumps.amm;
        let seeds = &[b"amm".as_ref(), &[bump]];
        let signer = &[&seeds[..]];

        if amount_a > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.amm_vault_a.to_account_info(),
                        to: ctx.accounts.recipient_account_a.to_account_info(),
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
                        from: ctx.accounts.amm_vault_b.to_account_info(),
                        to: ctx.accounts.recipient_account_b.to_account_info(),
                        authority: ctx.accounts.amm.to_account_info(),
                    },
                    signer,
                ),
                amount_b,
            )?;
        }

        // Burn shares (update pool state after transfers)
        let pool = &mut ctx.accounts.pool;
        pool.reserve_a = pool
            .reserve_a
            .checked_sub(amount_a)
            .ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool
            .reserve_b
            .checked_sub(amount_b)
            .ok_or(PrivacyError::MathOverflow)?;
        pool.total_shares = pool
            .total_shares
            .checked_sub(shares)
            .ok_or(PrivacyError::SharesExceedTotal)?;

        msg!(
            "Withdrawal Complete (shares={}): {} A / {} B",
            shares,
            amount_a,
            amount_b
        );
        Ok(())
    }

    /// Deposit liquidity into a specific Pool, while minting a private LP note into the AMM's
    /// single shared Merkle tree (Global Privacy Tree).
    ///
    /// - Permissionless (no TEE signature checks).
    /// - Computes shares *on-chain* from the pool's **virtual reserves** (`pool.reserve_a/b`)
    ///   + `pool.total_shares`.
    /// - Enforces `expected_shares` to protect the depositor from slippage.
    ///
    /// The `commitment` is computed off-chain (the program cannot validate secrets). It is expected
    /// to commit to `(nullifier, secret, shares, pool_id)` (see `circuits/withdraw_liquidity.circom`).
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
        // IMPORTANT (protocol-level):
        // - The program cannot validate the note preimage (nullifier/secret) or recompute the
        //   commitment. That binding is enforced only by the withdraw-liquidity ZK circuit.
        // - We *do* enforce correct routing at the account layer: the vaults used here must match
        //   `pool.vault_a/b` (canonical shared AMM vaults for this pool), so users can't redirect
        //   liquidity into arbitrary token accounts.
        require!(encrypted_note.len() <= 512, PrivacyError::NoteTooLong);
        require!(
            amount_a > 0 && amount_b > 0,
            PrivacyError::InvalidLiquidityDeposit
        );
        // Snapshot virtual reserves BEFORE transfer for share minting math.
        let reserve_a_before = ctx.accounts.pool.reserve_a;
        let reserve_b_before = ctx.accounts.pool.reserve_b;
        let total_before = ctx.accounts.pool.total_shares;

        // 0) Verify ZK Proof (Groth16) — binds (shares, pool_id) to commitment.
        // Public Inputs (4): [commitmentHi, commitmentLo, sharesVal, poolId]
        let pool_id = registry_pool_id_for_pool(&ctx.accounts.registry, ctx.accounts.pool.key())
            .ok_or(PrivacyError::PoolNotRegistered)?;

        let to_field_element = |slice: &[u8]| -> [u8; 32] {
            let mut element = [0u8; 32];
            let start = 32 - slice.len();
            element[start..].copy_from_slice(slice);
            element
        };

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
            &proof.a,
            &proof.b,
            &proof.c,
            &public_inputs,
            &VERIFYINGKEY_DEPOSIT_LIQUIDITY_BIND,
        )
        .map_err(|_| PrivacyError::InvalidProof)?;
        verifier.verify().map_err(|_| PrivacyError::InvalidProof)?;

        // 1) Transfer tokens A & B into this Pool's vaults.
        if amount_a > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TokenTransfer {
                        from: ctx.accounts.user_account_a.to_account_info(),
                        to: ctx.accounts.amm_vault_a.to_account_info(),
                        authority: ctx.accounts.payer.to_account_info(),
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
                        from: ctx.accounts.user_account_b.to_account_info(),
                        to: ctx.accounts.amm_vault_b.to_account_info(),
                        authority: ctx.accounts.payer.to_account_info(),
                    },
                ),
                amount_b,
            )?;
        }

        // 2) Append leaf (mint private LP note) into the AMM's global Merkle tree.
        let mut ix_data = SPL_APPEND_DISCRIMINATOR.to_vec();
        ix_data.extend_from_slice(&commitment);
        let append_ix = solana_program::instruction::Instruction {
            program_id: ctx.accounts.compression_program.key(),
            accounts: vec![
                solana_program::instruction::AccountMeta::new(
                    ctx.accounts.merkle_tree.key(),
                    false,
                ),
                solana_program::instruction::AccountMeta::new_readonly(
                    ctx.accounts.amm.key(),
                    true,
                ),
                solana_program::instruction::AccountMeta::new_readonly(
                    ctx.accounts.noop.key(),
                    false,
                ),
            ],
            data: ix_data,
        };
        let bump = ctx.bumps.amm;
        let seeds = &[b"amm".as_ref(), &[bump]];
        let signer = &[&seeds[..]];
        solana_program::program::invoke_signed(
            &append_ix,
            &[
                ctx.accounts.compression_program.to_account_info(),
                ctx.accounts.merkle_tree.to_account_info(),
                ctx.accounts.amm.to_account_info(),
                ctx.accounts.noop.to_account_info(),
            ],
            signer,
        )?;

        // 3) Read new root from SPL tree (same logic as `deposit`)
        let data = ctx.accounts.merkle_tree.try_borrow_data()?;
        let tree_struct_size = std::mem::size_of::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >();
        let tree_start = SPL_TREE_DATA_OFFSET;
        let tree_end = tree_start + tree_struct_size;
        if data.len() < tree_end {
            msg!("Error: Account data too small");
            return err!(PrivacyError::TreeDeserializationFailed);
        }
        let tree_data = &data[tree_start..tree_end];
        let tree = bytemuck::try_from_bytes::<
            ConcurrentMerkleTree<SPL_TREE_MAX_DEPTH, SPL_TREE_MAX_BUFFER_SIZE>,
        >(tree_data)
        .map_err(|_| PrivacyError::TreeDeserializationFailed)?;

        let seq = tree.active_index;
        let active_idx = if seq > 0 { (seq - 1) as usize % 64 } else { 63 };
        let new_root = tree.change_logs[active_idx].root;

        // 4) Update AMM deposit counter + emit event (same logic as `deposit`)
        let amm = &mut ctx.accounts.amm;
        let leaf_index = amm.total_deposits;
        let _ = new_root;
        amm.total_deposits = amm
            .total_deposits
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        // 5) Mint shares (share-based LP note). We update pool.total_shares on-chain.
        // The commitment is expected to encode (nullifier, secret, shares, pool_id) in the future circuit;
        // we can't verify that here (no secrets), but we can enforce that `expected_shares` matches
        // what the on-chain AMM math would mint.
        let pool = &mut ctx.accounts.pool;
        let minted_shares: u64 = if total_before == 0 {
            // First liquidity: shares = floor(sqrt(amount_a * amount_b))
            let prod = (amount_a as u128)
                .checked_mul(amount_b as u128)
                .ok_or(PrivacyError::MathOverflow)?;
            let root = integer_sqrt_u128(prod);
            require!(root <= (u64::MAX as u128), PrivacyError::MathOverflow);
            root as u64
        } else {
            require!(
                reserve_a_before > 0 && reserve_b_before > 0,
                PrivacyError::InvalidReserves
            );

            // Enforce "correct ratio" for subsequent LP deposits.
            //
            // Without this, users can deposit at arbitrary ratios and effectively "donate" the excess
            // of one side into the pool. That's a UX footgun and can create weird incentives.
            //
            // We allow a tiny tolerance due to integer division rounding:
            // - For a given `amount_a`, the ideal `amount_b` is:
            //     amount_b ~= amount_a * reserve_b / reserve_a
            //   We accept if `amount_b` is between floor and ceil of that value.
            //
            // NOTE: We do NOT require the symmetric reverse check (amount_a vs amount_b) because
            // integer rounding can make that reject otherwise valid pairs.
            let ra = reserve_a_before as u128;
            let rb = reserve_b_before as u128;
            let aa = amount_a as u128;
            let ab = amount_b as u128;

            let ideal_b_floor = aa
                .checked_mul(rb)
                .ok_or(PrivacyError::MathOverflow)?
                / ra;
            let ideal_b_ceil = aa
                .checked_mul(rb)
                .ok_or(PrivacyError::MathOverflow)?
                .checked_add(ra.saturating_sub(1))
                .ok_or(PrivacyError::MathOverflow)?
                / ra;

            require!(
                (ab >= ideal_b_floor && ab <= ideal_b_ceil),
                PrivacyError::InvalidLiquidityRatio
            );

            let share_a = (amount_a as u128)
                .checked_mul(total_before as u128)
                .ok_or(PrivacyError::MathOverflow)?
                / (reserve_a_before as u128);
            let share_b = (amount_b as u128)
                .checked_mul(total_before as u128)
                .ok_or(PrivacyError::MathOverflow)?
                / (reserve_b_before as u128);
            let m = core::cmp::min(share_a, share_b);
            require!(m <= (u64::MAX as u128), PrivacyError::MathOverflow);
            m as u64
        };
        require!(minted_shares > 0, PrivacyError::ZeroShares);
        require!(
            minted_shares == expected_shares,
            PrivacyError::SharesMismatch
        );
        pool.reserve_a = pool
            .reserve_a
            .checked_add(amount_a)
            .ok_or(PrivacyError::MathOverflow)?;
        pool.reserve_b = pool
            .reserve_b
            .checked_add(amount_b)
            .ok_or(PrivacyError::MathOverflow)?;
        pool.total_shares = pool
            .total_shares
            .checked_add(minted_shares)
            .ok_or(PrivacyError::MathOverflow)?;

        emit!(DepositEvent {
            commitment,
            leaf_index,
            amount_a,
            amount_b,
            encrypted_note,
        });

        Ok(())
    }

    /// Initialize the global Registry PDA at its full size.
    ///
    /// This exists to avoid relying on `init_if_needed + realloc` inside `create_pool`, which can
    /// fail due to Solana's inner-instruction realloc growth limit (~10KB).
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

}

#[derive(Accounts)]
#[instruction(tee_authority: Pubkey)]
pub struct CreateAmm<'info> {
    #[account(
        init,
        payer = payer,
        space = Amm::LEN,
        // Static seed => single instance.
        seeds = [b"amm"],
        bump,
    )]
    pub amm: Account<'info, Amm>,

    /// CHECK: Merkle tree account (SPL Account Compression tree).
    /// We don't deserialize it, but we enforce its owner.
    #[account(owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner)]
    pub merkle_tree: UncheckedAccount<'info>,

    /// CHECK: This program's executable account (must equal this program id).
    #[account(address = crate::ID)]
    pub program: UncheckedAccount<'info>,

    /// CHECK: Upgradeable Loader ProgramData account for `program`.
    pub program_data: UncheckedAccount<'info>,

    /// The program upgrade authority signer (must match `program_data` state).
    pub upgrade_authority: Signer<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(swap: RfqSwapUpdate)]
pub struct ExecuteRfqSwapAppend<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    // Global config (single-instance AMM PDA) - must be writable because we append one leaf.
    #[account(mut, seeds = [b"amm"], bump)]
    pub config: Box<Account<'info, Amm>>,

    // The TEE enclave authority (must be the configured key and must sign)
    #[account(address = config.tee_authority @ PrivacyError::UnauthorizedTEE)]
    pub tee_authority: Signer<'info>,

    /// CHECK: SPL compression program validates this account
    #[account(
        mut,
        address = config.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    /// Pool whose virtual reserves are updated by the TEE during this swap.
    #[account(mut, constraint = pool.amm == config.key() @ PrivacyError::InvalidPoolAmm)]
    pub pool: Account<'info, Pool>,

    /// Shared AMM vaults backing this pool's virtual reserves.
    #[account(
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
        constraint = amm_vault_a.mint == pool.mint_a @ PrivacyError::InvalidRecipientMint,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
        constraint = amm_vault_b.mint == pool.mint_b @ PrivacyError::InvalidRecipientMint,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    /// Spent bitmap shard PDA for `swap.index`.
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            config.key().as_ref(),
            &(swap.index / SPENT_BITMAP_SHARD_BITS).to_le_bytes()
        ],
        bump
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    #[account(address = SplCompression::id())]
    pub compression_program: Program<'info, SplCompression>,
    #[account(address = Noop::id())]
    pub noop: Program<'info, Noop>,
    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
    // Proof nodes are passed via `remaining_accounts`
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    // GLOBAL STATE
    #[account(mut, seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    // ASSET TO DEPOSIT
    pub mint: Box<Account<'info, Mint>>,

    /// Registry lookup table (single PDA) for mint<->asset_id validation.
    #[account(
        mut,
        seeds = [b"registry"],
        bump,
        constraint = registry_mint_is_registered(&registry, mint.key()) @ PrivacyError::AssetNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    // DESTINATION (Shared AMM Vault for this Mint)
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = amm
    )]
    pub amm_vault: Box<Account<'info, TokenAccount>>,

    // SOURCE (User Wallet)
    #[account(
        mut,
        constraint = user_source.mint == mint.key(),
        constraint = user_source.owner == payer.key() @ PrivacyError::InvalidUserTokenOwner
    )]
    pub user_source: Box<Account<'info, TokenAccount>>,

    /// CHECK: SPL Compression tree (validated by owner + address).
    #[account(
        mut,
        address = amm.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
    #[account(address = SplCompression::id())]
    pub compression_program: Program<'info, SplCompression>,
    #[account(address = Noop::id())]
    pub noop: Program<'info, Noop>,
    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositLiquidity<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    // GLOBAL STATE (Mutable because we update the Tree)
    #[account(mut, seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    // POOL STATE (mutable: we update total_shares + virtual reserves)
    #[account(
        mut,
        seeds = [amm.key().as_ref(), mint_a.key().as_ref(), mint_b.key().as_ref()],
        bump,
        constraint = pool.mint_a == mint_a.key() @ PrivacyError::InvalidPoolMints,
        constraint = pool.mint_b == mint_b.key() @ PrivacyError::InvalidPoolMints,
        constraint = mint_a.key().to_bytes() < mint_b.key().to_bytes() @ PrivacyError::NonCanonicalMintOrder,
    )]
    pub pool: Box<Account<'info, Pool>>,

    /// Registry lookup table for pool_id<->pool validation.
    #[account(
        mut,
        seeds = [b"registry"],
        bump,
        constraint = registry_pool_is_registered(&registry, pool.key()) @ PrivacyError::PoolNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    // ASSETS
    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    /// Shared AMM vaults backing this pool's virtual reserves.
    #[account(
        mut,
        associated_token::mint = mint_a,
        associated_token::authority = amm,
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        associated_token::mint = mint_b,
        associated_token::authority = amm,
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = user_account_a.owner == payer.key() @ PrivacyError::InvalidUserTokenOwner,
        constraint = user_account_a.mint == mint_a.key() @ PrivacyError::InvalidUserTokenMint,
    )]
    pub user_account_a: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        constraint = user_account_b.owner == payer.key() @ PrivacyError::InvalidUserTokenOwner,
        constraint = user_account_b.mint == mint_b.key() @ PrivacyError::InvalidUserTokenMint,
    )]
    pub user_account_b: Box<Account<'info, TokenAccount>>,

    /// CHECK: SPL Compression tree (validated by owner + address).
    #[account(
        mut,
        address = amm.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
    #[account(address = SplCompression::id())]
    pub compression_program: Program<'info, SplCompression>,
    #[account(address = Noop::id())]
    pub noop: Program<'info, Noop>,
    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreatePool<'info> {
    /// Global singleton AMM (privacy state).
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        init,
        payer = admin,
        space = Pool::LEN,
        seeds = [amm.key().as_ref(), mint_a.key().as_ref(), mint_b.key().as_ref()],
        bump,
        constraint = mint_a.key() != mint_b.key() @ PrivacyError::IdenticalMintsNotAllowed,
        constraint = mint_a.key().to_bytes() < mint_b.key().to_bytes() @ PrivacyError::NonCanonicalMintOrder,
    )]
    pub pool: Box<Account<'info, Pool>>,

    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    /// Shared AMM vault for mint_a (created once per mint; safe to init-if-needed).
    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = mint_a,
        associated_token::authority = amm
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,

    /// Shared AMM vault for mint_b (created once per mint; safe to init-if-needed).
    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = mint_b,
        associated_token::authority = amm
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    /// Registry lookup table PDA. Created once and then mutated.
    #[account(
        mut,
        seeds = [b"registry"],
        bump,
        constraint = registry.is_initialized @ PrivacyError::RegistryNotInitialized,
    )]
    pub registry: Box<Account<'info, Registry>>,

    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    /// Global singleton AMM (admin check).
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        init,
        payer = admin,
        space = Registry::INIT_LEN,
        seeds = [b"registry"],
        bump,
    )]
    pub registry: Box<Account<'info, Registry>>,

    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(mut, seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateAdmin<'info> {
    #[account(mut, seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(mut, seeds = [b"registry"], bump)]
    pub registry: Box<Account<'info, Registry>>,

    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct RotateTeeAuthority<'info> {
    #[account(mut, seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
// Notes:
// The `#[instruction(...)]` list must match the *leading* instruction args (in order).
// If it omits earlier args (like `proof`), Anchor will read the wrong offsets for later args
// when evaluating constraints (e.g. PDA seeds), causing nondeterministic `ConstraintSeeds` errors.
#[instruction(proof: Groth16Proof, root: [u8; 32], leaf_index: u32, amount: u64, relayer_fee: u64)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub payer: Signer<'info>, // Relayer

    // DESTINATION (Recipient token account)
    #[account(mut, constraint = recipient.mint == mint_output.key())]
    pub recipient: Box<Account<'info, TokenAccount>>,

    /// Relayer fee destination (must be a token account owned by the relayer signer).
    ///
    /// If `relayer_fee == 0`, this account is still required but unused.
    #[account(
        mut,
        constraint = relayer_fee_account.mint == mint_output.key() @ PrivacyError::InvalidRelayerFeeMint,
        constraint = relayer_fee_account.owner == payer.key() @ PrivacyError::InvalidRelayerFeeOwner,
    )]
    pub relayer_fee_account: Box<Account<'info, TokenAccount>>,

    // GLOBAL STATE
    #[account(seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>, 

    // The Asset to Withdraw
    pub mint_output: Box<Account<'info, Mint>>,

    /// Registry lookup table for mint registration + `asset_id` derivation.
    #[account(
        seeds = [b"registry"],
        bump,
        constraint = registry_mint_is_registered(&registry, mint_output.key()) @ PrivacyError::AssetNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    // SOURCE (Shared AMM Vault for this Mint)
    #[account(
        mut,
        associated_token::mint = mint_output,
        associated_token::authority = amm
    )]
    pub amm_vault: Box<Account<'info, TokenAccount>>,

    /// Spent bitmap shard PDA for `leaf_index`.
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            amm.key().as_ref(),
            &(leaf_index / SPENT_BITMAP_SHARD_BITS).to_le_bytes()
        ],
        bump
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    /// CHECK: SPL Compression tree (validated by owner + address).
    #[account(
        address = amm.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proof: Groth16Proof, root: [u8; 32], leaf_index: u32, shares: u64, relayer_fee: u64)]
pub struct WithdrawLiquidity<'info> {
    #[account(mut)]
    pub payer: Signer<'info>, // Relayer

    // GLOBAL STATE (for root verification)
    #[account(seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    // POOL STATE (mutable: we burn shares + update virtual reserves)
    #[account(
        mut,
        seeds = [amm.key().as_ref(), mint_a.key().as_ref(), mint_b.key().as_ref()],
        bump = pool.bump,
        constraint = pool.mint_a == mint_a.key() @ PrivacyError::InvalidPoolMints,
        constraint = pool.mint_b == mint_b.key() @ PrivacyError::InvalidPoolMints,
        constraint = mint_a.key().to_bytes() < mint_b.key().to_bytes() @ PrivacyError::NonCanonicalMintOrder,
    )]
    pub pool: Box<Account<'info, Pool>>,

    /// Registry lookup table for pool_id<->pool validation.
    #[account(
        seeds = [b"registry"],
        bump,
        constraint = registry_pool_is_registered(&registry, pool.key()) @ PrivacyError::PoolNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    // ASSETS
    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    /// Shared AMM vaults backing this pool's virtual reserves.
    #[account(
        mut,
        associated_token::mint = mint_a,
        associated_token::authority = amm,
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        associated_token::mint = mint_b,
        associated_token::authority = amm,
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    // RECIPIENT ACCOUNTS
    #[account(mut)]
    pub recipient_account_a: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub recipient_account_b: Box<Account<'info, TokenAccount>>,

    /// Spent bitmap shard PDA for `leaf_index`.
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            amm.key().as_ref(),
            &(leaf_index / SPENT_BITMAP_SHARD_BITS).to_le_bytes()
        ],
        bump
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    // TREE (linked to AMM)
    /// CHECK: SPL Compression tree (validated by owner + address).
    #[account(
        mut,
        address = amm.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    #[account(address = associated_token::ID)]
    pub associated_token_program: Program<'info, AssociatedToken>,
    #[account(address = solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Clone)]
pub struct SplCompression;
impl anchor_lang::Id for SplCompression {
    fn id() -> Pubkey {
        solana_program::pubkey!("cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK")
    }
}

#[derive(Clone)]
pub struct Noop;
impl anchor_lang::Id for Noop {
    fn id() -> Pubkey {
        solana_program::pubkey!("noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV")
    }
}

#[error_code]
pub enum PrivacyError {
    #[msg("Invalid Denomination")]
    InvalidDenomination,
    #[msg("Deposit amount must be > 0")]
    ZeroDepositAmount,
    #[msg("Unauthorized TEE")]
    UnauthorizedTEE,
    #[msg("Unauthorized admin")]
    UnauthorizedAdmin,
    #[msg("Unauthorized program upgrade authority")]
    UnauthorizedUpgradeAuthority,
    #[msg("Invalid pool mints")]
    InvalidPoolMints,
    #[msg("Pool AMM link mismatch")]
    InvalidPoolAmm,
    #[msg("Invalid pool vault for this mint")]
    InvalidPoolVault,
    #[msg("Invalid user token account owner")]
    InvalidUserTokenOwner,
    #[msg("Invalid user token account mint")]
    InvalidUserTokenMint,
    #[msg("Invalid relayer fee token account owner")]
    InvalidRelayerFeeOwner,
    #[msg("Invalid relayer fee token account mint")]
    InvalidRelayerFeeMint,
    #[msg("Invalid asset id")]
    InvalidAssetId,
    #[msg("Mint is not registered for this asset id (or asset id is wrong)")]
    InvalidAssetForMint,
    #[msg("Invalid pool id")]
    InvalidPoolId,
    #[msg("Pool is not registered for this pool id (or pool id is wrong)")]
    InvalidPoolForId,
    #[msg("Invalid liquidity deposit (require amount_a > 0 && amount_b > 0)")]
    InvalidLiquidityDeposit,
    #[msg("Invalid liquidity deposit ratio (must match pool reserves)")]
    InvalidLiquidityRatio,
    #[msg("Invalid pool reserves for share minting")]
    InvalidReserves,
    #[msg("Math overflow")]
    MathOverflow,
    #[msg("Total shares is zero")]
    ZeroTotalShares,
    #[msg("Shares must be > 0")]
    ZeroShares,
    #[msg("Shares exceed total_shares")]
    SharesExceedTotal,
    #[msg("Expected shares does not match on-chain share minting math")]
    SharesMismatch,
    #[msg("Asset registry mismatch")]
    AssetRegistryMismatch,
    #[msg("Pool registry mismatch")]
    PoolRegistryMismatch,
    #[msg("Registry is full")]
    RegistryFull,
    // NOTE: We intentionally keep registry governance derived from `amm.admin`
    // to avoid lockouts due to a mis-initialized/corrupted registry admin field.
    #[msg("Registry is not initialized")]
    RegistryNotInitialized,
    #[msg("Registry realloc too large (must be <= 10KB per instruction)")]
    RegistryReallocTooLarge,
    #[msg("Registry realloc failed")]
    RegistryReallocFailed,
    #[msg("Program is paused")]
    Paused,
    #[msg("Invalid admin pubkey")]
    InvalidAdmin,
    #[msg("Invalid commitment")]
    InvalidCommitment,
    #[msg("Insufficient user token balance")]
    InsufficientUserBalance,
    #[msg("Invalid TEE authority pubkey")]
    InvalidTEEAuthority,
    #[msg("Asset not registered")]
    AssetNotRegistered,
    #[msg("Pool not registered")]
    PoolNotRegistered,
    #[msg("Pool mints must be different (mint_a != mint_b)")]
    IdenticalMintsNotAllowed,
    #[msg("Non-canonical mint order (require mint_a < mint_b)")]
    NonCanonicalMintOrder,
    #[msg("Liquidity instructions are disabled until the circuit binds pool identity in the note")]
    LiquidityInstructionsDisabled,
    #[msg("Dual-asset withdrawal not supported by current circuit (amount_b must be 0)")]
    DualAssetWithdrawNotSupported,
    #[msg("Token relayer fee not supported by current instruction (relayer_fee must be 0)")]
    TokenRelayerFeeNotSupported,
    #[msg("Recipient token accounts must share the same owner")]
    InvalidRecipientOwner,
    #[msg("Recipient token accounts must match the pool mints")]
    InvalidRecipientMint,
    #[msg("Groth16 Proof Verification Failed")]
    InvalidProof,
    #[msg("Merkle Tree Deserialization Failed")]
    TreeDeserializationFailed,
    #[msg("Provided Root is not in the valid history of the Pool")]
    InvalidMerkleRoot,
    #[msg("Merkle Tree account does not match Pool state")]
    WrongTree,
    #[msg("Merkle Tree account is not owned by SPL Compression Program")]
    InvalidTreeOwner,
    #[msg("Invalid program data account (upgrade authority check failed)")]
    InvalidProgramData,
    #[msg("Relayer Fee exceeds withdrawal amount")]
    FeeExceedsAmount,
    #[msg("Invalid Compression Program ID")]
    InvalidCompressionProgram,
    #[msg("Invalid Log Wrapper Program ID")]
    InvalidLogWrapper,
    #[msg("Could not parse Verifying Key")]
    InvalidVerifyingKey,
    #[msg("Insufficient funds in the pool to pay out")]
    InsufficientPoolBalance,
    #[msg("Encrypted Note too long")]
    NoteTooLong,
    #[msg("SPL Compression failed to append leaf")]
    CompressionError,
    #[msg("Leaf index is outside the configured Merkle tree capacity")]
    LeafIndexOutOfRange,
    #[msg("Merkle tree is full (no more leaves can be appended)")]
    TreeFull,
    #[msg("Input note already spent")]
    AlreadySpent,
    #[msg("Too many Merkle proof accounts provided")]
    TooManyMerkleProofAccounts,
    #[msg("Spent bitmap shard index is out of range")]
    ShardIndexOutOfRange,
    #[msg("Registry state is corrupted (vector length mismatch)")]
    RegistryCorruption,
}
