use anchor_lang::{prelude::*, system_program::{transfer, Transfer}};
use light_hasher::{Hasher, Poseidon};
use spl_concurrent_merkle_tree::concurrent_merkle_tree::ConcurrentMerkleTree;

use crate::constants::{
    MERKLE_TREE_HEIGHT, NULLIFIER_SEED, POSEIDON_TREE_SEED, SPL_APPEND_DISCRIMINATOR,
    SPL_CLOSE_EMPTY_TREE_DISCRIMINATOR, SPL_REPLACE_LEAF_DISCRIMINATOR, SPL_TREE_DATA_OFFSET,
    SPL_TREE_MAX_BUFFER_SIZE, SPL_TREE_MAX_DEPTH, SPENT_BITMAP_SHARD_BITS, SPENT_BITMAP_SHARD_BYTES,
};
use crate::state::{MerkleTreeAccount, NullifierAccount};
use crate::errors::PrivacyError;
use crate::state::{Amm, Registry, SpentBitmapShard};

// -----------------------------------------------------------------------------
// Small protocol helpers (kept out of `lib.rs`)
// -----------------------------------------------------------------------------

pub fn amm_is_paused(amm: &Amm) -> bool {
    amm.paused
}

pub fn require_not_paused(amm: &Amm) -> Result<()> {
    require!(!amm_is_paused(amm), PrivacyError::Paused);
    Ok(())
}

/// Big-endian 32-byte field element from a byte slice.
pub fn to_field_element(slice: &[u8]) -> [u8; 32] {
    let mut elem = [0u8; 32];
    elem[32 - slice.len()..].copy_from_slice(slice);
    elem
}

/// Validate a Merkle root against the SPL tree changelog buffer.
pub fn require_valid_root(merkle_tree: &AccountInfo, root: &[u8; 32]) -> Result<()> {
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
pub fn post_append_update(
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
pub fn cpi_spl_append<'a>(
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
pub fn cpi_spl_replace_leaf<'a>(
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
pub fn validate_and_mark_spent(
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
pub fn validate_not_spent(
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

pub fn max_tree_leaves_u64() -> Result<u64> {
    // Poseidon tree capacity = 2^height leaves. The spent bitmap is keyed by
    // leaf_index, so its bound MUST track the ACTIVE (Poseidon) tree depth, not
    // the legacy SPL depth.
    1u64.checked_shl(MERKLE_TREE_HEIGHT as u32)
        .ok_or_else(|| PrivacyError::MathOverflow.into())
}

pub fn require_leaf_index_in_range(leaf_index: u32) -> Result<()> {
    let max = max_tree_leaves_u64()?;
    require!(
        (leaf_index as u64) < max,
        PrivacyError::LeafIndexOutOfRange
    );
    Ok(())
}

pub fn max_spent_shard_index_u32() -> Result<u32> {
    // Last valid leaf index = max_leaves - 1. Shard index = leaf_index / SHARD_BITS.
    let max_leaves = max_tree_leaves_u64()?;
    let max_leaf_index = max_leaves
        .checked_sub(1)
        .ok_or(PrivacyError::MathOverflow)?;
    let max_shard = max_leaf_index / (SPENT_BITMAP_SHARD_BITS as u64);
    u32::try_from(max_shard).map_err(|_| PrivacyError::MathOverflow.into())
}

pub fn ensure_registry_capacity<'info>(
    registry: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    new_len: usize,
) -> Result<()> {
    let current_len = registry.data_len();
    if current_len >= new_len {
        return Ok(());
    }

    // Top up lamports once so the account remains rent-exempt for the final size.
    let rent = Rent::get()?;
    let required = rent.minimum_balance(new_len);
    let current_lamports = registry.lamports();
    if current_lamports < required {
        let top_up = required
            .checked_sub(current_lamports)
            .ok_or(PrivacyError::MathOverflow)?;
        transfer(
            CpiContext::new(
                system_program.clone(),
                Transfer {
                    from: payer.clone(),
                    to: registry.clone(),
                },
            ),
            top_up,
        )?;
    }

    // Solana enforces a hard limit on how much account data can grow per instruction.
    // Grow the registry in small chunks (<= 10_240 bytes) to stay under the limit.
    let mut cur = current_len;
    while cur < new_len {
        let step = core::cmp::min(10_240usize, new_len - cur);
        let next = cur + step;
        registry
            .resize(next)
            .map_err(|_| PrivacyError::RegistryReallocFailed)?;
        cur = next;
    }

    Ok(())
}


// -----------------------------------------------------------------------------
// v2 Poseidon shielded path: commitment + tree ops
// -----------------------------------------------------------------------------

/// Two-layer domain-separated commitment computed on-chain — MUST match
/// `Commitment` in circuits/poseidon_commitment.circom:
///   `commitment = Poseidon(note_hash, value, id, kind)`
/// with each scalar encoded as a big-endian BN254 field element (the same
/// encoding the circuits' public inputs use, and that light-hasher == circomlib
/// was gate-verified against).
pub fn poseidon_commitment(
    note_hash: &[u8; 32],
    value: u64,
    id: u32,
    kind: u8,
) -> Result<[u8; 32]> {
    let mut value_fe = [0u8; 32];
    value_fe[24..].copy_from_slice(&value.to_be_bytes());
    let mut id_fe = [0u8; 32];
    id_fe[28..].copy_from_slice(&id.to_be_bytes());
    let mut kind_fe = [0u8; 32];
    kind_fe[31] = kind;
    Poseidon::hashv(&[note_hash, &value_fe, &id_fe, &kind_fe])
        .map_err(|_| PrivacyError::PoseidonHashFailed.into())
}

/// Append a commitment to the in-program Poseidon tree and return its leaf index
/// (captured before the append increments `next_index`). Replaces `cpi_spl_append`.
pub fn poseidon_append(
    merkle_tree: &AccountLoader<MerkleTreeAccount>,
    commitment: &[u8; 32],
) -> Result<u64> {
    let mut tree = merkle_tree.load_mut()?;
    let leaf_index = tree.next_index;
    crate::poseidon_merkle_tree::MerkleTree::append::<Poseidon>(*commitment, &mut tree)?;
    Ok(leaf_index)
}

/// Poseidon-tree replacement for `require_valid_root`: accept a proof only
/// against a recently-seen root.
pub fn require_poseidon_root(
    merkle_tree: &AccountLoader<MerkleTreeAccount>,
    root: &[u8; 32],
) -> Result<()> {
    let tree = merkle_tree.load()?;
    require!(
        crate::poseidon_merkle_tree::MerkleTree::is_known_root(&tree, *root),
        PrivacyError::InvalidMerkleRoot
    );
    Ok(())
}

/// CPI to SPL Account Compression `close_empty_tree` — closes the (already
/// zeroed) legacy keccak tree and sends its rent lamports to `recipient`.
/// Signed by the AMM PDA (the tree authority). One-time vacuum/close path.
pub fn cpi_spl_close_empty_tree<'a>(
    compression_program: &AccountInfo<'a>,
    merkle_tree: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    recipient: &AccountInfo<'a>,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let ix = solana_program::instruction::Instruction {
        program_id: compression_program.key(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new(merkle_tree.key(), false),
            solana_program::instruction::AccountMeta::new_readonly(authority.key(), true),
            solana_program::instruction::AccountMeta::new(recipient.key(), false),
        ],
        data: SPL_CLOSE_EMPTY_TREE_DISCRIMINATOR.to_vec(),
    };
    solana_program::program::invoke_signed(
        &ix,
        &[
            compression_program.clone(),
            merkle_tree.clone(),
            authority.clone(),
            recipient.clone(),
        ],
        signer_seeds,
    )?;
    Ok(())
}

// -----------------------------------------------------------------------------
// v2 Poseidon shielded path: PDA derivation + nullifier helpers
// -----------------------------------------------------------------------------

/// Derive the v2 Poseidon commitment-tree PDA for an AMM.
pub fn poseidon_tree_pda(amm: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POSEIDON_TREE_SEED, amm.as_ref()], &crate::ID)
}

/// Derive the spent-nullifier PDA. The nullifier is bound to the AMM so the same
/// Poseidon nullifier in different AMMs cannot collide; existence == spent.
/// Intended for clients / tests — on-chain spend instructions obtain the bump
/// from the Anchor `seeds`/`init` constraint instead of recomputing it here.
pub fn nullifier_pda(amm: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[NULLIFIER_SEED, amm.as_ref(), nullifier], &crate::ID)
}

/// Stamp a freshly-`init`'d nullifier marker as spent. Called by spend
/// instructions after the proof verifies; the `init` constraint already
/// guarantees the nullifier was unspent (a replay fails account creation).
pub fn record_nullifier(acct: &mut NullifierAccount, bump: u8) -> Result<()> {
    acct.spent_at_slot = Clock::get()?.slot;
    acct.bump = bump;
    Ok(())
}

pub fn integer_sqrt_u128(n: u128) -> u128 {
    // Integer sqrt via Newton's method (floor(sqrt(n))).
    if n == 0 {
        return 0;
    }
    let mut x0 = n;
    let mut x1 = (x0 + 1) >> 1;
    while x1 < x0 {
        x0 = x1;
        x1 = (x1 + n / x1) >> 1;
    }
    x0
}

pub fn registry_upsert_asset(reg: &mut Registry, mint: Pubkey, asset_id: u32) -> Result<()> {
    // Invariant: these vectors must remain in lock-step (index = asset_id).
    require!(
        reg.assets.len() == reg.mints_by_asset_id.len(),
        PrivacyError::RegistryCorruption
    );
    // Only used internally after selecting an id; enforce "append-only, no holes".
    let expected = reg.mints_by_asset_id.len() as u32;
    require!(asset_id == expected, PrivacyError::AssetRegistryMismatch);
    require!(reg.assets.len() < Registry::MAX_ASSETS, PrivacyError::RegistryFull);

    // Ensure mint is not already registered.
    require!(
        registry_asset_id_for_mint(reg, mint).is_none(),
        PrivacyError::AssetRegistryMismatch
    );

    reg.mints_by_asset_id.push(mint);
    reg.assets.push(crate::state::AssetEntry { mint, asset_id });
    Ok(())
}

/// Resolve `mint -> asset_id` (linear scan).
pub fn registry_asset_id_for_mint(reg: &Registry, mint: Pubkey) -> Option<u32> {
    reg.assets
        .iter()
        .find(|e| e.mint == mint)
        .map(|e| e.asset_id)
}

/// Allocate a fresh asset_id (array-style) and register `mint <-> asset_id`.
///
/// We pick the next sequential id (`mints_by_asset_id.len()`). This makes asset_ids:
/// - deterministic
/// - compact (no user-chosen holes)
/// - immune to user-supplied collisions
pub fn registry_get_or_alloc_asset_id(reg: &mut Registry, mint: Pubkey) -> Result<u32> {
    // If already registered, return the existing id (idempotent).
    if let Some(id) = registry_asset_id_for_mint(reg, mint) {
        return Ok(id);
    }

    let asset_id = reg.mints_by_asset_id.len() as u32;
    registry_upsert_asset(reg, mint, asset_id)?;
    Ok(asset_id)
}

pub fn registry_upsert_pool(reg: &mut Registry, pool: Pubkey, pool_id: u32) -> Result<()> {
    // Invariant: these vectors must remain in lock-step (index = pool_id).
    require!(
        reg.pools.len() == reg.pools_by_id.len(),
        PrivacyError::RegistryCorruption
    );
    // Only used internally after selecting an id; enforce "append-only, no holes".
    let expected = reg.pools_by_id.len() as u32;
    require!(pool_id == expected, PrivacyError::PoolRegistryMismatch);
    require!(reg.pools.len() < Registry::MAX_POOLS, PrivacyError::RegistryFull);

    // Ensure pool is not already registered.
    require!(
        registry_pool_id_for_pool(reg, pool).is_none(),
        PrivacyError::PoolRegistryMismatch
    );

    reg.pools_by_id.push(pool);
    reg.pools.push(crate::state::PoolEntry { pool, pool_id });
    Ok(())
}

/// Allocate a fresh pool_id (array-style) and register `pool -> pool_id` + `pool_id -> pool`.
///
/// We pick the next sequential id (`pools_by_id.len()`). This makes pool_ids:
/// - deterministic
/// - compact (no user-chosen holes)
/// - immune to user-supplied collisions
pub fn registry_alloc_and_register_pool(reg: &mut Registry, pool: Pubkey) -> Result<u32> {
    // If already registered, return the existing id (idempotent).
    if let Some(e) = reg.pools.iter().find(|e| e.pool == pool) {
        return Ok(e.pool_id);
    }

    let pool_id = reg.pools_by_id.len() as u32;
    registry_upsert_pool(reg, pool, pool_id)?;
    Ok(pool_id)
}

/// Resolve `pool -> pool_id` (linear scan).
pub fn registry_pool_id_for_pool(reg: &Registry, pool: Pubkey) -> Option<u32> {
    reg.pools.iter().find(|e| e.pool == pool).map(|e| e.pool_id)
}

pub fn registry_mint_is_registered(reg: &Registry, mint: Pubkey) -> bool {
    registry_asset_id_for_mint(reg, mint).is_some()
}

pub fn registry_pool_is_registered(reg: &Registry, pool: Pubkey) -> bool {
    registry_pool_id_for_pool(reg, pool).is_some()
}
