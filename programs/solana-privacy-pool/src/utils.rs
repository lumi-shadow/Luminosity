use anchor_lang::{prelude::*, system_program::{transfer, Transfer}};

use crate::constants::{SPL_TREE_MAX_DEPTH, SPENT_BITMAP_SHARD_BITS};
use crate::errors::PrivacyError;
use crate::state::{Amm, Registry};

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

pub fn max_tree_leaves_u64() -> Result<u64> {
    // ConcurrentMerkleTree capacity = 2^depth leaves.
    // Keep this centralized so all index-bound checks stay consistent with `SPL_TREE_MAX_DEPTH`.
    1u64.checked_shl(SPL_TREE_MAX_DEPTH as u32)
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
