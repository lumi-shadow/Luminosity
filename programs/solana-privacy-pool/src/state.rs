use anchor_lang::prelude::*;

use crate::constants::SPENT_BITMAP_SHARD_BYTES;

// -----------------------------------------------------------------------------
// Events (logs)
// -----------------------------------------------------------------------------

#[event]
pub struct DepositEvent {
    pub commitment: [u8; 32],
    pub leaf_index: u64,
    pub amount_a: u64,
    pub amount_b: u64,
    pub encrypted_note: Vec<u8>,
}

/// Swap event for append-only swap outputs.
///
/// - Input leaf is tombstoned (replaced) using `replace_leaf`.
/// - Output leaf is appended using `Append`.
///
/// This is the first step towards append-only notes + spent-by-index bitmaps.
#[event]
pub struct SwapAppendEvent {
    pub pool: Pubkey,
    pub input_commitment: [u8; 32],
    pub input_leaf_index: u32,
    pub output_commitment: [u8; 32],
    pub output_leaf_index: u64,
    pub new_reserve_a: u64,
    pub new_reserve_b: u64,
    pub encrypted_note: Vec<u8>,
}

// -----------------------------------------------------------------------------
// Accounts (state)
// -----------------------------------------------------------------------------

#[account]
pub struct Amm {
    pub admin: Pubkey,
    pub tee_authority: Pubkey,

    // Global privacy state.
    pub merkle_tree: Pubkey,
    pub total_deposits: u64,
    // Program-wide emergency pause flag (admin-controlled).
    pub paused: bool,
}

impl Amm {
    // 8 (Discriminator)
    // + 32 (admin)
    // + 32 (tee_authority)
    // + 32 (merkle_tree)
    // + 8 (total_deposits)
    // + 1 (paused)
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 1;
}

/// Sharded spent-by-index bitmap (global across the AMM's Merkle tree).
///
/// PDA seeds: `["spent", amm, shard_index_le]`
///
/// Bit numbering:
/// - leaf_index -> (shard_index = leaf_index / SHARD_BITS, bit = leaf_index % SHARD_BITS)
/// - byte = bit / 8, mask = 1 << (bit % 8)
#[account]
pub struct SpentBitmapShard {
    pub bits: [u8; SPENT_BITMAP_SHARD_BYTES],
}

impl SpentBitmapShard {
    pub const LEN: usize = SPENT_BITMAP_SHARD_BYTES;
}

/// Lookup table entry: mint -> asset_id.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct AssetEntry {
    pub mint: Pubkey,
    pub asset_id: u32,
}

#[account]
pub struct Pool {
    pub amm: Pubkey,
    pub mint_a: Pubkey,
    pub mint_b: Pubkey,
    /// Canonical shared AMM vault ATA for mint_a (authority = AMM PDA).
    pub vault_a: Pubkey,
    /// Canonical shared AMM vault ATA for mint_b (authority = AMM PDA).
    pub vault_b: Pubkey,
    /// Total outstanding LP shares for this pool (share-based liquidity notes).
    pub total_shares: u64,
    /// Virtual reserves for this pool (TEE-updated on swaps; updated on liquidity add/remove).
    ///
    /// IMPORTANT: These are NOT necessarily equal to any single token account's raw `.amount`
    /// because vaults can be shared and swaps may be accounted for without immediate on-chain
    /// token movement.
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub bump: u8,
}

impl Pool {
    // 8 (Discriminator)
    // + 32 (amm)
    // + 32 (mint_a)
    // + 32 (mint_b)
    // + 32 (vault_a)
    // + 32 (vault_b)
    // + 8 (total_shares)
    // + 8 (reserve_a)
    // + 8 (reserve_b)
    // + 1 (bump)
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 1;
}

/// Lookup table entry: pool -> pool_id.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct PoolEntry {
    pub pool: Pubkey,
    pub pool_id: u32,
}

/// Central registry PDA holding asset + pool lookup tables.
///
/// This avoids creating one PDA per mint / per pool.
#[account]
pub struct Registry {
    /// True once the registry has been initialized by the AMM admin.
    pub is_initialized: bool,
    /// mint -> asset_id (linear scan; cheap for <= ~few hundred)
    pub assets: Vec<AssetEntry>,
    /// asset_id -> mint (index = asset_id)
    pub mints_by_asset_id: Vec<Pubkey>,
    /// pool -> pool_id (linear scan)
    pub pools: Vec<PoolEntry>,
    /// pool_id -> pool (index = pool_id)
    pub pools_by_id: Vec<Pubkey>,
    pub bump: u8,
}

impl Registry {
    /// Hard caps to prevent unbounded registry growth (compute + realloc risk).
    ///
    /// Day-1 safety: keep lookups cheap and ensure `create_pool` cannot grow the registry until it
    /// hits Solana compute/account-growth limits.
    pub const MAX_ASSETS: usize = 1024;
    pub const MAX_POOLS: usize = 1024;

    /// Minimal allocation for an empty `Registry` (all vecs length=0).
    ///
    /// We intentionally do NOT pre-allocate the full max sizes here, because Solana limits
    /// account data size increases to ~10KB per instruction (and `init` happens via CPI).
    /// The registry grows incrementally via small reallocs when new assets/pools are added.
    pub const INIT_LEN: usize = 8
        + 1  // is_initialized
        + 4  // assets vec len
        + 4  // mints_by_asset_id vec len
        + 4  // pools vec len
        + 4  // pools_by_id vec len
        + 1; // bump

    /// Compute the required serialized size for the registry given element counts.
    pub fn required_len(assets_len: usize, mints_by_id_len: usize, pools_len: usize, pools_by_id_len: usize) -> usize {
        // 8 discriminator
        // + is_initialized(1)
        // + assets: 4 + n*(mint(32)+asset_id(4))
        // + mints_by_asset_id: 4 + n*32
        // + pools: 4 + n*(pool(32)+pool_id(4))
        // + pools_by_id: 4 + n*32
        // + bump(1)
        8
            + 1
            + 4 + (assets_len * (32 + 4))
            + 4 + (mints_by_id_len * 32)
            + 4 + (pools_len * (32 + 4))
            + 4 + (pools_by_id_len * 32)
            + 1
    }
}
