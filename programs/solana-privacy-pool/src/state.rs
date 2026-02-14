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

/// Swap event for append-only swap outputs (TEE path, legacy).
///
/// - Input leaf is tombstoned (replaced) using `replace_leaf`.
/// - Output leaf is appended using `Append`.
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

/// ZK swap event (permissionless Path C).
///
/// Emitted by `execute_zk_swap` — fully on-chain PMM pricing, no TEE.
#[event]
pub struct ZkSwapEvent {
    pub pool: Pubkey,
    pub input_commitment: [u8; 32],
    pub input_leaf_index: u32,
    pub output_commitment: [u8; 32],
    pub output_leaf_index: u64,
    pub amount_in: u64,
    pub amount_out: u64,
    pub asset_id_in: u32,
    pub asset_id_out: u32,
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

/// Admin-configurable PMM policy knobs (stored on each Pool).
///
/// All values are u16/i16 (max ±32 767 bps = ±327.67%). This keeps the struct compact (18 bytes)
/// while covering any realistic parameter range.
///
/// Sane defaults are provided via `PmmConfig::default()`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct PmmConfig {
    /// Additional spread for trade size: `spread += size_bps * size_spread_mult / 10_000`.
    pub size_spread_mult_bps: u16,
    /// Additional spread from oracle confidence: `spread += conf_bps * conf_spread_mult / 10_000`.
    pub conf_spread_mult_bps: u16,
    /// Additional spread per second of oracle staleness.
    pub stale_spread_bps_per_sec: u16,
    /// Hard cap on total spread (bps).
    pub max_spread_bps: u16,
    /// Inventory skew multiplier: `skew_bps = clamp(signal * skew_k / 10_000, ±max_skew)`.
    pub skew_k_bps: i16,
    /// Maximum absolute skew (bps).
    pub max_skew_bps: u16,
    /// Small-imbalance skew sensitivity denominator.
    /// Signal = |imbalance_bps| / skew_small_div (gentle linear ramp for small imbalances).
    pub skew_small_div_bps: u16,
    /// Only apply CPMM output cap when trade is >= this fraction of reserve_in (bps).
    pub cpmm_cap_min_size_bps: u16,
    /// Maximum oracle age in seconds before the swap is rejected.
    pub max_oracle_age_secs: u16,
}

impl PmmConfig {
    /// Serialized size: 9 × u16 = 18 bytes.
    pub const SIZE: usize = 9 * 2;
}

impl Default for PmmConfig {
    fn default() -> Self {
        Self {
            size_spread_mult_bps: 500,    // 5% of size_bps added to spread
            conf_spread_mult_bps: 2_000,  // 20% of oracle confidence width
            stale_spread_bps_per_sec: 5,  // 5 bps per second of staleness
            max_spread_bps: 500,          // 5% hard cap on spread
            skew_k_bps: 5_000,            // 50% multiplier on imbalance signal
            max_skew_bps: 200,            // 2% max skew
            skew_small_div_bps: 50,       // gentle linear signal divisor
            cpmm_cap_min_size_bps: 200,   // 2% threshold for CPMM cap
            max_oracle_age_secs: 60,      // 60s max oracle staleness
        }
    }
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
    /// Virtual reserves for this pool (updated on swaps and liquidity add/remove).
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub bump: u8,
    // --- V2 fields (ZK swap support) ---
    /// Pyth push-oracle price account for mint_a.
    pub oracle_a: Pubkey,
    /// Pyth push-oracle price account for mint_b.
    pub oracle_b: Pubkey,
    /// Mint decimals for mint_a (cached to avoid extra account reads during swaps).
    pub dec_a: u8,
    /// Mint decimals for mint_b.
    pub dec_b: u8,
    /// Base spread in bps applied to all swaps via the on-chain PMM.
    pub fee_bps: u16,
    /// Admin-tunable PMM pricing policy knobs.
    pub pmm: PmmConfig,
}

impl Pool {
    // 8 (Discriminator)
    // + 32 (amm) + 32 (mint_a) + 32 (mint_b) + 32 (vault_a) + 32 (vault_b)
    // + 8 (total_shares) + 8 (reserve_a) + 8 (reserve_b) + 1 (bump)
    // + 32 (oracle_a) + 32 (oracle_b) + 1 (dec_a) + 1 (dec_b) + 2 (fee_bps)
    // + 18 (PmmConfig)
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 8 + 8 + 8 + 1
        + 32 + 32 + 1 + 1 + 2
        + PmmConfig::SIZE;
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
