// Protocol / program-wide constants.

/// The byte offset where the actual Merkle Tree data begins inside the SPL Account.
/// Format: [Header (56 bytes)] [Tree Data...]
pub const SPL_TREE_DATA_OFFSET: usize = 56;

/// SPL Concurrent Merkle Tree parameters.
///
/// Notes:
/// - `SPL_TREE_MAX_DEPTH` and `SPL_TREE_MAX_BUFFER_SIZE` must match how the tree account was created
///   (see `scripts/init_mainnet.ts`).
/// - `canopyDepth` is a separate tree configuration and does not change `SPL_TREE_MAX_DEPTH`.
pub const SPL_TREE_MAX_DEPTH: usize = 24;
pub const SPL_TREE_MAX_BUFFER_SIZE: usize = 1024;

/// Spent-by-index bitmap configuration (sharded PDAs).
///
/// We track "spentness" for leaf indices in the global Merkle tree.
/// Each shard is a fixed-size bitmap to avoid per-spend PDA rent.
pub const SPENT_BITMAP_SHARD_BITS: u32 = 8_192; // 1024 bytes
pub const SPENT_BITMAP_SHARD_BYTES: usize = (SPENT_BITMAP_SHARD_BITS as usize) / 8;

/// The 8-byte discriminator (sighash) for the SPL Compression 'Append' instruction.
pub const SPL_APPEND_DISCRIMINATOR: [u8; 8] = [0x95, 0x78, 0x12, 0xde, 0xec, 0xe1, 0x58, 0xcb];

/// The 8-byte discriminator for the SPL Account Compression `replace_leaf` instruction.
///
/// Source of truth: `@solana/spl-account-compression` generated TS instruction.
pub const SPL_REPLACE_LEAF_DISCRIMINATOR: [u8; 8] =
    [0xcc, 0xa5, 0x4c, 0x64, 0x49, 0x93, 0x00, 0x80];

// NOTE: Avoid keeping unused constants in the on-chain crate; add back when needed.
