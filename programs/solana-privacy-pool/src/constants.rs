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

/// v2 Poseidon commitment tree (in-program, replaces the keccak SPL tree path).
///
/// `MERKLE_TREE_HEIGHT` MUST match the depth proven by the new Poseidon circuits
/// (privacy-cash / Light use 26). `ROOT_HISTORY_SIZE` is the membership-proof
/// validity window (how many recent roots stay acceptable).
pub const MERKLE_TREE_HEIGHT: u8 = 26;
pub const ROOT_HISTORY_SIZE: usize = 100;

/// PDA seed for the v2 Poseidon commitment tree: `[POSEIDON_TREE_SEED, amm]`.
pub const POSEIDON_TREE_SEED: &[u8] = b"poseidon_tree";
/// PDA seed for a spent-nullifier marker: `[NULLIFIER_SEED, amm, nullifier]`.
/// Existence of the PDA == the note is spent (replaces the leaf-index bitmap).
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Commitment domain tags. `commitment = Poseidon(noteHash, value, id, kind)`.
/// `kind` is baked per note-family so asset and LP notes can never collide even
/// when (value, id) coincide. MUST match the `kind` constants in the circuits
/// (poseidon_commitment.circom).
pub const KIND_ASSET: u8 = 1;
pub const KIND_LP: u8 = 2;

/// 8-byte discriminator for the SPL Account Compression `close_empty_tree`
/// instruction (used by the one-time keccak-tree vacuum/close to reclaim rent).
pub const SPL_CLOSE_EMPTY_TREE_DISCRIMINATOR: [u8; 8] = [50, 14, 219, 107, 78, 103, 16, 103];

// NOTE: Avoid keeping unused constants in the on-chain crate; add back when needed.
