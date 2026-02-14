// Centralized constants (kept out of `main.rs`).

// ---------------------------------------------------------------------
// Input validation limits (spam protection)
// ---------------------------------------------------------------------
pub(crate) const MAX_PUBKEY_B58_LEN: usize = 64; // base58 pubkeys are ~32-44 chars; keep slack.
pub(crate) const MAX_HEX_32_STR_LEN: usize = 2 + 64; // optional "0x" + 32 bytes hex
pub(crate) const MAX_B64_STR_LEN: usize = 512; // plenty for 32-byte keys and small blobs
pub(crate) const MAX_ENCRYPTED_BLOB_HEX_LEN: usize = 32 * 1024; // hex chars (not bytes)
pub(crate) const MAX_DECRYPTED_JSON_BYTES: usize = 16 * 1024; // browser inputs JSON should be small

// ---------------------------------------------------------------------
// Runtime defaults
// ---------------------------------------------------------------------
#[allow(dead_code)]
pub(crate) const DEFAULT_RELAYER_FEE_LAMPORTS: u64 = 5_000_000; // 0.005 SOL (legacy fixed-fee mode)
/// Default relayer fee in basis points (bps).
///
/// 25 bps = 0.25%.
pub(crate) const DEFAULT_RELAYER_FEE_BPS: u64 = 25;
pub(crate) const DEFAULT_NODE_MAX_OLD_SPACE_MB: u32 = 8192;

// ---------------------------------------------------------------------
// Prover artifact defaults
// ---------------------------------------------------------------------
pub(crate) const DEFAULT_WITHDRAW_WASM_PATH: &str = "/circuits/withdraw.wasm";
pub(crate) const DEFAULT_WITHDRAW_ZKEY_PATH: &str = "/circuits/withdraw_final.zkey";
pub(crate) const DEFAULT_WITHDRAW_WITNESS_JS: &str = "/circuits/withdraw_js/generate_witness.js";
pub(crate) const DEFAULT_WITHDRAW_WITNESS_BIN: &str = "/usr/local/bin/withdraw_witness";
pub(crate) const DEFAULT_RAPIDSNARK_PATH: &str = "/usr/local/bin/rapidsnark";

pub(crate) const DEFAULT_WITHDRAW_LIQUIDITY_WASM_PATH: &str = "/circuits/withdraw_liquidity.wasm";
pub(crate) const DEFAULT_WITHDRAW_LIQUIDITY_ZKEY_PATH: &str =
    "/circuits/withdraw_liquidity_final.zkey";
pub(crate) const DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_JS: &str =
    "/circuits/withdraw_liquidity_js/generate_witness.js";
pub(crate) const DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_BIN: &str =
    "/usr/local/bin/withdraw_liquidity_witness";

pub(crate) const DEFAULT_SWAP_ZK_WASM_PATH: &str = "/circuits/swap_zk.wasm";
pub(crate) const DEFAULT_SWAP_ZK_ZKEY_PATH: &str = "/circuits/swap_zk_final.zkey";
pub(crate) const DEFAULT_SWAP_ZK_WITNESS_JS: &str =
    "/circuits/swap_zk_js/generate_witness.js";
pub(crate) const DEFAULT_SWAP_ZK_WITNESS_BIN: &str = "/usr/local/bin/swap_zk_witness";

// ---------------------------------------------------------------------
// Common program constants
// ---------------------------------------------------------------------
pub(crate) const WSOL_MINT_B58: &str = "So11111111111111111111111111111111111111112";
