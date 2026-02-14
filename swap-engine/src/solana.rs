//! Solana RPC helpers + on-chain transaction builder.
//!
//! The swap engine intentionally does not use Anchor TS here.
//! We build the instruction data manually (Anchor ABI) because:
//! - the service is Rust
//! - the instruction args are simple and stable
//! - it avoids a dependency on Anchor client codegen

use crate::types::{AppError, PoolAccount, RfqSwapUpdate};
use borsh::BorshDeserialize;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signature, Signer};
#[allow(deprecated)]
use solana_sdk::system_program;
use solana_sdk::transaction::Transaction;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};
use solana_transaction_status::TransactionConfirmationStatus;

pub const SPL_ACCOUNT_COMPRESSION_PROGRAM_ID: &str = "cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK";
pub const SPL_NOOP_PROGRAM_ID: &str = "noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV";
pub const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

static MINT_DECIMALS_CACHE: OnceLock<HashMap<Pubkey, u8>> = OnceLock::new();
static POOL_CACHE: OnceLock<RwLock<HashMap<Pubkey, (PoolAccount, u128)>>> = OnceLock::new();

/// PMM config stored on-chain (9 × u16 = 18 bytes).
/// Must match `PmmConfig` in `programs/solana-privacy-pool/src/state.rs`.
#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct PmmConfigBorsh {
    pub size_spread_mult_bps: u16,
    pub conf_spread_mult_bps: u16,
    pub stale_spread_bps_per_sec: u16,
    pub max_spread_bps: u16,
    pub skew_k_bps: i16,
    pub max_skew_bps: u16,
    pub skew_small_div_bps: u16,
    pub cpmm_cap_min_size_bps: u16,
    pub max_oracle_age_secs: u16,
}

/// Must match the on-chain `Pool` account layout (V2, after migration).
/// See `programs/solana-privacy-pool/src/state.rs`.
#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct PoolBorsh {
    pub amm: Pubkey,
    pub mint_a: Pubkey,
    pub mint_b: Pubkey,
    pub vault_a: Pubkey,
    pub vault_b: Pubkey,
    pub total_shares: u64,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub bump: u8,
    // --- V2 fields (ZK swap / PMM support) ---
    pub oracle_a: Pubkey,
    pub oracle_b: Pubkey,
    pub dec_a: u8,
    pub dec_b: u8,
    pub fee_bps: u16,
    pub pmm: PmmConfigBorsh,
}

pub fn rpc_client(rpc_url: String) -> RpcClient {
    RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed())
}

pub fn anchor_discriminator(ix_name: &str) -> [u8; 8] {
    // Anchor discriminator for global instructions:
    // sha256("global:<ix_name>")[..8]
    let mut h = Sha256::new();
    h.update(format!("global:{ix_name}").as_bytes());
    let out = h.finalize();
    out[..8].try_into().expect("slice")
}

pub fn amm_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"amm"], program_id)
}

pub fn canonical_mints(a: Pubkey, b: Pubkey) -> (Pubkey, Pubkey) {
    if a.to_bytes() < b.to_bytes() {
        (a, b)
    } else {
        (b, a)
    }
}

pub fn pool_pda(program_id: &Pubkey, mint_a: &Pubkey, mint_b: &Pubkey) -> (Pubkey, u8) {
    // Pool seeds on-chain:
    //   [amm_pda, mint_a, mint_b] with canonical ordering mint_a < mint_b
    let (amm, _bump) = amm_pda(program_id);
    Pubkey::find_program_address(
        &[amm.as_ref(), mint_a.as_ref(), mint_b.as_ref()],
        program_id,
    )
}

#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct AssetEntryBorsh {
    pub mint: Pubkey,
    pub asset_id: u32,
}

#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct PoolEntryBorsh {
    pub pool: Pubkey,
    pub pool_id: u32,
}

#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct RegistryBorsh {
    pub is_initialized: bool,
    pub assets: Vec<AssetEntryBorsh>,
    pub mints_by_asset_id: Vec<Pubkey>,
    pub pools: Vec<PoolEntryBorsh>,
    pub pools_by_id: Vec<Pubkey>,
    pub bump: u8,
}

pub fn registry_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"registry"], program_id)
}

pub fn spent_shard_pda(program_id: &Pubkey, amm: &Pubkey, shard_index: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"spent", amm.as_ref(), &shard_index.to_le_bytes()],
        program_id,
    )
}

pub fn fetch_registry_pools(rpc: &RpcClient, program_id: &Pubkey) -> Result<Vec<Pubkey>, AppError> {
    let (reg, _bump) = registry_pda(program_id);
    let acc = rpc
        .get_account(&reg)
        .map_err(|e| AppError::BadGateway(format!("fetch registry failed: {e}")))?;
    if acc.data.len() < 8 {
        return Err(AppError::BadGateway("registry account too small".into()));
    }
    let body = &acc.data[8..];
    // Registry layout must match the on-chain Anchor account exactly.
    let reg = RegistryBorsh::try_from_slice(body)
        .map_err(|e| AppError::BadGateway(format!("registry decode failed: {e}")))?;
    if !reg.is_initialized {
        return Err(AppError::BadGateway("registry not initialized".into()));
    }
    Ok(reg.pools_by_id)
}

pub fn fetch_asset_id_for_mint(
    rpc: &RpcClient,
    program_id: &Pubkey,
    mint: &Pubkey,
) -> Result<u32, AppError> {
    let (reg, _bump) = registry_pda(program_id);
    let acc = rpc
        .get_account(&reg)
        .map_err(|e| AppError::BadGateway(format!("fetch registry failed: {e}")))?;
    if acc.data.len() < 8 {
        return Err(AppError::BadGateway("registry account too small".into()));
    }
    let body = &acc.data[8..];
    // See `fetch_registry_pools`.
    let reg = RegistryBorsh::try_from_slice(body)
        .map_err(|e| AppError::BadGateway(format!("registry decode failed: {e}")))?;
    if !reg.is_initialized {
        return Err(AppError::BadGateway("registry not initialized".into()));
    }
    for a in reg.assets {
        if &a.mint == mint {
            return Ok(a.asset_id);
        }
    }
    Err(AppError::BadGateway(
        "mint not registered in registry".into(),
    ))
}

pub fn fetch_pool(rpc: &RpcClient, pool: &Pubkey) -> Result<PoolAccount, AppError> {
    // The pool is an Anchor account with an 8-byte discriminator prefix,
    // followed by borsh-serialized fields.
    let acc = rpc
        .get_account(pool)
        .map_err(|e| AppError::BadGateway(format!("fetch pool failed: {e}")))?;
    if acc.data.len() < 8 {
        return Err(AppError::BadGateway("pool account too small".into()));
    }
    let body = &acc.data[8..];
    let p = PoolBorsh::try_from_slice(body)
        .map_err(|e| AppError::BadGateway(format!("pool decode failed: {e}")))?;
    Ok(PoolAccount {
        amm: p.amm,
        mint_a: p.mint_a,
        mint_b: p.mint_b,
        vault_a: p.vault_a,
        vault_b: p.vault_b,
        reserve_a: p.reserve_a,
        reserve_b: p.reserve_b,
    })
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn pool_cache() -> &'static RwLock<HashMap<Pubkey, (PoolAccount, u128)>> {
    POOL_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn upsert_pool_cache(pool: &Pubkey, p: PoolAccount) {
    let enabled = std::env::var("POOL_CACHE_ENABLED")
        .ok()
        .map(|v| v.trim().to_lowercase() != "false")
        .unwrap_or(true);
    if !enabled {
        return;
    }
    if let Ok(mut g) = pool_cache().write() {
        g.insert(*pool, (p, now_ms()));
    }
}

/// Remove a pool entry from the in-process cache.
///
/// This is safe to call after submitting an `execute` transaction:
/// - if the tx lands, the next `/quote` will fetch the updated on-chain reserves
/// - if the tx fails/expires, the next `/quote` will fetch the unchanged on-chain reserves
pub fn invalidate_pool_cache(pool: &Pubkey) {
    if let Ok(mut g) = pool_cache().write() {
        g.remove(pool);
    }
}

pub fn fetch_pool_cached(rpc: &RpcClient, pool: &Pubkey) -> Result<PoolAccount, AppError> {
    let enabled = std::env::var("POOL_CACHE_ENABLED")
        .ok()
        .map(|v| v.trim().to_lowercase() != "false")
        .unwrap_or(true);
    if !enabled {
        return fetch_pool(rpc, pool);
    }
    let mut ttl_ms: u128 = std::env::var("POOL_CACHE_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(250);
    // Safety clamp: very large TTLs can make quotes look "stuck" after executes.
    // Keep it small; this cache is only meant to smooth bursts and avoid repeated RPC hits.
    const TTL_MS_HARD_CAP: u128 = 2_000;
    if ttl_ms > TTL_MS_HARD_CAP {
        tracing::warn!(
            "POOL_CACHE_TTL_MS={}ms too large; clamping to {}ms",
            ttl_ms,
            TTL_MS_HARD_CAP
        );
        ttl_ms = TTL_MS_HARD_CAP;
    }

    if ttl_ms > 0 {
        if let Ok(g) = pool_cache().read() {
            if let Some((p, ts)) = g.get(pool) {
                if now_ms().saturating_sub(*ts) <= ttl_ms {
                    return Ok(p.clone());
                }
            }
        }
    }

    let p = fetch_pool(rpc, pool)?;
    if let Ok(mut g) = pool_cache().write() {
        g.insert(*pool, (p.clone(), now_ms()));
    }
    Ok(p)
}

pub fn fetch_token_account_amounts(
    rpc: &RpcClient,
    token_accounts: &[Pubkey],
) -> Result<Vec<Option<u64>>, AppError> {
    if token_accounts.is_empty() {
        return Ok(Vec::new());
    }
    let accs = rpc
        .get_multiple_accounts(token_accounts)
        .map_err(|e| AppError::BadGateway(format!("fetch multiple token accounts failed: {e}")))?;
    let mut out = Vec::with_capacity(accs.len());
    for acc in accs {
        let Some(acc) = acc else {
            out.push(None);
            continue;
        };
        if acc.data.len() < 72 {
            return Err(AppError::BadGateway("token account too small".into()));
        }
        let amt = u64::from_le_bytes(acc.data[64..72].try_into().expect("slice"));
        out.push(Some(amt));
    }
    Ok(out)
}

fn fetch_mint_decimals_via_rpc(rpc: &RpcClient, mint: &Pubkey) -> Result<u8, AppError> {
    // SPL Token Mint layout (82 bytes):
    //   mint_authority: COption<Pubkey>  (4 + 32)
    //   supply: u64                    (+8)   => offset 36..44
    //   decimals: u8                   (+1)   => offset 44
    //   is_initialized: bool           (+1)
    //   freeze_authority: COption<Pubkey> (4 + 32)
    let acc = rpc
        .get_account(mint)
        .map_err(|e| AppError::BadGateway(format!("fetch mint failed: {e}")))?;
    if acc.data.len() < 45 {
        return Err(AppError::BadGateway("mint account too small".into()));
    }
    Ok(acc.data[44])
}

/// Initialize a cache of SPL mint decimals by scanning the on-chain registry pools.
///
/// This is called once at process startup so we don't do an RPC fetch on every quote/execute.
pub fn init_mint_decimals_cache(rpc: &RpcClient, program_id: &Pubkey) -> Result<usize, AppError> {
    let pools = fetch_registry_pools(rpc, program_id)?;
    let mut mints: HashSet<Pubkey> = HashSet::new();
    for pk in pools {
        // Skip empty/default entries (unregistered pool_id slots).
        if pk == Pubkey::default() {
            continue;
        }
        let p = fetch_pool(rpc, &pk)?;
        mints.insert(p.mint_a);
        mints.insert(p.mint_b);
    }
    let mut map: HashMap<Pubkey, u8> = HashMap::with_capacity(mints.len());
    for mint in mints {
        let dec = fetch_mint_decimals_via_rpc(rpc, &mint)?;
        map.insert(mint, dec);
    }
    let n = map.len();
    MINT_DECIMALS_CACHE
        .set(map)
        .map_err(|_| AppError::BadGateway("mint decimals cache already initialized".into()))?;
    Ok(n)
}

/// Fetch mint decimals **from the in-memory cache** (no RPC).
///
/// The cache is populated once at startup via `init_mint_decimals_cache`.
pub fn fetch_mint_decimals(mint: &Pubkey) -> Result<u8, AppError> {
    let map = MINT_DECIMALS_CACHE
        .get()
        .ok_or_else(|| AppError::BadGateway("mint decimals cache not initialized".into()))?;
    map.get(mint).copied().ok_or_else(|| {
        AppError::BadRequest(format!(
            "unknown mint (decimals not cached from registry pools): {mint}"
        ))
    })
}

#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct AmmBorshV2 {
    pub admin: Pubkey,
    pub tee_authority: Pubkey,
    pub merkle_tree: Pubkey,
    pub total_deposits: u64,
    // Added in the current on-chain layout (v2): global emergency pause flag.
    pub paused: bool,
}

// Legacy AMM layout (kept on-chain for backward compatibility with already-deployed dev accounts).
#[derive(BorshDeserialize)]
#[allow(dead_code)]
struct AmmBorshV1 {
    pub admin: Pubkey,
    pub tee_authority: Pubkey,
    pub merkle_tree: Pubkey,
    pub total_deposits: u64,
    pub current_root_index: u64,
    pub roots: [[u8; 32]; 30],
}

pub fn fetch_amm_tree_and_tee(
    rpc: &RpcClient,
    program_id: &Pubkey,
) -> Result<(Pubkey, Pubkey), AppError> {
    // We read the on-chain AMM PDA and extract:
    // - merkle_tree address (SPL compression tree)
    // - tee_authority pubkey (must sign swaps)
    let (amm, _bump) = amm_pda(program_id);
    let acc = rpc
        .get_account(&amm)
        .map_err(|e| AppError::BadGateway(format!("fetch amm failed: {e}")))?;
    if acc.data.len() < 8 {
        return Err(AppError::BadGateway("amm account too small".into()));
    }
    let body = &acc.data[8..];
    // Prefer decoding the current layout, but keep fallback for legacy deployed accounts.
    if let Ok(a) = AmmBorshV2::try_from_slice(body) {
        return Ok((a.merkle_tree, a.tee_authority));
    }
    let a = AmmBorshV1::try_from_slice(body)
        .map_err(|e| AppError::BadGateway(format!("amm decode failed (v1/v2): {e}")))?;
    Ok((a.merkle_tree, a.tee_authority))
}

#[allow(clippy::too_many_arguments)]
pub fn execute_rfq_swap_append_tx(
    rpc: &RpcClient,
    program_id: Pubkey,
    tee_authority: &Keypair,
    pool: Pubkey,
    merkle_tree: Pubkey,
    // Expected pool reserves from the state snapshot used to compute `swap.new_reserve_*`.
    // This defends against TOCTOU races where another swap updates reserves before we submit.
    expected_pool_reserve_a: u64,
    expected_pool_reserve_b: u64,
    swap: RfqSwapUpdate,
    encrypted_note: &[u8],
    siblings: &[[u8; 32]],
) -> Result<Signature, AppError> {
    // This builds the Anchor instruction:
    //
    //   execute_rfq_swap_append(swap: RfqSwapUpdate, encrypted_note: Vec<u8>)
    //
    // The program performs:
    // - `replace_leaf` CPI to tombstone the input leaf (uses provided siblings as remaining accounts)
    // - `Append` CPI to mint the output leaf at a fresh index
    // - updates pool.virtual_reserves
    // - emits SwapAppendEvent (includes encrypted note bytes)
    let (config, _bump) = amm_pda(&program_id);

    let compression_program = Pubkey::from_str(SPL_ACCOUNT_COMPRESSION_PROGRAM_ID).expect("static");
    let noop_program = Pubkey::from_str(SPL_NOOP_PROGRAM_ID).expect("static");
    let token_program = Pubkey::from_str(SPL_TOKEN_PROGRAM_ID).expect("static");

    // Defense-in-depth:
    // - Ensure the provided merkle_tree matches on-chain AMM config
    // - Ensure the signing key matches on-chain expected tee_authority
    {
        let (onchain_tree, onchain_tee) = fetch_amm_tree_and_tee(rpc, &program_id)?;
        if onchain_tree != merkle_tree {
            tracing::warn!(
                provided = %merkle_tree,
                onchain = %onchain_tree,
                "merkle_tree mismatch"
            );
            return Err(AppError::Forbidden("merkle_tree mismatch".into()));
        }
        if onchain_tee != tee_authority.pubkey() {
            tracing::warn!(
                provided = %tee_authority.pubkey(),
                onchain_expected = %onchain_tee,
                "TEE key mismatch"
            );
            return Err(AppError::Forbidden("TEE key mismatch".into()));
        }
    }

    // Read pool to discover canonical vaults (needed by Phase 1 on-chain solvency guard).
    let pool_acc = fetch_pool(rpc, &pool)?;

    // TOCTOU guard: ensure pool reserves haven't changed since the snapshot we used
    // to compute `swap.new_reserve_a/b`.
    //
    // If they changed, the safest response is to fail closed and require the caller to re-quote.
    if pool_acc.reserve_a != expected_pool_reserve_a || pool_acc.reserve_b != expected_pool_reserve_b {
        tracing::warn!(
            expected_reserve_a = expected_pool_reserve_a,
            expected_reserve_b = expected_pool_reserve_b,
            onchain_reserve_a = pool_acc.reserve_a,
            onchain_reserve_b = pool_acc.reserve_b,
            "pool state changed before submit"
        );
        return Err(AppError::Forbidden(
            "pool state changed before submit (retry)".into(),
        ));
    }

    // Engine-side solvency guard against stale vault balances (race between fetch and submit).
    // This is redundant with the on-chain guard but provides earlier/friendlier failure.
    {
        let amts = fetch_token_account_amounts(rpc, &[pool_acc.vault_a, pool_acc.vault_b])?;
        let vault_a_amt = amts.get(0).and_then(|v| *v).unwrap_or(0);
        let vault_b_amt = amts.get(1).and_then(|v| *v).unwrap_or(0);
        if swap.new_reserve_a > vault_a_amt || swap.new_reserve_b > vault_b_amt {
            tracing::warn!(
                new_reserve_a = swap.new_reserve_a,
                vault_a = vault_a_amt,
                new_reserve_b = swap.new_reserve_b,
                vault_b = vault_b_amt,
                "solvency guard (pre-submit) failed"
            );
            return Err(AppError::Forbidden(
                "solvency guard (pre-submit) failed".into(),
            ));
        }
    }

    // Anchor args layout:
    // disc(8)
    // || swap(fields...)
    // || encrypted_note: vec<u8> = len(u32 LE) || bytes
    let mut data = Vec::with_capacity(8 + (32 * 3) + 4 + 8 + 8 + 4 + encrypted_note.len());
    data.extend_from_slice(&anchor_discriminator("execute_rfq_swap_append"));
    data.extend_from_slice(&swap.root);
    data.extend_from_slice(&swap.previous_leaf);
    data.extend_from_slice(&swap.new_leaf);
    data.extend_from_slice(&swap.index.to_le_bytes());
    data.extend_from_slice(&swap.new_reserve_a.to_le_bytes());
    data.extend_from_slice(&swap.new_reserve_b.to_le_bytes());
    data.extend_from_slice(&(encrypted_note.len() as u32).to_le_bytes());
    data.extend_from_slice(encrypted_note);

    // Accounts must match the on-chain `ExecuteRfqSwapAppend` context.
    // Bitmap shard: one PDA per 8192 leaf indices.
    let shard_index: u32 = swap.index / 8_192;
    let spent_shard = spent_shard_pda(&program_id, &config, shard_index).0;
    let mut accounts = vec![
        AccountMeta::new(tee_authority.pubkey(), true), // payer (always tee_authority)
        AccountMeta::new(config, false),            // writable (updates total_deposits)
        AccountMeta::new_readonly(tee_authority.pubkey(), true),
        AccountMeta::new(merkle_tree, false),
        AccountMeta::new(pool, false),
        AccountMeta::new(pool_acc.vault_a, false),
        AccountMeta::new(pool_acc.vault_b, false),
        AccountMeta::new(spent_shard, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new_readonly(compression_program, false),
        AccountMeta::new_readonly(noop_program, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    for s in siblings {
        accounts.push(AccountMeta::new_readonly(Pubkey::new_from_array(*s), false));
    }

    let ix = Instruction {
        program_id,
        accounts,
        data,
    };

    let bh = rpc
        .get_latest_blockhash()
        .map_err(|e| AppError::BadGateway(format!("blockhash failed: {e}")))?;
    let mut tx = Transaction::new_unsigned(Message::new(&[ix], Some(&tee_authority.pubkey())));
    tx.try_sign(&[tee_authority], bh)
        .map_err(|e| AppError::BadGateway(format!("sign tx failed: {e}")))?;
    // IMPORTANT: this is intentionally "submit only" (no sync confirmation on hot path).
    // Confirmation is handled by the job worker (or the client) via signature polling.
    rpc.send_transaction(&tx)
        .map_err(|e| AppError::BadGateway(format!("send tx failed: {e}")))
}

/// Block until `sig` is confirmed/finalized, or return an error/timeout.
///
/// This is a blocking helper (uses RPC polling + thread sleep). Call it from `spawn_blocking`.
pub fn wait_for_signature_confirmed(
    rpc: &RpcClient,
    sig: &Signature,
    timeout: Duration,
) -> Result<(), AppError> {
    let t0 = Instant::now();
    let mut backoff_ms: u64 = 250;
    loop {
        if t0.elapsed() > timeout {
            return Err(AppError::BadGateway(format!(
                "tx confirmation timeout after {}s",
                timeout.as_secs()
            )));
        }

        let st = rpc
            .get_signature_statuses(&[*sig])
            .map_err(|e| AppError::BadGateway(format!("get_signature_statuses failed: {e}")))?;

        let s0 = st.value.get(0).and_then(|v| v.as_ref());
        if let Some(s0) = s0 {
            if let Some(err) = &s0.err {
                tracing::warn!(?err, "tx failed while confirming");
                return Err(AppError::BadGateway("tx failed".into()));
            }

            // Treat "confirmed" or "finalized" as success.
            let ok = matches!(
                s0.confirmation_status,
                Some(TransactionConfirmationStatus::Confirmed | TransactionConfirmationStatus::Finalized)
            ) || s0.confirmations.is_none(); // `None` often indicates rooted/finalized depending on RPC version

            if ok {
                return Ok(());
            }
        }

        std::thread::sleep(Duration::from_millis(backoff_ms));
        backoff_ms = (backoff_ms.saturating_mul(2)).min(2_000);
    }
}
