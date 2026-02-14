// ─────────────────────────────────────────────────────────────────────────────
//  TEE‑Relayer – Fully‑Compilable Version (Fixed Builder & Warnings)
// ─────────────────────────────────────────────────────────────────────────────
use std::sync::atomic::AtomicU64;
use std::{
    collections::HashMap,
    convert::TryInto,
    env,
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::extract::{Json, State};
use axum::Json as AxumJson;

use ecies::{decrypt, utils::generate_keypair};
use hex;
use serde::{Deserialize, Serialize};
// SP1 removed (Circom-only relayer)
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_associated_token_account::instruction::create_associated_token_account_idempotent;
use spl_token::instruction as token_ix;

use tempfile::Builder;
use tokio::task;
// (moved) background job orchestration lives in `handlers`.
use tokio::sync::Semaphore;
// (moved) router/middleware setup lives in `router`.
use tracing::{debug, error, info, warn};
use tracing_subscriber;
// (moved) shared Value usage lives in `types`/`state`.
// (no std::time import needed; we use fully-qualified std::time in now_ms)
use std::time::Instant;
// (moved) unix permission checks live in `proving::preflight`.
mod allowlist;
mod auth;
mod config;
mod constants;
mod error;
mod handlers;
mod metrics;
mod preflight;
mod pricing;
mod proving;
mod rate_limit;
mod router;
mod state;
mod types;
mod utils;
mod validation;

use crate::error::{AppError, AppResult};
use crate::proving::preflight::parse_hex32_field;
use crate::state::{AppState, RelayJobKind};
use crate::validation::{ensure_len_le, ensure_pubkey_len};

const WSOL_MINT_B58: &str = "So11111111111111111111111111111111111111112";
use crate::types::{BrowserInputs, BrowserLiquidityInputs, EncryptedRequest, ProgressTx};

use base64::{engine::general_purpose, Engine as _};
// Note encryption (X25519 sealed-box + AES-256-GCM), used for relayer-prepared deposits.
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret as X25519EphemeralSecret, PublicKey as X25519PublicKey};
// arkworks no longer needed in Circom-only relayer (keccak-based commitments)
use crate::utils::{
    anchor_discriminator, associated_token_address, compute_commitment,
    compute_commitment_liquidity, current_merkle_tree_pubkey, fetch_indexer_proof, g1_negate_y_be,
    keccak256, merkle_root_from_witness, parse_first_json_value, registry_asset_id_for_mint,
    registry_pool_id_for_pool, spent_shard_pda, split_u128_be16_be16, tree_changelog_contains_root,
    u256_be32_from_dec_str, IndexerProofLookup,
};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
// ---------------------------------------------------------------------
//  CONFIGURATION
// ---------------------------------------------------------------------
const DEFAULT_PROGRAM_ID: &str = "p1VaCyyfzodMni1tSYhvUFd3MyGB6sb6NRFWPixXD54";
// Default to the public Solana mainnet RPC.
// Override via RPC_URL env at runtime (recommended for production).
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
// SP1 + ticket artifacts removed (Circom-only relayer).
use crate::allowlist as relayer_allowlist;
use crate::constants::DEFAULT_NODE_MAX_OLD_SPACE_MB;

/// System‑program ID – the constant version (no deprecation warning)
const SYSTEM_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// SPL account-compression program id (mainnet/devnet constant).
const SPL_ACCOUNT_COMPRESSION_ID: &str = "cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK";
/// SPL noop program id (used by account-compression CPI).
const SPL_NOOP_ID: &str = "noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV";

/// Depth of the on‑chain Merkle tree – must match the circuit (24 levels → 2²⁴ leaves)
const MERKLE_TREE_DEPTH: usize = 24;

/// SPL account-compression tree account layout: header is 56 bytes before the tree struct.
const SPL_TREE_DATA_OFFSET: usize = 56;

/// Must match how the tree was created (see `scripts/init_mainnet.ts`).
const SPL_TREE_MAX_DEPTH: usize = 24;
const SPL_TREE_MAX_BUFFER_SIZE: usize = 1024;

// (deleted) deposit cache backfill/poll defaults; relayer is indexer-only

// ---------------------------------------------------------------------
//  INPUT VALIDATION (spam protection)
// ---------------------------------------------------------------------
use crate::constants::{MAX_B64_STR_LEN, MAX_DECRYPTED_JSON_BYTES};

// (deleted) deposit cache / logs

// NOTE: The on-chain program no longer stores an `amm.roots` ring buffer.

// (deleted) DepositEvent log parsing / cache discriminator: relayer is indexer-only

// ---------------------------------------------------------------------
//  GLOBAL STATE & ERRORS
// ---------------------------------------------------------------------
// (deleted) DepositCache: relayer is indexer-only

// (moved) tree helpers live in `utils`.

// (moved) helper functions live in `preflight`, `validation`, and `proving::preflight`.

// ---------------------------------------------------------------------
//  MAIN
// ---------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("🔐 Starting TEE Relayer…");

    // ── 1️⃣  Generate TEE keypair
    let (tee_sk, tee_pk) = generate_keypair();
    info!("🔑 TEE Public Key: {}", hex::encode(tee_pk.serialize()));

    // ── 2️⃣  Relayer wallet: start empty, require /upload-key provisioning
    let relayer_wallet_opt = {
        warn!("⚠️ Starting without relayer key. Provision via /upload-key.");
        None
    };

    // ── 3️⃣  Program ID & RPC client
    let program_id = Pubkey::from_str(
        &env::var("PROGRAM_ID").unwrap_or_else(|_| DEFAULT_PROGRAM_ID.to_string()),
    )
    .unwrap_or_else(|e| {
        // Log the problem and terminate the binary.
        error!("Invalid PROGRAM_ID: {}", e);
        std::process::exit(1);
    });

    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string());
    let rpc_client = RpcClient::new(rpc_url);
    info!("🔗 RPC endpoint: {}", rpc_client.url());

    // ── 4️⃣  Build shared state
    let admin_token = config::required_admin_token().map_err(|e| {
        error!("{e}");
        e
    })?;

    // ── 4️⃣b  IP allowlist (opt-in)
    let allowlist_path: Option<std::path::PathBuf> = env::var("RELAYER_ALLOWLIST_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    let allowlist = if let Some(p) = allowlist_path.as_ref() {
        match relayer_allowlist::load_allowlist(p) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "failed to load RELAYER_ALLOWLIST_PATH ({}): {e}",
                    p.display()
                );
                relayer_allowlist::parse_allowlist_from_env()?
            }
        }
    } else {
        relayer_allowlist::parse_allowlist_from_env()?
    };

    if allowlist.is_empty() {
        warn!(
            "relayer IP allowlist disabled (no RELAYER_ALLOWLIST / RELAYER_ALLOWLIST_PATH). \
             This is fine behind a firewall, but do not expose this port publicly."
        );
    } else {
        info!("relayer IP allowlist enabled ({} entries)", allowlist.len());
    }

    let state = Arc::new(AppState {
        tee_secret: tee_sk,
        tee_public: tee_pk,
        relayer_wallet: Mutex::new(relayer_wallet_opt),
        admin_token,
        program_id,
        rpc: Arc::new(rpc_client),
        jobs: tokio::sync::RwLock::new(HashMap::new()),
        job_seq: AtomicU64::new(1),
        job_semaphore: Semaphore::new(
            env::var("RELAYER_MAX_CONCURRENT_JOBS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(2),
        ),
        rate_limiter: Mutex::new(rate_limit::RateLimiter::from_env()),
        allowlist: std::sync::RwLock::new(allowlist),
        allowlist_path,
        fee_ata_mints: Mutex::new(std::collections::HashSet::new()),
        price_cache: Mutex::new(std::collections::HashMap::new()),
        mint_decimals_cache: Mutex::new(std::collections::HashMap::new()),
    });

    // ── 5️⃣  Router
    let app = router::build(state.clone());

    // ── 6️⃣  Serve
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    info!("🚀 Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

// (moved) auth + public/admin handlers live in `auth` and `handlers`.

#[derive(Debug, Deserialize)]
struct PrepareDepositRequest {
    /// User wallet pubkey (base58). This will be the transaction fee payer.
    pub user_pubkey: String,
    /// User source token account (base58) for the deposit transfer.
    pub user_source: String,
    /// SPL mint pubkey (base58).
    pub mint: String,
    /// Deposit amount in base units.
    pub amount: u64,
    /// Recipient X25519 public key (base64, 32 bytes).
    pub recipient_x25519_pubkey_base64: String,
}

impl PrepareDepositRequest {
    fn validate(&self) -> Result<(), AppError> {
        ensure_pubkey_len("user_pubkey", &self.user_pubkey)?;
        ensure_pubkey_len("user_source", &self.user_source)?;
        ensure_pubkey_len("mint", &self.mint)?;
        ensure_len_le(
            "recipient_x25519_pubkey_base64",
            self.recipient_x25519_pubkey_base64.trim(),
            MAX_B64_STR_LEN,
        )?;
        if self.amount == 0 {
            return Err(AppError::BadRequest("amount must be > 0".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct PrepareDepositResponse {
    pub tx_base64: String,
    pub commitment_hex: String,
    pub asset_id: u32,
    pub proof_json: Groth16ProofJson,
    pub encrypted_note_base64: String,
    /// Relayer fee (base units, same mint as deposit). This is deducted from the requested amount.
    pub fee_amount: u64,
    /// Net deposited amount after fee (base units). This is what the note represents.
    pub net_amount: u64,
    /// Plaintext note for the user to store locally.
    pub note_plaintext: String,
    pub nullifier_hex: String,
    pub secret_hex: String,
}

#[derive(Debug, Deserialize)]
struct PrepareDepositLiquidityRequest {
    /// User wallet pubkey (base58). This will be the transaction fee payer.
    pub user_pubkey: String,
    /// Token accounts to debit (base58). Must match mint_a/mint_b respectively.
    pub user_account_a: String,
    pub user_account_b: String,
    /// Pool mints (base58). (May be provided in any order; relayer will canonicalize.)
    pub mint_a: String,
    pub mint_b: String,
    pub amount_a: u64,
    pub amount_b: u64,
    /// Expected shares (slippage protection). This must match the on-chain computed minted shares.
    pub expected_shares: u64,
    /// Recipient X25519 public key (base64, 32 bytes).
    pub recipient_x25519_pubkey_base64: String,
}

impl PrepareDepositLiquidityRequest {
    fn validate(&self) -> Result<(), AppError> {
        ensure_pubkey_len("user_pubkey", &self.user_pubkey)?;
        ensure_pubkey_len("user_account_a", &self.user_account_a)?;
        ensure_pubkey_len("user_account_b", &self.user_account_b)?;
        ensure_pubkey_len("mint_a", &self.mint_a)?;
        ensure_pubkey_len("mint_b", &self.mint_b)?;
        ensure_len_le(
            "recipient_x25519_pubkey_base64",
            self.recipient_x25519_pubkey_base64.trim(),
            MAX_B64_STR_LEN,
        )?;
        if self.amount_a == 0 || self.amount_b == 0 {
            return Err(AppError::BadRequest(
                "amount_a and amount_b must be > 0".into(),
            ));
        }
        if self.expected_shares == 0 {
            return Err(AppError::BadRequest("expected_shares must be > 0".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct PrepareDepositLiquidityResponse {
    pub tx_base64: String,
    pub commitment_hex: String,
    pub pool_id: u32,
    pub proof_json: Groth16ProofJson,
    pub encrypted_note_base64: String,
    pub note_plaintext: String,
    pub nullifier_hex: String,
    pub secret_hex: String,
}

/// Prepare a relayer-assisted `deposit` transaction.
///
/// Notes:
/// - The relayer does off-chain work (fee quote, asset_id lookup, note encryption, proof generation).
/// - The on-chain `deposit` instruction is permissionless (no relayer/TEE signature required).
/// - The user signs (fee payer + token owner) and submits.
async fn prepare_deposit(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<PrepareDepositRequest>,
) -> AppResult<AxumJson<PrepareDepositResponse>> {
    if let Err(e) = req.validate() {
        crate::metrics::inc_bad_payload_total();
        // Penalize bad payloads for spam control (same as /relay-job).
        if let Err(rl_e) = crate::rate_limit::rate_limit_bad(&state, peer.ip()) {
            return Err(rl_e);
        }
        return Err(e);
    }
    crate::rate_limit::rate_limit_ok(&state, peer.ip())?;
    // Cap concurrent expensive work (proof generation + RPC).
    let _permit = state
        .job_semaphore
        .acquire()
        .await
        .map_err(|_| AppError::Unavailable("concurrency limiter closed".into()))?;
    // Ensure relayer key is provisioned.
    let tee_signer: Arc<Keypair> = {
        let guard = state.relayer_wallet.lock().unwrap();
        match &*guard {
            Some(k) => k.clone(),
            None => {
                return Err(AppError::Internal(
                    "Relayer not yet initialized. Please upload key.".into(),
                ))
            }
        }
    };

    let user_pubkey = Pubkey::from_str(req.user_pubkey.trim())
        .map_err(|_| AppError::BadRequest("Invalid user_pubkey".into()))?;
    let user_source = Pubkey::from_str(req.user_source.trim())
        .map_err(|_| AppError::BadRequest("Invalid user_source".into()))?;
    let mint_pubkey = Pubkey::from_str(req.mint.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint".into()))?;
    if req.amount == 0 {
        return Err(AppError::BadRequest("amount must be > 0".into()));
    }

    // Fee quote (USD model) for relayer-assisted deposits.
    // We deduct the fee from the deposited amount, so the user spends exactly `req.amount` tokens.
    let fee_quote = crate::pricing::quote_fee(
        state.clone(),
        crate::pricing::FeeOp::DepositAsset,
        &req.mint,
        req.amount,
    )
    .await?;
    if !fee_quote.allowed {
        return Err(AppError::BadRequest(format!(
            "deposit amount too small: must be >= {} (fee + 5% buffer)",
            fee_quote.min_amount
        )));
    }
    let fee_amount: u64 = fee_quote.fee_amount;
    let net_amount: u64 = req
        .amount
        .checked_sub(fee_amount)
        .ok_or_else(|| AppError::BadRequest("amount too small to cover relayer fee".into()))?;
    if net_amount == 0 {
        return Err(AppError::BadRequest(
            "amount too small to cover relayer fee".into(),
        ));
    }

    // Decode recipient X25519 key (base64, 32 bytes).
    let pk_b64 = req.recipient_x25519_pubkey_base64.trim();
    let pk_bytes = general_purpose::STANDARD
        .decode(pk_b64.as_bytes())
        .map_err(|_| AppError::BadRequest("Invalid recipient_x25519_pubkey_base64".into()))?;
    if pk_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "recipient_x25519_pubkey_base64 must decode to 32 bytes".into(),
        ));
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pk_bytes);

    // PDAs
    let (amm_pda, _amm_bump) = Pubkey::find_program_address(&[b"amm"], &state.program_id);
    let (registry_pda, _reg_bump) = Pubkey::find_program_address(&[b"registry"], &state.program_id);
    let merkle_tree = current_merkle_tree_pubkey(&state.rpc, &state.program_id)?;

    // NOTE: Deposits no longer require the relayer key to match any on-chain TEE authority.
    // The provisioned key is used for fee collection + operational identity only.

    // Program IDs
    let token_program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("static SPL token program id");
    let associated_token_program_id =
        Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
            .expect("static associated token program id");
    let compression_program_id = Pubkey::from_str(SPL_ACCOUNT_COMPRESSION_ID)
        .map_err(|_| AppError::Internal("Invalid SPL_ACCOUNT_COMPRESSION_ID const".into()))?;
    let noop_program_id = Pubkey::from_str(SPL_NOOP_ID)
        .map_err(|_| AppError::Internal("Invalid SPL_NOOP_ID const".into()))?;

    // Canonical AMM vault ATA (owned by amm PDA).
    let amm_vault = associated_token_address(
        &amm_pda,
        &mint_pubkey,
        &token_program_id,
        &associated_token_program_id,
    );
    let relayer_fee_account = associated_token_address(
        &tee_signer.pubkey(),
        &mint_pubkey,
        &token_program_id,
        &associated_token_program_id,
    );

    // Derive asset_id for commitment binding.
    let asset_id = registry_asset_id_for_mint(&state.rpc, state.program_id, &mint_pubkey)?;

    // Generate note secrets.
    let mut nullifier = [0u8; 32];
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nullifier);
    rand::thread_rng().fill_bytes(&mut secret);

    // Two-layer commitment: noteHash = keccak256(nullifier || secret),
    // then commitment = keccak256(noteHash || amountLE8 || assetIdLE4)
    let note_hash = keccak256(&[nullifier.as_ref(), secret.as_ref()].concat());
    let commitment = keccak256(
        &[
            note_hash.as_ref(),
            &net_amount.to_le_bytes(),
            &asset_id.to_le_bytes(),
        ]
        .concat(),
    );
    let commitment_hex = hex::encode(commitment);

    // -----------------------------------------------------------------
    // WSOL wrapping/unwrap logic removed (tx size).
    // -----------------------------------------------------------------
    // We no longer support the "native SOL deposit" convenience where the client passes
    // `user_source == user_pubkey` and the relayer creates/syncs/closes a temp WSOL account.
    let wsol_mint = Pubkey::from_str(WSOL_MINT_B58).expect("static WSOL mint");
    if mint_pubkey == wsol_mint && user_source == user_pubkey {
        return Err(AppError::BadRequest(
            "WSOL wrapping is disabled: provide a WSOL token account as user_source (not the wallet pubkey)"
                .into(),
        ));
    }

    let mut pre_ixs: Vec<Instruction> = Vec::new();
    let user_source_for_ix: Pubkey = user_source;

    let nullifier_hex = hex::encode(nullifier);
    let secret_hex = hex::encode(secret);
    let note_plaintext = format!(
        "luminocity-asset-{}-{}-{}{}",
        mint_pubkey, net_amount, nullifier_hex, secret_hex
    );

    // Compact on-chain payload (keeps prepared tx under Solana legacy size limits):
    // [v=1][kind=0(asset)][asset_id:u32 LE][amount:u64 LE][nullifier32][secret32]
    let mut note_payload: Vec<u8> = Vec::with_capacity(1 + 1 + 4 + 8 + 32 + 32);
    note_payload.push(1u8);
    note_payload.push(0u8);
    note_payload.extend_from_slice(&asset_id.to_le_bytes());
    note_payload.extend_from_slice(&net_amount.to_le_bytes());
    note_payload.extend_from_slice(&nullifier);
    note_payload.extend_from_slice(&secret);

    // Encrypt for recipient (X25519 sealed-box v1):
    // payload = eph_pub(32) || nonce(12) || ct+tag
    let recipient = X25519PublicKey::from(pk32);
    let eph_secret = X25519EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_pub = X25519PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"p1vacy-note-x25519-v1", &mut okm)
        .map_err(|_| AppError::Internal("hkdf expand failed".into()))?;
    let cipher = Aes256Gcm::new_from_slice(&okm)
        .map_err(|_| AppError::Internal("aes init failed".into()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt((&nonce).into(), note_payload.as_ref())
        .map_err(|_| AppError::Internal("note encryption failed".into()))?;
    let mut encrypted_note: Vec<u8> = Vec::new();
    encrypted_note.extend_from_slice(eph_pub.as_bytes());
    encrypted_note.extend_from_slice(&nonce);
    encrypted_note.extend_from_slice(&ct);
    if encrypted_note.len() > 512 {
        return Err(AppError::BadRequest(format!(
            "encrypted_note too long: {} bytes (max 512)",
            encrypted_note.len()
        )));
    }
    let encrypted_note_base64 = general_purpose::STANDARD.encode(&encrypted_note);

    // Generate Groth16 proof for deposit binding (amount + asset_id bound to commitment).
    let (proof_a, proof_b, proof_c, proof_json) =
        generate_deposit_asset_bind_groth16(nullifier, secret, net_amount, asset_id, commitment)
            .await?;

    // Build deposit instruction data:
    // deposit(proof: Groth16Proof, amount: u64, commitment: [u8;32], encrypted_note: Vec<u8>)
    let deposit_disc = anchor_discriminator("deposit");
    let mut data = Vec::with_capacity(8 + 64 + 128 + 64 + 8 + 32 + 4 + encrypted_note.len());
    data.extend_from_slice(&deposit_disc);
    data.extend_from_slice(&proof_a);
    data.extend_from_slice(&proof_b);
    data.extend_from_slice(&proof_c);
    data.extend_from_slice(&net_amount.to_le_bytes());
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&(encrypted_note.len() as u32).to_le_bytes());
    data.extend_from_slice(&encrypted_note);

    let deposit_ix = Instruction {
        program_id: state.program_id,
        accounts: vec![
            // IMPORTANT: Must match on-chain `Deposit<'info>` account order (see IDL).
            AccountMeta::new(user_pubkey, true),           // payer
            AccountMeta::new(amm_pda, false),              // amm (mut)
            AccountMeta::new_readonly(mint_pubkey, false), // mint
            AccountMeta::new(registry_pda, false),         // registry (mut)
            AccountMeta::new(amm_vault, false),            // amm_vault (mut)
            AccountMeta::new(user_source_for_ix, false),   // user_source (mut)
            AccountMeta::new(merkle_tree, false),          // merkle_tree (mut)
            AccountMeta::new_readonly(token_program_id, false),
            AccountMeta::new_readonly(associated_token_program_id, false),
            AccountMeta::new_readonly(compression_program_id, false),
            AccountMeta::new_readonly(noop_program_id, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    };

    // Ensure relayer fee ATA exists.
    //
    // IMPORTANT: Putting ATA creation inside the prepared tx increases message size; if you're
    // hitting the legacy 1232-byte limit, pre-create fee ATAs out-of-band and keep the prepared
    // tx minimal. We only include the idempotent create if the ATA is missing.
    let fee_ata_missing = state.rpc.get_account(&relayer_fee_account).is_err();
    if fee_ata_missing {
        pre_ixs.push(create_associated_token_account_idempotent(
            &user_pubkey,         // funding address (user pays)
            &tee_signer.pubkey(), // owner
            &mint_pubkey,         // mint
            &token_program_id,    // token program
        ));
    }

    let fee_ix = if fee_amount > 0 {
        Some(
            token_ix::transfer(
                &token_program_id,
                &user_source_for_ix,
                &relayer_fee_account,
                &user_pubkey,
                &[],
                fee_amount,
            )
            .map_err(|e| AppError::Internal(format!("fee transfer ix build failed: {e}")))?,
        )
    } else {
        None
    };

    let recent = state
        .rpc
        .get_latest_blockhash()
        .map_err(|e| AppError::BadGateway(e.to_string()))?;

    // User-signed tx (no relayer/TEE signature required).
    let mut ixs: Vec<Instruction> = Vec::new();
    ixs.extend(pre_ixs);
    ixs.push(deposit_ix);
    if let Some(fee_ix) = fee_ix {
        ixs.push(fee_ix);
    }
    let mut tx = Transaction::new_with_payer(&ixs, Some(&user_pubkey));
    tx.message.recent_blockhash = recent;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| AppError::Internal(format!("tx serialize failed: {e}")))?;
    if tx_bytes.len() > 1232 {
        return Err(AppError::BadRequest(format!(
            "prepared transaction too large: {} > 1232 bytes (legacy tx). \
             Reduce accounts/instructions or switch to v0 + LUT.",
            tx_bytes.len()
        )));
    }
    let tx_base64 = general_purpose::STANDARD.encode(&tx_bytes);

    Ok(AxumJson(PrepareDepositResponse {
        tx_base64,
        commitment_hex,
        asset_id,
        proof_json,
        encrypted_note_base64,
        fee_amount,
        net_amount,
        note_plaintext,
        nullifier_hex,
        secret_hex,
    }))
}

/// Prepare a relayer-assisted `deposit_liquidity` transaction.
///
/// Notes:
/// - The relayer does off-chain work (note encryption, proof generation, RPC lookups).
/// - The on-chain `deposit_liquidity` instruction is permissionless (no relayer/TEE signature required).
/// - The user signs (fee payer + token owner) and submits.
async fn prepare_deposit_liquidity(
    State(state): State<Arc<AppState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<PrepareDepositLiquidityRequest>,
) -> AppResult<AxumJson<PrepareDepositLiquidityResponse>> {
    if let Err(e) = req.validate() {
        crate::metrics::inc_bad_payload_total();
        if let Err(rl_e) = crate::rate_limit::rate_limit_bad(&state, peer.ip()) {
            return Err(rl_e);
        }
        return Err(e);
    }
    crate::rate_limit::rate_limit_ok(&state, peer.ip())?;
    let _permit = state
        .job_semaphore
        .acquire()
        .await
        .map_err(|_| AppError::Unavailable("concurrency limiter closed".into()))?;
    // Ensure relayer key is provisioned.
    let tee_signer: Arc<Keypair> = {
        let guard = state.relayer_wallet.lock().unwrap();
        match &*guard {
            Some(k) => k.clone(),
            None => {
                return Err(AppError::Internal(
                    "Relayer not yet initialized. Please upload key.".into(),
                ))
            }
        }
    };

    let user_pubkey = Pubkey::from_str(req.user_pubkey.trim())
        .map_err(|_| AppError::BadRequest("Invalid user_pubkey".into()))?;
    let mut mint_a_in = Pubkey::from_str(req.mint_a.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint_a".into()))?;
    let mut mint_b_in = Pubkey::from_str(req.mint_b.trim())
        .map_err(|_| AppError::BadRequest("Invalid mint_b".into()))?;
    if mint_a_in == mint_b_in {
        return Err(AppError::BadRequest(
            "mint_a must differ from mint_b".into(),
        ));
    }
    let mut user_account_a = Pubkey::from_str(req.user_account_a.trim())
        .map_err(|_| AppError::BadRequest("Invalid user_account_a".into()))?;
    let mut user_account_b = Pubkey::from_str(req.user_account_b.trim())
        .map_err(|_| AppError::BadRequest("Invalid user_account_b".into()))?;
    let mut amount_a = req.amount_a;
    let mut amount_b = req.amount_b;
    if amount_a == 0 || amount_b == 0 {
        return Err(AppError::BadRequest(
            "amount_a and amount_b must be > 0".into(),
        ));
    }
    if req.expected_shares == 0 {
        return Err(AppError::BadRequest("expected_shares must be > 0".into()));
    }

    // Canonicalize mint order to match on-chain pool seed rule. Swap associated fields too.
    if mint_a_in.to_bytes() > mint_b_in.to_bytes() {
        std::mem::swap(&mut mint_a_in, &mut mint_b_in);
        std::mem::swap(&mut user_account_a, &mut user_account_b);
        std::mem::swap(&mut amount_a, &mut amount_b);
    }
    let mint_a = mint_a_in;
    let mint_b = mint_b_in;

    // Decode recipient X25519 key (base64, 32 bytes).
    let pk_b64 = req.recipient_x25519_pubkey_base64.trim();
    let pk_bytes = general_purpose::STANDARD
        .decode(pk_b64.as_bytes())
        .map_err(|_| AppError::BadRequest("Invalid recipient_x25519_pubkey_base64".into()))?;
    if pk_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "recipient_x25519_pubkey_base64 must decode to 32 bytes".into(),
        ));
    }
    let mut pk32 = [0u8; 32];
    pk32.copy_from_slice(&pk_bytes);

    // PDAs
    let (amm_pda, _amm_bump) = Pubkey::find_program_address(&[b"amm"], &state.program_id);
    let (registry_pda, _reg_bump) = Pubkey::find_program_address(&[b"registry"], &state.program_id);
    let (pool_pda, _pool_bump) = Pubkey::find_program_address(
        &[amm_pda.as_ref(), mint_a.as_ref(), mint_b.as_ref()],
        &state.program_id,
    );
    let merkle_tree = current_merkle_tree_pubkey(&state.rpc, &state.program_id)?;

    // NOTE: Liquidity deposits no longer require the relayer key to match any on-chain TEE authority.
    // The provisioned key is used for fee collection + operational identity only.

    // Program IDs
    let token_program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("static SPL token program id");
    let associated_token_program_id =
        Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
            .expect("static associated token program id");
    let compression_program_id = Pubkey::from_str(SPL_ACCOUNT_COMPRESSION_ID)
        .map_err(|_| AppError::Internal("Invalid SPL_ACCOUNT_COMPRESSION_ID const".into()))?;
    let noop_program_id = Pubkey::from_str(SPL_NOOP_ID)
        .map_err(|_| AppError::Internal("Invalid SPL_NOOP_ID const".into()))?;

    // Vault ATAs owned by AMM PDA (must match pool.vault_a/b).
    let amm_vault_a = associated_token_address(
        &amm_pda,
        &mint_a,
        &token_program_id,
        &associated_token_program_id,
    );
    let amm_vault_b = associated_token_address(
        &amm_pda,
        &mint_b,
        &token_program_id,
        &associated_token_program_id,
    );

    // Derive pool_id from Registry (pool -> pool_id).
    let pool_id = registry_pool_id_for_pool(&state.rpc, state.program_id, &pool_pda)?;

    // Generate note secrets, commitment binds to shares and pool_id.
    let mut nullifier = [0u8; 32];
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nullifier);
    rand::thread_rng().fill_bytes(&mut secret);
    let shares = req.expected_shares;
    // Two-layer commitment: noteHash = keccak256(nullifier || secret),
    // then commitment = keccak256(noteHash || sharesLE8 || poolIdLE4)
    let note_hash = keccak256(&[nullifier.as_ref(), secret.as_ref()].concat());
    let commitment = keccak256(
        &[
            note_hash.as_ref(),
            &shares.to_le_bytes(),
            &pool_id.to_le_bytes(),
        ]
        .concat(),
    );
    let commitment_hex = hex::encode(commitment);

    let nullifier_hex = hex::encode(nullifier);
    let secret_hex = hex::encode(secret);
    let note_plaintext = format!(
        "luminocity-lp-{}-{}-{}-{}{}",
        shares, mint_a, mint_b, nullifier_hex, secret_hex
    );

    // Compact on-chain payload:
    // [v=1][kind=1(lp)][pool_id:u32 LE][shares:u64 LE][nullifier32][secret32]
    let mut note_payload: Vec<u8> = Vec::with_capacity(1 + 1 + 4 + 8 + 32 + 32);
    note_payload.push(1u8);
    note_payload.push(1u8);
    note_payload.extend_from_slice(&pool_id.to_le_bytes());
    note_payload.extend_from_slice(&shares.to_le_bytes());
    note_payload.extend_from_slice(&nullifier);
    note_payload.extend_from_slice(&secret);

    // Encrypt for recipient (X25519 sealed-box v1).
    let recipient = X25519PublicKey::from(pk32);
    let eph_secret = X25519EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_pub = X25519PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"p1vacy-note-x25519-v1", &mut okm)
        .map_err(|_| AppError::Internal("hkdf expand failed".into()))?;
    let cipher = Aes256Gcm::new_from_slice(&okm)
        .map_err(|_| AppError::Internal("aes init failed".into()))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt((&nonce).into(), note_payload.as_ref())
        .map_err(|_| AppError::Internal("note encryption failed".into()))?;
    let mut encrypted_note: Vec<u8> = Vec::new();
    encrypted_note.extend_from_slice(eph_pub.as_bytes());
    encrypted_note.extend_from_slice(&nonce);
    encrypted_note.extend_from_slice(&ct);
    if encrypted_note.len() > 512 {
        return Err(AppError::BadRequest(format!(
            "encrypted_note too long: {} bytes (max 512)",
            encrypted_note.len()
        )));
    }
    let encrypted_note_base64 = general_purpose::STANDARD.encode(&encrypted_note);

    // Generate Groth16 proof for deposit binding (shares + pool_id bound to commitment).
    let (proof_a, proof_b, proof_c, proof_json) =
        generate_deposit_liquidity_bind_groth16(nullifier, secret, shares, pool_id, commitment)
            .await?;

    // -----------------------------------------------------------------
    // WSOL wrapping/unwrap logic removed (tx size).
    // -----------------------------------------------------------------
    // We no longer support the "native SOL liquidity deposit" convenience where the client passes
    // `user_account_{a,b} == user_pubkey` and the relayer creates/syncs/closes temp WSOL accounts.
    let wsol_mint = Pubkey::from_str(WSOL_MINT_B58).expect("static WSOL mint");
    if mint_a == wsol_mint && user_account_a == user_pubkey {
        return Err(AppError::BadRequest(
            "WSOL wrapping is disabled: provide a WSOL token account as user_account_a (not the wallet pubkey)"
                .into(),
        ));
    }
    if mint_b == wsol_mint && user_account_b == user_pubkey {
        return Err(AppError::BadRequest(
            "WSOL wrapping is disabled: provide a WSOL token account as user_account_b (not the wallet pubkey)"
                .into(),
        ));
    }

    let mut pre_ixs: Vec<Instruction> = Vec::new();
    let post_ixs: Vec<Instruction> = Vec::new();

    // Instruction data:
    // deposit_liquidity(proof, amount_a, amount_b, expected_shares, commitment, encrypted_note)
    let disc = anchor_discriminator("deposit_liquidity");
    let mut data =
        Vec::with_capacity(8 + 64 + 128 + 64 + 8 + 8 + 8 + 32 + 4 + encrypted_note.len());
    data.extend_from_slice(&disc);
    data.extend_from_slice(&proof_a);
    data.extend_from_slice(&proof_b);
    data.extend_from_slice(&proof_c);
    data.extend_from_slice(&amount_a.to_le_bytes());
    data.extend_from_slice(&amount_b.to_le_bytes());
    data.extend_from_slice(&req.expected_shares.to_le_bytes());
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&(encrypted_note.len() as u32).to_le_bytes());
    data.extend_from_slice(&encrypted_note);

    // IMPORTANT: Accounts must match on-chain `DepositLiquidity` order (see IDL).
    let deposit_liq_ix = Instruction {
        program_id: state.program_id,
        accounts: vec![
            AccountMeta::new(user_pubkey, true),           // payer
            AccountMeta::new(amm_pda, false),              // amm (mut)
            AccountMeta::new(pool_pda, false),             // pool (mut)
            AccountMeta::new(registry_pda, false),         // registry (mut)
            AccountMeta::new_readonly(mint_a, false),      // mint_a
            AccountMeta::new_readonly(mint_b, false),      // mint_b
            AccountMeta::new(amm_vault_a, false),          // amm_vault_a (mut)
            AccountMeta::new(amm_vault_b, false),          // amm_vault_b (mut)
            AccountMeta::new(user_account_a, false),       // user_account_a (mut)
            AccountMeta::new(user_account_b, false),       // user_account_b (mut)
            AccountMeta::new(merkle_tree, false),          // merkle_tree (mut)
            AccountMeta::new_readonly(token_program_id, false),
            AccountMeta::new_readonly(associated_token_program_id, false),
            AccountMeta::new_readonly(compression_program_id, false),
            AccountMeta::new_readonly(noop_program_id, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    };

    let recent = state
        .rpc
        .get_latest_blockhash()
        .map_err(|e| AppError::BadGateway(e.to_string()))?;

    let mut all_ixs: Vec<Instruction> = Vec::new();
    all_ixs.extend_from_slice(&pre_ixs);
    all_ixs.push(deposit_liq_ix);
    all_ixs.extend_from_slice(&post_ixs);

    let mut tx = Transaction::new_with_payer(&all_ixs, Some(&user_pubkey));
    tx.message.recent_blockhash = recent;
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| AppError::Internal(format!("tx serialize failed: {e}")))?;
    if tx_bytes.len() > 1232 {
        return Err(AppError::BadRequest(format!(
            "prepared transaction too large: {} > 1232 bytes (legacy tx). \
             Reduce accounts/instructions or switch to v0 + LUT.",
            tx_bytes.len()
        )));
    }
    let tx_base64 = general_purpose::STANDARD.encode(&tx_bytes);

    Ok(AxumJson(PrepareDepositLiquidityResponse {
        tx_base64,
        commitment_hex,
        pool_id,
        proof_json,
        encrypted_note_base64,
        note_plaintext,
        nullifier_hex,
        secret_hex,
    }))
}

// ---------------------------------------------------------------------
//  REQUEST /relay
// ---------------------------------------------------------------------
// (moved) request/response structs live in `types`, and helpers in `utils`.

/// Circom (Groth16) core relay logic (used by both `/relay` and `/relay-stream`).
async fn relay_circom_inner(
    state: Arc<AppState>,
    payload: EncryptedRequest,
    progress_tx: Option<ProgressTx>,
) -> AppResult<serde_json::Value> {
    debug!("⚡ Received relay request");
    utils::progress(&progress_tx, "wallet", "checking relayer key").await;

    payload.validate()?;

    // Ensure relayer key is provisioned
    let payer: Arc<Keypair> = {
        let guard = state.relayer_wallet.lock().unwrap();
        match &*guard {
            Some(k) => k.clone(),
            None => {
                return Err(AppError::Internal(
                    "Relayer not yet initialized. Please upload key.".into(),
                ))
            }
        }
    };

    // -----------------------------------------------------------------
    // 1️⃣  Decrypt payload (browser inputs – no Merkle data)
    // -----------------------------------------------------------------
    utils::progress(&progress_tx, "decrypt", "decrypting payload").await;
    let encrypted_bytes = hex::decode(&payload.encrypted_blob)
        .map_err(|_| AppError::BadRequest("Invalid hex in encrypted_blob".into()))?;

    let secret_bytes = state.tee_secret.serialize();
    let decrypted = decrypt(&secret_bytes, &encrypted_bytes)
        .map_err(|e| AppError::BadRequest(format!("ECIES decryption failed: {}", e)))?;
    if decrypted.len() > MAX_DECRYPTED_JSON_BYTES {
        return Err(AppError::BadRequest(format!(
            "decrypted payload too large: {} bytes (max {})",
            decrypted.len(),
            MAX_DECRYPTED_JSON_BYTES
        )));
    }

    let mut browser_inputs: BrowserInputs = serde_json::from_slice(&decrypted)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;
    validation::validate_browser_inputs(&browser_inputs)?;
    // Fee is a public input bound in-circuit, but the relayer is the one generating the proof.
    // Therefore, the relayer must be the source-of-truth for the fee to avoid client-side
    // rounding/timing mismatches (e.g. oracle price moves between /fee quote and job submit).
    let expected_fee = crate::pricing::quote_fee(
        state.clone(),
        crate::pricing::FeeOp::WithdrawAsset,
        &browser_inputs.mint,
        browser_inputs.amount,
    )
    .await?
    .fee_amount;
    if browser_inputs.fee != 0 && browser_inputs.fee != expected_fee {
        warn!(
            "client provided fee mismatch: got={} expected={} (overwriting with expected)",
            browser_inputs.fee, expected_fee
        );
    }
    browser_inputs.fee = expected_fee;
    utils::progress(&progress_tx, "decrypt", "payload decrypted").await;

    // Derive asset_id from on-chain Registry (mint -> asset_id).
    let mint_pubkey = Pubkey::from_str(&browser_inputs.mint)
        .map_err(|e| AppError::BadRequest(format!("Invalid mint pubkey: {e}")))?;
    let asset_id = registry_asset_id_for_mint(&state.rpc, state.program_id, &mint_pubkey)?;

    // -----------------------------------------------------------------
    // 2️⃣  No ticket in Circom mode.
    // -----------------------------------------------------------------

    // -----------------------------------------------------------------
    // 3️⃣  Decode note preimage inputs (no on-chain nullifier PDA check).
    // -----------------------------------------------------------------
    // With bitmap nullification, the leaf index is the "spent key".
    // The nullifier remains a private note secret (used only inside the commitment),
    // but we do not publish or check its hash on-chain anymore.
    let nullifier_bytes = hex::decode(&browser_inputs.nullifier)
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?;
    if nullifier_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "nullifier must be 32 bytes (hex-encoded)".into(),
        ));
    }

    // -----------------------------------------------------------------
    // 4️⃣  Compute Merkle proof (relayer side)
    // -----------------------------------------------------------------
    utils::progress(&progress_tx, "merkle", "computing leaf commitment").await;
    let commitment = compute_commitment(
        &hex::encode(nullifier_bytes),
        &browser_inputs.secret,
        browser_inputs.amount,
        asset_id,
    )?;
    utils::progress(
        &progress_tx,
        "merkle",
        format!("leaf commitment computed: {}", hex::encode(commitment)),
    )
    .await;

    // Use the current on-chain Merkle tree pubkey for changelog (root/path buffer) lookups.
    let current_tree_pubkey = current_merkle_tree_pubkey(&state.rpc, &state.program_id)?;

    // -----------------------------------------------------------------
    // 4️⃣a  Source-of-truth: tree-indexer HTTP API (required)
    // -----------------------------------------------------------------
    let indexer_url = env::var("INDEXER_URL").map_err(|_| {
        AppError::BadGateway("INDEXER_URL is required (relayer is indexer-only)".into())
    })?;
    let indexer_url = indexer_url.trim().trim_end_matches('/').to_string();
    if indexer_url.is_empty() {
        return Err(AppError::BadGateway(
            "INDEXER_URL is required (relayer is indexer-only)".into(),
        ));
    }

    let commitment_hex = hex::encode(commitment);
    utils::progress(&progress_tx, "indexer", "querying indexer for root+proof").await;
    let (leaf_index, merkle_path, path_indices, root_hex) = match fetch_indexer_proof(
        &indexer_url,
        &commitment_hex,
        &state.admin_token,
    ) {
        Ok(IndexerProofLookup::Found(p)) => {
            if p.depth != MERKLE_TREE_DEPTH {
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned wrong depth (expected={} got={}): indexer={}",
                    MERKLE_TREE_DEPTH, p.depth, indexer_url
                )));
            }
            if p.siblings_hex.len() != MERKLE_TREE_DEPTH || p.path_bits.len() != MERKLE_TREE_DEPTH {
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned invalid proof shape (siblings={} path_bits={} expected={}): indexer={}",
                    p.siblings_hex.len(),
                    p.path_bits.len(),
                    MERKLE_TREE_DEPTH,
                    indexer_url
                )));
            }
            // Fail fast: leaf returned by indexer must match the commitment we computed.
            let leaf_bytes = parse_hex32_field("indexer.leaf_hex", &p.leaf_hex)?;
            if leaf_bytes == [0u8; 32] {
                metrics::inc_indexer_mismatch_total();
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned empty leaf for commitment={}: indexer={}",
                    commitment_hex, indexer_url
                )));
            }
            if leaf_bytes != commitment {
                metrics::inc_indexer_mismatch_total();
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned non-matching leaf (commitment={} leaf_hex={}): indexer={}",
                    commitment_hex,
                    p.leaf_hex,
                    indexer_url
                )));
            }
            utils::progress(
                &progress_tx,
                "indexer",
                format!("indexer proof ok (leaf_index={})", p.leaf_index),
            )
            .await;
            (
                p.leaf_index,
                p.siblings_hex,
                p.path_bits
                    .into_iter()
                    .map(|b| (b & 1) as u32)
                    .collect::<Vec<u32>>(),
                p.root_hex,
            )
        }
        Ok(IndexerProofLookup::NotFound(detail)) => {
            // After swaps, the spent note leaf is replaced, so the commitment genuinely
            // is no longer in the tree.
            return Err(AppError::BadRequest(format!(
                "Commitment not found in tree-indexer (likely spent via swap / leaf replaced, or wrong note). commitment={} indexer={} detail={}",
                commitment_hex, indexer_url, detail
            )));
        }
        Ok(IndexerProofLookup::Unavailable(detail)) => {
            return Err(AppError::BadGateway(format!(
                "tree-indexer unavailable/out-of-sync: indexer={} detail={}",
                indexer_url, detail
            )));
        }
        Err(e) => {
            return Err(AppError::BadGateway(format!(
                "tree-indexer query failed: indexer={} err={}",
                indexer_url, e
            )));
        }
    };
    let max_leaf_index = 1u32.checked_shl(MERKLE_TREE_DEPTH as u32).unwrap_or(0);
    if leaf_index >= max_leaf_index {
        return Err(AppError::BadGateway(format!(
            "tree-indexer returned invalid leaf_index={} for depth={}",
            leaf_index, MERKLE_TREE_DEPTH
        )));
    }
    utils::progress(
        &progress_tx,
        "merkle",
        format!("commitment found at leaf_index={}", leaf_index),
    )
    .await;

    // -----------------------------------------------------------------
    // 5️⃣a  Fast fail: bitmap spent-by-index check (best-effort)
    // -----------------------------------------------------------------
    {
        let (amm_pda, _amm_bump) = Pubkey::find_program_address(&[b"amm"], &state.program_id);
        let shard_index: u32 = leaf_index / 8_192;
        let spent_pk = spent_shard_pda(&state.program_id, &amm_pda, shard_index);
        match state
            .rpc
            .get_account_with_commitment(&spent_pk, CommitmentConfig::confirmed())
        {
            Ok(r) => {
                if let Some(acc) = r.value {
                    // Anchor account: 8-byte discriminator + 1024 bytes bitmap
                    if acc.data.len() >= 8 + 1024 {
                        let bit_in_shard: u32 = leaf_index % 8_192;
                        let byte_i: usize = (bit_in_shard / 8) as usize;
                        let mask: u8 = 1u8 << (bit_in_shard % 8);
                        let b = acc.data[8 + byte_i];
                        if (b & mask) != 0 {
                            return Err(AppError::Forbidden("Already spent (bitmap)".into()));
                        }
                    }
                }
            }
            Err(_) => {
                // best-effort only; on-chain enforces
            }
        }
    }

    // -----------------------------------------------------------------
    // 5️⃣  Generate Groth16 proof inside enclave (snarkjs fullprove)
    // -----------------------------------------------------------------
    // Sanity-check the root is actually usable on-chain (tree changelog).
    let root_bytes: [u8; 32] = hex::decode(&root_hex)
        .map_err(|_| AppError::Internal("indexer root_hex decode failed".into()))?
        .try_into()
        .map_err(|_| AppError::Internal("indexer root must be 32 bytes".into()))?;
    let in_tree = tree_changelog_contains_root(&state.rpc, &current_tree_pubkey, root_bytes)?;
    if !in_tree {
        return Err(AppError::BadGateway(
            "tree-indexer returned a root that is not in on-chain history".into(),
        ));
    }

    utils::progress(
        &progress_tx,
        "prove",
        "generating Groth16 proof (rapidsnark)",
    )
    .await;
    let (proof_a, proof_b, proof_c, root_bytes) = generate_withdraw_groth16(
        &browser_inputs,
        leaf_index,
        &merkle_path,
        &path_indices,
        &root_hex,
        asset_id,
    )
    .await?;
    utils::progress(&progress_tx, "prove", "proof generated").await;

    // -----------------------------------------------------------------
    // 6️⃣  Submit on-chain withdraw (Groth16)
    // -----------------------------------------------------------------
    utils::progress(&progress_tx, "chain", "sending withdraw transaction").await;
    let rpc = &state.rpc;
    let recipient_token_account = Pubkey::from_str(&browser_inputs.recipient)
        .map_err(|e| AppError::BadRequest(format!("Invalid recipient token account: {e}")))?;
    if browser_inputs.sol_destination.is_some() {
        return Err(AppError::BadRequest(
            "sol_destination is no longer supported: withdraw WSOL to a WSOL token account and unwrap client-side"
                .into(),
        ));
    }

    // PDAs
    let (amm_pda, _amm_bump) = Pubkey::find_program_address(&[b"amm"], &state.program_id);
    let (registry_pda, _reg_bump) = Pubkey::find_program_address(&[b"registry"], &state.program_id);

    // Programs
    let token_program_id = Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .expect("static SPL token program id");
    let associated_token_program_id =
        Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
            .expect("static associated token program id");

    // Canonical addresses
    let amm_vault = associated_token_address(
        &amm_pda,
        &mint_pubkey,
        &token_program_id,
        &associated_token_program_id,
    );
    let relayer_fee_account = associated_token_address(
        &payer.pubkey(),
        &mint_pubkey,
        &token_program_id,
        &associated_token_program_id,
    );

    // Instruction data layout matches on-chain Anchor:
    // withdraw(proof, root, leaf_index, amount, relayer_fee)
    let withdraw_disc = anchor_discriminator("withdraw");
    let mut withdraw_data = Vec::with_capacity(8 + 64 + 128 + 64 + 32 + 4 + 8 + 8);
    withdraw_data.extend_from_slice(&withdraw_disc);
    withdraw_data.extend_from_slice(&proof_a);
    withdraw_data.extend_from_slice(&proof_b);
    withdraw_data.extend_from_slice(&proof_c);
    withdraw_data.extend_from_slice(&root_bytes);
    withdraw_data.extend_from_slice(&leaf_index.to_le_bytes());
    withdraw_data.extend_from_slice(&browser_inputs.amount.to_le_bytes());
    withdraw_data.extend_from_slice(&browser_inputs.fee.to_le_bytes());

    let shard_index: u32 = leaf_index / 8_192;
    let spent_shard = spent_shard_pda(&state.program_id, &amm_pda, shard_index);
    let withdraw_ix = Instruction {
        program_id: state.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(recipient_token_account, false),
            AccountMeta::new(relayer_fee_account, false),
            AccountMeta::new_readonly(amm_pda, false),
            AccountMeta::new_readonly(mint_pubkey, false),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(amm_vault, false),
            AccountMeta::new(spent_shard, false),
            AccountMeta::new_readonly(current_tree_pubkey, false),
            AccountMeta::new_readonly(token_program_id, false),
            AccountMeta::new_readonly(associated_token_program_id, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: withdraw_data,
    };

    let recent = rpc
        .get_latest_blockhash()
        .map_err(|e| AppError::BadGateway(e.to_string()))?;
    // Ensure the relayer's fee ATA exists (even if fee=0, the program expects the account).
    //
    // CU-optimized strategy:
    // - Cache "fee ATA exists" per mint in-memory
    // - Only do one RPC existence check per mint (per relayer lifetime)
    // - Only include the idempotent create instruction when we believe it's missing
    let mut ixs: Vec<Instruction> = vec![];
    let need_fee_ata_create = {
        let mut cache = state.fee_ata_mints.lock().unwrap();
        if cache.contains(&mint_pubkey) {
            false
        } else {
            match rpc.get_account(&relayer_fee_account) {
                Ok(_) => {
                    cache.insert(mint_pubkey);
                    false
                }
                Err(_) => true,
            }
        }
    };
    if need_fee_ata_create {
        utils::progress(
            &progress_tx,
            "fee_ata",
            format!("creating relayer fee ATA for mint {}", mint_pubkey),
        )
        .await;
        ixs.push(create_associated_token_account_idempotent(
            &payer.pubkey(),   // funding address (relayer pays)
            &payer.pubkey(),   // owner
            &mint_pubkey,      // mint
            &token_program_id, // token program
        ));
    }
    ixs.push(withdraw_ix);
    let tx =
        Transaction::new_signed_with_payer(&ixs, Some(&payer.pubkey()), &[payer.as_ref()], recent);
    // Hard safety: prevent "transaction too large" failures at send-time.
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| AppError::Internal(format!("withdraw tx serialize failed: {e}")))?;
    if tx_bytes.len() > 1232 {
        return Err(AppError::Internal(format!(
            "withdraw transaction too large: {} > 1232 bytes (legacy tx). Reduce instructions/accounts or use v0 + LUT.",
            tx_bytes.len()
        )));
    }
    let signature = rpc
        .send_and_confirm_transaction(&tx)
        .map_err(|e| AppError::BadGateway(format!("Withdraw transaction failed: {e}")))?;

    utils::progress(
        &progress_tx,
        "done",
        format!("withdraw success: {}", signature),
    )
    .await;
    Ok(serde_json::json!({ "status": "success", "signature": signature.to_string() }))
}

/// Circom (Groth16) relay logic for `withdraw_liquidity`.
async fn relay_circom_liquidity_inner(
    state: Arc<AppState>,
    payload: EncryptedRequest,
    progress_tx: Option<ProgressTx>,
) -> AppResult<serde_json::Value> {
    debug!("⚡ Received relay-liquidity request");
    utils::progress(&progress_tx, "wallet", "checking relayer key").await;

    payload.validate()?;

    // Ensure relayer key is provisioned
    let payer: Arc<Keypair> = {
        let guard = state.relayer_wallet.lock().unwrap();
        match &*guard {
            Some(k) => k.clone(),
            None => {
                return Err(AppError::Internal(
                    "Relayer not yet initialized. Please upload key.".into(),
                ))
            }
        }
    };

    // -----------------------------------------------------------------
    // 1️⃣  Decrypt payload (browser inputs – no Merkle data)
    // -----------------------------------------------------------------
    utils::progress(&progress_tx, "decrypt", "decrypting payload").await;
    let encrypted_bytes = hex::decode(&payload.encrypted_blob)
        .map_err(|_| AppError::BadRequest("Invalid hex in encrypted_blob".into()))?;

    let secret_bytes = state.tee_secret.serialize();
    let decrypted = decrypt(&secret_bytes, &encrypted_bytes)
        .map_err(|e| AppError::BadRequest(format!("ECIES decryption failed: {}", e)))?;
    if decrypted.len() > MAX_DECRYPTED_JSON_BYTES {
        return Err(AppError::BadRequest(format!(
            "decrypted payload too large: {} bytes (max {})",
            decrypted.len(),
            MAX_DECRYPTED_JSON_BYTES
        )));
    }

    let browser_inputs: BrowserLiquidityInputs = serde_json::from_slice(&decrypted)
        .map_err(|_| AppError::BadRequest("Decrypted payload is not valid JSON".into()))?;
    validation::validate_browser_liquidity_inputs(&browser_inputs)?;
    utils::progress(&progress_tx, "decrypt", "payload decrypted").await;

    if browser_inputs.fee != 0 {
        return Err(AppError::BadRequest(
            "withdraw_liquidity: relayer fee must be 0 (token relayer fees not supported)".into(),
        ));
    }
    if browser_inputs.shares == 0 {
        return Err(AppError::BadRequest(
            "withdraw_liquidity: shares must be > 0".into(),
        ));
    }

    let recipient_owner = Pubkey::from_str(&browser_inputs.recipient_owner)
        .map_err(|e| AppError::BadRequest(format!("Invalid recipient_owner pubkey: {e}")))?;

    // Canonicalize mint order to match the on-chain pool seed rule.
    let mint_a_in = Pubkey::from_str(&browser_inputs.mint_a)
        .map_err(|e| AppError::BadRequest(format!("Invalid mint_a pubkey: {e}")))?;
    let mint_b_in = Pubkey::from_str(&browser_inputs.mint_b)
        .map_err(|e| AppError::BadRequest(format!("Invalid mint_b pubkey: {e}")))?;
    if mint_a_in == mint_b_in {
        return Err(AppError::BadRequest(
            "mint_a must differ from mint_b".into(),
        ));
    }
    let (mint_a, mint_b) = if mint_a_in.to_bytes() < mint_b_in.to_bytes() {
        (mint_a_in, mint_b_in)
    } else {
        (mint_b_in, mint_a_in)
    };

    // PDAs
    let (amm_pda, _amm_bump) = Pubkey::find_program_address(&[b"amm"], &state.program_id);
    let (registry_pda, _reg_bump) = Pubkey::find_program_address(&[b"registry"], &state.program_id);
    let (pool_pda, _pool_bump) = Pubkey::find_program_address(
        &[amm_pda.as_ref(), mint_a.as_ref(), mint_b.as_ref()],
        &state.program_id,
    );

    // Derive pool_id from on-chain Registry (pool -> pool_id).
    let pool_id = registry_pool_id_for_pool(&state.rpc, state.program_id, &pool_pda)?;

    // -----------------------------------------------------------------
    // 2️⃣  Decode note preimage inputs (no on-chain nullifier PDA check).
    // -----------------------------------------------------------------
    let nullifier_bytes = hex::decode(&browser_inputs.nullifier)
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?;
    if nullifier_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "nullifier must be 32 bytes (hex-encoded)".into(),
        ));
    }

    // -----------------------------------------------------------------
    // 3️⃣  Compute Merkle proof (tree-indexer required)
    // -----------------------------------------------------------------
    utils::progress(&progress_tx, "merkle", "computing leaf commitment").await;
    let commitment = compute_commitment_liquidity(
        &hex::encode(nullifier_bytes),
        &browser_inputs.secret,
        browser_inputs.shares,
        pool_id,
    )?;
    utils::progress(
        &progress_tx,
        "merkle",
        format!(
            "liquidity leaf commitment computed: {}",
            hex::encode(commitment)
        ),
    )
    .await;

    let current_tree_pubkey = current_merkle_tree_pubkey(&state.rpc, &state.program_id)?;

    let indexer_url = env::var("INDEXER_URL").map_err(|_| {
        AppError::BadGateway("INDEXER_URL is required (relayer is indexer-only)".into())
    })?;
    let indexer_url = indexer_url.trim().trim_end_matches('/').to_string();
    if indexer_url.is_empty() {
        return Err(AppError::BadGateway(
            "INDEXER_URL is required (relayer is indexer-only)".into(),
        ));
    }

    let commitment_hex = hex::encode(commitment);
    utils::progress(&progress_tx, "indexer", "querying indexer for root+proof").await;
    let (leaf_index, merkle_path, path_indices, root_hex) = match fetch_indexer_proof(
        &indexer_url,
        &commitment_hex,
        &state.admin_token,
    ) {
        Ok(IndexerProofLookup::Found(p)) => {
            if p.depth != MERKLE_TREE_DEPTH {
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned wrong depth (expected={} got={}): indexer={}",
                    MERKLE_TREE_DEPTH, p.depth, indexer_url
                )));
            }
            if p.siblings_hex.len() != MERKLE_TREE_DEPTH || p.path_bits.len() != MERKLE_TREE_DEPTH {
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned invalid proof shape (siblings={} path_bits={} expected={}): indexer={}",
                    p.siblings_hex.len(),
                    p.path_bits.len(),
                    MERKLE_TREE_DEPTH,
                    indexer_url
                )));
            }
            // Fail fast: leaf returned by indexer must match the commitment we computed.
            let leaf_bytes = parse_hex32_field("indexer.leaf_hex", &p.leaf_hex)?;
            if leaf_bytes == [0u8; 32] {
                metrics::inc_indexer_mismatch_total();
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned empty leaf for commitment={}: indexer={}",
                    commitment_hex, indexer_url
                )));
            }
            if leaf_bytes != commitment {
                metrics::inc_indexer_mismatch_total();
                return Err(AppError::BadGateway(format!(
                    "tree-indexer returned non-matching leaf (commitment={} leaf_hex={}): indexer={}",
                    commitment_hex,
                    p.leaf_hex,
                    indexer_url
                )));
            }
            utils::progress(
                &progress_tx,
                "indexer",
                format!("indexer proof ok (leaf_index={})", p.leaf_index),
            )
            .await;
            (
                p.leaf_index,
                p.siblings_hex,
                p.path_bits
                    .into_iter()
                    .map(|b| (b & 1) as u32)
                    .collect::<Vec<u32>>(),
                p.root_hex,
            )
        }
        Ok(IndexerProofLookup::NotFound(detail)) => {
            return Err(AppError::BadRequest(format!(
                "Commitment not found in tree-indexer (likely spent via swap / leaf replaced, or wrong note). commitment={} indexer={} detail={}",
                commitment_hex, indexer_url, detail
            )));
        }
        Ok(IndexerProofLookup::Unavailable(detail)) => {
            return Err(AppError::BadGateway(format!(
                "tree-indexer unavailable/out-of-sync: indexer={} detail={}",
                indexer_url, detail
            )));
        }
        Err(e) => {
            return Err(AppError::BadGateway(format!(
                "tree-indexer query failed: indexer={} err={}",
                indexer_url, e
            )));
        }
    };
    let max_leaf_index = 1u32.checked_shl(MERKLE_TREE_DEPTH as u32).unwrap_or(0);
    if leaf_index >= max_leaf_index {
        return Err(AppError::BadGateway(format!(
            "tree-indexer returned invalid leaf_index={} for depth={}",
            leaf_index, MERKLE_TREE_DEPTH
        )));
    }
    utils::progress(
        &progress_tx,
        "merkle",
        format!("commitment found at leaf_index={}", leaf_index),
    )
    .await;

    // Fast fail: bitmap spent-by-index check (best-effort; on-chain enforces).
    {
        let shard_index: u32 = leaf_index / 8_192;
        let spent_pk = spent_shard_pda(&state.program_id, &amm_pda, shard_index);
        match state
            .rpc
            .get_account_with_commitment(&spent_pk, CommitmentConfig::confirmed())
        {
            Ok(r) => {
                if let Some(acc) = r.value {
                    if acc.data.len() >= 8 + 1024 {
                        let bit_in_shard: u32 = leaf_index % 8_192;
                        let byte_i: usize = (bit_in_shard / 8) as usize;
                        let mask: u8 = 1u8 << (bit_in_shard % 8);
                        let b = acc.data[8 + byte_i];
                        if (b & mask) != 0 {
                            return Err(AppError::Forbidden("Already spent (bitmap)".into()));
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }

    // Sanity-check the root is actually usable on-chain (tree changelog).
    let root_bytes: [u8; 32] = hex::decode(&root_hex)
        .map_err(|_| AppError::Internal("indexer root_hex decode failed".into()))?
        .try_into()
        .map_err(|_| AppError::Internal("indexer root must be 32 bytes".into()))?;
    let in_tree = tree_changelog_contains_root(&state.rpc, &current_tree_pubkey, root_bytes)?;
    if !in_tree {
        return Err(AppError::BadGateway(
            "tree-indexer returned a root that is not in on-chain history".into(),
        ));
    }

    // -----------------------------------------------------------------
    // 4️⃣  Generate Groth16 proof (withdraw_liquidity)
    // -----------------------------------------------------------------
    utils::progress(
        &progress_tx,
        "prove",
        "generating Groth16 proof (rapidsnark)",
    )
    .await;
    let (proof_a, proof_b, proof_c, root_bytes) = generate_withdraw_liquidity_groth16(
        &browser_inputs,
        leaf_index,
        &merkle_path,
        &path_indices,
        &root_hex,
        pool_id,
        recipient_owner,
    )
    .await?;
    utils::progress(&progress_tx, "prove", "proof generated").await;

    // -----------------------------------------------------------------
    // 5️⃣  Submit on-chain withdraw_liquidity (Groth16)
    // -----------------------------------------------------------------
    utils::progress(
        &progress_tx,
        "chain",
        "sending withdraw_liquidity transaction",
    )
    .await;

    let token_program_id =
        Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").expect("token program");
    let associated_token_program_id =
        Pubkey::from_str("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").expect("ata program");

    // Recipients are the canonical ATAs for the recipient owner.
    let recipient_account_a = associated_token_address(
        &recipient_owner,
        &mint_a,
        &token_program_id,
        &associated_token_program_id,
    );
    let recipient_account_b = associated_token_address(
        &recipient_owner,
        &mint_b,
        &token_program_id,
        &associated_token_program_id,
    );

    // AMM vault ATAs (authority = AMM PDA).
    let amm_vault_a = associated_token_address(
        &amm_pda,
        &mint_a,
        &token_program_id,
        &associated_token_program_id,
    );
    let amm_vault_b = associated_token_address(
        &amm_pda,
        &mint_b,
        &token_program_id,
        &associated_token_program_id,
    );

    let withdraw_disc = anchor_discriminator("withdraw_liquidity");
    let mut withdraw_data = Vec::with_capacity(8 + 64 + 128 + 64 + 32 + 4 + 8 + 8);
    withdraw_data.extend_from_slice(&withdraw_disc);
    withdraw_data.extend_from_slice(&proof_a);
    withdraw_data.extend_from_slice(&proof_b);
    withdraw_data.extend_from_slice(&proof_c);
    withdraw_data.extend_from_slice(&root_bytes);
    withdraw_data.extend_from_slice(&leaf_index.to_le_bytes());
    withdraw_data.extend_from_slice(&browser_inputs.shares.to_le_bytes());
    withdraw_data.extend_from_slice(&0u64.to_le_bytes()); // relayer_fee must be 0

    let shard_index: u32 = leaf_index / 8_192;
    let spent_shard = spent_shard_pda(&state.program_id, &amm_pda, shard_index);
    let withdraw_ix = Instruction {
        program_id: state.program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),         // payer
            AccountMeta::new_readonly(amm_pda, false),      // amm
            AccountMeta::new(pool_pda, false),              // pool (write, mutated)
            AccountMeta::new_readonly(registry_pda, false), // registry
            AccountMeta::new_readonly(mint_a, false),       // mint_a
            AccountMeta::new_readonly(mint_b, false),       // mint_b
            AccountMeta::new(amm_vault_a, false),           // amm_vault_a
            AccountMeta::new(amm_vault_b, false),           // amm_vault_b
            AccountMeta::new(recipient_account_a, false),   // recipient_account_a
            AccountMeta::new(recipient_account_b, false),   // recipient_account_b
            AccountMeta::new(spent_shard, false),           // spent_shard
            AccountMeta::new(current_tree_pubkey, false),   // merkle_tree (mut)
            AccountMeta::new_readonly(token_program_id, false),
            AccountMeta::new_readonly(associated_token_program_id, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data: withdraw_data,
    };

    let recent = state
        .rpc
        .get_latest_blockhash()
        .map_err(|e| AppError::BadGateway(e.to_string()))?;
    let tx = Transaction::new_signed_with_payer(
        &[withdraw_ix],
        Some(&payer.pubkey()),
        &[payer.as_ref()],
        recent,
    );
    // Hard safety: prevent "transaction too large" failures at send-time.
    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| AppError::Internal(format!("withdraw_liquidity tx serialize failed: {e}")))?;
    if tx_bytes.len() > 1232 {
        return Err(AppError::Internal(format!(
            "withdraw_liquidity transaction too large: {} > 1232 bytes (legacy tx). Reduce instructions/accounts or use v0 + LUT.",
            tx_bytes.len()
        )));
    }
    let signature = state
        .rpc
        .send_and_confirm_transaction(&tx)
        .map_err(|e| AppError::BadGateway(format!("WithdrawLiquidity tx failed: {e}")))?;

    utils::progress(
        &progress_tx,
        "done",
        format!("withdraw_liquidity success: {}", signature),
    )
    .await;
    Ok(serde_json::json!({ "status": "success", "signature": signature.to_string() }))
}

// ---------------------------------------------------------------------
//  HELPERS
// ---------------------------------------------------------------------

use crate::constants::{
    DEFAULT_RAPIDSNARK_PATH, DEFAULT_WITHDRAW_LIQUIDITY_WASM_PATH,
    DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_BIN, DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_JS,
    DEFAULT_WITHDRAW_LIQUIDITY_ZKEY_PATH, DEFAULT_WITHDRAW_WASM_PATH, DEFAULT_WITHDRAW_WITNESS_BIN,
    DEFAULT_WITHDRAW_WITNESS_JS, DEFAULT_WITHDRAW_ZKEY_PATH,
};

const DEFAULT_DEPOSIT_ASSET_BIND_WASM_PATH: &str = "/circuits/deposit_asset_bind.wasm";
const DEFAULT_DEPOSIT_ASSET_BIND_ZKEY_PATH: &str = "/circuits/deposit_asset_bind_final.zkey";
const DEFAULT_DEPOSIT_ASSET_BIND_WITNESS_JS: &str =
    "/circuits/deposit_asset_bind_js/generate_witness.js";
const DEFAULT_DEPOSIT_ASSET_BIND_WITNESS_BIN: &str = "/usr/local/bin/deposit_asset_bind_witness";

const DEFAULT_DEPOSIT_LIQUIDITY_BIND_WASM_PATH: &str = "/circuits/deposit_liquidity_bind.wasm";
const DEFAULT_DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH: &str =
    "/circuits/deposit_liquidity_bind_final.zkey";
const DEFAULT_DEPOSIT_LIQUIDITY_BIND_WITNESS_JS: &str =
    "/circuits/deposit_liquidity_bind_js/generate_witness.js";
const DEFAULT_DEPOSIT_LIQUIDITY_BIND_WITNESS_BIN: &str =
    "/usr/local/bin/deposit_liquidity_bind_witness";

const DEFAULT_SWAP_ZK_WASM_PATH: &str = "/circuits/swap_zk.wasm";
const DEFAULT_SWAP_ZK_ZKEY_PATH: &str = "/circuits/swap_zk_final.zkey";
const DEFAULT_SWAP_ZK_WITNESS_JS: &str = "/circuits/swap_zk_js/generate_witness.js";
const DEFAULT_SWAP_ZK_WITNESS_BIN: &str = "/usr/local/bin/swap_zk_witness";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Groth16ProofJson {
    // rapidsnark often outputs projective coordinates: ["x","y","1"].
    // snarkjs outputs affine: ["x","y"].
    // We accept both and take the first 2 elements.
    pub pi_a: Vec<String>,
    // expected shape: [[x0,x1],[y0,y1]] where each inner vec has 2 elements
    pub pi_b: Vec<Vec<String>>,
    // same as pi_a: ["x","y",...]
    pub pi_c: Vec<String>,
}

// (moved) json/merkle helpers live in `utils`.

async fn generate_withdraw_groth16(
    browser_inputs: &BrowserInputs,
    leaf_index: u32,
    merkle_path: &[String],
    path_indices: &[u32],
    root_hex: &str,
    asset_id: u32,
) -> AppResult<([u8; 64], [u8; 128], [u8; 64], [u8; 32])> {
    if merkle_path.len() != MERKLE_TREE_DEPTH {
        return Err(AppError::Internal(format!(
            "merkle_path must be {} elements",
            MERKLE_TREE_DEPTH
        )));
    }
    if path_indices.len() != MERKLE_TREE_DEPTH {
        return Err(AppError::Internal(format!(
            "path_indices must be {} elements",
            MERKLE_TREE_DEPTH
        )));
    }

    let nullifier_bytes: [u8; 32] = hex::decode(&browser_inputs.nullifier)
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("nullifier must be 32 bytes".into()))?;
    let secret_bytes: [u8; 32] = hex::decode(&browser_inputs.secret)
        .map_err(|_| AppError::BadRequest("Invalid hex in secret".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("secret must be 32 bytes".into()))?;

    let root_bytes: [u8; 32] = hex::decode(root_hex)
        .map_err(|_| AppError::BadRequest("Invalid hex in root".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("root must be 32 bytes".into()))?;

    let recipient_pubkey = Pubkey::from_str(&browser_inputs.recipient)
        .map_err(|e| AppError::BadRequest(format!("Invalid recipient token account: {e}")))?;
    let recipient_bytes: [u8; 32] = recipient_pubkey.to_bytes();

    let (root_hi, root_lo) = split_u128_be16_be16(&root_bytes);
    let (rec_hi, rec_lo) = split_u128_be16_be16(&recipient_bytes);

    let amount_le8 = browser_inputs.amount.to_le_bytes();
    let asset_id_le4 = asset_id.to_le_bytes();

    // Circom expects Merkle path arrays bottom-up (leaf -> root):
    // currentHash[0] = leaf; loop i=0..levels-1 consumes sibling at that level.
    // ---------- 1️⃣  Keep the order returned by the cache (leaf → root) ----------
    // `merkle_path` is already leaf‑→‑root (sibling of leaf first, sibling of the
    // node just below the root last). The circuit expects exactly this order,
    // so we **do not reverse** it.
    let mut path_elements: Vec<Vec<u8>> = Vec::with_capacity(MERKLE_TREE_DEPTH);
    for s in merkle_path.iter() {
        let b: [u8; 32] = hex::decode(s)
            .map_err(|_| AppError::Internal("Invalid hex in merkle_path".into()))?
            .try_into()
            .map_err(|_| AppError::Internal("merkle_path element must be 32 bytes".into()))?;
        path_elements.push(b.to_vec());
    }

    // ---------- 2️⃣  Direction bits (leaf -> root) ----------
    // Prefer indexer-provided bits when available (source-of-truth).
    // Cache fallback passes leaf_index-derived bits.
    let path_indices: Vec<u32> = path_indices.to_vec();

    // Self-check: make sure the root implied by (leaf, pathElements, pathIndices) matches `root_hex`.
    // If this fails, Circom will also fail (VerifySplit on root).
    let leaf_commitment = compute_commitment(
        &browser_inputs.nullifier,
        &browser_inputs.secret,
        browser_inputs.amount,
        asset_id,
    )?;
    let computed_root = merkle_root_from_witness(leaf_commitment, &path_elements, &path_indices)?;
    if computed_root != root_bytes {
        return Err(AppError::Internal(format!(
            "Merkle witness/root mismatch before snarkjs: root_hex={} computed_root_hex={} leaf_index={} first_bits={:?} first_path0={}",
            root_hex,
            hex::encode(computed_root),
            leaf_index,
            path_indices.iter().take(8).copied().collect::<Vec<_>>(),
            path_elements.get(0).map(|b| hex::encode(b)).unwrap_or_else(|| "<none>".into())
        )));
    }

    let input_json = serde_json::json!({
        // public inputs (8)
        "rootHi": root_hi,
        "rootLo": root_lo,
        "recipientHi": rec_hi,
        "recipientLo": rec_lo,
        "relayerFee": browser_inputs.fee.to_string(),
        "amountVal": browser_inputs.amount.to_string(),
        "assetId": asset_id.to_string(),
        "leafIndex": leaf_index.to_string(),

        // private inputs
        "nullifier": nullifier_bytes.to_vec(),
        "secret": secret_bytes.to_vec(),
        "amount": amount_le8.to_vec(),
        "assetIdBytes": asset_id_le4.to_vec(),
        "pathElements": path_elements,
        "pathIndices": path_indices,
    });

    let dir = Builder::new()
        .prefix("withdraw_fullprove")
        .tempdir_in(utils::relayer_tmpdir())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let input_path = dir.path().join("input.json");
    let witness_path = dir.path().join("witness.wtns");
    let proof_path = dir.path().join("proof.json");
    let public_path = dir.path().join("public.json");
    tokio::fs::write(&input_path, input_json.to_string())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Fail fast on missing prover artifacts (before spawning witness/prover).
    proving::preflight::preflight_prove_artifacts(RelayJobKind::Withdraw)?;

    let wasm_path =
        env::var("WITHDRAW_WASM_PATH").unwrap_or_else(|_| DEFAULT_WITHDRAW_WASM_PATH.to_string());
    let witness_js =
        env::var("WITHDRAW_WITNESS_JS").unwrap_or_else(|_| DEFAULT_WITHDRAW_WITNESS_JS.to_string());
    let witness_bin = env::var("WITHDRAW_WITNESS_BIN")
        .unwrap_or_else(|_| DEFAULT_WITHDRAW_WITNESS_BIN.to_string());
    let zkey_path =
        env::var("WITHDRAW_ZKEY_PATH").unwrap_or_else(|_| DEFAULT_WITHDRAW_ZKEY_PATH.to_string());
    let node_max_old_space_mb: u32 = env::var("NODE_MAX_OLD_SPACE_MB")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_NODE_MAX_OLD_SPACE_MB);
    let node_options = format!("--max-old-space-size={}", node_max_old_space_mb);

    let rapidsnark_path =
        env::var("RAPIDSNARK_PATH").unwrap_or_else(|_| DEFAULT_RAPIDSNARK_PATH.to_string());

    // `spawn_blocking(move || ...)` moves captured variables; keep originals for reads after.
    let input_path_run = input_path.clone();
    let witness_path_run = witness_path.clone();
    let proof_path_run = proof_path.clone();
    let public_path_run = public_path.clone();
    let wasm_path_run = wasm_path.clone();
    let witness_js_run = witness_js.clone();
    let witness_bin_run = witness_bin.clone();
    let zkey_path_run = zkey_path.clone();
    let node_options_run = node_options.clone();
    let rapidsnark_path_run = rapidsnark_path.clone();

    let (witness_ms, rapidsnark_ms, total_ms, used_native_witness) = task::spawn_blocking(
        move || -> Result<(u128, u128, u128, bool), (String, Option<i32>, Option<i32>)> {
        let t_total = Instant::now();
        // 🛑 CRITICAL: delete old outputs so we don't get "trailing characters"
        // from partially-overwritten JSON (or stale witness files).
        if proof_path_run.exists() {
            std::fs::remove_file(&proof_path_run).map_err(|e| {
                (
                    format!("Failed to delete old proof.json: {}", e),
                    None,
                    None,
                )
            })?;
        }
        if public_path_run.exists() {
            std::fs::remove_file(&public_path_run).map_err(|e| {
                (
                    format!("Failed to delete old public.json: {}", e),
                    None,
                    None,
                )
            })?;
        }
        if witness_path_run.exists() {
            // Not strictly required, but avoids confusing stale witness reuse.
            let _ = std::fs::remove_file(&witness_path_run);
        }

        // 1) Generate witness (prefer native, but allow fallback if out-of-sync).
        let mut used_native_witness = std::path::Path::new(&witness_bin_run).is_file();
        let mut witness_ms: u128 = 0;

        let run_witness = |prefer_native: bool| -> Result<(u128, bool), (String, Option<i32>, Option<i32>)> {
            // Clear any stale witness before generating.
            if witness_path_run.exists() {
                let _ = std::fs::remove_file(&witness_path_run);
            }
            let t_witness = Instant::now();
            let actually_native = prefer_native && std::path::Path::new(&witness_bin_run).is_file();
            let w = if actually_native {
                // Preferred: native circom C++ witness generator.
                // NOTE: the binary expects `<binary>.dat` next to it (same basename).
                std::process::Command::new(&witness_bin_run)
                    .args(&[
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            } else {
                // Fallback: JS/WASM witness generator.
                std::process::Command::new("node")
                    .env("NODE_OPTIONS", &node_options_run)
                    .args(&[
                        &witness_js_run,
                        &wasm_path_run,
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            };
            let w = match w {
                Ok(o) => o,
                Err(e) => return Err((format!("witness generator spawn failed: {e}"), None, None)),
            };
            if !w.status.success() {
                let stderr = String::from_utf8_lossy(&w.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&w.stdout).trim().to_string();
                let code = w.status.code();
                #[cfg(unix)]
                let signal = w.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((format!(
                    "witness generation failed (code={:?}, signal={:?}, witness_bin='{}', wasm='{}', js='{}', NODE_OPTIONS='{}'). stderr='{}' stdout='{}'",
                    code, signal, witness_bin_run, wasm_path_run, witness_js_run, node_options_run, stderr, stdout
                ), code, signal));
            }
            Ok((t_witness.elapsed().as_millis(), actually_native))
        };

        let (w1_ms, w1_native) = run_witness(used_native_witness)?;
        witness_ms += w1_ms;
        used_native_witness = w1_native;

        // 2) Prove using rapidsnark (retry once with WASM witness if native witness is out-of-sync).
        let run_rapidsnark = || -> Result<u128, (String, Option<i32>, Option<i32>)> {
            let t_prove = Instant::now();
            let p = std::process::Command::new(&rapidsnark_path_run)
                .args(&[
                    &zkey_path_run,
                    witness_path_run.to_str().unwrap(),
                    proof_path_run.to_str().unwrap(),
                    public_path_run.to_str().unwrap(),
                ])
                .output();
            let p = match p {
                Ok(o) => o,
                Err(e) => return Err((format!("rapidsnark spawn failed: {e}"), None, None)),
            };
            if !p.status.success() {
                let stderr = String::from_utf8_lossy(&p.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&p.stdout).trim().to_string();
                let code = p.status.code();
                #[cfg(unix)]
                let signal = p.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                let hint = match signal {
                    // SIGILL
                    Some(4) => " HINT: signal 4 is SIGILL (illegal instruction). This usually means the rapidsnark binary was built with CPU instructions not supported by the runtime CPU. Common causes: running linux/amd64 under emulation (Apple Silicon Docker Desktop), or a rapidsnark build requiring AVX/AVX2. Use a more portable rapidsnark build, or run the relayer on a real amd64 Linux host with AVX2.",
                    // SIGSEGV
                    Some(11) => " HINT: signal 11 is SIGSEGV (segfault). This can happen from ABI/cpu issues or corrupted inputs. Try a different rapidsnark build and check witness generation output.",
                    _ => "",
                };
                return Err((format!(
                    "rapidsnark failed (code={:?}, signal={:?}). stderr='{}' stdout='{}'{}",
                    code, signal, stderr, stdout, hint
                ), code, signal));
            }
            Ok(t_prove.elapsed().as_millis())
        };

        let rapidsnark_ms = match run_rapidsnark() {
            Ok(ms) => ms,
            Err((msg, code, signal)) => {
                let is_invalid_witness = msg.contains("Invalid witness length");
                if used_native_witness && is_invalid_witness {
                    // Retry with JS/WASM witness generator. This fixes cases where the native witness binary
                    // is built from a different circuit version than the shipped .zkey.
                    let (w2_ms, _w2_native) = run_witness(false)?;
                    witness_ms += w2_ms;
                    used_native_witness = false;
                    run_rapidsnark().map_err(|(m2, c2, s2)| {
                        (
                            format!(
                                "{} RETRY: also failed after regenerating witness via WASM/JS. (original_err='{}')",
                                m2, msg
                            ),
                            c2,
                            s2,
                        )
                    })?
                } else {
                    return Err((msg, code, signal));
                }
            }
        };

        let total_ms = t_total.elapsed().as_millis();
        Ok((witness_ms, rapidsnark_ms, total_ms, used_native_witness))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|(msg, _code, _signal)| AppError::Internal(msg))?;

    info!(
        "prove timings (withdraw): witness_ms={} rapidsnark_ms={} total_ms={} witness_kind={}",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        if used_native_witness {
            "native"
        } else {
            "wasm"
        }
    );
    metrics::observe_prove_timings(
        "withdraw",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        used_native_witness,
    );

    let proof_bytes = tokio::fs::read(&proof_path)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let proof: Groth16ProofJson = parse_first_json_value(&proof_bytes).map_err(|e| {
        let preview = String::from_utf8_lossy(&proof_bytes)
            .chars()
            .take(300)
            .collect::<String>();
        AppError::Internal(format!(
            "Failed to parse snarkjs proof.json: {} (first300='{}')",
            e, preview
        ))
    })?;

    if proof.pi_a.len() < 2 || proof.pi_c.len() < 2 || proof.pi_b.len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (pi_a/pi_b/pi_c too short)".into(),
        ));
    }
    if proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (pi_b inner arrays too short)".into(),
        ));
    }

    let ax = u256_be32_from_dec_str(&proof.pi_a[0])?;
    let ay = u256_be32_from_dec_str(&proof.pi_a[1])?;
    // groth16-solana expects -A (negated G1 point) for the pairing check.
    let ay_neg = g1_negate_y_be(&ay)?;
    // snarkjs G2 is [[x0, x1],[y0,y1]]; groth16_solana expects c1||c0 ordering for each Fq2.
    let bx_c1 = u256_be32_from_dec_str(&proof.pi_b[0][1])?;
    let bx_c0 = u256_be32_from_dec_str(&proof.pi_b[0][0])?;
    let by_c1 = u256_be32_from_dec_str(&proof.pi_b[1][1])?;
    let by_c0 = u256_be32_from_dec_str(&proof.pi_b[1][0])?;
    let cx = u256_be32_from_dec_str(&proof.pi_c[0])?;
    let cy = u256_be32_from_dec_str(&proof.pi_c[1])?;

    let mut a = [0u8; 64];
    a[0..32].copy_from_slice(&ax);
    a[32..64].copy_from_slice(&ay_neg);
    let mut b = [0u8; 128];
    b[0..32].copy_from_slice(&bx_c1);
    b[32..64].copy_from_slice(&bx_c0);
    b[64..96].copy_from_slice(&by_c1);
    b[96..128].copy_from_slice(&by_c0);
    let mut c = [0u8; 64];
    c[0..32].copy_from_slice(&cx);
    c[32..64].copy_from_slice(&cy);

    Ok((a, b, c, root_bytes))
}

async fn generate_withdraw_liquidity_groth16(
    browser_inputs: &BrowserLiquidityInputs,
    leaf_index: u32,
    merkle_path: &[String],
    path_indices: &[u32],
    root_hex: &str,
    pool_id: u32,
    recipient_owner: Pubkey,
) -> AppResult<([u8; 64], [u8; 128], [u8; 64], [u8; 32])> {
    if merkle_path.len() != MERKLE_TREE_DEPTH {
        return Err(AppError::Internal(format!(
            "merkle_path must be {} elements",
            MERKLE_TREE_DEPTH
        )));
    }
    if path_indices.len() != MERKLE_TREE_DEPTH {
        return Err(AppError::Internal(format!(
            "path_indices must be {} elements",
            MERKLE_TREE_DEPTH
        )));
    }

    let nullifier_bytes: [u8; 32] = hex::decode(&browser_inputs.nullifier)
        .map_err(|_| AppError::BadRequest("Invalid hex in nullifier".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("nullifier must be 32 bytes".into()))?;
    let secret_bytes: [u8; 32] = hex::decode(&browser_inputs.secret)
        .map_err(|_| AppError::BadRequest("Invalid hex in secret".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("secret must be 32 bytes".into()))?;

    let root_bytes: [u8; 32] = hex::decode(root_hex)
        .map_err(|_| AppError::BadRequest("Invalid hex in root".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("root must be 32 bytes".into()))?;

    let recipient_bytes: [u8; 32] = recipient_owner.to_bytes();

    let (root_hi, root_lo) = split_u128_be16_be16(&root_bytes);
    let (rec_hi, rec_lo) = split_u128_be16_be16(&recipient_bytes);

    let shares_le8 = browser_inputs.shares.to_le_bytes();
    let pool_id_le4 = pool_id.to_le_bytes();

    let mut path_elements: Vec<Vec<u8>> = Vec::with_capacity(MERKLE_TREE_DEPTH);
    for s in merkle_path.iter() {
        let b: [u8; 32] = hex::decode(s)
            .map_err(|_| AppError::Internal("Invalid hex in merkle_path".into()))?
            .try_into()
            .map_err(|_| AppError::Internal("merkle_path element must be 32 bytes".into()))?;
        path_elements.push(b.to_vec());
    }
    let path_indices: Vec<u32> = path_indices.to_vec();

    // Self-check: ensure witness matches the supplied root.
    let leaf_commitment = compute_commitment_liquidity(
        &browser_inputs.nullifier,
        &browser_inputs.secret,
        browser_inputs.shares,
        pool_id,
    )?;
    let computed_root = merkle_root_from_witness(leaf_commitment, &path_elements, &path_indices)?;
    if computed_root != root_bytes {
        return Err(AppError::Internal(format!(
            "Merkle witness/root mismatch before snarkjs (liquidity): root_hex={} computed_root_hex={} leaf_index={}",
            root_hex,
            hex::encode(computed_root),
            leaf_index
        )));
    }

    let input_json = serde_json::json!({
        // public inputs (8)
        "rootHi": root_hi,
        "rootLo": root_lo,
        "recipientHi": rec_hi,
        "recipientLo": rec_lo,
        "relayerFee": "0",
        "sharesVal": browser_inputs.shares.to_string(),
        "poolId": pool_id.to_string(),
        "leafIndex": leaf_index.to_string(),

        // private inputs
        "nullifier": nullifier_bytes.to_vec(),
        "secret": secret_bytes.to_vec(),
        "shares": shares_le8.to_vec(),
        "poolIdBytes": pool_id_le4.to_vec(),
        "pathElements": path_elements,
        "pathIndices": path_indices,
    });

    let dir = Builder::new()
        .prefix("withdraw_liquidity_fullprove")
        .tempdir_in(utils::relayer_tmpdir())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let input_path = dir.path().join("input.json");
    let witness_path = dir.path().join("witness.wtns");
    let proof_path = dir.path().join("proof.json");
    let public_path = dir.path().join("public.json");
    tokio::fs::write(&input_path, input_json.to_string())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Fail fast on missing prover artifacts (before spawning witness/prover).
    proving::preflight::preflight_prove_artifacts(RelayJobKind::WithdrawLiquidity)?;

    let wasm_path = env::var("WITHDRAW_LIQUIDITY_WASM_PATH")
        .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_WASM_PATH.to_string());
    let witness_js = env::var("WITHDRAW_LIQUIDITY_WITNESS_JS")
        .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_JS.to_string());
    let witness_bin = env::var("WITHDRAW_LIQUIDITY_WITNESS_BIN")
        .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_BIN.to_string());
    let zkey_path = env::var("WITHDRAW_LIQUIDITY_ZKEY_PATH")
        .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_ZKEY_PATH.to_string());
    let node_max_old_space_mb: u32 = env::var("NODE_MAX_OLD_SPACE_MB")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_NODE_MAX_OLD_SPACE_MB);
    let node_options = format!("--max-old-space-size={}", node_max_old_space_mb);

    let rapidsnark_path =
        env::var("RAPIDSNARK_PATH").unwrap_or_else(|_| DEFAULT_RAPIDSNARK_PATH.to_string());

    let input_path_run = input_path.clone();
    let witness_path_run = witness_path.clone();
    let proof_path_run = proof_path.clone();
    let public_path_run = public_path.clone();
    let wasm_path_run = wasm_path.clone();
    let witness_js_run = witness_js.clone();
    let witness_bin_run = witness_bin.clone();
    let zkey_path_run = zkey_path.clone();
    let node_options_run = node_options.clone();
    let rapidsnark_path_run = rapidsnark_path.clone();

    let (witness_ms, rapidsnark_ms, total_ms, used_native_witness) = task::spawn_blocking(
        move || -> Result<(u128, u128, u128, bool), (String, Option<i32>, Option<i32>)> {
        let t_total = Instant::now();
        if proof_path_run.exists() {
            let _ = std::fs::remove_file(&proof_path_run);
        }
        if public_path_run.exists() {
            let _ = std::fs::remove_file(&public_path_run);
        }
        if witness_path_run.exists() {
            let _ = std::fs::remove_file(&witness_path_run);
        }

        let mut used_native_witness = std::path::Path::new(&witness_bin_run).is_file();
        let mut witness_ms: u128 = 0;

        let run_witness = |prefer_native: bool| -> Result<(u128, bool), (String, Option<i32>, Option<i32>)> {
            if witness_path_run.exists() {
                let _ = std::fs::remove_file(&witness_path_run);
            }
            let t_witness = Instant::now();
            let actually_native = prefer_native && std::path::Path::new(&witness_bin_run).is_file();
            let w = if actually_native {
                std::process::Command::new(&witness_bin_run)
                    .args(&[
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            } else {
                std::process::Command::new("node")
                    .env("NODE_OPTIONS", &node_options_run)
                    .args(&[
                        &witness_js_run,
                        &wasm_path_run,
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            };
            let w = match w {
                Ok(o) => o,
                Err(e) => return Err((format!("witness generator spawn failed: {e}"), None, None)),
            };
            if !w.status.success() {
                let stderr = String::from_utf8_lossy(&w.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&w.stdout).trim().to_string();
                let code = w.status.code();
                #[cfg(unix)]
                let signal = w.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((
                    format!(
                        "witness generation failed (liquidity) (code={:?}, signal={:?}, witness_bin='{}', wasm='{}', js='{}', NODE_OPTIONS='{}'). stderr='{}' stdout='{}'",
                        code, signal, witness_bin_run, wasm_path_run, witness_js_run, node_options_run, stderr, stdout
                    ),
                    code,
                    signal,
                ));
            }
            Ok((t_witness.elapsed().as_millis(), actually_native))
        };

        let (w1_ms, w1_native) = run_witness(used_native_witness)?;
        witness_ms += w1_ms;
        used_native_witness = w1_native;

        let run_rapidsnark = || -> Result<u128, (String, Option<i32>, Option<i32>)> {
            let t_prove = Instant::now();
            let p = std::process::Command::new(&rapidsnark_path_run)
                .args(&[
                    &zkey_path_run,
                    witness_path_run.to_str().unwrap(),
                    proof_path_run.to_str().unwrap(),
                    public_path_run.to_str().unwrap(),
                ])
                .output();
            let p = match p {
                Ok(o) => o,
                Err(e) => return Err((format!("rapidsnark spawn failed: {e}"), None, None)),
            };
            if !p.status.success() {
                let stderr = String::from_utf8_lossy(&p.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&p.stdout).trim().to_string();
                let code = p.status.code();
                #[cfg(unix)]
                let signal = p.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((
                    format!(
                        "rapidsnark failed (liquidity) (code={:?}, signal={:?}). stderr='{}' stdout='{}'",
                        code, signal, stderr, stdout
                    ),
                    code,
                    signal,
                ));
            }
            Ok(t_prove.elapsed().as_millis())
        };

        let rapidsnark_ms = match run_rapidsnark() {
            Ok(ms) => ms,
            Err((msg, code, signal)) => {
                let is_invalid_witness = msg.contains("Invalid witness length");
                if used_native_witness && is_invalid_witness {
                    let (w2_ms, _w2_native) = run_witness(false)?;
                    witness_ms += w2_ms;
                    used_native_witness = false;
                    run_rapidsnark().map_err(|(m2, c2, s2)| {
                        (
                            format!(
                                "{} RETRY: also failed after regenerating witness via WASM/JS. (original_err='{}')",
                                m2, msg
                            ),
                            c2,
                            s2,
                        )
                    })?
                } else {
                    return Err((msg, code, signal));
                }
            }
        };

        let total_ms = t_total.elapsed().as_millis();
        Ok((witness_ms, rapidsnark_ms, total_ms, used_native_witness))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|(msg, _code, _signal)| AppError::Internal(msg))?;

    info!(
        "prove timings (withdraw_liquidity): witness_ms={} rapidsnark_ms={} total_ms={} witness_kind={}",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        if used_native_witness { "native" } else { "wasm" }
    );
    metrics::observe_prove_timings(
        "withdraw_liquidity",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        used_native_witness,
    );

    let proof_bytes = tokio::fs::read(&proof_path)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let proof: Groth16ProofJson = parse_first_json_value(&proof_bytes)
        .map_err(|e| AppError::Internal(format!("Failed to parse liquidity proof.json: {e}")))?;

    if proof.pi_a.len() < 2 || proof.pi_c.len() < 2 || proof.pi_b.len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (liquidity) (pi_a/pi_b/pi_c too short)".into(),
        ));
    }
    if proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (liquidity) (pi_b inner arrays too short)".into(),
        ));
    }

    let ax = u256_be32_from_dec_str(&proof.pi_a[0])?;
    let ay = u256_be32_from_dec_str(&proof.pi_a[1])?;
    let ay_neg = g1_negate_y_be(&ay)?;
    let bx_c1 = u256_be32_from_dec_str(&proof.pi_b[0][1])?;
    let bx_c0 = u256_be32_from_dec_str(&proof.pi_b[0][0])?;
    let by_c1 = u256_be32_from_dec_str(&proof.pi_b[1][1])?;
    let by_c0 = u256_be32_from_dec_str(&proof.pi_b[1][0])?;
    let cx = u256_be32_from_dec_str(&proof.pi_c[0])?;
    let cy = u256_be32_from_dec_str(&proof.pi_c[1])?;

    let mut a = [0u8; 64];
    a[0..32].copy_from_slice(&ax);
    a[32..64].copy_from_slice(&ay_neg);
    let mut b = [0u8; 128];
    b[0..32].copy_from_slice(&bx_c1);
    b[32..64].copy_from_slice(&bx_c0);
    b[64..96].copy_from_slice(&by_c1);
    b[96..128].copy_from_slice(&by_c0);
    let mut c = [0u8; 64];
    c[0..32].copy_from_slice(&cx);
    c[32..64].copy_from_slice(&cy);

    Ok((a, b, c, root_bytes))
}

async fn generate_deposit_asset_bind_groth16(
    nullifier: [u8; 32],
    secret: [u8; 32],
    amount: u64,
    asset_id: u32,
    commitment: [u8; 32],
) -> AppResult<([u8; 64], [u8; 128], [u8; 64], Groth16ProofJson)> {
    let (commit_hi, commit_lo) = split_u128_be16_be16(&commitment);
    let amount_le8 = amount.to_le_bytes();
    let asset_id_le4 = asset_id.to_le_bytes();

    let input_json = serde_json::json!({
        // public inputs (4)
        "commitmentHi": commit_hi,
        "commitmentLo": commit_lo,
        "amountVal": amount.to_string(),
        "assetId": asset_id.to_string(),

        // private inputs
        "nullifier": nullifier.to_vec(),
        "secret": secret.to_vec(),
        "amount": amount_le8.to_vec(),
        "assetIdBytes": asset_id_le4.to_vec(),
    });

    let dir = Builder::new()
        .prefix("deposit_asset_bind_fullprove")
        .tempdir_in(utils::relayer_tmpdir())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let input_path = dir.path().join("input.json");
    let witness_path = dir.path().join("witness.wtns");
    let proof_path = dir.path().join("proof.json");
    let public_path = dir.path().join("public.json");
    tokio::fs::write(&input_path, input_json.to_string())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let wasm_path = env::var("DEPOSIT_ASSET_BIND_WASM_PATH")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_ASSET_BIND_WASM_PATH.to_string());
    let witness_js = env::var("DEPOSIT_ASSET_BIND_WITNESS_JS")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_ASSET_BIND_WITNESS_JS.to_string());
    let witness_bin = env::var("DEPOSIT_ASSET_BIND_WITNESS_BIN")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_ASSET_BIND_WITNESS_BIN.to_string());
    let zkey_path = env::var("DEPOSIT_ASSET_BIND_ZKEY_PATH")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_ASSET_BIND_ZKEY_PATH.to_string());
    let node_max_old_space_mb: u32 = env::var("NODE_MAX_OLD_SPACE_MB")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_NODE_MAX_OLD_SPACE_MB);
    let node_options = format!("--max-old-space-size={}", node_max_old_space_mb);
    let rapidsnark_path =
        env::var("RAPIDSNARK_PATH").unwrap_or_else(|_| DEFAULT_RAPIDSNARK_PATH.to_string());

    let input_path_run = input_path.clone();
    let witness_path_run = witness_path.clone();
    let proof_path_run = proof_path.clone();
    let public_path_run = public_path.clone();
    let wasm_path_run = wasm_path.clone();
    let witness_js_run = witness_js.clone();
    let witness_bin_run = witness_bin.clone();
    let zkey_path_run = zkey_path.clone();
    let node_options_run = node_options.clone();
    let rapidsnark_path_run = rapidsnark_path.clone();

    let (witness_ms, rapidsnark_ms, total_ms, used_native_witness) = task::spawn_blocking(
        move || -> Result<(u128, u128, u128, bool), (String, Option<i32>, Option<i32>)> {
            let t_total = Instant::now();
            if proof_path_run.exists() {
                let _ = std::fs::remove_file(&proof_path_run);
            }
            if public_path_run.exists() {
                let _ = std::fs::remove_file(&public_path_run);
            }
            if witness_path_run.exists() {
                let _ = std::fs::remove_file(&witness_path_run);
            }

            let used_native_witness = std::path::Path::new(&witness_bin_run).is_file();
            let t_witness = Instant::now();
            let w = if used_native_witness {
                std::process::Command::new(&witness_bin_run)
                    .args(&[
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            } else {
                std::process::Command::new("node")
                    .env("NODE_OPTIONS", &node_options_run)
                    .args(&[
                        &witness_js_run,
                        &wasm_path_run,
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            };
            let w = match w {
                Ok(o) => o,
                Err(e) => return Err((format!("witness generator spawn failed: {e}"), None, None)),
            };
            if !w.status.success() {
                let stderr = String::from_utf8_lossy(&w.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&w.stdout).trim().to_string();
                let code = w.status.code();
                #[cfg(unix)]
                let signal = w.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((
                    format!(
                        "witness generation failed (deposit_asset_bind) (code={:?}, signal={:?}, witness_bin='{}', wasm='{}', js='{}', NODE_OPTIONS='{}'). stderr='{}' stdout='{}'",
                        code, signal, witness_bin_run, wasm_path_run, witness_js_run, node_options_run, stderr, stdout
                    ),
                    code,
                    signal,
                ));
            }
            let witness_ms = t_witness.elapsed().as_millis();

            let t_prove = Instant::now();
            let p = std::process::Command::new(&rapidsnark_path_run)
                .args(&[
                    &zkey_path_run,
                    witness_path_run.to_str().unwrap(),
                    proof_path_run.to_str().unwrap(),
                    public_path_run.to_str().unwrap(),
                ])
                .output();
            let p = match p {
                Ok(o) => o,
                Err(e) => return Err((format!("rapidsnark spawn failed: {e}"), None, None)),
            };
            if !p.status.success() {
                let stderr = String::from_utf8_lossy(&p.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&p.stdout).trim().to_string();
                let code = p.status.code();
                #[cfg(unix)]
                let signal = p.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((
                    format!(
                        "rapidsnark failed (deposit_asset_bind) (code={:?}, signal={:?}). stderr='{}' stdout='{}'",
                        code, signal, stderr, stdout
                    ),
                    code,
                    signal,
                ));
            }
            let rapidsnark_ms = t_prove.elapsed().as_millis();
            let total_ms = t_total.elapsed().as_millis();
            Ok((witness_ms, rapidsnark_ms, total_ms, used_native_witness))
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|(msg, _code, _signal)| AppError::Internal(msg))?;

    info!(
        "prove timings (deposit_asset_bind): witness_ms={} rapidsnark_ms={} total_ms={} witness_kind={}",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        if used_native_witness { "native" } else { "wasm" }
    );
    metrics::observe_prove_timings(
        "deposit_asset_bind",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        used_native_witness,
    );

    let proof_bytes = tokio::fs::read(&proof_path)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let proof: Groth16ProofJson = parse_first_json_value(&proof_bytes).map_err(|e| {
        AppError::Internal(format!(
            "Failed to parse deposit_asset_bind proof.json: {e}"
        ))
    })?;

    if proof.pi_a.len() < 2 || proof.pi_c.len() < 2 || proof.pi_b.len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (deposit_asset_bind) (pi_a/pi_b/pi_c too short)".into(),
        ));
    }
    if proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (deposit_asset_bind) (pi_b inner arrays too short)".into(),
        ));
    }

    let ax = u256_be32_from_dec_str(&proof.pi_a[0])?;
    let ay = u256_be32_from_dec_str(&proof.pi_a[1])?;
    let ay_neg = g1_negate_y_be(&ay)?;
    let bx_c1 = u256_be32_from_dec_str(&proof.pi_b[0][1])?;
    let bx_c0 = u256_be32_from_dec_str(&proof.pi_b[0][0])?;
    let by_c1 = u256_be32_from_dec_str(&proof.pi_b[1][1])?;
    let by_c0 = u256_be32_from_dec_str(&proof.pi_b[1][0])?;
    let cx = u256_be32_from_dec_str(&proof.pi_c[0])?;
    let cy = u256_be32_from_dec_str(&proof.pi_c[1])?;

    let mut a = [0u8; 64];
    a[0..32].copy_from_slice(&ax);
    a[32..64].copy_from_slice(&ay_neg);
    let mut b = [0u8; 128];
    b[0..32].copy_from_slice(&bx_c1);
    b[32..64].copy_from_slice(&bx_c0);
    b[64..96].copy_from_slice(&by_c1);
    b[96..128].copy_from_slice(&by_c0);
    let mut c = [0u8; 64];
    c[0..32].copy_from_slice(&cx);
    c[32..64].copy_from_slice(&cy);

    Ok((a, b, c, proof))
}

async fn generate_deposit_liquidity_bind_groth16(
    nullifier: [u8; 32],
    secret: [u8; 32],
    shares: u64,
    pool_id: u32,
    commitment: [u8; 32],
) -> AppResult<([u8; 64], [u8; 128], [u8; 64], Groth16ProofJson)> {
    let (commit_hi, commit_lo) = split_u128_be16_be16(&commitment);
    let shares_le8 = shares.to_le_bytes();
    let pool_id_le4 = pool_id.to_le_bytes();

    let input_json = serde_json::json!({
        // public inputs (4)
        "commitmentHi": commit_hi,
        "commitmentLo": commit_lo,
        "sharesVal": shares.to_string(),
        "poolId": pool_id.to_string(),

        // private inputs
        "nullifier": nullifier.to_vec(),
        "secret": secret.to_vec(),
        "shares": shares_le8.to_vec(),
        "poolIdBytes": pool_id_le4.to_vec(),
    });

    let dir = Builder::new()
        .prefix("deposit_liquidity_bind_fullprove")
        .tempdir_in(utils::relayer_tmpdir())
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let input_path = dir.path().join("input.json");
    let witness_path = dir.path().join("witness.wtns");
    let proof_path = dir.path().join("proof.json");
    let public_path = dir.path().join("public.json");
    tokio::fs::write(&input_path, input_json.to_string())
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let wasm_path = env::var("DEPOSIT_LIQUIDITY_BIND_WASM_PATH")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_LIQUIDITY_BIND_WASM_PATH.to_string());
    let witness_js = env::var("DEPOSIT_LIQUIDITY_BIND_WITNESS_JS")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_LIQUIDITY_BIND_WITNESS_JS.to_string());
    let witness_bin = env::var("DEPOSIT_LIQUIDITY_BIND_WITNESS_BIN")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_LIQUIDITY_BIND_WITNESS_BIN.to_string());
    let zkey_path = env::var("DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH")
        .unwrap_or_else(|_| DEFAULT_DEPOSIT_LIQUIDITY_BIND_ZKEY_PATH.to_string());
    let node_max_old_space_mb: u32 = env::var("NODE_MAX_OLD_SPACE_MB")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_NODE_MAX_OLD_SPACE_MB);
    let node_options = format!("--max-old-space-size={}", node_max_old_space_mb);
    let rapidsnark_path =
        env::var("RAPIDSNARK_PATH").unwrap_or_else(|_| DEFAULT_RAPIDSNARK_PATH.to_string());

    let input_path_run = input_path.clone();
    let witness_path_run = witness_path.clone();
    let proof_path_run = proof_path.clone();
    let public_path_run = public_path.clone();
    let wasm_path_run = wasm_path.clone();
    let witness_js_run = witness_js.clone();
    let witness_bin_run = witness_bin.clone();
    let zkey_path_run = zkey_path.clone();
    let node_options_run = node_options.clone();
    let rapidsnark_path_run = rapidsnark_path.clone();

    let (witness_ms, rapidsnark_ms, total_ms, used_native_witness) = task::spawn_blocking(
        move || -> Result<(u128, u128, u128, bool), (String, Option<i32>, Option<i32>)> {
            let t_total = Instant::now();
            if proof_path_run.exists() {
                let _ = std::fs::remove_file(&proof_path_run);
            }
            if public_path_run.exists() {
                let _ = std::fs::remove_file(&public_path_run);
            }
            if witness_path_run.exists() {
                let _ = std::fs::remove_file(&witness_path_run);
            }

            let used_native_witness = std::path::Path::new(&witness_bin_run).is_file();
            let t_witness = Instant::now();
            let w = if used_native_witness {
                std::process::Command::new(&witness_bin_run)
                    .args(&[
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            } else {
                std::process::Command::new("node")
                    .env("NODE_OPTIONS", &node_options_run)
                    .args(&[
                        &witness_js_run,
                        &wasm_path_run,
                        input_path_run.to_str().unwrap(),
                        witness_path_run.to_str().unwrap(),
                    ])
                    .output()
            };
            let w = match w {
                Ok(o) => o,
                Err(e) => return Err((format!("witness generator spawn failed: {e}"), None, None)),
            };
            if !w.status.success() {
                let stderr = String::from_utf8_lossy(&w.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&w.stdout).trim().to_string();
                let code = w.status.code();
                #[cfg(unix)]
                let signal = w.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((
                    format!(
                        "witness generation failed (deposit_liquidity_bind) (code={:?}, signal={:?}, witness_bin='{}', wasm='{}', js='{}', NODE_OPTIONS='{}'). stderr='{}' stdout='{}'",
                        code, signal, witness_bin_run, wasm_path_run, witness_js_run, node_options_run, stderr, stdout
                    ),
                    code,
                    signal,
                ));
            }
            let witness_ms = t_witness.elapsed().as_millis();

            let t_prove = Instant::now();
            let p = std::process::Command::new(&rapidsnark_path_run)
                .args(&[
                    &zkey_path_run,
                    witness_path_run.to_str().unwrap(),
                    proof_path_run.to_str().unwrap(),
                    public_path_run.to_str().unwrap(),
                ])
                .output();
            let p = match p {
                Ok(o) => o,
                Err(e) => return Err((format!("rapidsnark spawn failed: {e}"), None, None)),
            };
            if !p.status.success() {
                let stderr = String::from_utf8_lossy(&p.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&p.stdout).trim().to_string();
                let code = p.status.code();
                #[cfg(unix)]
                let signal = p.status.signal();
                #[cfg(not(unix))]
                let signal: Option<i32> = None;
                return Err((
                    format!(
                        "rapidsnark failed (deposit_liquidity_bind) (code={:?}, signal={:?}). stderr='{}' stdout='{}'",
                        code, signal, stderr, stdout
                    ),
                    code,
                    signal,
                ));
            }
            let rapidsnark_ms = t_prove.elapsed().as_millis();
            let total_ms = t_total.elapsed().as_millis();
            Ok((witness_ms, rapidsnark_ms, total_ms, used_native_witness))
        },
    )
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|(msg, _code, _signal)| AppError::Internal(msg))?;

    info!(
        "prove timings (deposit_liquidity_bind): witness_ms={} rapidsnark_ms={} total_ms={} witness_kind={}",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        if used_native_witness { "native" } else { "wasm" }
    );
    metrics::observe_prove_timings(
        "deposit_liquidity_bind",
        witness_ms,
        rapidsnark_ms,
        total_ms,
        used_native_witness,
    );

    let proof_bytes = tokio::fs::read(&proof_path)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let proof: Groth16ProofJson = parse_first_json_value(&proof_bytes).map_err(|e| {
        AppError::Internal(format!(
            "Failed to parse deposit_liquidity_bind proof.json: {e}"
        ))
    })?;

    if proof.pi_a.len() < 2 || proof.pi_c.len() < 2 || proof.pi_b.len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (deposit_liquidity_bind) (pi_a/pi_b/pi_c too short)".into(),
        ));
    }
    if proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(AppError::Internal(
            "Malformed proof.json (deposit_liquidity_bind) (pi_b inner arrays too short)".into(),
        ));
    }

    let ax = u256_be32_from_dec_str(&proof.pi_a[0])?;
    let ay = u256_be32_from_dec_str(&proof.pi_a[1])?;
    let ay_neg = g1_negate_y_be(&ay)?;
    let bx_c1 = u256_be32_from_dec_str(&proof.pi_b[0][1])?;
    let bx_c0 = u256_be32_from_dec_str(&proof.pi_b[0][0])?;
    let by_c1 = u256_be32_from_dec_str(&proof.pi_b[1][1])?;
    let by_c0 = u256_be32_from_dec_str(&proof.pi_b[1][0])?;
    let cx = u256_be32_from_dec_str(&proof.pi_c[0])?;
    let cy = u256_be32_from_dec_str(&proof.pi_c[1])?;

    let mut a = [0u8; 64];
    a[0..32].copy_from_slice(&ax);
    a[32..64].copy_from_slice(&ay_neg);
    let mut b = [0u8; 128];
    b[0..32].copy_from_slice(&bx_c1);
    b[32..64].copy_from_slice(&bx_c0);
    b[64..96].copy_from_slice(&by_c1);
    b[96..128].copy_from_slice(&by_c0);
    let mut c = [0u8; 64];
    c[0..32].copy_from_slice(&cx);
    c[32..64].copy_from_slice(&cy);

    Ok((a, b, c, proof))
}

// ---------------------------------------------------------------------
//  NEW MERKLE‑PROOF HELPERS (relayer side)
// ---------------------------------------------------------------------

// (moved) indexer/http helpers live in `utils`.

// (moved) commitment/registry/anchor helpers live in `utils`.

// (deleted) cache backfill tx parsing helpers (relayer is indexer-only)

// (deleted) cache backfill helper (relayer is indexer-only)

// (deleted) cache backfill tx parsing helpers (relayer is indexer-only)

// (deleted) cache backfill tree-op extraction (relayer is indexer-only)

// (deleted) cache backfill helper (relayer is indexer-only)

// (moved) on-chain tree helpers live in `utils`.

// (deleted) tx->merkle_tree filter helper (relayer is indexer-only)

// (deleted) deposit cache builder (relayer is indexer-only)
// (deleted) deposit cache poller (relayer is indexer-only)
