//! Background rebalance loop: periodically sweeps accumulated profits and
//! rebalances inventory between the TEE wallet and pool vaults.
//!
//! The on-chain `rebalance` instruction enforces the k-invariant, so the worst
//! case for a buggy delta calculation here is a reverted transaction — never a
//! loss of LP value.

use crate::config::Config;
use crate::solana::{
    associated_token_address, build_rebalance_tx, fetch_pool, fetch_registry_pools,
    fetch_token_account_amounts,
};
use crate::types::PoolAccount;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Spawn the rebalance background loop. Runs until the process exits.
pub fn spawn(
    cfg: Arc<Config>,
    rpc: Arc<RpcClient>,
    tee_keypair: Arc<std::sync::Mutex<Option<Arc<Keypair>>>>,
) {
    let interval_secs = cfg.rebalance_interval_secs;
    if interval_secs == 0 {
        info!("rebalance loop disabled (REBALANCE_INTERVAL_SECS=0)");
        return;
    }
    tokio::spawn(async move {
        info!("rebalance loop started (interval={}s, threshold={}%)", interval_secs, cfg.rebalance_threshold_pct);
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let kp = {
                let guard = tee_keypair.lock().unwrap();
                match guard.as_ref() {
                    Some(k) => Arc::clone(k),
                    None => {
                        debug!("rebalance: TEE keypair not provisioned yet, skipping");
                        continue;
                    }
                }
            };
            if let Err(e) = run_rebalance_cycle(&cfg, &rpc, &kp).await {
                warn!("rebalance cycle failed: {e}");
            }
        }
    });
}

async fn run_rebalance_cycle(
    cfg: &Config,
    rpc: &RpcClient,
    tee_authority: &Keypair,
) -> anyhow::Result<()> {
    let rpc_ref = rpc;
    let pool_pks = fetch_registry_pools(rpc_ref, &cfg.program_id)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let tee_pk = tee_authority.pubkey();

    for pool_pk in pool_pks {
        if let Err(e) = rebalance_pool(cfg, rpc_ref, tee_authority, &tee_pk, &pool_pk) {
            warn!("rebalance pool {} failed: {e}", pool_pk);
        }
    }
    Ok(())
}

fn rebalance_pool(
    cfg: &Config,
    rpc: &RpcClient,
    tee_authority: &Keypair,
    tee_pk: &Pubkey,
    pool_pk: &Pubkey,
) -> anyhow::Result<()> {
    let pool: PoolAccount = fetch_pool(rpc, pool_pk)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let tee_ata_a = associated_token_address(tee_pk, &pool.mint_a);
    let tee_ata_b = associated_token_address(tee_pk, &pool.mint_b);

    let balances = fetch_token_account_amounts(rpc, &[tee_ata_a, tee_ata_b])
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let bal_a = balances.first().copied().flatten().unwrap_or(0);
    let bal_b = balances.get(1).copied().flatten().unwrap_or(0);

    if bal_a == 0 && bal_b == 0 {
        return Ok(());
    }

    let threshold_pct = cfg.rebalance_threshold_pct.max(1);

    // Compute target inventory: equal split of TEE holdings.
    // If TEE has excess tokens that represent accumulated profit, sweep them
    // into the pool (positive delta). This increases k and benefits LPs.
    //
    // We deposit any surplus that exceeds the threshold, keeping a working
    // buffer in the TEE wallet for upcoming fills.
    let target_a = pool.reserve_a / 10; // 10% of pool as target TEE buffer
    let target_b = pool.reserve_b / 10;

    let drift_a_pct = if target_a > 0 {
        ((bal_a as i128 - target_a as i128).unsigned_abs() * 100 / target_a as u128) as u64
    } else if bal_a > 0 {
        100
    } else {
        0
    };

    let drift_b_pct = if target_b > 0 {
        ((bal_b as i128 - target_b as i128).unsigned_abs() * 100 / target_b as u128) as u64
    } else if bal_b > 0 {
        100
    } else {
        0
    };

    if drift_a_pct < threshold_pct && drift_b_pct < threshold_pct {
        debug!(
            "pool {} rebalance skipped (drift_a={}%, drift_b={}%, threshold={}%)",
            pool_pk, drift_a_pct, drift_b_pct, threshold_pct
        );
        return Ok(());
    }

    // LP-safety policy:
    // - Only sweep surplus from TEE into vaults (delta > 0).
    // - Never auto-withdraw from vaults (delta < 0).
    //
    // This makes the automated rebalance path strictly non-extractive for LPs:
    // reserves can only increase here, never decrease.
    let raw_delta_a = (bal_a as i128) - (target_a as i128);
    let raw_delta_b = (bal_b as i128) - (target_b as i128);
    let delta_a: i64 = if raw_delta_a > 0 {
        raw_delta_a.min(i64::MAX as i128) as i64
    } else {
        0
    };
    let delta_b: i64 = if raw_delta_b > 0 {
        raw_delta_b.min(i64::MAX as i128) as i64
    } else {
        0
    };

    if delta_a == 0 && delta_b == 0 {
        return Ok(());
    }

    // Pre-flight k-invariant check (mirror on-chain semantics with checked math).
    let old_k = (pool.reserve_a as u128)
        .checked_mul(pool.reserve_b as u128)
        .ok_or_else(|| anyhow::anyhow!("rebalance old_k overflow"))?;
    let new_a = (pool.reserve_a as u128)
        .checked_add(delta_a as u128)
        .ok_or_else(|| anyhow::anyhow!("rebalance new_a overflow"))?;
    let new_b = (pool.reserve_b as u128)
        .checked_add(delta_b as u128)
        .ok_or_else(|| anyhow::anyhow!("rebalance new_b overflow"))?;
    let new_k = new_a
        .checked_mul(new_b)
        .ok_or_else(|| anyhow::anyhow!("rebalance new_k overflow"))?;
    if new_k < old_k {
        debug!(
            "pool {} rebalance would violate k-invariant (old_k={}, new_k={}), skipping",
            pool_pk, old_k, new_k
        );
        return Ok(());
    }

    let recent_blockhash = rpc.get_latest_blockhash()
        .map_err(|e| anyhow::anyhow!("get blockhash: {e}"))?;

    let tx = build_rebalance_tx(
        cfg.program_id,
        *pool_pk,
        &pool,
        delta_a,
        delta_b,
        recent_blockhash,
        tee_authority,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            info!(
                "rebalance pool {} ok: sig={}, delta_a={}, delta_b={}",
                pool_pk, sig, delta_a, delta_b
            );
            // Immediately refresh TEE balance cache so next quote sees updated inventory.
            crate::solana::refresh_tee_balance_cache(rpc, &[tee_ata_a, tee_ata_b]);
        }
        Err(e) => {
            warn!(
                "rebalance pool {} tx failed: {} (delta_a={}, delta_b={})",
                pool_pk, e, delta_a, delta_b
            );
        }
    }

    Ok(())
}
