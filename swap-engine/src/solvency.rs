use crate::types::AppError;
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

pub struct ComputeSolvencyParams<'a> {
    pub rpc: &'a RpcClient,
    pub program_id: Pubkey,
    pub indexer_url: String,
}

#[derive(serde::Serialize, Clone)]
pub struct SolvencyMintRow {
    pub mint: String,
    pub vault: String,
    pub vault_balance: u64,
    pub reserved_in_pools: u64,
    pub free_for_asset_notes: i64,
}

#[derive(serde::Serialize, Clone)]
pub struct SolvencyPoolRow {
    pub pool: String,
    pub mint_a: String,
    pub mint_b: String,
    pub vault_a: String,
    pub vault_b: String,
    pub vault_a_balance: u64,
    pub vault_b_balance: u64,
    pub reserve_a: u64,
    pub reserve_b: u64,
    /// Headroom/backing buffer (vault_balance - reserve). Must be >= 0 to be fully backed.
    pub headroom_a: i64,
    pub headroom_b: i64,
    /// Backward-compat alias (deprecated): same as headroom_a/headroom_b.
    pub drift_a: i64,
    pub drift_b: i64,
}

#[derive(serde::Serialize, Clone)]
pub struct SolvencyResponse {
    pub ok: bool,
    pub program_id: String,
    pub indexer_url: String,
    pub ts_ms: u64,
    pub mints: Vec<SolvencyMintRow>,
    pub pools: Vec<SolvencyPoolRow>,
    pub warnings: Vec<String>,
}

pub fn compute_solvency(params: ComputeSolvencyParams<'_>) -> Result<SolvencyResponse, AppError> {
    let pool_pks = crate::solana::fetch_registry_pools(params.rpc, &params.program_id)?;
    let mut pools = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Collect unique vaults per mint (and verify consistency).
    let mut mint_to_vault: std::collections::HashMap<Pubkey, Pubkey> =
        std::collections::HashMap::new();
    let mut vaults: Vec<Pubkey> = Vec::new();

    for pk in pool_pks {
        if pk == Pubkey::default() {
            continue;
        }
        let p = crate::solana::fetch_pool(params.rpc, &pk)?;
        for (m, v) in [(p.mint_a, p.vault_a), (p.mint_b, p.vault_b)] {
            if let Some(prev) = mint_to_vault.get(&m) {
                if *prev != v {
                    warnings.push(format!(
                        "mint {} has inconsistent vault mapping: {} vs {}",
                        m, prev, v
                    ));
                }
            } else {
                mint_to_vault.insert(m, v);
                vaults.push(v);
            }
        }
        pools.push((pk, p));
    }

    let vault_amounts = crate::solana::fetch_token_account_amounts(params.rpc, &vaults)?;
    let mut vault_map: std::collections::HashMap<Pubkey, u64> = std::collections::HashMap::new();
    for (i, v) in vaults.iter().enumerate() {
        let amt = vault_amounts.get(i).and_then(|x| *x).unwrap_or(0);
        vault_map.insert(*v, amt);
    }

    // Aggregate reserved sums per mint across all pools (critical for shared vault model).
    let mut reserved_by_mint: std::collections::HashMap<Pubkey, u128> =
        std::collections::HashMap::new();
    for (_pk, p) in &pools {
        *reserved_by_mint.entry(p.mint_a).or_insert(0) += p.reserve_a as u128;
        *reserved_by_mint.entry(p.mint_b).or_insert(0) += p.reserve_b as u128;
    }

    let mut pool_rows: Vec<SolvencyPoolRow> = Vec::new();
    let mut ok = true;
    for (pk, p) in &pools {
        let va = vault_map.get(&p.vault_a).copied().unwrap_or(0);
        let vb = vault_map.get(&p.vault_b).copied().unwrap_or(0);
        let headroom_a = (va as i128) - (p.reserve_a as i128);
        let headroom_b = (vb as i128) - (p.reserve_b as i128);
        if headroom_a < 0 || headroom_b < 0 {
            ok = false;
        }
        let headroom_a_i64 = headroom_a.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        let headroom_b_i64 = headroom_b.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        pool_rows.push(SolvencyPoolRow {
            pool: pk.to_string(),
            mint_a: p.mint_a.to_string(),
            mint_b: p.mint_b.to_string(),
            vault_a: p.vault_a.to_string(),
            vault_b: p.vault_b.to_string(),
            vault_a_balance: va,
            vault_b_balance: vb,
            reserve_a: p.reserve_a,
            reserve_b: p.reserve_b,
            headroom_a: headroom_a_i64,
            headroom_b: headroom_b_i64,
            // deprecated alias
            drift_a: headroom_a_i64,
            drift_b: headroom_b_i64,
        });
    }

    let mut mint_rows: Vec<SolvencyMintRow> = Vec::new();
    for (mint, vault) in mint_to_vault {
        let vault_bal = vault_map.get(&vault).copied().unwrap_or(0);
        let reserved = reserved_by_mint.get(&mint).copied().unwrap_or(0);
        if reserved > u64::MAX as u128 {
            ok = false;
            warnings.push(format!("mint {} reserved_in_pools overflow", mint));
        }
        let reserved_u64 = reserved.min(u64::MAX as u128) as u64;
        let free = (vault_bal as i128) - (reserved_u64 as i128);
        if free < 0 {
            ok = false;
        }
        mint_rows.push(SolvencyMintRow {
            mint: mint.to_string(),
            vault: vault.to_string(),
            vault_balance: vault_bal,
            reserved_in_pools: reserved_u64,
            free_for_asset_notes: free.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
        });
    }
    mint_rows.sort_by(|a, b| a.mint.cmp(&b.mint));

    Ok(SolvencyResponse {
        ok,
        program_id: params.program_id.to_string(),
        indexer_url: params.indexer_url,
        ts_ms: (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64),
        mints: mint_rows,
        pools: pool_rows,
        warnings,
    })
}
