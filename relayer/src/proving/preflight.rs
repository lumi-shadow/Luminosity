use crate::constants::{
    DEFAULT_RAPIDSNARK_PATH, DEFAULT_WITHDRAW_LIQUIDITY_WASM_PATH,
    DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_BIN, DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_JS,
    DEFAULT_WITHDRAW_LIQUIDITY_ZKEY_PATH, DEFAULT_WITHDRAW_WASM_PATH, DEFAULT_WITHDRAW_WITNESS_BIN,
    DEFAULT_WITHDRAW_WITNESS_JS, DEFAULT_WITHDRAW_ZKEY_PATH,
};
use crate::error::{AppError, AppResult};
use crate::state::RelayJobKind;
use std::env;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn ensure_file_nonempty(path: &str, label: &str) -> AppResult<u64> {
    let m = std::fs::metadata(path)
        .map_err(|e| AppError::Unavailable(format!("{label} missing at '{path}': {e}")))?;
    if !m.is_file() || m.len() == 0 {
        return Err(AppError::Unavailable(format!(
            "{label} invalid/empty at '{path}'"
        )));
    }
    Ok(m.len())
}

pub fn ensure_exec(path: &str, label: &str) -> AppResult<()> {
    let m = std::fs::metadata(path)
        .map_err(|e| AppError::Unavailable(format!("{label} missing at '{path}': {e}")))?;
    if !m.is_file() || m.len() == 0 {
        return Err(AppError::Unavailable(format!(
            "{label} invalid/empty at '{path}'"
        )));
    }
    #[cfg(unix)]
    {
        let mode = m.permissions().mode();
        if (mode & 0o111) == 0 {
            return Err(AppError::Unavailable(format!(
                "{label} is not executable: '{path}' (mode={:o})",
                mode
            )));
        }
    }
    Ok(())
}

pub fn parse_hex32_field(label: &str, s: &str) -> AppResult<[u8; 32]> {
    let s = s.trim().trim_start_matches("0x");
    let v = hex::decode(s).map_err(|_| AppError::BadGateway(format!("invalid hex in {label}")))?;
    if v.len() != 32 {
        return Err(AppError::BadGateway(format!(
            "{label} must be 32 bytes, got {}",
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

pub fn preflight_prove_artifacts(kind: RelayJobKind) -> AppResult<()> {
    // Shared prover binary.
    let rapidsnark_path =
        env::var("RAPIDSNARK_PATH").unwrap_or_else(|_| DEFAULT_RAPIDSNARK_PATH.to_string());
    ensure_exec(&rapidsnark_path, "RAPIDSNARK_PATH")?;

    match kind {
        RelayJobKind::Withdraw => {
            let wasm_path = env::var("WITHDRAW_WASM_PATH")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_WASM_PATH.to_string());
            let witness_js = env::var("WITHDRAW_WITNESS_JS")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_WITNESS_JS.to_string());
            let witness_bin = env::var("WITHDRAW_WITNESS_BIN")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_WITNESS_BIN.to_string());
            let zkey_path = env::var("WITHDRAW_ZKEY_PATH")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_ZKEY_PATH.to_string());

            ensure_file_nonempty(&wasm_path, "WITHDRAW_WASM_PATH")?;
            ensure_file_nonempty(&witness_js, "WITHDRAW_WITNESS_JS")?;
            ensure_file_nonempty(&zkey_path, "WITHDRAW_ZKEY_PATH")?;
            // Native witness is optional; if present, ensure its paired .dat exists.
            if std::path::Path::new(&witness_bin).is_file() {
                ensure_exec(&witness_bin, "WITHDRAW_WITNESS_BIN")?;
                let dat = format!("{witness_bin}.dat");
                ensure_file_nonempty(&dat, "WITHDRAW_WITNESS_BIN.dat")?;
            }
        }
        RelayJobKind::WithdrawLiquidity => {
            let wasm_path = env::var("WITHDRAW_LIQUIDITY_WASM_PATH")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_WASM_PATH.to_string());
            let witness_js = env::var("WITHDRAW_LIQUIDITY_WITNESS_JS")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_JS.to_string());
            let witness_bin = env::var("WITHDRAW_LIQUIDITY_WITNESS_BIN")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_WITNESS_BIN.to_string());
            let zkey_path = env::var("WITHDRAW_LIQUIDITY_ZKEY_PATH")
                .unwrap_or_else(|_| DEFAULT_WITHDRAW_LIQUIDITY_ZKEY_PATH.to_string());

            ensure_file_nonempty(&wasm_path, "WITHDRAW_LIQUIDITY_WASM_PATH")?;
            ensure_file_nonempty(&witness_js, "WITHDRAW_LIQUIDITY_WITNESS_JS")?;
            ensure_file_nonempty(&zkey_path, "WITHDRAW_LIQUIDITY_ZKEY_PATH")?;
            if std::path::Path::new(&witness_bin).is_file() {
                ensure_exec(&witness_bin, "WITHDRAW_LIQUIDITY_WITNESS_BIN")?;
                let dat = format!("{witness_bin}.dat");
                ensure_file_nonempty(&dat, "WITHDRAW_LIQUIDITY_WITNESS_BIN.dat")?;
            }
        }
    }
    Ok(())
}
