use std::env;

use ecies::{encrypt, PublicKey};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let tee_pubkey_hex = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: encrypt_blob <tee_pubkey_hex> <json_payload>"))?;
    let json_payload = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: encrypt_blob <tee_pubkey_hex> <json_payload>"))?;

    let tee_pubkey_bytes = hex::decode(tee_pubkey_hex.trim())
        .map_err(|e| anyhow::anyhow!("invalid tee_pubkey_hex: {e}"))?;
    let pk = PublicKey::parse_slice(&tee_pubkey_bytes, None)
        .map_err(|e| anyhow::anyhow!("failed to parse tee pubkey: {e:?}"))?;

    let ct = encrypt(&pk.serialize(), json_payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt failed: {e:?}"))?;
    println!("{}", hex::encode(ct));
    Ok(())
}
