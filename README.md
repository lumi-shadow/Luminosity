# Luminosity

Privacy pool + execution services on Solana.

Users interact via **notes** (bearer secrets). The chain enforces state transitions; off-chain services do proving / execution.

### Status (beta / rapid deployment)

- **This is beta** and moving fast.
- **During short periods in beta, the deployed on-chain program may differ from this repo.** This can happen for urgent fixes or staged rollouts. Treat this repo as the source reference, but expect occasional temporary drift.
- **Unaudited**.

## Repo layout

- **On-chain program (Anchor)**: `programs/solana-privacy-pool/`
- **Circom circuits (source)**: `circuits/`
- **Relayer (Rust)**: `relayer/`
- **Swap engine (Rust)**: `swap-engine/`

## What we don’t publish here

- Deployment configs (Docker/compose), infra files
- Built proving artifacts / binaries (zkeys, wasm, witness generators, `circuit-out/`)
- Any key material (`*.json` keypairs), `.env`, credentials

## Security quick notes

- **Notes are bearer secrets**. Treat them like private keys.
- `relayer/` and `swap-engine/` have admin/provisioning endpoints guarded by `ADMIN_TOKEN`. Do not expose them without strong auth + network controls.

## Build

```bash
cd relayer && cargo build
cd ../swap-engine && cargo build
cd ../programs/solana-privacy-pool && cargo build
```

## License

Apache-2.0 (see `LICENSE`).
