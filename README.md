# Luminosity

Private DeFi on Solana. Deposit, swap, and provide liquidity — without linking your wallet to your activity.

## The problem

Every DeFi transaction on Solana is fully public. Your wallet, your balances, your trades, your LP positions — all visible to anyone. MEV bots front-run you. Onlookers profile you. There's no opt-out.

## What Luminosity does

Luminosity is a **privacy pool** that breaks the on-chain link between deposits and withdrawals. You deposit tokens and receive a **note** (a secret you store locally). When you want to withdraw, swap, or remove liquidity, you prove you hold a valid note — without revealing which deposit it came from.

- **Private withdrawals** — withdraw to any wallet, unlinkable to the original deposit
- **Private swaps** — swap between token pairs inside the pool without exposing trade intent
- **Private liquidity** — provide and remove LP, earning fees without a public position

All of this works with **any SPL token**, not just SOL.

## What's actually built (and live on mainnet)

This isn't a demo. The full system is deployed and operational:

- **On-chain Anchor program** with Groth16 proof verification for every deposit and withdrawal (4 circuits, 4 verifying keys baked into the program)
- **4 Circom circuits** using Keccak256 — withdraw, withdraw liquidity, deposit binding (asset), deposit binding (LP)
- **SPL Concurrent Merkle Tree** (depth 24 / 16M+ leaf capacity) storing note commitments
- **Sharded spent bitmaps** instead of per-nullifier PDAs — efficient on-chain double-spend prevention that doesn't bloat state
- **Asset registry** binding mints to circuit-level IDs — you can't withdraw SOL with a USDC note
- **Solvency checks** on every swap and LP withdrawal — virtual reserves are validated against actual vault balances
- **TEE-attested relayer** (Rust) that generates proofs and submits transactions — designed for Marlin Oyster, works standalone
- **RFQ swap engine** (Rust) with Pyth oracle integration — quotes swaps, checks price staleness + confidence, emits encrypted output notes on-chain

## How notes work

A note is `keccak256(nullifier || secret || amount || assetId)`. You keep the preimage; the chain only stores the hash in a Merkle tree. To withdraw, a Groth16 proof shows you know a note in the tree without revealing which one. The program verifies the proof, checks the spent bitmap, and pays out.

For swaps, the engine tombstones your old note's leaf and appends a new one atomically. You get the new note back encrypted in on-chain event logs.

## Repo layout

```
programs/solana-privacy-pool/   On-chain program (Anchor)
circuits/                       Circom circuits (4 circuits, Keccak256)
relayer/                        Proof generation + tx submission (Rust)
swap-engine/                    RFQ swap execution (Rust, Pyth oracles)
```

## Status

**Beta / rapid deployment.** Live on mainnet, moving fast. During short periods in beta, the deployed program may temporarily differ from this repo (urgent fixes, staged rollouts). Unaudited.

## Build

```bash
cd relayer && cargo build
cd ../swap-engine && cargo build
cd ../programs/solana-privacy-pool && cargo build
```

## License

Apache-2.0 (see `LICENSE`).
