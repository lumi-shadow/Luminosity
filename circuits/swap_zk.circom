pragma circom 2.0.0;

// ZK Swap proof (Path C — two-layer commitment, no Merkle tree, no CPMM).
//
// Proves that the prover knows the preimage of the input note commitment using
// the two-layer commitment scheme:
//
//   Layer 1:  noteHash   = keccak256(nullifier || secret)               [64 bytes → 32 bytes]
//   Layer 2:  commitment = keccak256(noteHash  || amountLE8 || assetIdLE4) [44 bytes → 32 bytes]
//
// Design rationale:
//
//   This circuit intentionally does NOT include:
//   - The Merkle tree  (SPL Account Compression verifies inclusion on-chain via replace_leaf CPI)
//   - CPMM/PMM math    (the on-chain program computes amount_out with Pyth oracle pricing)
//   - Output commitment (the on-chain program computes it via the keccak256 syscall)
//
//   By splitting the commitment into two hash layers, Layer 1 (noteHash) is independent of
//   any on-chain state.  The user pre-computes noteHash offline and provides it in the proof.
//   The on-chain program then computes Layer 2 using the PMM-determined amount_out, producing
//   the output commitment deterministically — no TEE, no reserve binding in the proof, and
//   fully concurrent (multiple proofs never invalidate each other).
//
// Security model:
//
//   - Input note ownership:  proven by knowledge of (nullifier, secret) preimage  [this circuit]
//   - Merkle inclusion:      verified on-chain by SPL Compression (replace_leaf CPI)
//   - Swap pricing:          computed on-chain by PMM with Pyth oracle
//   - Output commitment:     computed on-chain via keccak256 syscall from (noteHashOut, amount_out, assetIdOut)
//   - Slippage:              enforced on-chain (amount_out >= minAmountOut)
//   - Double-spend:          prevented by spent-by-index bitmap (same as existing swap path)
//
// Bound-but-unconstrained public inputs:
//
//   noteHashOutHi/Lo, assetIdOut, and minAmountOut appear as public inputs but have no internal
//   circuit constraints.  Their purpose is purely cryptographic binding: because Groth16
//   verification includes ALL public inputs in the pairing equation, changing any of them
//   invalidates the proof.  This prevents a front-runner or malicious relayer from substituting
//   the output note recipient or lowering slippage protection after the user generates the proof.
//
// Public input ordering (must match on-chain verifier):
//
//   [0] inputCommitmentHi   — input note commitment bytes[0..16]  (128 bits)
//   [1] inputCommitmentLo   — input note commitment bytes[16..32] (128 bits)
//   [2] amountIn            — swap input amount                   (u64)
//   [3] assetIdIn           — input asset registry id             (u32)
//   [4] noteHashOutHi       — output note secret hash bytes[0..16]  (128 bits, bound)
//   [5] noteHashOutLo       — output note secret hash bytes[16..32] (128 bits, bound)
//   [6] assetIdOut          — output asset registry id            (u32, bound)
//   [7] minAmountOut        — slippage floor                      (u64, bound)

include "circomlib/circuits/bitify.circom";
include "keccak-circom/circuits/keccak.circom";

// ---------------------------------------------------------------------------
// Utility templates (identical to existing circuits for consistency)
// ---------------------------------------------------------------------------

template Byte2Bits() {
    signal input in;
    signal output out[8];
    component n2b = Num2Bits(8);
    n2b.in <== in;
    for (var i = 0; i < 8; i++) out[i] <== n2b.out[i];
}

template Bits2Byte() {
    signal input in[8];
    signal output out;
    component b2n = Bits2Num(8);
    for (var i = 0; i < 8; i++) b2n.in[i] <== in[i];
    out <== b2n.out;
}

// Check that 'bytes' (32) matches 'hi' (16) + 'lo' (16).
// Used to bind a 32-byte hash output to the (hi, lo) split used in on-chain public inputs.
template VerifySplit() {
    signal input bytes[32];
    signal input hi;
    signal input lo;
    var sumHi = 0;
    var sumLo = 0;
    for (var i = 0; i < 16; i++) { sumHi = sumHi * 256 + bytes[i]; }
    for (var i = 0; i < 16; i++) { sumLo = sumLo * 256 + bytes[16 + i]; }
    hi === sumHi;
    lo === sumLo;
}

// ---------------------------------------------------------------------------
// Two-layer commitment hashers
// ---------------------------------------------------------------------------

// Layer 1: noteHash = keccak256(nullifier || secret)
//
// Input:  nullifier (32 bytes) || secret (32 bytes) = 64 bytes = 512 bits
// Output: noteHash (32 bytes)
//
// This hash binds the user's spending credentials into an opaque 32-byte blob
// that can safely appear on-chain without revealing the preimage.
template NoteHasher() {
    signal input nullifier[32];
    signal input secret[32];
    signal output hash[32];

    // 32 + 32 = 64 bytes = 512 bits
    component keccak = Keccak(512, 256);
    var idx = 0;

    // Feed nullifier bytes
    component nBits[32];
    for (var i = 0; i < 32; i++) {
        nBits[i] = Byte2Bits();
        nBits[i].in <== nullifier[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== nBits[i].out[b]; idx++; }
    }

    // Feed secret bytes
    component sBits[32];
    for (var i = 0; i < 32; i++) {
        sBits[i] = Byte2Bits();
        sBits[i].in <== secret[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== sBits[i].out[b]; idx++; }
    }

    // Convert Keccak output bits to bytes
    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== keccak.out[i*8 + b];
        hash[i] <== outBytes[i].out;
    }
}

// Layer 2: commitment = keccak256(noteHash || amount || assetId)
//
// Input:  noteHash (32 bytes) || amount (8 bytes LE) || assetId (4 bytes LE) = 44 bytes = 352 bits
// Output: commitment (32 bytes)
//
// This is the value that gets stored as a leaf in the Merkle tree.
// For deposits, the user computes this off-chain.
// For swaps, the on-chain program computes this using the keccak256 syscall
// with the PMM-determined amount_out (hence why amount is NOT in the ZK proof for output notes).
template CommitmentHasherV2() {
    signal input noteHash[32];
    signal input amount[8];
    signal input assetId[4];
    signal output hash[32];

    // 32 + 8 + 4 = 44 bytes = 352 bits
    component keccak = Keccak(352, 256);
    var idx = 0;

    // Feed noteHash bytes
    component nhBits[32];
    for (var i = 0; i < 32; i++) {
        nhBits[i] = Byte2Bits();
        nhBits[i].in <== noteHash[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== nhBits[i].out[b]; idx++; }
    }

    // Feed amount bytes (little-endian u64)
    component aBits[8];
    for (var i = 0; i < 8; i++) {
        aBits[i] = Byte2Bits();
        aBits[i].in <== amount[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== aBits[i].out[b]; idx++; }
    }

    // Feed assetId bytes (little-endian u32)
    component idBits[4];
    for (var i = 0; i < 4; i++) {
        idBits[i] = Byte2Bits();
        idBits[i].in <== assetId[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== idBits[i].out[b]; idx++; }
    }

    // Convert Keccak output bits to bytes
    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== keccak.out[i*8 + b];
        hash[i] <== outBytes[i].out;
    }
}

// ---------------------------------------------------------------------------
// Main circuit
// ---------------------------------------------------------------------------

template SwapZK() {
    // ===================== PUBLIC INPUTS (8) =====================

    // Input note commitment, split into two 128-bit halves (big-endian byte interpretation).
    // This is the leaf value that SPL Compression will tombstone via replace_leaf.
    signal input inputCommitmentHi;
    signal input inputCommitmentLo;

    // Swap input amount (u64, base units).
    // This value is exposed publicly so the on-chain program can:
    //   1) use it as input to the PMM pricing formula
    //   2) update pool reserves (reserve_in += amountIn)
    signal input amountIn;

    // Input asset registry id (u32).
    // The on-chain program verifies this matches the pool's mint via the Registry.
    signal input assetIdIn;

    // Output note secret hash, split into two 128-bit halves.
    // noteHashOut = keccak256(newNullifier || newSecret), computed by the user off-chain.
    // Bound to the proof to prevent a relayer/front-runner from redirecting the output note.
    // The on-chain program uses this to compute the output commitment:
    //   outputCommitment = keccak256(noteHashOut || amount_out_LE8 || assetIdOut_LE4)
    signal input noteHashOutHi;
    signal input noteHashOutLo;

    // Output asset registry id (u32).
    // Bound to the proof; the on-chain program verifies it matches the pool's other mint.
    signal input assetIdOut;

    // Minimum acceptable output amount (u64, slippage protection).
    // Bound to the proof; the on-chain program enforces amount_out >= minAmountOut.
    signal input minAmountOut;

    // ===================== PRIVATE INPUTS =====================

    signal input nullifier[32];       // Input note nullifier (32 bytes)
    signal input secret[32];          // Input note secret    (32 bytes)
    signal input amountInBytes[8];    // Input amount as LE bytes (must encode to amountIn)
    signal input assetIdInBytes[4];   // Input asset id as LE bytes (must encode to assetIdIn)

    // ===================== CONSTRAINTS =====================

    // ---- 1) Two-layer input commitment ----
    //
    // Layer 1: noteHash = keccak256(nullifier || secret)
    // Proves the prover knows the spending credentials for the input note.

    component noteHasher = NoteHasher();
    for (var i = 0; i < 32; i++) {
        noteHasher.nullifier[i] <== nullifier[i];
        noteHasher.secret[i] <== secret[i];
    }

    // Layer 2: commitment = keccak256(noteHash || amountInBytes || assetIdInBytes)
    // Proves the derived noteHash + amount + assetId produce the claimed input commitment.

    component commitHasher = CommitmentHasherV2();
    for (var i = 0; i < 32; i++) commitHasher.noteHash[i] <== noteHasher.hash[i];
    for (var i = 0; i < 8; i++)  commitHasher.amount[i]   <== amountInBytes[i];
    for (var i = 0; i < 4; i++)  commitHasher.assetId[i]  <== assetIdInBytes[i];

    // ---- 2) Bind commitment hash to public (hi, lo) ----
    //
    // The on-chain program reconstructs the 32-byte commitment from (hi, lo) and passes
    // it to SPL Compression replace_leaf.  This constraint ensures the ZK-proven commitment
    // matches the one being tombstoned in the tree.

    component cSplit = VerifySplit();
    cSplit.hi <== inputCommitmentHi;
    cSplit.lo <== inputCommitmentLo;
    for (var i = 0; i < 32; i++) cSplit.bytes[i] <== commitHasher.hash[i];

    // ---- 3) Bind private LE bytes to public integer values ----
    //
    // The on-chain program encodes amountIn and assetIdIn as big-endian field elements
    // and includes them in the Groth16 public input array.  These constraints ensure the
    // private byte arrays used in the Keccak preimage match the public integer values.

    // amountInBytes (8 LE bytes) must encode to amountIn (u64)
    var amountCheck = 0;
    for (var i = 0; i < 8; i++) {
        amountCheck += amountInBytes[i] * (256 ** i);
    }
    amountIn === amountCheck;

    // assetIdInBytes (4 LE bytes) must encode to assetIdIn (u32)
    var assetIdCheck = 0;
    for (var i = 0; i < 4; i++) {
        assetIdCheck += assetIdInBytes[i] * (256 ** i);
    }
    assetIdIn === assetIdCheck;

    // ---- 4) Range constraints ----
    //
    // Constrained public inputs (amountIn, assetIdIn) are already range-bound by the
    // byte binding above (sum of 8-bit values × powers of 256 cannot exceed the type width).
    //
    // Bound-but-unconstrained public inputs need explicit range checks to prevent
    // "free field element" attacks where a malicious prover (or verifier mismatch) uses
    // values outside the expected integer range.

    // amountIn: implicitly constrained to [0, 2^64 - 1] by 8-byte LE binding.
    // assetIdIn: implicitly constrained to [0, 2^32 - 1] by 4-byte LE binding.

    // noteHashOutHi/Lo: each must fit in 128 bits (16-byte half of a 32-byte hash).
    component nhOutHiR = Num2Bits(128);
    nhOutHiR.in <== noteHashOutHi;
    component nhOutLoR = Num2Bits(128);
    nhOutLoR.in <== noteHashOutLo;

    // assetIdOut: must fit in 32 bits (u32 on-chain).
    component aidOutR = Num2Bits(32);
    aidOutR.in <== assetIdOut;

    // minAmountOut: must fit in 64 bits (u64 on-chain).
    component minOutR = Num2Bits(64);
    minOutR.in <== minAmountOut;
}

// ---------------------------------------------------------------------------
// Instantiation
// ---------------------------------------------------------------------------
//
// 8 public inputs — matches the on-chain Groth16Verifier::<8> and vk_ic.len() == 9.
// Order must exactly match the on-chain public input encoding in execute_zk_swap.

component main {public [
    inputCommitmentHi,
    inputCommitmentLo,
    amountIn,
    assetIdIn,
    noteHashOutHi,
    noteHashOutLo,
    assetIdOut,
    minAmountOut
]} = SwapZK();
