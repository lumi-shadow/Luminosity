pragma circom 2.0.0;

// Deposit binding proof (asset notes) — two-layer commitment format.
//
// Proves that the public commitment corresponds to:
//   Layer 1:  noteHash   = keccak256(nullifier || secret)
//   Layer 2:  commitment = keccak256(noteHash  || amountLE8 || assetIdLE4)
//
// This circuit intentionally does NOT include the Merkle tree.
// It is designed to be used by an on-chain verifier to bind the deposit amount to the commitment.

include "circomlib/circuits/bitify.circom";
include "keccak-circom/circuits/keccak.circom";

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

// Check that 'bytes' (32) matches 'hi' (16) + 'lo' (16)
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

// Layer 1: noteHash = keccak256(nullifier || secret)
// 64 bytes = 512 bits
template NoteHasher() {
    signal input nullifier[32];
    signal input secret[32];
    signal output hash[32];

    component keccak = Keccak(512, 256);
    var idx = 0;

    component nBits[32];
    for (var i = 0; i < 32; i++) {
        nBits[i] = Byte2Bits(); nBits[i].in <== nullifier[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== nBits[i].out[b]; idx++; }
    }
    component sBits[32];
    for (var i = 0; i < 32; i++) {
        sBits[i] = Byte2Bits(); sBits[i].in <== secret[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== sBits[i].out[b]; idx++; }
    }

    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== keccak.out[i*8 + b];
        hash[i] <== outBytes[i].out;
    }
}

// Layer 2: commitment = keccak256(noteHash || amount || assetId)
// 44 bytes = 352 bits
template CommitmentHasherV2() {
    signal input noteHash[32];
    signal input amount[8];
    signal input assetId[4];
    signal output hash[32];

    component keccak = Keccak(352, 256);
    var idx = 0;

    component nhBits[32];
    for (var i = 0; i < 32; i++) {
        nhBits[i] = Byte2Bits(); nhBits[i].in <== noteHash[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== nhBits[i].out[b]; idx++; }
    }
    component aBits[8];
    for (var i = 0; i < 8; i++) {
        aBits[i] = Byte2Bits(); aBits[i].in <== amount[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== aBits[i].out[b]; idx++; }
    }
    component idBits[4];
    for (var i = 0; i < 4; i++) {
        idBits[i] = Byte2Bits(); idBits[i].in <== assetId[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== idBits[i].out[b]; idx++; }
    }

    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== keccak.out[i*8 + b];
        hash[i] <== outBytes[i].out;
    }
}

template DepositAssetBind() {
    // PUBLIC INPUTS
    signal input commitmentHi;
    signal input commitmentLo;
    signal input amountVal; // u64
    signal input assetId;   // u32

    // PRIVATE INPUTS
    signal input nullifier[32];
    signal input secret[32];
    signal input amount[8];        // LE bytes
    signal input assetIdBytes[4];  // LE bytes

    // Layer 1: noteHash = keccak256(nullifier || secret)
    component noteHasher = NoteHasher();
    for (var i = 0; i < 32; i++) { noteHasher.nullifier[i] <== nullifier[i]; noteHasher.secret[i] <== secret[i]; }

    // Layer 2: commitment = keccak256(noteHash || amount || assetId)
    component cHasher = CommitmentHasherV2();
    for (var i = 0; i < 32; i++) cHasher.noteHash[i] <== noteHasher.hash[i];
    for (var i = 0; i < 8; i++) cHasher.amount[i] <== amount[i];
    for (var i = 0; i < 4; i++) cHasher.assetId[i] <== assetIdBytes[i];

    // Bind commitment bytes to public (hi, lo)
    component cSplit = VerifySplit();
    cSplit.hi <== commitmentHi;
    cSplit.lo <== commitmentLo;
    for (var i = 0; i < 32; i++) cSplit.bytes[i] <== cHasher.hash[i];

    // Bind amount bytes to public amountVal
    var amountCheck = 0;
    for (var i = 0; i < 8; i++) {
        amountCheck += amount[i] * (256 ** i);
    }
    amountVal === amountCheck;

    // Bind assetId bytes to public assetId
    var assetCheck = 0;
    for (var i = 0; i < 4; i++) {
        assetCheck += assetIdBytes[i] * (256 ** i);
    }
    assetId === assetCheck;
}

// Public signals: commitment split into (hi, lo), plus (amountVal, assetId).
component main {public [commitmentHi, commitmentLo, amountVal, assetId]} = DepositAssetBind();
