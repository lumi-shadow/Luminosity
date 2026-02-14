pragma circom 2.0.0;

// Asset withdrawal circuit — two-layer commitment format.
//
// Leaf/commitment (two-layer):
//   Layer 1:  noteHash   = keccak256(nullifier || secret)
//   Layer 2:  commitment = keccak256(noteHash  || amountLE8 || assetIdLE4)

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

// Keccak256(left || right) where both are provided as bit arrays (256 bits each).
// This avoids repeatedly decomposing the intermediate hash bytes via Num2Bits(8) at every Merkle level.
template HashLeftRightBits() {
    signal input left[256];
    signal input right[256];
    signal output hash[256];

    component keccak = Keccak(512, 256);
    for (var i = 0; i < 256; i++) keccak.in[i] <== left[i];
    for (var i = 0; i < 256; i++) keccak.in[256 + i] <== right[i];
    for (var i = 0; i < 256; i++) hash[i] <== keccak.out[i];
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
// Outputs both hashBits (for Merkle tree traversal) and hash bytes (for compatibility).
template CommitmentHasherV2Bits() {
    signal input noteHash[32];
    signal input amount[8];
    signal input assetId[4];
    signal output hashBits[256];
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

    for (var i = 0; i < 256; i++) hashBits[i] <== keccak.out[i];

    // Expose bytes for compatibility with existing interfaces.
    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== keccak.out[i*8 + b];
        hash[i] <== outBytes[i].out;
    }
}

template Withdraw(levels) {
    // PUBLIC INPUTS
    signal input rootHi; 
    signal input rootLo;
    signal input recipientHi; 
    signal input recipientLo; 
    signal input relayerFee;
    signal input amountVal; // u64 amount (public)
    signal input assetId;   // u32 asset id (public)
    signal input leafIndex; // u32 leaf index (public) for bitmap nullification

    // SECURITY / TRUST MODEL (READ THIS BEFORE REVIEWING):
    //
    // 1) "Can someone change recipient in the on-chain tx after the proof is created?"
    //    - No. `recipientHi/recipientLo` are PUBLIC INPUTS and therefore part of the statement the
    //      proof attests to.
    //    - The on-chain program constructs these same public inputs from the instruction's
    //      `recipient` account pubkey and verifies Groth16 against them.
    //    - If a relayer/attacker changes the recipient account in the transaction, the on-chain
    //      public inputs change and the proof will fail verification.
    //
    // 2) "So where is the remaining trust assumption?"
    //    - The recipient is NOT included in the note commitment preimage
    //      (commitment = keccak(noteHash || amount || assetId)).
    //    - That means whoever can GENERATE a proof (i.e. whoever knows the note secrets) can
    //      choose any recipient at proving time.
    //
    // 3) Intended hackathon design:
    //    - The relayer/TEE generates proofs and is assumed honest via remote attestation + fixed
    //      code policy, so it will honor the user's requested recipient when proving.
    //
    // PRIVATE INPUTS
    signal input nullifier[32];
    signal input secret[32];
    signal input amount[8];     
    signal input assetIdBytes[4];
    signal input pathElements[levels][32];
    signal input pathIndices[levels];

    // ---- Safety/range constraints for public inputs ----
    // Recipient pubkey halves are 16 bytes each in the on-chain public input encoding.
    // Constrain them to 128-bit ranges explicitly (prevents "free field element" usage).
    component recHiN2B = Num2Bits(128);
    recHiN2B.in <== recipientHi;
    component recLoN2B = Num2Bits(128);
    recLoN2B.in <== recipientLo;

    // Fee is a u64 on-chain. Constrain it to 64 bits and enforce fee <= amount.
    // `amountVal` is already bound to 8 bytes (u64) later in the circuit.
    component feeN2B = Num2Bits(64);
    feeN2B.in <== relayerFee;

    // 1. Two-layer commitment
    // Layer 1: noteHash = keccak256(nullifier || secret)
    component noteHasher = NoteHasher();
    for(var i=0; i<32; i++) { noteHasher.nullifier[i] <== nullifier[i]; noteHasher.secret[i] <== secret[i]; }

    // Layer 2: commitment = keccak256(noteHash || amount || assetId)
    component cHasher = CommitmentHasherV2Bits();
    for(var i=0; i<32; i++) cHasher.noteHash[i] <== noteHasher.hash[i];
    for(var i=0; i<8; i++) cHasher.amount[i] <== amount[i];
    for(var i=0; i<4; i++) cHasher.assetId[i] <== assetIdBytes[i];

    // 2. Merkle Tree
    component hashers[levels];
    // Keep the running hash in *bits* to avoid re-decomposing it at each level.
    signal currentHashBits[levels + 1][256];
    for (var i = 0; i < 256; i++) currentHashBits[0][i] <== cHasher.hashBits[i];

    // Predeclare per-level path decompositions (Circom forbids declaring components inside loops).
    component pBits[levels][32];
    signal pathBits[levels][256];

    // Bind leafIndex to pathIndices (explicitly).
    // - leafIndex is u32 on-chain
    // - pathIndices are the low `levels` bits (little-endian)
    component leafN2B = Num2Bits(32);
    leafN2B.in <== leafIndex;
    for (var i = 0; i < levels; i++) {
        pathIndices[i] === leafN2B.out[i];
    }
    // Ensure no bits above the Merkle depth are set.
    for (var i = levels; i < 32; i++) {
        leafN2B.out[i] === 0;
    }

    for (var i = 0; i < levels; i++) {
        hashers[i] = HashLeftRightBits();

        // Convert path element bytes -> bits once per level (unavoidable).
        for (var b = 0; b < 32; b++) {
            pBits[i][b] = Byte2Bits();
            pBits[i][b].in <== pathElements[i][b];
            for (var k = 0; k < 8; k++) pathBits[i][b*8 + k] <== pBits[i][b].out[k];
        }

        // Conditional swap at the *bit* level.
        for (var j = 0; j < 256; j++) {
            var pBit = pathBits[i][j];
            var cBit = currentHashBits[i][j];
            hashers[i].left[j] <== cBit + pathIndices[i] * (pBit - cBit);
            hashers[i].right[j] <== pBit - pathIndices[i] * (pBit - cBit);
        }

        for (var j = 0; j < 256; j++) currentHashBits[i + 1][j] <== hashers[i].hash[j];
    }

    // 3. Check Root
    // Convert final hash bits -> bytes for the existing split check.
    signal rootBytes[32];
    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== currentHashBits[levels][i*8 + b];
        rootBytes[i] <== outBytes[i].out;
    }
    component rCheck = VerifySplit();
    rCheck.hi <== rootHi;
    rCheck.lo <== rootLo;
    for(var i=0; i<32; i++) rCheck.bytes[i] <== rootBytes[i];
    
    // 5) Verify amount bytes match the public amount value
    var amountCheck = 0;
    for (var i = 0; i < 8; i++) {
        amountCheck += amount[i] * (256 ** i);
    }
    amountVal === amountCheck;

    // Fee must be <= amount (no underflow in u64 space).
    // We force (amountVal - relayerFee) to fit in 64 bits; if relayerFee > amountVal this becomes a huge field element.
    signal feeDiff <== amountVal - relayerFee;
    component feeDiffN2B = Num2Bits(64);
    feeDiffN2B.in <== feeDiff;

    // 6. Verify assetIdBytes match public assetId
    var assetCheck = 0;
    for (var i = 0; i < 4; i++) {
        assetCheck += assetIdBytes[i] * (256 ** i);
    }
    assetId === assetCheck;
}

component main {public [rootHi, rootLo, recipientHi, recipientLo, relayerFee, amountVal, assetId, leafIndex]} = Withdraw(24);
