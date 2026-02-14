pragma circom 2.0.0;

// Liquidity withdraw circuit (share-based, pool-bound) — two-layer commitment format.
//
// Leaf/commitment (two-layer):
//   Layer 1:  noteHash   = keccak256(nullifier || secret)
//   Layer 2:  commitment = keccak256(noteHash  || sharesLE8 || poolIdLE4)
//
// Public inputs:
//   - rootHi, rootLo
//   - recipientHi, recipientLo
//   - relayerFee
//   - sharesVal
//   - poolId
//   - leafIndex

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

// Layer 2: commitment = keccak256(noteHash || shares || poolId)
// 44 bytes = 352 bits
// Outputs both hashBits (for Merkle tree traversal) and hash bytes (for compatibility).
template CommitmentHasherV2Bits() {
    signal input noteHash[32];
    signal input shares[8];
    signal input poolId[4];
    signal output hashBits[256];
    signal output hash[32];

    component keccak = Keccak(352, 256);
    var idx = 0;

    component nhBits[32];
    for (var i = 0; i < 32; i++) {
        nhBits[i] = Byte2Bits(); nhBits[i].in <== noteHash[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== nhBits[i].out[b]; idx++; }
    }
    component shBits[8];
    for (var i = 0; i < 8; i++) {
        shBits[i] = Byte2Bits(); shBits[i].in <== shares[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== shBits[i].out[b]; idx++; }
    }
    component idBits[4];
    for (var i = 0; i < 4; i++) {
        idBits[i] = Byte2Bits(); idBits[i].in <== poolId[i];
        for (var b = 0; b < 8; b++) { keccak.in[idx] <== idBits[i].out[b]; idx++; }
    }

    for (var i = 0; i < 256; i++) hashBits[i] <== keccak.out[i];

    component outBytes[32];
    for (var i = 0; i < 32; i++) {
        outBytes[i] = Bits2Byte();
        for (var b = 0; b < 8; b++) outBytes[i].in[b] <== keccak.out[i*8 + b];
        hash[i] <== outBytes[i].out;
    }
}

template WithdrawLiquidity(levels) {
    // PUBLIC INPUTS
    signal input rootHi;
    signal input rootLo;
    signal input recipientHi;
    signal input recipientLo;
    signal input relayerFee;
    signal input sharesVal; // u64 shares (public)
    signal input poolId;    // u32 pool id (public)
    signal input leafIndex; // u32 leaf index (public) for bitmap nullification

    // SECURITY / TRUST MODEL (READ THIS BEFORE REVIEWING):
    //
    // 1) "Can someone change recipient in the on-chain tx after the proof is created?"
    //    - No. `recipientHi/recipientLo` are PUBLIC INPUTS and therefore part of the statement the
    //      proof attests to.
    //    - The on-chain program constructs these public inputs from the instruction's recipient
    //      OWNER pubkey (the owner shared across recipient token accounts A/B) and verifies Groth16
    //      against them.
    //    - If a relayer/attacker changes the recipient owner in the transaction, the on-chain
    //      public inputs change and the proof will fail verification.
    //
    // 2) "So where is the remaining trust assumption?"
    //    - The recipient is NOT included in the LP note commitment preimage
    //      (commitment = keccak(noteHash || shares || poolId)).
    //    - That means whoever can GENERATE a proof (i.e. whoever knows the note secrets) can
    //      choose any recipient owner at proving time.
    //
    // 3) Intended hackathon design:
    //    - The relayer/TEE generates proofs and is assumed honest via remote attestation + fixed
    //      code policy, so it will honor the user's requested recipient when proving.
    //
    // HARDENING TODO (POST-HACKATHON):
    // - Make withdrawals trust-minimized Tornado-style by ensuring the relayer never learns note
    //   secrets (user proves locally; relayer only broadcasts), OR bind recipient into the note
    //   commitment / add an additional recipient-binding tag and regenerate VKs.

    // PRIVATE INPUTS
    signal input nullifier[32];
    signal input secret[32];
    signal input shares[8];
    signal input poolIdBytes[4];
    signal input pathElements[levels][32];
    signal input pathIndices[levels];

    // ---- Safety/range constraints for public inputs ----
    // Recipient owner pubkey halves are 16 bytes each in the on-chain public input encoding.
    component recHiN2B = Num2Bits(128);
    recHiN2B.in <== recipientHi;
    component recLoN2B = Num2Bits(128);
    recLoN2B.in <== recipientLo;

    // On-chain currently requires relayer_fee == 0 for liquidity withdrawals.
    // Keep the circuit consistent with that rule.
    relayerFee === 0;

    // 1) Two-layer commitment
    // Layer 1: noteHash = keccak256(nullifier || secret)
    component noteHasher = NoteHasher();
    for (var i = 0; i < 32; i++) { noteHasher.nullifier[i] <== nullifier[i]; noteHasher.secret[i] <== secret[i]; }

    // Layer 2: commitment = keccak256(noteHash || shares || poolId)
    component cHasher = CommitmentHasherV2Bits();
    for (var i = 0; i < 32; i++) cHasher.noteHash[i] <== noteHasher.hash[i];
    for (var i = 0; i < 8; i++) cHasher.shares[i] <== shares[i];
    for (var i = 0; i < 4; i++) cHasher.poolId[i] <== poolIdBytes[i];

    // 2) Merkle Tree
    component hashers[levels];
    // Keep the running hash in bits to avoid re-decomposing intermediate nodes each level.
    signal currentHashBits[levels + 1][256];
    for (var i = 0; i < 256; i++) currentHashBits[0][i] <== cHasher.hashBits[i];

    // Predeclare per-level path decompositions (Circom forbids declaring components inside loops).
    component pBits[levels][32];
    signal pathBits[levels][256];

    // Bind leafIndex to pathIndices (explicitly).
    component leafN2B = Num2Bits(32);
    leafN2B.in <== leafIndex;
    for (var i = 0; i < levels; i++) {
        pathIndices[i] === leafN2B.out[i];
    }
    for (var i = levels; i < 32; i++) {
        leafN2B.out[i] === 0;
    }

    for (var i = 0; i < levels; i++) {
        hashers[i] = HashLeftRightBits();

        for (var b = 0; b < 32; b++) {
            pBits[i][b] = Byte2Bits();
            pBits[i][b].in <== pathElements[i][b];
            for (var k = 0; k < 8; k++) pathBits[i][b*8 + k] <== pBits[i][b].out[k];
        }

        for (var j = 0; j < 256; j++) {
            var pBit = pathBits[i][j];
            var cBit = currentHashBits[i][j];
            hashers[i].left[j] <== cBit + pathIndices[i] * (pBit - cBit);
            hashers[i].right[j] <== pBit - pathIndices[i] * (pBit - cBit);
        }

        for (var j = 0; j < 256; j++) currentHashBits[i + 1][j] <== hashers[i].hash[j];
    }

    // 3) Root check
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
    for (var i = 0; i < 32; i++) rCheck.bytes[i] <== rootBytes[i];

    // 5) shares bytes match sharesVal (LE8 -> u64)
    var sharesCheck = 0;
    for (var i = 0; i < 8; i++) {
        sharesCheck += shares[i] * (256 ** i);
    }
    sharesVal === sharesCheck;

    // 6) poolIdBytes match poolId (LE4 -> u32)
    var poolCheck = 0;
    for (var i = 0; i < 4; i++) {
        poolCheck += poolIdBytes[i] * (256 ** i);
    }
    poolId === poolCheck;
}

component main {public [rootHi, rootLo, recipientHi, recipientLo, relayerFee, sharesVal, poolId, leafIndex]} = WithdrawLiquidity(24);
