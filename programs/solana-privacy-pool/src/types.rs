use anchor_lang::prelude::*;

/// Groth16 proof container (keeps instruction args + IDL cleaner than 3 separate byte arrays).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Groth16Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

/// RFQ swap parameters provided by the TEE (legacy path).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct RfqSwapUpdate {
    pub root: [u8; 32],
    pub previous_leaf: [u8; 32],
    pub new_leaf: [u8; 32],
    pub index: u32,
    /// New virtual reserves for the pool, in canonical mint order (pool.mint_a, pool.mint_b).
    pub new_reserve_a: u64,
    pub new_reserve_b: u64,
}

/// Parameters for the permissionless ZK swap instruction.
///
/// The prover supplies a Groth16 proof that binds (inputCommitment, amountIn, assetIdIn,
/// noteHashOut, assetIdOut, minAmountOut). The on-chain PMM computes the actual `amount_out`
/// and the program computes the output commitment Layer 2 hash.
///
/// Double-spend prevention: spent-by-index bitmap (leaf_index can only be used once).
/// Merkle membership is NOT verified on-chain (the circuit does not include a Merkle proof
/// and the tombstone CPI was removed to fit within the 1232-byte transaction limit).
/// Future hardening: embed Merkle proof verification inside the ZK circuit.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ZkSwapParams {
    /// Merkle root for the input leaf's replace_leaf CPI.
    pub root: [u8; 32],
    /// The input commitment (public input to Groth16 proof).
    pub input_commitment: [u8; 32],
    /// Leaf index of the input commitment (for spent bitmap).
    pub input_leaf_index: u32,
    /// Layer 1 hash of the output note: keccak256(nullifier_out || secret_out).
    /// This is a public input to the ZK proof (split into hi/lo).
    pub note_hash_out: [u8; 32],
    /// Encrypted output note (for the recipient to decrypt off-chain).
    pub encrypted_note: Vec<u8>,
}
