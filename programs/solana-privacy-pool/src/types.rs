use anchor_lang::prelude::*;

/// Groth16 proof container (keeps instruction args + IDL cleaner than 3 separate byte arrays).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct Groth16Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

/// RFQ swap parameters provided by the TEE.
///
/// The TEE signs the transaction (`tee_authority`), updates the Merkle tree leaf, and updates the
/// on-chain pool virtual reserves to reflect the swap.
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
