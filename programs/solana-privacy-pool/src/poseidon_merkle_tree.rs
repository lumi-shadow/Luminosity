//! In-program Poseidon append-only Merkle tree with a bounded root-history
//! window — the v2 commitment tree that will replace the keccak-based
//! `spl_concurrent_merkle_tree` CPI path.
//!
//! The filled-subtrees append core is adapted from Light Protocol's
//! `light-sparse-merkle-tree` crate (Apache-2.0):
//!   https://github.com/Lightprotocol/light-protocol/blob/b2a236409bb7797615d217fbf4fff498c852d25e/sparse-merkle-tree/src/merkle_tree.rs
//!
//! Differences from upstream: upstream is a generic in-memory
//! `SparseMerkleTree<H, HEIGHT>`; here the state is held in an Anchor
//! `zero_copy` account ([`crate::state::MerkleTreeAccount`]) so it persists
//! on-chain, and we add a fixed-size root-history ring buffer (the standard
//! Tornado `MerkleTreeWithHistory` pattern) so a proof built against a
//! recently-superseded root still verifies. Hashing is generic over
//! `light_hasher::Hasher` (instantiated with `Poseidon` at the call site).
//!
//! Additive: no instruction wires this yet; the live keccak tree is untouched.

use anchor_lang::prelude::*;
use light_hasher::Hasher;

use crate::errors::PrivacyError;
use crate::state::MerkleTreeAccount;

pub struct MerkleTree;

impl MerkleTree {
    /// Seed an empty tree. Every filled-subtree slot starts at the hasher's
    /// precomputed zero-subtree value for that level, and the root is the zero
    /// value at the top of the tree (height `H`). The first history slot is set
    /// to that empty root so `is_known_root` accepts proofs against the fresh
    /// tree.
    pub fn initialize<H: Hasher>(tree: &mut MerkleTreeAccount) -> Result<()> {
        let height = tree.height as usize;
        let zeros = H::zero_bytes();

        for (subtree, zero) in tree.subtrees.iter_mut().zip(zeros.iter()).take(height) {
            *subtree = *zero;
        }

        let empty_root = zeros[height];
        tree.root = empty_root;
        tree.root_history[0] = empty_root;
        Ok(())
    }

    /// Insert `leaf` at the next free index and recompute the root in O(height).
    ///
    /// Walking from the leaf upward: at each level the running hash is the left
    /// child on an even index (its right sibling is an empty subtree, and the
    /// running hash becomes that level's cached subtree) or the right child on
    /// an odd index (its left sibling is the cached subtree). The sibling at
    /// each level is recorded as the authentication path. The new root is
    /// pushed into the history ring. Returns the authentication path.
    pub fn append<H: Hasher>(
        leaf: [u8; 32],
        tree: &mut MerkleTreeAccount,
    ) -> Result<Vec<[u8; 32]>> {
        let height = tree.height as usize;
        let root_history_size = tree.root_history_size as usize;

        // Tree holds at most 2^height leaves; refuse once exhausted.
        require!(
            tree.next_index < (1u64 << height),
            PrivacyError::MerkleTreeFull
        );

        let mut current_index = tree.next_index as usize;
        let mut running = leaf;
        let mut proof: Vec<[u8; 32]> = vec![[0u8; 32]; height];

        let zeros = H::zero_bytes();
        for (level, (subtree, zero)) in tree
            .subtrees
            .iter_mut()
            .zip(zeros.iter())
            .take(height)
            .enumerate()
        {
            let (left, right) = if current_index % 2 == 0 {
                // Even index: running hash is the left child; right is empty,
                // and we cache the running hash as this level's subtree.
                *subtree = running;
                proof[level] = *zero;
                (running, *zero)
            } else {
                // Odd index: the cached subtree is our left sibling.
                proof[level] = *subtree;
                (*subtree, running)
            };
            running = H::hashv(&[&left, &right]).map_err(|_| PrivacyError::PoseidonHashFailed)?;
            current_index /= 2;
        }

        tree.root = running;
        tree.next_index = tree
            .next_index
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?;

        // Advance the root-history ring buffer and store the new root.
        let next_slot = (tree.root_index as usize)
            .checked_add(1)
            .ok_or(PrivacyError::MathOverflow)?
            % root_history_size;
        tree.root_index = next_slot as u64;
        tree.root_history[next_slot] = running;

        Ok(proof)
    }

    /// Whether `root` is any of the retained historical roots. Scans the ring
    /// newest-first from the current root. Lets a proof built against a recent
    /// root remain valid for the length of the history window. The all-zero
    /// value is never accepted as a root.
    pub fn is_known_root(tree: &MerkleTreeAccount, root: [u8; 32]) -> bool {
        if root == [0u8; 32] {
            return false;
        }

        let size = tree.root_history_size as usize;
        let start = tree.root_index as usize;
        let mut i = start;
        loop {
            if tree.root_history[i] == root {
                return true;
            }
            i = if i == 0 { size - 1 } else { i - 1 };
            if i == start {
                return false;
            }
        }
    }
}

#[cfg(test)]
mod poseidon_gate_tests {
    use light_hasher::{Hasher, Poseidon};

    /// A field element from a small integer, as a 32-byte big-endian value.
    fn fe(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = n;
        b
    }

    /// GATE: `light-hasher`'s Poseidon MUST be byte-for-byte identical to the
    /// circomlib Poseidon the circuits use, or on-chain roots will never match
    /// prover roots. Reference values produced with `circomlibjs`
    /// `buildPoseidon()`:
    ///   poseidon([1,2]) = 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    ///   poseidon([0,0]) = 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864
    #[test]
    fn light_hasher_poseidon_matches_circomlib() {
        let h12 = Poseidon::hashv(&[&fe(1), &fe(2)]).unwrap();
        let expected_1_2: [u8; 32] = [
            0x11, 0x5c, 0xc0, 0xf5, 0xe7, 0xd6, 0x90, 0x41, 0x3d, 0xf6, 0x4c, 0x6b, 0x96, 0x62,
            0xe9, 0xcf, 0x2a, 0x36, 0x17, 0xf2, 0x74, 0x32, 0x45, 0x51, 0x9e, 0x19, 0x60, 0x7a,
            0x44, 0x17, 0x18, 0x9a,
        ];
        assert_eq!(h12, expected_1_2, "poseidon([1,2]) != circomlib reference");

        let z = Poseidon::hashv(&[&fe(0), &fe(0)]).unwrap();
        let expected_0_0: [u8; 32] = [
            0x20, 0x98, 0xf5, 0xfb, 0x9e, 0x23, 0x9e, 0xab, 0x3c, 0xea, 0xc3, 0xf2, 0x7b, 0x81,
            0xe4, 0x81, 0xdc, 0x31, 0x24, 0xd5, 0x5f, 0xfe, 0xd5, 0x23, 0xa8, 0x39, 0xee, 0x84,
            0x46, 0xb6, 0x48, 0x64,
        ];
        assert_eq!(z, expected_0_0, "poseidon([0,0]) != circomlib reference");
    }
}
