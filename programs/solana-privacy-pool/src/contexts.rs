//! Account validation structs for every program instruction.
//!
//! Organised by domain:
//!   1. Admin / governance
//!   2. Pool creation & configuration
//!   3. Deposits (asset + liquidity)
//!   4. Withdrawals (asset + liquidity)
//!   5. Swaps (RFQ / TEE + ZK / permissionless)
//!   6. Clear swaps (Jupiter RFQ / non-private settlement)

use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{Mint, Token, TokenAccount},
};
use pyth_solana_receiver_sdk::price_update::PriceUpdateV2;

use crate::constants::*;
use crate::errors::PrivacyError;
use crate::state::*;
use crate::types::*;
use crate::utils::*;

// ---------------------------------------------------------------------------
// External program IDs (SPL Compression + Noop)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SplCompression;
impl anchor_lang::Id for SplCompression {
    fn id() -> Pubkey {
        solana_program::pubkey!("cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK")
    }
}

#[derive(Clone)]
pub struct Noop;
impl anchor_lang::Id for Noop {
    fn id() -> Pubkey {
        solana_program::pubkey!("noopb9bkMVfRPU8AsbpTUg8AQkHtKwMYZiFUjNRtMmV")
    }
}

// ===========================================================================
//  1. ADMIN / GOVERNANCE
// ===========================================================================

/// Create the single-instance AMM config account.
#[derive(Accounts)]
#[instruction(tee_authority: Pubkey)]
pub struct CreateAmm<'info> {
    #[account(
        init,
        payer = payer,
        space = Amm::LEN,
        seeds = [b"amm"],
        bump,
    )]
    pub amm: Account<'info, Amm>,

    /// CHECK: SPL Account Compression Merkle tree – owner enforced.
    #[account(owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner)]
    pub merkle_tree: UncheckedAccount<'info>,

    /// CHECK: This program's executable account.
    #[account(address = crate::ID)]
    pub program: UncheckedAccount<'info>,

    /// CHECK: BPF Upgradeable Loader ProgramData for `program`.
    pub program_data: UncheckedAccount<'info>,

    /// Must match the upgrade authority stored in `program_data`.
    pub upgrade_authority: Signer<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Toggle the global emergency pause flag.
#[derive(Accounts)]
pub struct SetPaused<'info> {
    #[account(mut, seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,
    pub admin: Signer<'info>,
}

/// Rotate protocol admin key.
#[derive(Accounts)]
pub struct RotateAdmin<'info> {
    #[account(mut, seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(mut, seeds = [b"registry"], bump)]
    pub registry: Box<Account<'info, Registry>>,

    pub admin: Signer<'info>,
}

/// Rotate the TEE authority with full borrow cleanup for one pool.
///
/// Recalls all borrowed tokens to the vault via the AMM PDA delegate (no old
/// TEE signature needed — handles compromised key rotation). Zeros the
/// borrow ledger, updates `amm.tee_authority`, and grants `u64::MAX`
/// delegate on the new TEE's ATAs.
///
/// Signers: admin + new TEE.
#[derive(Accounts)]
pub struct RotateTeeWithBorrowCleanup<'info> {
    #[account(mut, seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    pub admin: Signer<'info>,

    /// Incoming TEE authority — must sign to authorize delegate on its ATAs.
    pub new_tee_authority: Signer<'info>,

    #[account(
        mut,
        constraint = pool.amm == amm.key() @ PrivacyError::InvalidPoolAmm,
    )]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        mut,
        seeds = [b"borrow", pool.key().as_ref()],
        bump = borrow_ledger.bump,
        constraint = borrow_ledger.pool == pool.key() @ PrivacyError::InvalidBorrowLedger,
    )]
    pub borrow_ledger: Box<Account<'info, BorrowLedger>>,

    #[account(
        mut,
        constraint = vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub vault_a: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub vault_b: Box<Account<'info, TokenAccount>>,

    /// Old TEE's ATA for mint_a — source for recall (AMM PDA is delegate).
    #[account(
        mut,
        associated_token::authority = amm.tee_authority,
        associated_token::mint = mint_a,
    )]
    pub old_tee_ata_a: Box<Account<'info, TokenAccount>>,

    /// Old TEE's ATA for mint_b.
    #[account(
        mut,
        associated_token::authority = amm.tee_authority,
        associated_token::mint = mint_b,
    )]
    pub old_tee_ata_b: Box<Account<'info, TokenAccount>>,

    /// New TEE's ATA for mint_a — delegate will be granted here.
    #[account(
        mut,
        associated_token::authority = new_tee_authority,
        associated_token::mint = mint_a,
    )]
    pub new_tee_ata_a: Box<Account<'info, TokenAccount>>,

    /// New TEE's ATA for mint_b.
    #[account(
        mut,
        associated_token::authority = new_tee_authority,
        associated_token::mint = mint_b,
    )]
    pub new_tee_ata_b: Box<Account<'info, TokenAccount>>,

    #[account(address = pool.mint_a)]
    pub mint_a: Box<Account<'info, Mint>>,

    #[account(address = pool.mint_b)]
    pub mint_b: Box<Account<'info, Mint>>,

    pub token_program: Program<'info, Token>,
}

/// Initialize the global Registry PDA.
#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        init,
        payer = admin,
        space = Registry::INIT_LEN,
        seeds = [b"registry"],
        bump,
    )]
    pub registry: Box<Account<'info, Registry>>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Initialize the v2 Poseidon commitment tree (zero_copy). Admin-gated; the AMM
/// PDA is recorded as the tree authority. Call once. Additive — runs alongside
/// the legacy keccak SPL tree until the spend paths are migrated.
#[derive(Accounts)]
pub struct InitPoseidonTree<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        init,
        payer = admin,
        space = MerkleTreeAccount::LEN,
        seeds = [POSEIDON_TREE_SEED, amm.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Admin: zero one leaf of the legacy keccak SPL tree (one step of the vacuum
/// that must precede `close_empty_tree`). Reuses the SPL `replace_leaf` CPI
/// (which writes a zero leaf), signed by the AMM PDA (the tree authority).
/// Merkle proof nodes are passed via `remaining_accounts`.
#[derive(Accounts)]
pub struct AdminVacuumKeccakLeaf<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    /// CHECK: legacy SPL keccak tree (validated by owner + address).
    #[account(
        mut,
        address = amm.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner,
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    pub admin: Signer<'info>,
    pub compression_program: Program<'info, SplCompression>,
    pub noop: Program<'info, Noop>,
}

/// Admin: close the (already-zeroed) legacy keccak SPL tree and send its rent
/// lamports to `rent_recipient`. Signed by the AMM PDA (the tree authority).
#[derive(Accounts)]
pub struct AdminCloseKeccakTree<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    /// CHECK: legacy SPL keccak tree (validated by owner + address).
    #[account(
        mut,
        address = amm.merkle_tree,
        owner = SplCompression::id() @ PrivacyError::InvalidTreeOwner,
    )]
    pub merkle_tree: UncheckedAccount<'info>,

    /// CHECK: destination for the reclaimed rent lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,

    pub admin: Signer<'info>,
    pub compression_program: Program<'info, SplCompression>,
}

// ===========================================================================
//  2. POOL CREATION & CONFIGURATION
// ===========================================================================

/// Create a trading pair pool (e.g. SOL / USDC).
#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        init,
        payer = admin,
        space = Pool::LEN,
        seeds = [amm.key().as_ref(), mint_a.key().as_ref(), mint_b.key().as_ref()],
        bump,
        constraint = mint_a.key() != mint_b.key() @ PrivacyError::IdenticalMintsNotAllowed,
        constraint = mint_a.key().to_bytes() < mint_b.key().to_bytes() @ PrivacyError::NonCanonicalMintOrder,
    )]
    pub pool: Box<Account<'info, Pool>>,

    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    /// Shared AMM vault for mint_a (created once per mint).
    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = mint_a,
        associated_token::authority = amm,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,

    /// Shared AMM vault for mint_b.
    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = mint_b,
        associated_token::authority = amm,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"registry"],
        bump,
        constraint = registry.is_initialized @ PrivacyError::RegistryNotInitialized,
    )]
    pub registry: Box<Account<'info, Registry>>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Configure pool oracle feeds, fee, and PMM policy. Admin-only.
#[derive(Accounts)]
pub struct ConfigurePool<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        mut,
        constraint = pool.amm == amm.key() @ PrivacyError::InvalidPoolAmm,
        constraint = pool.mint_a == mint_a.key() @ PrivacyError::InvalidPoolMints,
        constraint = pool.mint_b == mint_b.key() @ PrivacyError::InvalidPoolMints,
    )]
    pub pool: Box<Account<'info, Pool>>,

    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    pub admin: Signer<'info>,
}

// ===========================================================================
//  3. DEPOSITS
// ===========================================================================

/// Shield a single asset into the tree (pre-swap deposit).
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut, seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        mut,
        seeds = [b"registry"],
        bump,
        constraint = registry_mint_is_registered(&registry, mint.key()) @ PrivacyError::AssetNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = amm,
    )]
    pub amm_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = user_source.mint == mint.key(),
        constraint = user_source.owner == payer.key() @ PrivacyError::InvalidUserTokenOwner,
    )]
    pub user_source: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [POSEIDON_TREE_SEED, amm.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Deposit liquidity into a pool and mint a private LP note.
#[derive(Accounts)]
pub struct DepositLiquidity<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut, seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        mut,
        seeds = [amm.key().as_ref(), mint_a.key().as_ref(), mint_b.key().as_ref()],
        bump,
        constraint = pool.mint_a == mint_a.key() @ PrivacyError::InvalidPoolMints,
        constraint = pool.mint_b == mint_b.key() @ PrivacyError::InvalidPoolMints,
        constraint = mint_a.key().to_bytes() < mint_b.key().to_bytes() @ PrivacyError::NonCanonicalMintOrder,
    )]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        seeds = [b"borrow", pool.key().as_ref()],
        bump = borrow_ledger.bump,
        constraint = borrow_ledger.pool == pool.key() @ PrivacyError::InvalidBorrowLedger,
    )]
    pub borrow_ledger: Box<Account<'info, BorrowLedger>>,

    #[account(
        mut,
        seeds = [b"registry"],
        bump,
        constraint = registry_pool_is_registered(&registry, pool.key()) @ PrivacyError::PoolNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    #[account(
        mut,
        associated_token::mint = mint_a,
        associated_token::authority = amm,
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        associated_token::mint = mint_b,
        associated_token::authority = amm,
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = user_account_a.owner == payer.key() @ PrivacyError::InvalidUserTokenOwner,
        constraint = user_account_a.mint == mint_a.key() @ PrivacyError::InvalidUserTokenMint,
    )]
    pub user_account_a: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        constraint = user_account_b.owner == payer.key() @ PrivacyError::InvalidUserTokenOwner,
        constraint = user_account_b.mint == mint_b.key() @ PrivacyError::InvalidUserTokenMint,
    )]
    pub user_account_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [POSEIDON_TREE_SEED, amm.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

// ===========================================================================
//  4. WITHDRAWALS
// ===========================================================================

/// Withdraw (unshield) a single asset – private note -> public token.
#[derive(Accounts)]
#[instruction(proof: Groth16Proof, root: [u8; 32], leaf_index: u32, amount: u64, relayer_fee: u64)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut, constraint = recipient.mint == mint_output.key())]
    pub recipient: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = relayer_fee_account.mint == mint_output.key() @ PrivacyError::InvalidRelayerFeeMint,
        constraint = relayer_fee_account.owner == payer.key() @ PrivacyError::InvalidRelayerFeeOwner,
    )]
    pub relayer_fee_account: Box<Account<'info, TokenAccount>>,

    #[account(seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    pub mint_output: Box<Account<'info, Mint>>,

    #[account(
        seeds = [b"registry"],
        bump,
        constraint = registry_mint_is_registered(&registry, mint_output.key()) @ PrivacyError::AssetNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    #[account(
        mut,
        associated_token::mint = mint_output,
        associated_token::authority = amm,
    )]
    pub amm_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            amm.key().as_ref(),
            &(leaf_index / SPENT_BITMAP_SHARD_BITS).to_le_bytes(),
        ],
        bump,
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    #[account(
        seeds = [POSEIDON_TREE_SEED, amm.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Withdraw liquidity – private LP note -> public tokens for both mints.
#[derive(Accounts)]
#[instruction(proof: Groth16Proof, root: [u8; 32], leaf_index: u32, shares: u64, relayer_fee: u64)]
pub struct WithdrawLiquidity<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(
        mut,
        seeds = [amm.key().as_ref(), mint_a.key().as_ref(), mint_b.key().as_ref()],
        bump = pool.bump,
        constraint = pool.mint_a == mint_a.key() @ PrivacyError::InvalidPoolMints,
        constraint = pool.mint_b == mint_b.key() @ PrivacyError::InvalidPoolMints,
        constraint = mint_a.key().to_bytes() < mint_b.key().to_bytes() @ PrivacyError::NonCanonicalMintOrder,
    )]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        seeds = [b"registry"],
        bump,
        constraint = registry_pool_is_registered(&registry, pool.key()) @ PrivacyError::PoolNotRegistered,
    )]
    pub registry: Box<Account<'info, Registry>>,

    pub mint_a: Box<Account<'info, Mint>>,
    pub mint_b: Box<Account<'info, Mint>>,

    #[account(
        mut,
        associated_token::mint = mint_a,
        associated_token::authority = amm,
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        mut,
        associated_token::mint = mint_b,
        associated_token::authority = amm,
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub recipient_account_a: Box<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub recipient_account_b: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            amm.key().as_ref(),
            &(leaf_index / SPENT_BITMAP_SHARD_BITS).to_le_bytes(),
        ],
        bump,
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    #[account(
        seeds = [POSEIDON_TREE_SEED, amm.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    // -- Borrow-aware accounts --

    /// Borrow ledger for the pool. Required to prevent caller-side omission
    /// from underpaying LP withdrawals when borrows are active.
    #[account(
        mut,
        seeds = [b"borrow", pool.key().as_ref()],
        bump = borrow_ledger.bump,
        constraint = borrow_ledger.pool == pool.key() @ PrivacyError::InvalidBorrowLedger,
    )]
    pub borrow_ledger: Box<Account<'info, BorrowLedger>>,

    /// TEE ATA for mint_a — required when borrow_ledger has active borrows.
    #[account(
        mut,
        associated_token::authority = amm.tee_authority,
        associated_token::mint = mint_a,
    )]
    pub tee_ata_a: Option<Box<Account<'info, TokenAccount>>>,

    /// TEE ATA for mint_b — required when borrow_ledger has active borrows.
    #[account(
        mut,
        associated_token::authority = amm.tee_authority,
        associated_token::mint = mint_b,
    )]
    pub tee_ata_b: Option<Box<Account<'info, TokenAccount>>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

// ===========================================================================
//  5. SWAPS
// ===========================================================================

/// RFQ swap (legacy TEE path) – tombstone input leaf, append output leaf.
#[derive(Accounts)]
#[instruction(swap: RfqSwapUpdate)]
pub struct ExecuteRfqSwapAppend<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(mut, seeds = [b"amm"], bump)]
    pub config: Box<Account<'info, Amm>>,

    /// TEE enclave authority – must match the configured key and sign.
    #[account(address = config.tee_authority @ PrivacyError::UnauthorizedTEE)]
    pub tee_authority: Signer<'info>,

    #[account(
        mut,
        seeds = [POSEIDON_TREE_SEED, config.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(mut, constraint = pool.amm == config.key() @ PrivacyError::InvalidPoolAmm)]
    pub pool: Account<'info, Pool>,

    #[account(
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
        constraint = amm_vault_a.mint == pool.mint_a @ PrivacyError::InvalidRecipientMint,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
        constraint = amm_vault_b.mint == pool.mint_b @ PrivacyError::InvalidRecipientMint,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            config.key().as_ref(),
            &(swap.index / SPENT_BITMAP_SHARD_BITS).to_le_bytes(),
        ],
        bump,
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Permissionless ZK swap (Path C) – on-chain PMM pricing via Pyth oracles.
#[derive(Accounts)]
#[instruction(proof: Groth16Proof, params: ZkSwapParams, amount_in: u64, asset_id_in: u32, asset_id_out: u32, min_amount_out: u64)]
pub struct ExecuteZkSwap<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Global AMM config – writable (total_deposits counter).
    #[account(mut, seeds = [b"amm"], bump)]
    pub config: Box<Account<'info, Amm>>,

    /// Pool whose virtual reserves are updated.
    #[account(mut, constraint = pool.amm == config.key() @ PrivacyError::InvalidPoolAmm)]
    pub pool: Box<Account<'info, Pool>>,

    /// Registry for asset_id validation.
    #[account(seeds = [b"registry"], bump)]
    pub registry: Box<Account<'info, Registry>>,

    #[account(
        mut,
        seeds = [POSEIDON_TREE_SEED, config.key().as_ref()],
        bump,
    )]
    pub merkle_tree: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        constraint = amm_vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
        constraint = amm_vault_a.mint == pool.mint_a @ PrivacyError::InvalidRecipientMint,
    )]
    pub amm_vault_a: Box<Account<'info, TokenAccount>>,
    #[account(
        constraint = amm_vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
        constraint = amm_vault_b.mint == pool.mint_b @ PrivacyError::InvalidRecipientMint,
    )]
    pub amm_vault_b: Box<Account<'info, TokenAccount>>,

    /// Pyth PriceUpdateV2 for mint_a – address validated against pool.oracle_a.
    #[account(constraint = oracle_a.key() == pool.oracle_a @ PrivacyError::InvalidOracleAccount)]
    pub oracle_a: Account<'info, PriceUpdateV2>,
    /// Pyth PriceUpdateV2 for mint_b – address validated against pool.oracle_b.
    #[account(constraint = oracle_b.key() == pool.oracle_b @ PrivacyError::InvalidOracleAccount)]
    pub oracle_b: Account<'info, PriceUpdateV2>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SpentBitmapShard::LEN,
        seeds = [
            b"spent",
            config.key().as_ref(),
            &(params.input_leaf_index / SPENT_BITMAP_SHARD_BITS).to_le_bytes(),
        ],
        bump,
    )]
    pub spent_shard: Box<Account<'info, SpentBitmapShard>>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

// ===========================================================================
//  6. BORROW / REPAY (TEE liquidity borrowing)
// ===========================================================================

/// Initialize a per-pool borrow ledger. Admin-only.
#[derive(Accounts)]
pub struct InitBorrowLedger<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(constraint = pool.amm == amm.key() @ PrivacyError::InvalidPoolAmm)]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        init,
        payer = admin,
        space = BorrowLedger::LEN,
        seeds = [b"borrow", pool.key().as_ref()],
        bump,
    )]
    pub borrow_ledger: Account<'info, BorrowLedger>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Borrow tokens from pool vaults to the TEE wallet.
#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(address = amm.tee_authority @ PrivacyError::UnauthorizedTEE)]
    pub tee_authority: Signer<'info>,

    #[account(
        mut,
        constraint = pool.amm == amm.key() @ PrivacyError::InvalidPoolAmm,
    )]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        mut,
        constraint = vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub vault_a: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub vault_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::authority = tee_authority,
        associated_token::mint = mint_a,
    )]
    pub tee_ata_a: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::authority = tee_authority,
        associated_token::mint = mint_b,
    )]
    pub tee_ata_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"borrow", pool.key().as_ref()],
        bump = borrow_ledger.bump,
        constraint = borrow_ledger.pool == pool.key() @ PrivacyError::InvalidBorrowLedger,
    )]
    pub borrow_ledger: Account<'info, BorrowLedger>,

    #[account(address = pool.mint_a)]
    pub mint_a: Box<Account<'info, Mint>>,

    #[account(address = pool.mint_b)]
    pub mint_b: Box<Account<'info, Mint>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

/// Repay borrowed tokens / pay interest from TEE wallet back to pool vaults.
///
/// Also used as the context for `pay_interest`.
#[derive(Accounts)]
pub struct Repay<'info> {
    #[account(seeds = [b"amm"], bump)]
    pub amm: Box<Account<'info, Amm>>,

    #[account(address = amm.tee_authority @ PrivacyError::UnauthorizedTEE)]
    pub tee_authority: Signer<'info>,

    #[account(
        mut,
        constraint = pool.amm == amm.key() @ PrivacyError::InvalidPoolAmm,
    )]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        mut,
        constraint = vault_a.key() == pool.vault_a @ PrivacyError::InvalidPoolVault,
    )]
    pub vault_a: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        constraint = vault_b.key() == pool.vault_b @ PrivacyError::InvalidPoolVault,
    )]
    pub vault_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::authority = tee_authority,
        associated_token::mint = mint_a,
    )]
    pub tee_ata_a: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::authority = tee_authority,
        associated_token::mint = mint_b,
    )]
    pub tee_ata_b: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [b"borrow", pool.key().as_ref()],
        bump = borrow_ledger.bump,
        constraint = borrow_ledger.pool == pool.key() @ PrivacyError::InvalidBorrowLedger,
    )]
    pub borrow_ledger: Account<'info, BorrowLedger>,

    #[account(address = pool.mint_a)]
    pub mint_a: Box<Account<'info, Mint>>,

    #[account(address = pool.mint_b)]
    pub mint_b: Box<Account<'info, Mint>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

/// Update the max borrow cap on a borrow ledger. Admin-only.
#[derive(Accounts)]
pub struct SetMaxBorrowBps<'info> {
    #[account(seeds = [b"amm"], bump, has_one = admin @ PrivacyError::UnauthorizedAdmin)]
    pub amm: Box<Account<'info, Amm>>,

    pub admin: Signer<'info>,

    #[account(constraint = pool.amm == amm.key() @ PrivacyError::InvalidPoolAmm)]
    pub pool: Box<Account<'info, Pool>>,

    #[account(
        mut,
        seeds = [b"borrow", pool.key().as_ref()],
        bump = borrow_ledger.bump,
        constraint = borrow_ledger.pool == pool.key() @ PrivacyError::InvalidBorrowLedger,
    )]
    pub borrow_ledger: Account<'info, BorrowLedger>,
}

