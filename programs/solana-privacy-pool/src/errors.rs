use anchor_lang::prelude::*;

#[error_code]
pub enum PrivacyError {
    // ---- Input / argument validation ----
    #[msg("Invalid denomination")]
    InvalidDenomination,
    #[msg("Deposit amount must be > 0")]
    ZeroDepositAmount,
    #[msg("Invalid commitment (all zeros)")]
    InvalidCommitment,
    #[msg("Encrypted note too long (max 512 bytes)")]
    NoteTooLong,
    #[msg("Invalid asset id")]
    InvalidAssetId,
    #[msg("Invalid pool id")]
    InvalidPoolId,
    #[msg("Invalid admin pubkey")]
    InvalidAdmin,
    #[msg("Invalid TEE authority pubkey")]
    InvalidTEEAuthority,

    // ---- Authorization ----
    #[msg("Unauthorized TEE")]
    UnauthorizedTEE,
    #[msg("Unauthorized admin")]
    UnauthorizedAdmin,
    #[msg("Unauthorized program upgrade authority")]
    UnauthorizedUpgradeAuthority,
    #[msg("Program is paused")]
    Paused,

    // ---- Account validation ----
    #[msg("Invalid pool mints")]
    InvalidPoolMints,
    #[msg("Pool AMM link mismatch")]
    InvalidPoolAmm,
    #[msg("Invalid pool vault for this mint")]
    InvalidPoolVault,
    #[msg("Invalid user token account owner")]
    InvalidUserTokenOwner,
    #[msg("Invalid user token account mint")]
    InvalidUserTokenMint,
    #[msg("Invalid relayer fee token account owner")]
    InvalidRelayerFeeOwner,
    #[msg("Invalid relayer fee token account mint")]
    InvalidRelayerFeeMint,
    #[msg("Recipient token accounts must share the same owner")]
    InvalidRecipientOwner,
    #[msg("Recipient token accounts must match the pool mints")]
    InvalidRecipientMint,
    #[msg("Invalid program data account (upgrade authority check failed)")]
    InvalidProgramData,
    #[msg("Insufficient user token balance")]
    InsufficientUserBalance,
    #[msg("Pool mints must be different (mint_a != mint_b)")]
    IdenticalMintsNotAllowed,
    #[msg("Non-canonical mint order (require mint_a < mint_b)")]
    NonCanonicalMintOrder,

    // ---- Registry ----
    #[msg("Asset not registered")]
    AssetNotRegistered,
    #[msg("Mint is not registered for this asset id (or asset id is wrong)")]
    InvalidAssetForMint,
    #[msg("Pool not registered")]
    PoolNotRegistered,
    #[msg("Invalid pool id for pool")]
    InvalidPoolForId,
    #[msg("Asset registry mismatch")]
    AssetRegistryMismatch,
    #[msg("Pool registry mismatch")]
    PoolRegistryMismatch,
    #[msg("Registry is full")]
    RegistryFull,
    #[msg("Registry is not initialized")]
    RegistryNotInitialized,
    #[msg("Registry realloc too large (must be <= 10 KB per instruction)")]
    RegistryReallocTooLarge,
    #[msg("Registry realloc failed")]
    RegistryReallocFailed,
    #[msg("Registry state is corrupted (vector length mismatch)")]
    RegistryCorruption,

    // ---- Merkle tree ----
    #[msg("Merkle tree deserialization failed")]
    TreeDeserializationFailed,
    #[msg("Provided root is not in the valid changelog history")]
    InvalidMerkleRoot,
    #[msg("Merkle tree account does not match AMM state")]
    WrongTree,
    #[msg("Merkle tree account is not owned by SPL Compression")]
    InvalidTreeOwner,
    #[msg("Leaf index is outside the configured Merkle tree capacity")]
    LeafIndexOutOfRange,
    #[msg("Merkle tree is full (no more leaves can be appended)")]
    TreeFull,
    #[msg("Too many Merkle proof accounts provided")]
    TooManyMerkleProofAccounts,
    #[msg("SPL Compression failed to append leaf")]
    CompressionError,
    #[msg("Invalid Compression Program ID")]
    InvalidCompressionProgram,
    #[msg("Invalid Log Wrapper Program ID")]
    InvalidLogWrapper,

    // ---- Spent bitmap ----
    #[msg("Input note already spent")]
    AlreadySpent,
    #[msg("Spent bitmap shard index is out of range")]
    ShardIndexOutOfRange,

    // ---- ZK proof ----
    #[msg("Groth16 proof verification failed")]
    InvalidProof,
    #[msg("Could not parse verifying key")]
    InvalidVerifyingKey,

    // ---- Liquidity / shares ----
    #[msg("Invalid liquidity deposit (require amount_a > 0 && amount_b > 0)")]
    InvalidLiquidityDeposit,
    #[msg("Invalid liquidity deposit ratio (must match pool reserves)")]
    InvalidLiquidityRatio,
    #[msg("Invalid pool reserves for share minting")]
    InvalidReserves,
    #[msg("Total shares is zero")]
    ZeroTotalShares,
    #[msg("Shares must be > 0")]
    ZeroShares,
    #[msg("Shares exceed total_shares")]
    SharesExceedTotal,
    #[msg("Expected shares does not match on-chain share minting math")]
    SharesMismatch,
    #[msg("Liquidity instructions are disabled until the circuit binds pool identity in the note")]
    LiquidityInstructionsDisabled,
    #[msg("Dual-asset withdrawal not supported by current circuit (amount_b must be 0)")]
    DualAssetWithdrawNotSupported,
    #[msg("Token relayer fee not supported by current instruction (relayer_fee must be 0)")]
    TokenRelayerFeeNotSupported,

    // ---- Swap / PMM ----
    #[msg("Invalid or unconfigured Pyth oracle account")]
    InvalidOracleAccount,
    #[msg("Oracle price account not owned by the Pyth program")]
    InvalidOracleOwner,
    #[msg("Oracle price is stale (exceeded max age)")]
    OracleStale,
    #[msg("Slippage exceeded (amount_out < minAmountOut)")]
    SlippageExceeded,
    #[msg("Swap output is zero")]
    ZeroSwapOutput,
    #[msg("Invalid PMM config (values out of sane range)")]
    InvalidPmmConfig,
    #[msg("Relayer fee exceeds withdrawal amount")]
    FeeExceedsAmount,

    // ---- General ----
    #[msg("Insufficient funds in the pool to pay out")]
    InsufficientPoolBalance,
    #[msg("Math overflow")]
    MathOverflow,
}
