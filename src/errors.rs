use thiserror::Error;

/// Error types for the FROST threshold signature scheme.
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum FrostError {
    /// Invalid participant count
    #[error("Invalid participant count: expected at least 2 participants")]
    InvalidParticipantCount,

    /// Invalid threshold value
    #[error("Invalid threshold: must be at least 1 and at most n-1")]
    InvalidThreshold,

    /// DKG round 1 commitments are invalid
    #[error("Invalid DKG round 1 commitments")]
    InvalidDkgRound1Commitments,

    /// DKG round 2 shares are invalid
    #[error("Invalid DKG round 2 shares")]
    InvalidDkgRound2Shares,

    /// Invalid nonce commitments
    #[error("Invalid nonce commitments")]
    InvalidNonceCommitments,

    /// Invalid signature share
    #[error("Invalid signature share")]
    InvalidSignatureShare,

    /// Not enough signature shares to reach threshold
    #[error("Not enough signature shares: expected at least {expected} shares, got {got}")]
    NotEnoughShares { expected: usize, got: usize },

    /// Participant not found in signing session
    #[error("Participant {0} not found in signing session")]
    ParticipantNotFound(u64),

    /// Duplicate participant in signing session
    #[error("Duplicate participant {0} in signing session")]
    DuplicateParticipant(u64),

    /// Invalid message format
    #[error("Invalid message format")]
    InvalidMessage,

    /// Invalid public key
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid Taproot key tweak
    #[error("Invalid Taproot key tweak")]
    InvalidTaprootTweak,

    /// Secp256k1 related errors
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    /// Random number generation error
    #[error("Random number generation error")]
    RngError,

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Other errors
    #[error("Other error: {0}")]
    Other(String),
}

/// Result type for the FROST threshold signature scheme.
pub type Result<T> = std::result::Result<T, FrostError>;
