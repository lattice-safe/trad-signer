//! Unified error types for all signing operations.

/// Errors that can occur during signing, verification, or key management.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The provided private key bytes are invalid (wrong length, out of range, or malformed).
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// The provided public key bytes are invalid or not on the expected curve.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The provided signature bytes are invalid or malformed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// The signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Signature verification did not pass.
    #[error("verification failed")]
    VerificationFailed,

    /// The provided digest/hash has an unexpected length.
    #[error("invalid hash length: expected {expected}, got {got}")]
    InvalidHashLength {
        /// Expected digest length in bytes.
        expected: usize,
        /// Actual digest length provided.
        got: usize,
    },

    /// Failed to generate random bytes from the OS CSPRNG.
    #[error("entropy error")]
    EntropyError,

    /// BLS signature aggregation failed.
    #[error("aggregation error: {0}")]
    AggregationError(String),

    /// Encoding or decoding failed (bech32, base58, compact size, hex).
    #[error("encoding error: {0}")]
    EncodingError(String),

    /// Parsing failed (descriptors, PSBT, script).
    #[error("parse error: {0}")]
    ParseError(String),
}
