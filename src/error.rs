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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_invalid_private_key() {
        let e = SignerError::InvalidPrivateKey("too short".into());
        assert_eq!(e.to_string(), "invalid private key: too short");
    }

    #[test]
    fn test_display_invalid_public_key() {
        let e = SignerError::InvalidPublicKey("not on curve".into());
        assert!(e.to_string().contains("not on curve"));
    }

    #[test]
    fn test_display_invalid_signature() {
        let e = SignerError::InvalidSignature("bad DER".into());
        assert!(e.to_string().contains("bad DER"));
    }

    #[test]
    fn test_display_signing_failed() {
        let e = SignerError::SigningFailed("nonce error".into());
        assert!(e.to_string().contains("nonce error"));
    }

    #[test]
    fn test_display_verification_failed() {
        let e = SignerError::VerificationFailed;
        assert_eq!(e.to_string(), "verification failed");
    }

    #[test]
    fn test_display_invalid_hash_length() {
        let e = SignerError::InvalidHashLength { expected: 32, got: 20 };
        let s = e.to_string();
        assert!(s.contains("32"));
        assert!(s.contains("20"));
    }

    #[test]
    fn test_display_entropy_error() {
        assert_eq!(SignerError::EntropyError.to_string(), "entropy error");
    }

    #[test]
    fn test_display_aggregation_error() {
        let e = SignerError::AggregationError("no shares".into());
        assert!(e.to_string().contains("no shares"));
    }

    #[test]
    fn test_display_encoding_error() {
        let e = SignerError::EncodingError("bad bech32".into());
        assert!(e.to_string().contains("bad bech32"));
    }

    #[test]
    fn test_display_parse_error() {
        let e = SignerError::ParseError("invalid descriptor".into());
        assert!(e.to_string().contains("invalid descriptor"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SignerError>();
    }
}
