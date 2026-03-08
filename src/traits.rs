//! Unified trait interfaces for all signing algorithms.
//!
//! Every chain module implements these traits, providing a consistent API
//! regardless of the underlying cryptographic algorithm.

use zeroize::Zeroizing;

/// A type that can produce cryptographic signatures.
pub trait Signer {
    /// The signature type produced by this signer.
    type Signature;
    /// The error type returned on failure.
    type Error;

    /// Sign a raw message. The implementation applies chain-specific hashing internally
    /// (e.g., Keccak-256 for Ethereum, double-SHA-256 for Bitcoin).
    fn sign(&self, message: &[u8]) -> Result<Self::Signature, Self::Error>;

    /// Sign a pre-hashed digest directly. The caller is responsible for applying
    /// the correct hash function. Returns `InvalidHashLength` if the digest
    /// length doesn't match the expected hash output size.
    fn sign_prehashed(&self, digest: &[u8]) -> Result<Self::Signature, Self::Error>;

    /// Return the public key as bytes (compressed format where applicable).
    /// - ECDSA (secp256k1, P-256): 33 bytes (SEC1 compressed)
    /// - Ed25519: 32 bytes
    /// - BIP-340 Schnorr: 32 bytes (x-only)
    /// - BLS12-381: 48 bytes (compressed G1)
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Return the public key in uncompressed format.
    /// - ECDSA (secp256k1, P-256): 65 bytes (`04 || x || y`)
    /// - Ed25519 / Schnorr / BLS: same as `public_key_bytes()` (no uncompressed form)
    fn public_key_bytes_uncompressed(&self) -> Vec<u8>;
}

/// A type that can verify cryptographic signatures.
pub trait Verifier {
    /// The signature type this verifier accepts.
    type Signature;
    /// The error type returned on failure.
    type Error;

    /// Verify a signature against a raw message. The implementation applies
    /// chain-specific hashing internally.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<bool, Self::Error>;

    /// Verify a signature against a pre-hashed digest.
    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Self::Error>;
}

/// A type that represents a cryptographic key pair capable of signing.
pub trait KeyPair: Signer {
    /// Generate a new random key pair using OS entropy (CSPRNG).
    fn generate() -> Result<Self, <Self as Signer>::Error>
    where
        Self: Sized;

    /// Reconstruct a key pair from raw private key bytes (32 bytes).
    fn from_bytes(private_key: &[u8]) -> Result<Self, <Self as Signer>::Error>
    where
        Self: Sized;

    /// Export the private key as auto-zeroizing bytes.
    /// The returned `Zeroizing<Vec<u8>>` will scrub the memory on drop.
    fn private_key_bytes(&self) -> Zeroizing<Vec<u8>>;

    /// Reconstruct a key pair from a 64-byte expanded keypair (seed ∥ pubkey).
    /// Default impl uses only the first 32 bytes (seed).
    fn from_keypair_bytes(keypair: &[u8]) -> Result<Self, <Self as Signer>::Error>
    where
        Self: Sized,
    {
        if keypair.len() < 32 {
            return Self::from_bytes(keypair); // will error with proper message
        }
        Self::from_bytes(&keypair[..32])
    }

    /// Export the full keypair as `private_key ∥ public_key`.
    /// Default: 32B seed + compressed pubkey.
    fn keypair_bytes(&self) -> Zeroizing<Vec<u8>> {
        let priv_key = self.private_key_bytes();
        let pub_key = self.public_key_bytes();
        let mut kp = Vec::with_capacity(priv_key.len() + pub_key.len());
        kp.extend_from_slice(&priv_key);
        kp.extend_from_slice(&pub_key);
        Zeroizing::new(kp)
    }
}
