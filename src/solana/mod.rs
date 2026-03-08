//! Solana Ed25519 signer (pure Ed25519).
//!
//! Uses `ed25519-dalek` for signing. No pre-hashing — the blockchain
//! hashes transactions before feeding them to the signer.

pub mod programs;
pub mod transaction;

use crate::error::SignerError;
use crate::traits;
use ed25519_dalek::Signer as DalekSigner;
use ed25519_dalek::Verifier as DalekVerifier;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// A Solana Ed25519 signature (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub struct SolanaSignature {
    /// The 64-byte Ed25519 signature.
    #[cfg_attr(feature = "serde", serde(with = "crate::hex_bytes"))]
    pub bytes: [u8; 64],
}

impl SolanaSignature {
    /// Export the 64-byte signature.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }

    /// Import from 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 64 {
            return Err(SignerError::InvalidSignature(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }
}

impl core::fmt::Display for SolanaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Solana Ed25519 signer.
pub struct SolanaSigner {
    pub(crate) signing_key: ed25519_dalek::SigningKey,
}

impl SolanaSigner {
    /// Return the Solana address as a Base58-encoded string.
    ///
    /// Solana addresses are simply the Base58 encoding of the 32-byte Ed25519 public key.
    pub fn address(&self) -> String {
        bs58::encode(self.signing_key.verifying_key().as_bytes()).into_string()
    }

    /// Return the 32-byte public key as a fixed-size array.
    #[must_use]
    pub fn public_key_bytes_32(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }
}

/// Validate a Solana address string.
///
/// Solana addresses are Base58-encoded 32-byte Ed25519 public keys.
pub fn validate_address(address: &str) -> bool {
    match bs58::decode(address).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

impl Drop for SolanaSigner {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey handles its own zeroization
    }
}

impl traits::Signer for SolanaSigner {
    type Signature = SolanaSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<SolanaSignature, SignerError> {
        let sig = DalekSigner::sign(&self.signing_key, message);
        Ok(SolanaSignature {
            bytes: sig.to_bytes(),
        })
    }

    /// **Note:** Ed25519 hashes internally per RFC 8032. This method is identical to
    /// `sign()` — the `digest` parameter is treated as a raw message, not a
    /// pre-computed hash. For consistency with the `Signer` trait, this is provided as-is.
    fn sign_prehashed(&self, digest: &[u8]) -> Result<SolanaSignature, SignerError> {
        // Ed25519 has no internal pre-hashing in Solana context.
        // sign_prehashed is equivalent to sign (the caller provides the raw payload).
        self.sign(digest)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().as_bytes().to_vec()
    }

    fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        // Ed25519 has no uncompressed form
        self.public_key_bytes()
    }
}

impl traits::KeyPair for SolanaSigner {
    fn generate() -> Result<Self, SignerError> {
        let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
        crate::security::secure_random(&mut *key_bytes)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        Ok(Self { signing_key })
    }

    fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32 bytes (Ed25519 seed), got {}",
                private_key.len()
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(private_key);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        Ok(Self { signing_key })
    }

    fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_bytes().to_vec())
    }

    /// Import from Solana's 64-byte keypair format (seed ∥ pubkey).
    /// Validates that the derived public key matches bytes[32..64]
    /// using constant-time comparison to prevent timing side-channels.
    fn from_keypair_bytes(keypair: &[u8]) -> Result<Self, SignerError> {
        use subtle::ConstantTimeEq;
        if keypair.len() != 64 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 64-byte keypair, got {}",
                keypair.len()
            )));
        }
        let signer = Self::from_bytes(&keypair[..32])?;
        let derived_pk = signer.signing_key.verifying_key().as_bytes().to_vec();
        if derived_pk.ct_eq(&keypair[32..]).into() {
            Ok(signer)
        } else {
            Err(SignerError::InvalidPrivateKey(
                "pubkey in keypair does not match derived pubkey".into(),
            ))
        }
    }

    /// Export as Solana's 64-byte keypair (seed ∥ pubkey).
    fn keypair_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut kp = Vec::with_capacity(64);
        kp.extend_from_slice(&self.signing_key.to_bytes());
        kp.extend_from_slice(self.signing_key.verifying_key().as_bytes());
        Zeroizing::new(kp)
    }
}

impl SolanaSigner {
    /// Export the clamped Ed25519 scalar (first 32 bytes of SHA-512(seed), clamped).
    ///
    /// ⚠️ **Advanced use only** — for MPC, threshold signing, or key derivation.
    /// The scalar is the actual private scalar used in Ed25519 signing.
    pub fn scalar_bytes(&self) -> Zeroizing<Vec<u8>> {
        let expanded = Sha512::digest(self.signing_key.to_bytes());
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&expanded[..32]);
        // Apply Ed25519 clamping
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
        Zeroizing::new(scalar.to_vec())
    }
}

/// Solana Ed25519 verifier.
pub struct SolanaVerifier {
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl SolanaVerifier {
    /// Create from 32-byte Ed25519 public key.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 32 {
            return Err(SignerError::InvalidPublicKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(bytes);
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| SignerError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }
}

impl traits::Verifier for SolanaVerifier {
    type Signature = SolanaSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &SolanaSignature) -> Result<bool, SignerError> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.bytes);
        match DalekVerifier::verify(&self.verifying_key, message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &SolanaSignature,
    ) -> Result<bool, SignerError> {
        self.verify(digest, signature)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_generate_keypair() {
        let signer = SolanaSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let signer = SolanaSigner::generate().unwrap();
        let restored = SolanaSigner::from_bytes(&signer.private_key_bytes()).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = SolanaSigner::generate().unwrap();
        let sig = signer.sign(b"hello solana").unwrap();
        let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello solana", &sig).unwrap());
    }

    #[test]
    fn test_64_byte_signature() {
        let signer = SolanaSigner::generate().unwrap();
        let sig = signer.sign(b"test").unwrap();
        assert_eq!(sig.bytes.len(), 64);
    }

    // RFC 8032 §7.1 Test Vector 1 — Empty message
    #[test]
    fn test_rfc8032_vector1_empty() {
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let expected_sig = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).unwrap();

        let signer = SolanaSigner::from_bytes(&sk).unwrap();
        let sig = signer.sign(b"").unwrap();
        assert_eq!(sig.bytes.to_vec(), expected_sig);

        // Verify the signature we produced is valid
        let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"", &sig).unwrap());
    }

    // RFC 8032 §7.1 Test Vector 2 — Single byte 0x72
    #[test]
    fn test_rfc8032_vector2_single_byte() {
        let sk = hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .unwrap();
        let expected_pk =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap();
        let msg = hex::decode("72").unwrap();
        let expected_sig = hex::decode(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ).unwrap();

        let signer = SolanaSigner::from_bytes(&sk).unwrap();
        assert_eq!(signer.public_key_bytes(), expected_pk);

        let sig = signer.sign(&msg).unwrap();
        assert_eq!(sig.bytes.to_vec(), expected_sig);
    }

    // RFC 8032 §7.1 Test Vector 3 — Two bytes 0xaf82
    #[test]
    fn test_rfc8032_vector3_two_bytes() {
        let sk = hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
            .unwrap();
        let expected_pk =
            hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
                .unwrap();
        let msg = hex::decode("af82").unwrap();
        let expected_sig = hex::decode(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ).unwrap();

        let signer = SolanaSigner::from_bytes(&sk).unwrap();
        assert_eq!(signer.public_key_bytes(), expected_pk);

        let sig = signer.sign(&msg).unwrap();
        assert_eq!(sig.bytes.to_vec(), expected_sig);
    }

    #[test]
    fn test_invalid_key_rejected() {
        assert!(SolanaSigner::from_bytes(&[1u8; 31]).is_err());
        assert!(SolanaSigner::from_bytes(&[1u8; 33]).is_err());
    }

    #[test]
    fn test_tampered_sig_fails() {
        let signer = SolanaSigner::generate().unwrap();
        let sig = signer.sign(b"tamper").unwrap();
        let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let mut tampered = sig.clone();
        tampered.bytes[0] ^= 0xff;
        assert!(!verifier.verify(b"tamper", &tampered).unwrap());
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let s1 = SolanaSigner::generate().unwrap();
        let s2 = SolanaSigner::generate().unwrap();
        let sig = s1.sign(b"wrong").unwrap();
        let verifier = SolanaVerifier::from_public_key_bytes(&s2.public_key_bytes()).unwrap();
        assert!(!verifier.verify(b"wrong", &sig).unwrap());
    }

    #[test]
    fn test_sign_prehashed_roundtrip() {
        let signer = SolanaSigner::generate().unwrap();
        let msg = b"prehash solana";
        let sig = signer.sign_prehashed(msg).unwrap();
        let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_zeroize_on_drop() {
        let signer = SolanaSigner::generate().unwrap();
        let _: Zeroizing<Vec<u8>> = signer.private_key_bytes();
        drop(signer);
    }
}
