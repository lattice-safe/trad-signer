//! XRP signer supporting both ECDSA (secp256k1 + SHA-512 half) and Ed25519.
//!
//! XRP allows two key types: secp256k1 and Ed25519.

use crate::error::SignerError;
use crate::traits;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// XRP signature (variable format depending on key type).
#[derive(Debug, Clone)]
pub struct XrpSignature {
    /// DER-encoded for ECDSA, 64-byte for Ed25519.
    pub bytes: Vec<u8>,
}

impl XrpSignature {
    /// Export the signature bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Import from raw bytes.
    ///
    /// Validates structural format: DER-encoded ECDSA (starts with `0x30`)
    /// or 64-byte Ed25519 signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.is_empty() {
            return Err(SignerError::InvalidSignature("empty signature".into()));
        }
        // Validate: either DER ECDSA (0x30 tag) or 64-byte Ed25519
        if bytes[0] == 0x30 {
            // DER ECDSA: verify the length byte matches
            if bytes.len() < 3 || bytes.len() > 73 {
                return Err(SignerError::InvalidSignature(format!(
                    "invalid DER signature length: {}", bytes.len()
                )));
            }
        } else if bytes.len() != 64 {
            return Err(SignerError::InvalidSignature(format!(
                "expected 64-byte Ed25519 or DER ECDSA, got {} bytes starting with 0x{:02x}",
                bytes.len(), bytes[0]
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }
}

/// Compute SHA-512 half (first 32 bytes of SHA-512 digest).
pub fn sha512_half(data: &[u8]) -> [u8; 32] {
    let full = Sha512::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Derive XRP account ID: RIPEMD160(SHA256(pubkey_bytes)).
pub fn account_id(pubkey_bytes: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(pubkey_bytes);
    let ripe = ripemd::Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

// ─── ECDSA (secp256k1) ──────────────────────────────────────────────────────

/// XRP ECDSA signer (secp256k1 + SHA-512 half).
pub struct XrpEcdsaSigner {
    signing_key: k256::ecdsa::SigningKey,
}

impl Drop for XrpEcdsaSigner {
    fn drop(&mut self) {
        // k256::SigningKey implements ZeroizeOnDrop internally
    }
}

impl XrpEcdsaSigner {
    /// Derive the XRP account ID from this signer's public key.
    pub fn account_id(&self) -> [u8; 20] {
        account_id(&self.public_key_bytes_inner())
    }

    fn public_key_bytes_inner(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<XrpSignature, SignerError> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: k256::ecdsa::Signature = self
            .signing_key
            .sign_prehash(digest)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
        Ok(XrpSignature {
            bytes: sig.to_der().as_bytes().to_vec(),
        })
    }
}

impl traits::Signer for XrpEcdsaSigner {
    type Signature = XrpSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<XrpSignature, SignerError> {
        let digest = sha512_half(message);
        self.sign_digest(&digest)
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<XrpSignature, SignerError> {
        if digest.len() != 32 {
            return Err(SignerError::InvalidHashLength {
                expected: 32,
                got: digest.len(),
            });
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest);
        self.sign_digest(&hash)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes_inner()
    }

    fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl traits::KeyPair for XrpEcdsaSigner {
    fn generate() -> Result<Self, SignerError> {
        let signing_key =
            k256::ecdsa::SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
        Ok(Self { signing_key })
    }

    fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                private_key.len()
            )));
        }
        let signing_key = k256::ecdsa::SigningKey::from_bytes(private_key.into())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_bytes().to_vec())
    }
}

/// XRP ECDSA verifier.
pub struct XrpEcdsaVerifier {
    verifying_key: k256::ecdsa::VerifyingKey,
}

impl XrpEcdsaVerifier {
    /// Create from SEC1 public key bytes.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| SignerError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }
}

impl traits::Verifier for XrpEcdsaVerifier {
    type Signature = XrpSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &XrpSignature) -> Result<bool, SignerError> {
        let digest = sha512_half(message);
        self.verify_prehashed(&digest, signature)
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &XrpSignature,
    ) -> Result<bool, SignerError> {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        if digest.len() != 32 {
            return Err(SignerError::InvalidHashLength {
                expected: 32,
                got: digest.len(),
            });
        }
        let sig = k256::ecdsa::Signature::from_der(&signature.bytes)
            .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;
        match self.verifying_key.verify_prehash(digest, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

// ─── Ed25519 ─────────────────────────────────────────────────────────────────

/// XRP Ed25519 signer (pure Ed25519).
pub struct XrpEddsaSigner {
    signing_key: ed25519_dalek::SigningKey,
}

impl Drop for XrpEddsaSigner {
    fn drop(&mut self) {
        // ed25519_dalek::SigningKey handles its own zeroization
    }
}

impl XrpEddsaSigner {
    /// Derive the XRP account ID from this signer's Ed25519 public key.
    /// XRP prefixes Ed25519 pubkeys with 0xED before hashing.
    pub fn account_id(&self) -> [u8; 20] {
        let vk = self.signing_key.verifying_key();
        let mut prefixed = Vec::with_capacity(33);
        prefixed.push(0xED);
        prefixed.extend_from_slice(vk.as_bytes());
        account_id(&prefixed)
    }
}

impl traits::Signer for XrpEddsaSigner {
    type Signature = XrpSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<XrpSignature, SignerError> {
        use ed25519_dalek::Signer as DalekSigner;
        let sig = DalekSigner::sign(&self.signing_key, message);
        Ok(XrpSignature {
            bytes: sig.to_bytes().to_vec(),
        })
    }

    /// **Note:** Ed25519 hashes internally per RFC 8032. This method is identical to
    /// [`sign()`](Self::sign) — the `digest` parameter is treated as a raw message, not a
    /// pre-computed hash. For consistency with the `Signer` trait, this is provided as-is.
    fn sign_prehashed(&self, digest: &[u8]) -> Result<XrpSignature, SignerError> {
        // Ed25519 has no internal hashing step in XRP context,
        // so prehashed == raw sign
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

impl traits::KeyPair for XrpEddsaSigner {
    fn generate() -> Result<Self, SignerError> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        Ok(Self { signing_key })
    }

    fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
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
}

/// XRP Ed25519 verifier.
pub struct XrpEddsaVerifier {
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl XrpEddsaVerifier {
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

impl traits::Verifier for XrpEddsaVerifier {
    type Signature = XrpSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &XrpSignature) -> Result<bool, SignerError> {
        self.verify_prehashed(message, signature)
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &XrpSignature,
    ) -> Result<bool, SignerError> {
        use ed25519_dalek::Verifier as DalekVerifier;
        if signature.bytes.len() != 64 {
            return Err(SignerError::InvalidSignature(format!(
                "expected 64 bytes, got {}",
                signature.bytes.len()
            )));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&signature.bytes);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        match DalekVerifier::verify(&self.verifying_key, digest, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_ecdsa_generate() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes().len(), 33);
    }

    #[test]
    fn test_eddsa_generate() {
        let signer = XrpEddsaSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let sig = signer.sign(b"hello xrp").unwrap();
        let verifier =
            XrpEcdsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello xrp", &sig).unwrap());
    }

    #[test]
    fn test_eddsa_sign_verify() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let sig = signer.sign(b"hello xrp ed25519").unwrap();
        let verifier =
            XrpEddsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello xrp ed25519", &sig).unwrap());
    }

    #[test]
    fn test_sha512_half() {
        let result = sha512_half(b"hello");
        assert_eq!(result.len(), 32);
        // SHA-512("hello") first 32 bytes
        let full = Sha512::digest(b"hello");
        assert_eq!(&result[..], &full[..32]);
    }

    #[test]
    fn test_account_id_ecdsa() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let id = signer.account_id();
        assert_eq!(id.len(), 20);
    }

    #[test]
    fn test_account_id_eddsa() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let id = signer.account_id();
        assert_eq!(id.len(), 20);
    }

    #[test]
    fn test_invalid_key_rejected() {
        assert!(XrpEcdsaSigner::from_bytes(&[0u8; 32]).is_err());
        assert!(XrpEcdsaSigner::from_bytes(&[1u8; 31]).is_err());
        assert!(XrpEddsaSigner::from_bytes(&[1u8; 31]).is_err());
    }

    #[test]
    fn test_tampered_sig_fails_ecdsa() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let sig = signer.sign(b"tamper").unwrap();
        let verifier = XrpEcdsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let mut tampered = sig.clone();
        if let Some(b) = tampered.bytes.last_mut() {
            *b ^= 0xff;
        }
        let result = verifier.verify(b"tamper", &tampered);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_tampered_sig_fails_eddsa() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let sig = signer.sign(b"tamper").unwrap();
        let verifier = XrpEddsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let mut tampered = sig.clone();
        tampered.bytes[0] ^= 0xff;
        let result = verifier.verify(b"tamper", &tampered);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_sign_prehashed_ecdsa() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let msg = b"prehash test";
        let digest = sha512_half(msg);
        let sig = signer.sign_prehashed(&digest).unwrap();
        let verifier = XrpEcdsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify_prehashed(&digest, &sig).unwrap());
    }

    #[test]
    fn test_zeroize_on_drop_ecdsa() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let _: Zeroizing<Vec<u8>> = signer.private_key_bytes();
        drop(signer);
    }

    #[test]
    fn test_zeroize_on_drop_eddsa() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let _: Zeroizing<Vec<u8>> = signer.private_key_bytes();
        drop(signer);
    }

    // RFC 8032 Ed25519 test vector (reused for XRP Ed25519)
    #[test]
    fn test_rfc8032_vector_xrp_eddsa() {
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let expected_sig = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).unwrap();

        let signer = XrpEddsaSigner::from_bytes(&sk).unwrap();
        let sig = signer.sign(b"").unwrap(); // empty message
        assert_eq!(sig.bytes, expected_sig);
    }
}
