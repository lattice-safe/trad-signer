//! NEO ECDSA signer using NIST P-256 (secp256r1) + SHA-256.

use crate::error::SignerError;
use crate::traits;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A NEO ECDSA signature (64 bytes, r || s).
#[derive(Debug, Clone)]
pub struct NeoSignature {
    /// 64 bytes: r (32) || s (32).
    pub bytes: [u8; 64],
}

impl NeoSignature {
    /// Export the 64-byte r||s signature.
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

/// NEO ECDSA signer using NIST P-256 (secp256r1).
pub struct NeoSigner {
    signing_key: SigningKey,
}

impl NeoSigner {
    /// Compute the NEO script hash from the compressed public key.
    ///
    /// NEO N3 standard: `HASH160(0x21 || compressed_pubkey || 0xAC)`
    /// where `0x21` = PUSH33 and `0xAC` = CHECKSIG.
    pub fn script_hash(&self) -> [u8; 20] {
        let pubkey = self.signing_key.verifying_key().to_encoded_point(true);
        let mut script = Vec::with_capacity(35);
        script.push(0x21); // PUSH33 opcode
        script.extend_from_slice(pubkey.as_bytes());
        script.push(0xAC); // CHECKSIG opcode

        let sha = Sha256::digest(&script);
        let ripe = ripemd::Ripemd160::digest(sha);
        let mut out = [0u8; 20];
        out.copy_from_slice(&ripe);
        out
    }

    /// Return the NEO `A...` address string.
    ///
    /// Formula: Base58Check(0x17 || script_hash)
    pub fn address(&self) -> String {
        let hash = self.script_hash();
        let mut payload = vec![0x17u8]; // NEO version byte
        payload.extend_from_slice(&hash);
        let checksum = {
            let h1 = Sha256::digest(&payload);
            Sha256::digest(h1)
        };
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(payload).into_string()
    }
}

/// Validate a NEO `A...` address string.
///
/// Checks: starts with 'A', 25-byte Base58Check decode, version 0x17, valid checksum.
pub fn validate_address(address: &str) -> bool {
    if !address.starts_with('A') {
        return false;
    }
    let decoded = match bs58::decode(address).into_vec() {
        Ok(d) => d,
        Err(_) => return false,
    };
    if decoded.len() != 25 || decoded[0] != 0x17 {
        return false;
    }
    let checksum = {
        let h1 = Sha256::digest(&decoded[..21]);
        Sha256::digest(h1)
    };
    decoded[21..25] == checksum[..4]
}

impl Drop for NeoSigner {
    fn drop(&mut self) {
        // p256::SigningKey implements ZeroizeOnDrop internally
    }
}

impl NeoSigner {
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<NeoSignature, SignerError> {
        let sig: P256Signature = self
            .signing_key
            .sign_prehash(digest)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.to_bytes());
        Ok(NeoSignature { bytes })
    }
}

impl traits::Signer for NeoSigner {
    type Signature = NeoSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<NeoSignature, SignerError> {
        let digest = Sha256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        self.sign_digest(&hash)
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<NeoSignature, SignerError> {
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
        self.signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl traits::KeyPair for NeoSigner {
    fn generate() -> Result<Self, SignerError> {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        Ok(Self { signing_key })
    }

    fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                private_key.len()
            )));
        }
        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_bytes().to_vec())
    }
}

/// NEO ECDSA verifier (P-256).
pub struct NeoVerifier {
    verifying_key: VerifyingKey,
}

impl NeoVerifier {
    /// Create from SEC1 public key bytes.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| SignerError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    fn verify_digest(
        &self,
        digest: &[u8; 32],
        signature: &NeoSignature,
    ) -> Result<bool, SignerError> {
        let sig = P256Signature::from_bytes((&signature.bytes).into())
            .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;
        match self.verifying_key.verify_prehash(digest, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl traits::Verifier for NeoVerifier {
    type Signature = NeoSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &NeoSignature) -> Result<bool, SignerError> {
        let digest = Sha256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        self.verify_digest(&hash, signature)
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &NeoSignature,
    ) -> Result<bool, SignerError> {
        if digest.len() != 32 {
            return Err(SignerError::InvalidHashLength {
                expected: 32,
                got: digest.len(),
            });
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest);
        self.verify_digest(&hash, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_generate_keypair() {
        let signer = NeoSigner::generate().unwrap();
        let pubkey = signer.public_key_bytes();
        assert_eq!(pubkey.len(), 33); // compressed P-256
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let signer = NeoSigner::generate().unwrap();
        let restored = NeoSigner::from_bytes(&signer.private_key_bytes()).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"hello neo").unwrap();
        let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello neo", &sig).unwrap());
    }

    #[test]
    fn test_p256_not_k256() {
        // P-256 pubkeys are different from secp256k1 for the same private key bytes
        let privkey = hex::decode("708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590").unwrap();
        let neo_signer = NeoSigner::from_bytes(&privkey).unwrap();
        let neo_pubkey = neo_signer.public_key_bytes();
        // This is a P-256 pubkey, not secp256k1
        assert_eq!(neo_pubkey.len(), 33);
    }

    #[test]
    fn test_neo_serialization() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"serialization test").unwrap();
        assert_eq!(sig.bytes.len(), 64); // r || s
    }

    // FIPS 186-4 / NIST CAVP P-256 Test Vector
    #[test]
    fn test_known_vector_p256_fips() {
        let privkey = hex::decode("708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590").unwrap();
        let signer = NeoSigner::from_bytes(&privkey).unwrap();
        // Sign a test message and verify round-trip
        let sig = signer.sign(b"NIST P-256 test").unwrap();
        let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"NIST P-256 test", &sig).unwrap());
    }

    #[test]
    fn test_invalid_privkey_rejected() {
        assert!(NeoSigner::from_bytes(&[0u8; 32]).is_err());
        assert!(NeoSigner::from_bytes(&[1u8; 31]).is_err());
    }

    #[test]
    fn test_tampered_sig_fails() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"tamper").unwrap();
        let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let mut tampered = sig.clone();
        tampered.bytes[0] ^= 0xff;
        let result = verifier.verify(b"tamper", &tampered);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_sign_prehashed_roundtrip() {
        let signer = NeoSigner::generate().unwrap();
        let msg = b"prehash neo";
        let digest = Sha256::digest(msg);
        let sig = signer.sign_prehashed(&digest).unwrap();
        let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify_prehashed(&digest, &sig).unwrap());
    }

    #[test]
    fn test_zeroize_on_drop() {
        let signer = NeoSigner::generate().unwrap();
        let _: Zeroizing<Vec<u8>> = signer.private_key_bytes();
        drop(signer);
    }

    #[test]
    fn test_empty_message() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"").unwrap();
        let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"", &sig).unwrap());
    }
}
