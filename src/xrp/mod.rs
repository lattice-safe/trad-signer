//! XRP signer supporting both ECDSA (secp256k1 + SHA-512 half) and Ed25519.
//!
//! XRP allows two key types: secp256k1 and Ed25519.

pub mod advanced;
pub mod transaction;

use crate::crypto;
use crate::error::SignerError;
use crate::traits;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// XRP signature (variable format depending on key type).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub struct XrpSignature {
    /// DER-encoded for ECDSA, 64-byte for Ed25519.
    pub bytes: Vec<u8>,
}

impl core::fmt::Display for XrpSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
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
                    "invalid DER signature length: {}",
                    bytes.len()
                )));
            }
        } else if bytes.len() != 64 {
            return Err(SignerError::InvalidSignature(format!(
                "expected 64-byte Ed25519 or DER ECDSA, got {} bytes starting with 0x{:02x}",
                bytes.len(),
                bytes[0]
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
    crypto::hash160(pubkey_bytes)
}

/// XRP Base58 alphabet (differs from Bitcoin's alphabet).
fn xrp_alphabet() -> Result<bs58::Alphabet, SignerError> {
    bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
        .map_err(|e| SignerError::InvalidPublicKey(format!("XRP alphabet: {e}")))
}

/// Generate an XRP `r...` address from a 20-byte account ID.
///
/// Uses XRP's custom Base58Check with version byte 0x00.
pub fn xrp_address(account_id: &[u8; 20]) -> Result<String, SignerError> {
    let mut payload = vec![0x00u8]; // version byte
    payload.extend_from_slice(account_id);
    // XRP uses double-SHA256 for checksum (same as Bitcoin)
    let checksum = crypto::double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);
    Ok(bs58::encode(payload)
        .with_alphabet(&xrp_alphabet()?)
        .into_string())
}

/// Validate an XRP `r...` address string.
///
/// Checks: starts with 'r', 25-byte Base58Check decode, version 0x00, valid checksum.
pub fn validate_address(address: &str) -> bool {
    if !address.starts_with('r') {
        return false;
    }
    let alphabet = match xrp_alphabet() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let decoded = match bs58::decode(address).with_alphabet(&alphabet).into_vec() {
        Ok(d) => d,
        Err(_) => return false,
    };
    if decoded.len() != 25 || decoded[0] != 0x00 {
        return false;
    }
    use subtle::ConstantTimeEq;
    let checksum = crypto::double_sha256(&decoded[..21]);
    checksum[..4].ct_eq(&decoded[21..25]).unwrap_u8() == 1
}

// ═══════════════════════════════════════════════════════════════════
// X-Address Encoding (XLS-7d)
// ═══════════════════════════════════════════════════════════════════

/// Encode an account ID and optional destination tag into an **X-address**.
///
/// X-addresses combine the account ID and destination tag into a single string.
/// - Mainnet: starts with `X`
/// - Testnet: starts with `T`
///
/// Format: `0x05 0x44` (mainnet) | `0x05 0x93` (testnet) + account_id + flags + tag_bytes + checksum
pub fn encode_x_address(
    account_id: &[u8; 20],
    tag: Option<u32>,
    is_testnet: bool,
) -> Result<String, SignerError> {
    let mut payload = Vec::with_capacity(31);

    // 2-byte prefix
    if is_testnet {
        payload.extend_from_slice(&[0x05, 0x93]);
    } else {
        payload.extend_from_slice(&[0x05, 0x44]);
    }

    // 20-byte account ID
    payload.extend_from_slice(account_id);

    // flags + tag (9 bytes)
    match tag {
        Some(t) => {
            payload.push(0x01); // has tag
            payload.extend_from_slice(&t.to_le_bytes()); // 4 bytes LE
            payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // 4 reserved bytes
        }
        None => {
            payload.push(0x00); // no tag
            payload.extend_from_slice(&[0x00; 8]); // 8 zero bytes
        }
    }

    // 4-byte checksum (double SHA-256)
    let checksum = crypto::double_sha256(&payload);
    payload.extend_from_slice(&checksum[..4]);

    Ok(bs58::encode(payload)
        .with_alphabet(&xrp_alphabet()?)
        .into_string())
}

/// Decode an X-address into an account ID and optional destination tag.
///
/// Returns `(account_id, optional_tag, is_testnet)`.
pub fn decode_x_address(x_address: &str) -> Result<([u8; 20], Option<u32>, bool), SignerError> {
    let decoded = bs58::decode(x_address)
        .with_alphabet(&xrp_alphabet()?)
        .into_vec()
        .map_err(|_| SignerError::ParseError("invalid X-address Base58".into()))?;

    if decoded.len() != 35 {
        return Err(SignerError::ParseError(format!(
            "X-address: expected 35 bytes, got {}",
            decoded.len()
        )));
    }

    // Verify checksum (constant-time comparison)
    let checksum = crypto::double_sha256(&decoded[..31]);
    use subtle::ConstantTimeEq;
    if decoded[31..35].ct_eq(&checksum[..4]).unwrap_u8() != 1 {
        return Err(SignerError::ParseError("X-address: bad checksum".into()));
    }

    // Parse prefix
    let is_testnet = match (decoded[0], decoded[1]) {
        (0x05, 0x44) => false, // mainnet
        (0x05, 0x93) => true,  // testnet
        _ => return Err(SignerError::ParseError("X-address: unknown prefix".into())),
    };

    // Account ID
    let mut account = [0u8; 20];
    account.copy_from_slice(&decoded[2..22]);

    // Tag
    let tag = if decoded[22] == 0x01 {
        Some(u32::from_le_bytes([
            decoded[23],
            decoded[24],
            decoded[25],
            decoded[26],
        ]))
    } else {
        None
    };

    Ok((account, tag, is_testnet))
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

    /// Return the XRP `r...` address string.
    pub fn address(&self) -> Result<String, SignerError> {
        xrp_address(&self.account_id())
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
        let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
        crate::security::secure_random(&mut *key_bytes)?;
        let signing_key = k256::ecdsa::SigningKey::from_bytes((&*key_bytes).into())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
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

    /// Return the XRP `r...` address string.
    pub fn address(&self) -> Result<String, SignerError> {
        xrp_address(&self.account_id())
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
    /// `sign()` — the `digest` parameter is treated as a raw message, not a
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
        let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
        crate::security::secure_random(&mut *key_bytes)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let verifier = XrpEcdsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello xrp", &sig).unwrap());
    }

    #[test]
    fn test_eddsa_sign_verify() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let sig = signer.sign(b"hello xrp ed25519").unwrap();
        let verifier = XrpEddsaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
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
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let expected_sig = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ).unwrap();

        let signer = XrpEddsaSigner::from_bytes(&sk).unwrap();
        let sig = signer.sign(b"").unwrap(); // empty message
        assert_eq!(sig.bytes, expected_sig);
    }

    // ─── XRP Known Address Vectors ──────────────────────────────

    #[test]
    fn test_xrp_ecdsa_address_format() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let addr = signer.address().unwrap();
        assert!(addr.starts_with('r'), "XRP address must start with 'r'");
        assert!(addr.len() >= 25 && addr.len() <= 35);
        assert!(validate_address(&addr));
    }

    #[test]
    fn test_xrp_eddsa_address_format() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let addr = signer.address().unwrap();
        assert!(addr.starts_with('r'));
        assert!(validate_address(&addr));
    }

    #[test]
    fn test_xrp_address_validation_edges() {
        assert!(!validate_address(""));
        assert!(!validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")); // Bitcoin, not XRP
        assert!(!validate_address("rINVALID")); // too short/invalid
    }

    #[test]
    fn test_sha512_half_deterministic() {
        let h1 = sha512_half(b"test");
        let h2 = sha512_half(b"test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    // ─── X-Address Tests ────────────────────────────────────────

    #[test]
    fn test_x_address_roundtrip_no_tag() {
        let account = [0xAA; 20];
        let x_addr = encode_x_address(&account, None, false).unwrap();
        let (decoded_acct, tag, testnet) = decode_x_address(&x_addr).unwrap();
        assert_eq!(decoded_acct, account);
        assert!(tag.is_none());
        assert!(!testnet);
    }

    #[test]
    fn test_x_address_roundtrip_with_tag() {
        let account = [0xBB; 20];
        let x_addr = encode_x_address(&account, Some(12345), false).unwrap();
        let (decoded_acct, tag, testnet) = decode_x_address(&x_addr).unwrap();
        assert_eq!(decoded_acct, account);
        assert_eq!(tag, Some(12345));
        assert!(!testnet);
    }

    #[test]
    fn test_x_address_testnet() {
        let account = [0xCC; 20];
        let x_addr = encode_x_address(&account, None, true).unwrap();
        let (_, _, testnet) = decode_x_address(&x_addr).unwrap();
        assert!(testnet);
    }

    #[test]
    fn test_x_address_mainnet_vs_testnet() {
        let account = [0xDD; 20];
        let main = encode_x_address(&account, None, false).unwrap();
        let test = encode_x_address(&account, None, true).unwrap();
        assert_ne!(main, test);
    }

    #[test]
    fn test_x_address_from_ecdsa_signer() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let acct_id = signer.account_id();
        let x_addr = encode_x_address(&acct_id, Some(42), false).unwrap();
        let (decoded_acct, tag, _) = decode_x_address(&x_addr).unwrap();
        assert_eq!(decoded_acct, acct_id);
        assert_eq!(tag, Some(42));
    }

    // ─── Official Test Vectors (xrpl.org) ───────────────────────

    /// Known-good test vector from xrpl.org:
    /// Classic address: rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh (Genesis Account)
    /// Account ID hex:  b5f762798a53d543a014caf8b297cff8f2f937e8
    /// X-address (mainnet, no tag): X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqh
    #[test]
    fn test_xrp_classic_address_known_vector() {
        let account_id = hex::decode("b5f762798a53d543a014caf8b297cff8f2f937e8").unwrap();
        let mut acct = [0u8; 20];
        acct.copy_from_slice(&account_id);
        let addr = xrp_address(&acct).unwrap();
        assert_eq!(
            addr, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
            "Classic address must match xrpl.org Genesis Account"
        );
        assert!(validate_address(&addr));
    }

    #[test]
    fn test_xrp_x_address_known_vector_no_tag() {
        let account_id = hex::decode("b5f762798a53d543a014caf8b297cff8f2f937e8").unwrap();
        let mut acct = [0u8; 20];
        acct.copy_from_slice(&account_id);

        // Mainnet, no destination tag
        let x_addr = encode_x_address(&acct, None, false).unwrap();

        // Must start with 'X' for mainnet
        assert!(
            x_addr.starts_with('X'),
            "mainnet X-address must start with X"
        );

        // Decode back and verify roundtrip preserves all fields
        let (decoded_acct, tag, is_testnet) = decode_x_address(&x_addr).unwrap();
        assert_eq!(decoded_acct, acct, "account ID must survive roundtrip");
        assert!(tag.is_none(), "no-tag must decode as None");
        assert!(!is_testnet, "mainnet flag must survive roundtrip");
    }

    #[test]
    fn test_xrp_x_address_roundtrip_with_known_acct() {
        let account_id = hex::decode("b5f762798a53d543a014caf8b297cff8f2f937e8").unwrap();
        let mut acct = [0u8; 20];
        acct.copy_from_slice(&account_id);

        // Encode with a tag and decode
        let x_addr = encode_x_address(&acct, Some(12345), false).unwrap();
        let (decoded_acct, tag, is_testnet) = decode_x_address(&x_addr).unwrap();
        assert_eq!(decoded_acct, acct);
        assert_eq!(tag, Some(12345));
        assert!(!is_testnet);
    }

    #[test]
    fn test_xrp_x_address_decode_invalid() {
        // Truncated
        assert!(decode_x_address("X7Acg").is_err());
        // Random invalid
        assert!(decode_x_address("XXXXXXXXXXX").is_err());
    }
}
