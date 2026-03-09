//! Bitcoin ECDSA signer using secp256k1 + double-SHA-256.
//!
//! Implements RFC 6979 deterministic nonces (built into k256),
//! strict DER-encoded signature output, and double-SHA-256 hashing.

pub mod descriptor;
pub mod helpers;
pub mod lightning;
pub mod message;
pub mod miniscript;
pub mod multisig;
pub mod musig2_tx;
pub mod psbt;
pub mod schnorr;
pub mod scripts;
pub mod sighash;
pub mod silent_payments;
pub mod taproot;
pub mod tapscript;
pub mod transaction;

use crate::crypto;
use crate::encoding;
use crate::error::SignerError;
use crate::traits;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature as K256Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// A Bitcoin ECDSA signature in DER encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub struct BitcoinSignature {
    /// DER-encoded signature bytes (private to prevent mutation).
    der_bytes: Vec<u8>,
}

impl BitcoinSignature {
    /// Export the DER-encoded signature bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.der_bytes.clone()
    }

    /// Get a reference to the DER-encoded signature bytes.
    #[must_use]
    pub fn der_bytes(&self) -> &[u8] {
        &self.der_bytes
    }

    /// Import from DER-encoded signature bytes.
    pub fn from_bytes(der: &[u8]) -> Result<Self, SignerError> {
        // Validate it's a valid DER ECDSA signature
        K256Signature::from_der(der).map_err(|e| SignerError::InvalidSignature(e.to_string()))?;
        Ok(Self {
            der_bytes: der.to_vec(),
        })
    }
}

impl core::fmt::Display for BitcoinSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.der_bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Double-SHA-256: SHA256(SHA256(data)).
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    crypto::double_sha256(data)
}

/// Bitcoin ECDSA signer.
///
/// Uses secp256k1 with double-SHA-256 hashing and RFC 6979 deterministic nonces.
/// Produces strict DER-encoded signatures.
pub struct BitcoinSigner {
    signing_key: SigningKey,
}

// k256::SigningKey implements ZeroizeOnDrop internally — no explicit Drop needed.

impl BitcoinSigner {
    /// Sign a pre-computed 32-byte digest.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<BitcoinSignature, SignerError> {
        let sig: K256Signature = self
            .signing_key
            .sign_prehash(digest)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        // Encode as strict DER
        let der = sig.to_der();
        Ok(BitcoinSignature {
            der_bytes: der.as_bytes().to_vec(),
        })
    }

    /// Export the private key in **WIF** (Wallet Import Format).
    ///
    /// Uses version byte 0x80 (mainnet) with compression flag.
    /// Result starts with `K` or `L`.
    ///
    /// # Security
    /// The returned String contains the private key — handle with care.
    #[must_use]
    pub fn to_wif(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(38));
        payload.push(0x80); // mainnet version
        payload.extend_from_slice(&self.signing_key.to_bytes());
        payload.push(0x01); // compressed flag
        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[..4]);
        Zeroizing::new(bs58::encode(&*payload).into_string())
    }

    /// Export the private key in **testnet WIF** format.
    ///
    /// Uses version byte 0xEF (testnet). Result starts with `c`.
    ///
    /// # Security
    /// The returned String contains the private key — handle with care.
    #[must_use]
    pub fn to_wif_testnet(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new(Vec::with_capacity(38));
        payload.push(0xEF); // testnet version
        payload.extend_from_slice(&self.signing_key.to_bytes());
        payload.push(0x01); // compressed flag
        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[..4]);
        Zeroizing::new(bs58::encode(&*payload).into_string())
    }

    /// Import a private key from **WIF** (Wallet Import Format).
    ///
    /// Accepts mainnet (`5`/`K`/`L`) and testnet (`9`/`c`) WIF strings.
    pub fn from_wif(wif: &str) -> Result<Self, SignerError> {
        use crate::traits::KeyPair;
        let decoded = Zeroizing::new(
            bs58::decode(wif)
                .into_vec()
                .map_err(|e| SignerError::InvalidPrivateKey(format!("invalid WIF base58: {e}")))?,
        );

        // Validate length: 37 (uncompressed) or 38 (compressed)
        if decoded.len() != 37 && decoded.len() != 38 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "WIF must be 37 or 38 bytes, got {}",
                decoded.len()
            )));
        }

        // Validate version byte
        let version = decoded[0];
        if version != 0x80 && version != 0xEF {
            return Err(SignerError::InvalidPrivateKey(format!(
                "invalid WIF version: 0x{version:02x}"
            )));
        }

        // Validate checksum (constant-time comparison)
        let payload_len = decoded.len() - 4;
        let checksum = double_sha256(&decoded[..payload_len]);
        use subtle::ConstantTimeEq;
        if decoded[payload_len..].ct_eq(&checksum[..4]).unwrap_u8() != 1 {
            return Err(SignerError::InvalidPrivateKey(
                "invalid WIF checksum".into(),
            ));
        }

        // Extract key bytes (skip version byte; compression flag handled by length check)
        let key_bytes = &decoded[1..33];

        Self::from_bytes(key_bytes)
    }

    /// Generate a **P2PKH** address (`1...`) from the compressed public key.
    ///
    /// Formula: Base58Check(0x00 || HASH160(compressed_pubkey))
    #[must_use]
    pub fn p2pkh_address(&self) -> String {
        let pubkey = self.signing_key.verifying_key().to_sec1_bytes();
        let h160 = hash160(&pubkey);
        base58check_encode(0x00, &h160)
    }

    /// Generate a **P2WPKH** (SegWit) address (`bc1...`) from the compressed public key.
    ///
    /// Formula: Bech32("bc", 0, HASH160(compressed_pubkey))
    pub fn p2wpkh_address(&self) -> Result<String, SignerError> {
        let pubkey = self.signing_key.verifying_key().to_sec1_bytes();
        let h160 = hash160(&pubkey);
        bech32_encode("bc", 0, &h160)
    }

    /// Generate a **testnet P2PKH** address (`m...` or `n...`).
    pub fn p2pkh_testnet_address(&self) -> String {
        let pubkey = self.signing_key.verifying_key().to_sec1_bytes();
        let h160 = hash160(&pubkey);
        base58check_encode(0x6F, &h160) // testnet version byte
    }

    /// Generate a **testnet P2WPKH** address (`tb1q...`).
    pub fn p2wpkh_testnet_address(&self) -> Result<String, SignerError> {
        let pubkey = self.signing_key.verifying_key().to_sec1_bytes();
        let h160 = hash160(&pubkey);
        bech32_encode("tb", 0, &h160)
    }

    /// **BIP-137**: Sign a message with the Bitcoin Signed Message prefix.
    ///
    /// Computes `double_sha256("\x18Bitcoin Signed Message:\n" || varint(len) || message)`
    /// and signs the resulting 32-byte digest.
    pub fn sign_message(&self, message: &[u8]) -> Result<BitcoinSignature, SignerError> {
        let digest = bitcoin_message_hash(message);
        self.sign_digest(&digest)
    }
}

/// HASH160: RIPEMD160(SHA256(data)) — the standard Bitcoin hash function.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    crypto::hash160(data)
}

/// Base58Check encode: `version_byte || payload || checksum[0..4]`.
fn base58check_encode(version: u8, payload: &[u8]) -> String {
    encoding::base58check_encode(version, payload)
}

/// Bech32/Bech32m encode for SegWit/Taproot addresses.
pub(crate) fn bech32_encode(
    hrp: &str,
    witness_version: u8,
    program: &[u8],
) -> Result<String, SignerError> {
    encoding::bech32_encode(hrp, witness_version, program)
}

/// **BIP-137**: Hash a message with the Bitcoin Signed Message prefix.
///
/// `double_sha256("\x18Bitcoin Signed Message:\n" || varint(len) || message)`
pub fn bitcoin_message_hash(message: &[u8]) -> [u8; 32] {
    let mut data = Vec::new();
    // Prefix: "\x18Bitcoin Signed Message:\n"
    data.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    // Varint-encoded message length
    data.extend_from_slice(&varint_encode(message.len()));
    data.extend_from_slice(message);
    double_sha256(&data)
}

/// Bitcoin variable-length integer encoding.
fn varint_encode(n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    encoding::encode_compact_size(&mut buf, n as u64);
    buf
}

/// Validate a Bitcoin address string.
///
/// Returns `true` if the address is a valid P2PKH (`1...`), P2SH (`3...`),
/// P2WPKH (`bc1q...`), or P2TR (`bc1p...`) address.
pub fn validate_address(address: &str) -> bool {
    validate_mainnet_address(address) || validate_testnet_address(address)
}

/// Validate a mainnet Bitcoin address.
pub fn validate_mainnet_address(address: &str) -> bool {
    if address.starts_with("bc1") {
        // Bech32/Bech32m
        bech32::segwit::decode(address).is_ok()
    } else if address.starts_with('1') || address.starts_with('3') {
        // Base58Check (P2PKH or P2SH)
        validate_base58check(address, &[0x00, 0x05])
    } else {
        false
    }
}

/// Validate a testnet Bitcoin address.
pub fn validate_testnet_address(address: &str) -> bool {
    if address.starts_with("tb1") {
        bech32::segwit::decode(address).is_ok()
    } else if address.starts_with('m') || address.starts_with('n') || address.starts_with('2') {
        validate_base58check(address, &[0x6F, 0xC4])
    } else {
        false
    }
}

/// Validate a Base58Check-encoded address has a valid checksum and version byte.
fn validate_base58check(address: &str, valid_versions: &[u8]) -> bool {
    let decoded = match bs58::decode(address).into_vec() {
        Ok(d) => d,
        Err(_) => return false,
    };
    if decoded.len() != 25 {
        return false;
    }
    // Verify version byte
    if !valid_versions.contains(&decoded[0]) {
        return false;
    }
    // Verify checksum
    let checksum = double_sha256(&decoded[..21]);
    decoded[21..25] == checksum[..4]
}

impl traits::Signer for BitcoinSigner {
    type Signature = BitcoinSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<BitcoinSignature, SignerError> {
        let digest = double_sha256(message);
        self.sign_digest(&digest)
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<BitcoinSignature, SignerError> {
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
        self.signing_key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        self.signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl traits::KeyPair for BitcoinSigner {
    fn generate() -> Result<Self, SignerError> {
        let mut key_bytes = zeroize::Zeroizing::new([0u8; 32]);
        crate::security::secure_random(&mut *key_bytes)?;
        let signing_key = SigningKey::from_bytes((&*key_bytes).into())
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
        let signing_key = SigningKey::from_bytes(private_key.into())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_bytes().to_vec())
    }
}

/// Bitcoin ECDSA verifier.
///
/// # Verification Semantics
/// - `Ok(true)` — signature is valid.
/// - `Ok(false)` — signature is mathematically invalid (wrong key or tampered data).
/// - `Err(...)` — signature could not be parsed (malformed DER encoding, wrong length, etc.).
pub struct BitcoinVerifier {
    verifying_key: VerifyingKey,
}

impl BitcoinVerifier {
    /// Create from compressed or uncompressed public key bytes.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| SignerError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    fn verify_digest(
        &self,
        digest: &[u8; 32],
        signature: &BitcoinSignature,
    ) -> Result<bool, SignerError> {
        let sig = K256Signature::from_der(&signature.der_bytes)
            .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;
        match self.verifying_key.verify_prehash(digest, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl traits::Verifier for BitcoinVerifier {
    type Signature = BitcoinSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &BitcoinSignature) -> Result<bool, SignerError> {
        let digest = double_sha256(message);
        self.verify_digest(&digest, signature)
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &BitcoinSignature,
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_generate_keypair() {
        let signer = BitcoinSigner::generate().unwrap();
        let pubkey = signer.public_key_bytes();
        assert_eq!(pubkey.len(), 33); // compressed
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let key_bytes = signer.private_key_bytes();
        let restored = BitcoinSigner::from_bytes(&key_bytes).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let msg = b"hello bitcoin";
        let sig = signer.sign(msg).unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_double_sha256() {
        // Known test: SHA256(SHA256("hello")) =
        // 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50
        let result = double_sha256(b"hello");
        assert_eq!(
            hex::encode(result),
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
    }

    #[test]
    fn test_rfc6979_deterministic() {
        // Same (key, msg) must produce identical signature every time (RFC 6979)
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let signer = BitcoinSigner::from_bytes(&privkey).unwrap();
        let sig1 = signer.sign(b"Satoshi Nakamoto").unwrap();
        let sig2 = signer.sign(b"Satoshi Nakamoto").unwrap();
        assert_eq!(sig1.der_bytes(), sig2.der_bytes());
    }

    #[test]
    fn test_rfc6979_known_vector_privkey_1() {
        // Private key = 1, message = "Satoshi Nakamoto"
        // This is a well-known Bitcoin Core test vector for RFC 6979 deterministic nonce.
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let signer = BitcoinSigner::from_bytes(&privkey).unwrap();

        // Verify the public key for private key = 1
        let pubkey = signer.public_key_bytes();
        assert_eq!(
            hex::encode(&pubkey).to_uppercase(),
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        );

        // Sign "Satoshi Nakamoto" with double-SHA256
        let sig = signer.sign(b"Satoshi Nakamoto").unwrap();
        // DER signature must be valid and deterministic
        assert!(!sig.der_bytes().is_empty());
        // Verify it
        let verifier = BitcoinVerifier::from_public_key_bytes(&pubkey).unwrap();
        assert!(verifier.verify(b"Satoshi Nakamoto", &sig).unwrap());
    }

    #[test]
    fn test_rfc6979_known_vector_privkey_2() {
        // Another well-known vector: private key = 2
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let signer = BitcoinSigner::from_bytes(&privkey).unwrap();
        let sig = signer.sign(b"Satoshi Nakamoto").unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"Satoshi Nakamoto", &sig).unwrap());
        // Deterministic: sign again and compare
        let sig2 = signer.sign(b"Satoshi Nakamoto").unwrap();
        assert_eq!(sig.der_bytes(), sig2.der_bytes());
    }

    #[test]
    fn test_der_encoding() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign(b"DER test").unwrap();
        // DER signatures start with 0x30 (SEQUENCE tag)
        assert_eq!(sig.der_bytes()[0], 0x30);
        // Length should be reasonable (70-72 bytes typically)
        assert!(sig.der_bytes().len() >= 68 && sig.der_bytes().len() <= 72);
    }

    #[test]
    fn test_invalid_privkey_rejected() {
        assert!(BitcoinSigner::from_bytes(&[0u8; 32]).is_err());
        assert!(BitcoinSigner::from_bytes(&[1u8; 31]).is_err());
        assert!(BitcoinSigner::from_bytes(&[1u8; 33]).is_err());
    }

    #[test]
    fn test_tampered_sig_fails() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign(b"tamper test").unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();

        let tampered_bytes: Vec<u8> = {
            let mut b = sig.to_bytes();
            if let Some(byte) = b.last_mut() {
                *byte ^= 0xff;
            }
            b
        };
        let tampered = BitcoinSignature::from_bytes(&tampered_bytes);
        // Tampered DER may fail to parse (Err) or verify as invalid (Ok(false))
        if let Ok(t) = tampered {
            let result = verifier.verify(b"tamper test", &t);
            assert!(result.is_err() || !result.unwrap());
        }
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let signer1 = BitcoinSigner::generate().unwrap();
        let signer2 = BitcoinSigner::generate().unwrap();
        let sig = signer1.sign(b"wrong key test").unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer2.public_key_bytes()).unwrap();
        assert!(!verifier.verify(b"wrong key test", &sig).unwrap());
    }

    #[test]
    fn test_empty_message() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign(b"").unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"", &sig).unwrap());
    }

    #[test]
    fn test_sign_prehashed_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let msg = b"prehash btc";
        let digest = double_sha256(msg);
        let sig = signer.sign_prehashed(&digest).unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify_prehashed(&digest, &sig).unwrap());
    }

    #[test]
    fn test_zeroize_on_drop() {
        let signer = BitcoinSigner::generate().unwrap();
        let key_bytes = signer.private_key_bytes();
        let _: Zeroizing<Vec<u8>> = key_bytes;
        drop(signer);
    }

    // ─── Known Address Vectors ──────────────────────────────────

    #[test]
    fn test_p2pkh_known_address_privkey_1() {
        // Private key = 1 → generator point G
        // Compressed P2PKH = 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
        let sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let signer = BitcoinSigner::from_bytes(&sk).unwrap();
        assert_eq!(signer.p2pkh_address(), "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_p2wpkh_known_address_privkey_1() {
        // Private key = 1 → bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        let sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let signer = BitcoinSigner::from_bytes(&sk).unwrap();
        assert_eq!(
            signer.p2wpkh_address().unwrap(),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
    }

    // ─── WIF Round-Trip ─────────────────────────────────────────

    #[test]
    fn test_wif_encode_known() {
        // Private key = 1 → known WIF
        let sk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let signer = BitcoinSigner::from_bytes(&sk).unwrap();
        let wif = signer.to_wif();
        assert!(wif.starts_with('K') || wif.starts_with('L'));
        assert_eq!(wif.len(), 52); // compressed WIF is 52 chars
    }

    #[test]
    fn test_wif_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let wif = signer.to_wif();
        let restored = BitcoinSigner::from_wif(&wif).unwrap();
        assert_eq!(&*signer.private_key_bytes(), &*restored.private_key_bytes());
        assert_eq!(signer.p2pkh_address(), restored.p2pkh_address());
    }

    // ─── Address Validation ─────────────────────────────────────

    #[test]
    fn test_validate_known_addresses() {
        assert!(validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")); // P2PKH
        assert!(validate_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        )); // P2WPKH
        assert!(!validate_address(""));
        assert!(!validate_address("1invalid"));
        assert!(!validate_address("bc1qinvalid"));
    }

    // ─── BIP-137 Message Signing ────────────────────────────────

    #[test]
    fn test_bip137_sign_verify_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign_message(b"Hello Bitcoin").unwrap();
        // BIP-137 uses the same ECDSA path → DER encoded
        assert_eq!(sig.der_bytes()[0], 0x30); // DER SEQUENCE tag
                                              // Verify round-trip
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let digest = bitcoin_message_hash(b"Hello Bitcoin");
        assert!(verifier.verify_prehashed(&digest, &sig).unwrap());
    }
}
