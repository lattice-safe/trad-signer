//! Ethereum ECDSA signer using secp256k1 + Keccak-256.
//!
//! Implements EIP-2 Low-S normalization, recovery ID (v, r, s),
//! and Ethereum address derivation.

use crate::error::SignerError;
use crate::traits;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// An Ethereum ECDSA signature with recovery ID.
#[derive(Debug, Clone)]
pub struct EthereumSignature {
    /// The R component (32 bytes).
    pub r: [u8; 32],
    /// The S component (32 bytes), guaranteed to be low-S (EIP-2).
    pub s: [u8; 32],
    /// Recovery ID: 27 or 28 (legacy), or chain_id * 2 + 35 + rec_id (EIP-155).
    pub v: u8,
}

impl EthereumSignature {
    /// Encode as 65-byte `r || s || v`.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }

    /// Decode from 65-byte `r || s || v`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 65 {
            return Err(SignerError::InvalidSignature(format!(
                "expected 65 bytes, got {}",
                bytes.len()
            )));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        Ok(Self {
            r,
            s,
            v: bytes[64],
        })
    }
}

/// Ethereum ECDSA signer.
///
/// Wraps a secp256k1 `SigningKey` and applies Keccak-256 hashing,
/// EIP-2 Low-S normalization, and recovery ID calculation.
pub struct EthereumSigner {
    signing_key: SigningKey,
}

impl Drop for EthereumSigner {
    fn drop(&mut self) {
        // k256::SigningKey implements ZeroizeOnDrop internally
    }
}

impl EthereumSigner {
    /// Derive the Ethereum address from this signer's public key.
    /// Returns the 20-byte address (last 20 bytes of keccak256(uncompressed_pubkey[1..])).
    pub fn address(&self) -> [u8; 20] {
        let vk = self.signing_key.verifying_key();
        let point = vk.to_encoded_point(false);
        let pubkey_bytes = &point.as_bytes()[1..]; // skip the 0x04 prefix
        let hash = Keccak256::digest(pubkey_bytes);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }

    /// Sign a pre-hashed 32-byte digest and return the Ethereum signature.
    fn sign_digest(&self, digest: &[u8; 32]) -> Result<EthereumSignature, SignerError> {
        let (sig, rec_id) = self
            .signing_key
            .sign_prehash_recoverable(digest)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        let sig_bytes = sig.to_bytes();
        r_bytes.copy_from_slice(&sig_bytes[..32]);
        s_bytes.copy_from_slice(&sig_bytes[32..]);

        // EIP-2 Low-S normalization
        let mut v = rec_id.to_byte();
        let sig_normalized = sig.normalize_s();
        if let Some(normalized) = sig_normalized {
            let norm_bytes = normalized.to_bytes();
            s_bytes.copy_from_slice(&norm_bytes[32..]);
            // Flip recovery ID when S is normalized
            v ^= 1;
        }

        Ok(EthereumSignature {
            r: r_bytes,
            s: s_bytes,
            v: 27 + v,
        })
    }

    /// **EIP-712**: Sign typed structured data.
    ///
    /// Computes `keccak256("\x19\x01" || domain_separator || struct_hash)` and signs it.
    ///
    /// - `domain_separator`: 32-byte keccak256 hash of the EIP-712 domain (see [`Eip712Domain::separator`]).
    /// - `struct_hash`: 32-byte keccak256 hash of the typed struct (computed by the caller).
    pub fn sign_typed_data(
        &self,
        domain_separator: &[u8; 32],
        struct_hash: &[u8; 32],
    ) -> Result<EthereumSignature, SignerError> {
        let digest = eip712_hash(domain_separator, struct_hash);
        self.sign_digest(&digest)
    }

    /// **EIP-191**: Sign a personal message (as used by MetaMask `personal_sign`).
    ///
    /// Computes `keccak256("\x19Ethereum Signed Message:\n{len}{message}")` and signs it.
    /// This is the standard for off-chain message signing in Ethereum wallets.
    pub fn personal_sign(&self, message: &[u8]) -> Result<EthereumSignature, SignerError> {
        let digest = eip191_hash(message);
        self.sign_digest(&digest)
    }

    /// **EIP-155**: Sign a message with chain-specific replay protection.
    ///
    /// Produces `v = {0,1} + chain_id * 2 + 35` instead of `v = 27/28`.
    /// This is required for mainnet Ethereum transactions since the Spurious Dragon fork.
    ///
    /// Common chain IDs: 1 (mainnet), 5 (Goerli), 11155111 (Sepolia), 137 (Polygon).
    pub fn sign_with_chain_id(
        &self,
        message: &[u8],
        chain_id: u64,
    ) -> Result<EthereumSignature, SignerError> {
        let digest = Keccak256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        self.sign_digest_with_chain_id(&hash, chain_id)
    }

    /// **EIP-155**: Sign a pre-hashed digest with chain-specific replay protection.
    pub fn sign_digest_with_chain_id(
        &self,
        digest: &[u8; 32],
        chain_id: u64,
    ) -> Result<EthereumSignature, SignerError> {
        let mut sig = self.sign_digest(digest)?;
        // Convert v from legacy (27/28) to EIP-155 (35 + chain_id*2 + {0,1})
        let recovery_bit = sig.v - 27; // 0 or 1
        sig.v = (recovery_bit as u64)
            .checked_add(chain_id.checked_mul(2).ok_or_else(|| {
                SignerError::SigningFailed("chain_id overflow".into())
            })?)
            .and_then(|v| v.checked_add(35))
            .ok_or_else(|| SignerError::SigningFailed("EIP-155 v overflow".into()))?
            as u8;
        Ok(sig)
    }

    /// **EIP-191**: Sign a personal message with chain-specific v value.
    pub fn personal_sign_with_chain_id(
        &self,
        message: &[u8],
        chain_id: u64,
    ) -> Result<EthereumSignature, SignerError> {
        let digest = eip191_hash(message);
        self.sign_digest_with_chain_id(&digest, chain_id)
    }

    /// Return the EIP-55 checksummed hex address string (e.g., `0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B`).
    pub fn address_checksum(&self) -> String {
        eip55_checksum(&self.address())
    }
}

/// Return an EIP-55 checksummed hex address string from 20 raw bytes.
///
/// The EIP-55 spec: hex-encode the address, then uppercase each hex digit
/// whose corresponding nibble in the keccak256 of the lowercase hex is >= 8.
pub fn eip55_checksum(address: &[u8; 20]) -> String {
    let hex_lower: String = address.iter().map(|b| format!("{b:02x}")).collect();
    let hash = Keccak256::digest(hex_lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_lower.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            (hash[i / 2] >> 4) & 0x0f
        } else {
            hash[i / 2] & 0x0f
        };
        if hash_nibble >= 8 {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// **ecrecover**: Recover the signer's Ethereum address from a message and signature.
///
/// Internally keccak256-hashes the message and performs ECDSA recovery.
/// Returns the 20-byte address of the signer.
pub fn ecrecover(message: &[u8], signature: &EthereumSignature) -> Result<[u8; 20], SignerError> {
    let digest = Keccak256::digest(message);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    ecrecover_digest(&hash, signature)
}

/// **ecrecover** from a pre-hashed 32-byte digest, useful for EIP-712 / EIP-191.
pub fn ecrecover_digest(digest: &[u8; 32], signature: &EthereumSignature) -> Result<[u8; 20], SignerError> {
    let rec_id = RecoveryId::try_from(signature.v.wrapping_sub(27))
        .map_err(|_| SignerError::InvalidSignature("invalid recovery id (v must be 27 or 28)".into()))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&signature.r);
    sig_bytes[32..].copy_from_slice(&signature.s);
    let sig = K256Signature::from_bytes((&sig_bytes).into())
        .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;

    let recovered_key = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
        .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;

    let point = recovered_key.to_encoded_point(false);
    let pubkey_bytes = &point.as_bytes()[1..];
    let hash = Keccak256::digest(pubkey_bytes);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

/// Compute the EIP-191 personal message hash:
/// `keccak256("\x19Ethereum Signed Message:\n" || len(message) || message)`
///
/// Uses stack-based formatting to avoid heap allocation.
pub fn eip191_hash(message: &[u8]) -> [u8; 32] {
    use core::fmt::Write;
    // Max message length decimal digits: usize::MAX = 20 digits
    // Prefix is 26 bytes + up to 20 digits = 46 bytes max
    let mut prefix_buf = [0u8; 64];
    let prefix_len = {
        struct SliceWriter<'a> { buf: &'a mut [u8], pos: usize }
        impl<'a> Write for SliceWriter<'a> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let end = self.pos + bytes.len();
                if end > self.buf.len() { return Err(core::fmt::Error); }
                self.buf[self.pos..end].copy_from_slice(bytes);
                self.pos = end;
                Ok(())
            }
        }
        let mut w = SliceWriter { buf: &mut prefix_buf, pos: 0 };
        // write_fmt cannot fail here — buffer is large enough
        let _ = write!(w, "\x19Ethereum Signed Message:\n{}", message.len());
        w.pos
    };
    let mut hasher = Keccak256::new();
    hasher.update(&prefix_buf[..prefix_len]);
    hasher.update(message);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

/// **EIP-712** domain separator parameters.
///
/// Use [`Eip712Domain::separator`] to compute the 32-byte domain separator hash.
///
/// ```ignore
/// let domain = Eip712Domain {
///     name: "MyDapp",
///     version: "1",
///     chain_id: 1,
///     verifying_contract: &hex!("CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"),
/// };
/// let sep = domain.separator();
/// ```
pub struct Eip712Domain<'a> {
    /// Human-readable name of the signing domain (e.g., "Uniswap").
    pub name: &'a str,
    /// Current major version of the signing domain (e.g., "1").
    pub version: &'a str,
    /// EIP-155 chain ID (1 = mainnet, 5 = goerli, etc.).
    pub chain_id: u64,
    /// Address of the contract that will verify the signature (20 bytes).
    pub verifying_contract: &'a [u8; 20],
}

impl<'a> Eip712Domain<'a> {
    /// The EIP-712 domain type hash:
    /// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
    pub fn type_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&Keccak256::digest(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ));
        hash
    }

    /// Compute the 32-byte domain separator.
    ///
    /// `keccak256(abi.encode(TYPE_HASH, keccak256(name), keccak256(version), chainId, verifyingContract))`
    pub fn separator(&self) -> [u8; 32] {
        let type_hash = Self::type_hash();
        let name_hash = Keccak256::digest(self.name.as_bytes());
        let version_hash = Keccak256::digest(self.version.as_bytes());

        // ABI encode: 5 * 32 bytes = 160 bytes
        let mut encoded = [0u8; 160];
        encoded[0..32].copy_from_slice(&type_hash);
        encoded[32..64].copy_from_slice(&name_hash);
        encoded[64..96].copy_from_slice(&version_hash);

        // uint256 chainId (big-endian, right-aligned in 32 bytes)
        encoded[120..128].copy_from_slice(&self.chain_id.to_be_bytes());

        // address verifyingContract (right-aligned in 32 bytes, last 20 bytes)
        encoded[140..160].copy_from_slice(self.verifying_contract);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&Keccak256::digest(encoded));
        hash
    }
}

/// Compute the EIP-712 signing hash:
/// `keccak256("\x19\x01" || domain_separator || struct_hash)`
pub fn eip712_hash(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut payload = [0u8; 66]; // 2 + 32 + 32
    payload[0] = 0x19;
    payload[1] = 0x01;
    payload[2..34].copy_from_slice(domain_separator);
    payload[34..66].copy_from_slice(struct_hash);

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Keccak256::digest(payload));
    hash
}


impl traits::Signer for EthereumSigner {
    type Signature = EthereumSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<EthereumSignature, SignerError> {
        let digest = Keccak256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        self.sign_digest(&hash)
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<EthereumSignature, SignerError> {
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

impl traits::KeyPair for EthereumSigner {
    fn generate() -> Result<Self, SignerError> {
        let signing_key = SigningKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
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

/// Ethereum ECDSA verifier.
pub struct EthereumVerifier {
    verifying_key: VerifyingKey,
}

impl EthereumVerifier {
    /// Create a verifier from raw compressed or uncompressed public key bytes.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| SignerError::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Verify against a pre-hashed digest.
    fn verify_digest(
        &self,
        digest: &[u8; 32],
        signature: &EthereumSignature,
    ) -> Result<bool, SignerError> {
        let rec_id = RecoveryId::from_byte(signature.v.wrapping_sub(27))
            .ok_or_else(|| SignerError::InvalidSignature("invalid recovery id".into()))?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let k256_sig = K256Signature::from_bytes((&sig_bytes).into())
            .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;

        let recovered = VerifyingKey::recover_from_prehash(digest, &k256_sig, rec_id)
            .map_err(|e| SignerError::InvalidSignature(e.to_string()))?;

        Ok(bool::from(
            recovered
                .to_encoded_point(true)
                .as_bytes()
                .ct_eq(self.verifying_key.to_encoded_point(true).as_bytes()),
        ))
    }
}

impl traits::Verifier for EthereumVerifier {
    type Signature = EthereumSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &EthereumSignature) -> Result<bool, SignerError> {
        let digest = Keccak256::digest(message);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        self.verify_digest(&hash, signature)
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &EthereumSignature,
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

impl EthereumVerifier {
    /// **EIP-712**: Verify a typed data signature.
    ///
    /// Recomputes `keccak256("\x19\x01" || domain_separator || struct_hash)` and verifies.
    pub fn verify_typed_data(
        &self,
        domain_separator: &[u8; 32],
        struct_hash: &[u8; 32],
        signature: &EthereumSignature,
    ) -> Result<bool, SignerError> {
        let digest = eip712_hash(domain_separator, struct_hash);
        self.verify_digest(&digest, signature)
    }

    /// **EIP-191**: Verify a personal message signature.
    ///
    /// Recomputes `keccak256("\x19Ethereum Signed Message:\n{len}{message}")` and verifies.
    pub fn verify_personal_sign(
        &self,
        message: &[u8],
        signature: &EthereumSignature,
    ) -> Result<bool, SignerError> {
        let digest = eip191_hash(message);
        self.verify_digest(&digest, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_generate_keypair() {
        let signer = EthereumSigner::generate().unwrap();
        let pubkey = signer.public_key_bytes();
        assert_eq!(pubkey.len(), 33); // compressed
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let key_bytes = signer.private_key_bytes();
        let restored = EthereumSigner::from_bytes(&key_bytes).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let msg = b"hello ethereum";
        let sig = signer.sign(msg).unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_keccak256_hash() {
        let hash = Keccak256::digest(b"hello");
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_low_s_enforcement() {
        // Sign many messages and verify S is always <= N/2
        use k256::elliptic_curve::Curve;
        let signer = EthereumSigner::generate().unwrap();
        let order = k256::Secp256k1::ORDER;
        let half_n = order.shr_vartime(1);

        for i in 0u32..50 {
            let msg = format!("test message {}", i);
            let sig = signer.sign(msg.as_bytes()).unwrap();
            let s = k256::U256::from_be_slice(&sig.s);
            assert!(s <= half_n, "S value not low-S normalized");
        }
    }

    #[test]
    fn test_recovery_id() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"test recovery").unwrap();
        assert!(sig.v == 27 || sig.v == 28);
    }

    #[test]
    fn test_address_derivation() {
        // Known test vector: private key -> Ethereum address
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279f3c6f2b54729a0f29e")
                .unwrap();
        let signer = EthereumSigner::from_bytes(&privkey).unwrap();
        let addr = signer.address();
        assert_eq!(
            hex::encode(addr).to_lowercase(),
            "0d77521fa96e4c41e4190cab2dbe0d613c4afa9d"
        );
    }

    #[test]
    fn test_known_vector_eth() {
        // Known private key -> sign "hello" -> verify passes
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279f3c6f2b54729a0f29e")
                .unwrap();
        let signer = EthereumSigner::from_bytes(&privkey).unwrap();
        let sig = signer.sign(b"hello").unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello", &sig).unwrap());
        // v must be 27 or 28
        assert!(sig.v == 27 || sig.v == 28);
    }

    #[test]
    fn test_invalid_privkey_rejected() {
        // All zeros
        assert!(EthereumSigner::from_bytes(&[0u8; 32]).is_err());
        // Too short
        assert!(EthereumSigner::from_bytes(&[1u8; 31]).is_err());
        // Too long
        assert!(EthereumSigner::from_bytes(&[1u8; 33]).is_err());
    }

    #[test]
    fn test_tampered_sig_fails() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"test tamper").unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();

        // Flip a byte in r
        let mut tampered = sig.clone();
        tampered.r[0] ^= 0xff;
        // Tampered signature should either fail verification or return false
        let result = verifier.verify(b"test tamper", &tampered);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let signer1 = EthereumSigner::generate().unwrap();
        let signer2 = EthereumSigner::generate().unwrap();
        let sig = signer1.sign(b"test wrong key").unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer2.public_key_bytes()).unwrap();
        let result = verifier.verify(b"test wrong key", &sig).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_empty_message() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"").unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"", &sig).unwrap());
    }

    #[test]
    fn test_large_message() {
        let signer = EthereumSigner::generate().unwrap();
        let msg = vec![0xab_u8; 1_000_000]; // 1 MB
        let sig = signer.sign(&msg).unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(&msg, &sig).unwrap());
    }

    #[test]
    fn test_sign_prehashed_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let msg = b"prehash test";
        let digest = Keccak256::digest(msg);

        let sig_raw = signer.sign(msg).unwrap();
        let sig_pre = signer.sign_prehashed(&digest).unwrap();

        // Both should verify
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(msg, &sig_raw).unwrap());
        assert!(verifier.verify_prehashed(&digest, &sig_pre).unwrap());
    }

    #[test]
    fn test_verify_prehashed() {
        let signer = EthereumSigner::generate().unwrap();
        let msg = b"verify prehash";
        let digest = Keccak256::digest(msg);
        let sig = signer.sign(msg).unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify_prehashed(&digest, &sig).unwrap());
    }

    #[test]
    fn test_zeroize_on_drop() {
        let signer = EthereumSigner::generate().unwrap();
        let key_bytes = signer.private_key_bytes();
        // Verify the type is Zeroizing (compile-time guarantee)
        let _: Zeroizing<Vec<u8>> = key_bytes;
        // Drop and generate fresh — verifying the API contract
        drop(signer);
        let fresh = EthereumSigner::generate().unwrap();
        let _: Zeroizing<Vec<u8>> = fresh.private_key_bytes();
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = EthereumSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.r, restored.r);
        assert_eq!(sig.s, restored.s);
        assert_eq!(sig.v, restored.v);
    }

    // ─── EIP-712 Tests ──────────────────────────────────────────────────

    #[test]
    fn test_eip712_domain_type_hash() {
        let type_hash = Eip712Domain::type_hash();
        // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        let expected = Keccak256::digest(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        assert_eq!(type_hash[..], expected[..]);
    }

    #[test]
    fn test_eip712_domain_separator() {
        let contract_addr: [u8; 20] = [0xCC; 20];
        let domain = Eip712Domain {
            name: "TestDapp",
            version: "1",
            chain_id: 1,
            verifying_contract: &contract_addr,
        };
        let sep = domain.separator();
        // Domain separator must be 32 bytes and deterministic
        assert_eq!(sep.len(), 32);
        let sep2 = domain.separator();
        assert_eq!(sep, sep2);
    }

    #[test]
    fn test_eip712_hash_prefix() {
        let domain_sep = [0xAA_u8; 32];
        let struct_hash = [0xBB_u8; 32];
        let hash = eip712_hash(&domain_sep, &struct_hash);
        // The hash must be 32 bytes and different from just keccak256(struct_hash)
        assert_eq!(hash.len(), 32);
        let plain_hash = Keccak256::digest(struct_hash);
        assert_ne!(&hash[..], &plain_hash[..]);
    }

    #[test]
    fn test_eip712_sign_verify_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();

        let contract_addr: [u8; 20] = [0xCC; 20];
        let domain = Eip712Domain {
            name: "MyDapp",
            version: "1",
            chain_id: 1,
            verifying_contract: &contract_addr,
        };
        let domain_sep = domain.separator();

        // Simulate a struct hash (e.g., keccak256 of an encoded Permit struct)
        let struct_hash: [u8; 32] = {
            let mut h = [0u8; 32];
            h.copy_from_slice(&Keccak256::digest(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"));
            h
        };

        let sig = signer.sign_typed_data(&domain_sep, &struct_hash).unwrap();
        assert!(sig.v == 27 || sig.v == 28);

        // Verify
        assert!(verifier.verify_typed_data(&domain_sep, &struct_hash, &sig).unwrap());
    }

    #[test]
    fn test_eip712_wrong_domain_fails() {
        let signer = EthereumSigner::generate().unwrap();
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();

        let struct_hash = [0xBB_u8; 32];
        let domain_sep = [0xAA_u8; 32];
        let sig = signer.sign_typed_data(&domain_sep, &struct_hash).unwrap();

        // Verify with wrong domain must fail
        let wrong_domain = [0xFF_u8; 32];
        let result = verifier.verify_typed_data(&wrong_domain, &struct_hash, &sig).unwrap();
        assert!(!result);
    }

    // ─── EIP-191 Tests ──────────────────────────────────────────────────

    #[test]
    fn test_eip191_sign_verify_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let msg = b"Hello from trad-signer!";
        let sig = signer.personal_sign(msg).unwrap();
        assert!(sig.v == 27 || sig.v == 28);
        assert!(verifier.verify_personal_sign(msg, &sig).unwrap());
    }

    #[test]
    fn test_eip191_hash_known_vector() {
        // keccak256("\x19Ethereum Signed Message:\n5hello")
        let hash = eip191_hash(b"hello");
        let expected = Keccak256::digest(b"\x19Ethereum Signed Message:\n5hello");
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_eip191_wrong_message_fails() {
        let signer = EthereumSigner::generate().unwrap();
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let sig = signer.personal_sign(b"correct message").unwrap();
        let result = verifier.verify_personal_sign(b"wrong message", &sig);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_eip191_differs_from_raw_sign() {
        let signer = EthereumSigner::generate().unwrap();
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let msg = b"test";
        let raw_sig = signer.sign(msg).unwrap();
        let personal_sig = signer.personal_sign(msg).unwrap();
        // They must produce different signatures (different hash)
        assert_ne!(raw_sig.r, personal_sig.r);
        // personal_sign signature should NOT verify via raw verify
        let result = verifier.verify(msg, &personal_sig).unwrap();
        assert!(!result);
    }
}
