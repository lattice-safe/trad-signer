//! **BIP-32** Hierarchical Deterministic (HD) key derivation for secp256k1.
//!
//! Implements master key generation from seed, hardened & normal child derivation,
//! and BIP-44 path parsing (`m/44'/60'/0'/0/0`).
//!
//! # Example
//! ```no_run
//! use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let seed = [0xab_u8; 64];
//!     let master = ExtendedPrivateKey::from_seed(&seed)?;
//!     let path = DerivationPath::parse("m/44'/60'/0'/0/0")?;
//!     let child = master.derive_path(&path)?;
//!     Ok(())
//! }
//! ```

use crate::crypto;
use crate::error::SignerError;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// The BIP-32 master key derivation salt.
const BIP32_SEED_KEY: &[u8] = b"Bitcoin seed";

/// A BIP-32 extended private key (key + chain code).
pub struct ExtendedPrivateKey {
    /// The 32-byte private key scalar.
    key: Zeroizing<[u8; 32]>,
    /// The 32-byte chain code used for child derivation.
    /// Chain code is security-sensitive: knowing it + public key enables
    /// deriving all non-hardened child keys.
    chain_code: Zeroizing<[u8; 32]>,
    /// Derivation depth (0 = master).
    depth: u8,
    /// Parent key fingerprint (first 4 bytes of HASH160(parent_pubkey)).
    parent_fingerprint: [u8; 4],
    /// Child index used in derivation (includes hardened bit if applicable).
    child_index: u32,
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        // key and chain_code are both Zeroizing — automatically scrubbed on drop.
    }
}

impl ExtendedPrivateKey {
    /// Derive the master key from a BIP-39 seed (typically 16–64 bytes).
    ///
    /// Computes `HMAC-SHA512("Bitcoin seed", seed)`.
    /// Left 32 bytes = private key, right 32 bytes = chain code.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignerError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "BIP-32 seed must be 16–64 bytes, got {}",
                seed.len()
            )));
        }

        let mut mac = HmacSha512::new_from_slice(BIP32_SEED_KEY)
            .map_err(|_| SignerError::InvalidPrivateKey("HMAC init failed".into()))?;
        mac.update(seed);
        let mut result = mac.finalize().into_bytes();

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&result[..32]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        chain_code.copy_from_slice(&result[32..]);

        // Zeroize the full HMAC output immediately
        use zeroize::Zeroize;
        for b in result.iter_mut() {
            b.zeroize();
        }

        // Validate the key is a valid secp256k1 scalar
        k256::SecretKey::from_bytes((&*key).into())
            .map_err(|_| SignerError::InvalidPrivateKey("master key is zero or >= n".into()))?;

        Ok(Self {
            key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
        })
    }

    /// Derive a child key at the given index.
    ///
    /// If `hardened` is true, uses hardened derivation (index + 0x80000000).
    pub fn derive_child(&self, index: u32, hardened: bool) -> Result<Self, SignerError> {
        use zeroize::Zeroize;

        let mut mac = HmacSha512::new_from_slice(&*self.chain_code)
            .map_err(|_| SignerError::InvalidPrivateKey("HMAC init failed".into()))?;

        let effective_index = if hardened {
            index.checked_add(0x8000_0000)
                .ok_or_else(|| SignerError::InvalidPrivateKey("index overflow".into()))?
        } else {
            index
        };

        if hardened {
            // Hardened: HMAC-SHA512(chain_code, 0x00 || key || index)
            mac.update(&[0x00]);
            mac.update(&*self.key);
        } else {
            // Normal: HMAC-SHA512(chain_code, public_key || index)
            let sk = k256::SecretKey::from_bytes((&*self.key).into())
                .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
            let pk = sk.public_key().to_encoded_point(true);
            mac.update(pk.as_bytes());
        }

        mac.update(&effective_index.to_be_bytes());
        let mut result = mac.finalize().into_bytes();

        let mut il = [0u8; 32];
        il.copy_from_slice(&result[..32]);
        let mut child_chain = Zeroizing::new([0u8; 32]);
        child_chain.copy_from_slice(&result[32..]);

        // Zeroize the full HMAC output immediately — il and child_chain are copies
        for b in result.iter_mut() {
            b.zeroize();
        }

        // child_key = (il + parent_key) mod n
        let derive_result = (|| -> Result<Zeroizing<[u8; 32]>, SignerError> {
            let parent_scalar = k256::NonZeroScalar::try_from(&*self.key as &[u8])
                .map_err(|_| SignerError::InvalidPrivateKey("parent key invalid".into()))?;
            let il_scalar = k256::NonZeroScalar::try_from(&il as &[u8])
                .map_err(|_| SignerError::InvalidPrivateKey("derived key is zero".into()))?;

            // Add scalars: parent + il mod n
            let child_scalar = parent_scalar.as_ref() + il_scalar.as_ref();

            // Validate the child scalar is non-zero (CtOption -> Option)
            let child_nz: Option<k256::NonZeroScalar> =
                k256::NonZeroScalar::new(child_scalar).into();
            let child_secret = k256::SecretKey::from(
                child_nz.ok_or_else(|| {
                    SignerError::InvalidPrivateKey("child key is zero".into())
                })?,
            );

            let mut child_key = Zeroizing::new([0u8; 32]);
            child_key.copy_from_slice(&child_secret.to_bytes());
            Ok(child_key)
        })();

        // Always zeroize il regardless of success/failure
        il.zeroize();

        let child_key = derive_result?;

        // Compute parent fingerprint: HASH160(parent_pubkey)[..4]
        let parent_fp = {
            let sk = k256::SecretKey::from_bytes((&*self.key).into())
                .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
            let pk_bytes = sk.public_key().to_encoded_point(true);
            let h160 = crypto::hash160(pk_bytes.as_bytes());
            let mut fp = [0u8; 4];
            fp.copy_from_slice(&h160[..4]);
            fp
        };

        Ok(Self {
            key: child_key,
            chain_code: child_chain,
            depth: self.depth.saturating_add(1),
            parent_fingerprint: parent_fp,
            child_index: effective_index,
        })
    }

    /// Derive a child key following a full derivation path.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, SignerError> {
        let mut current = Self {
            key: self.key.clone(),
            chain_code: self.chain_code.clone(),
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
        };
        for step in &path.steps {
            current = current.derive_child(step.index, step.hardened)?;
        }
        Ok(current)
    }

    /// Get the raw 32-byte private key.
    #[must_use]
    pub fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.key.to_vec())
    }

    /// Get the compressed public key (33 bytes).
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, SignerError> {
        let sk = k256::SecretKey::from_bytes((&*self.key).into())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        Ok(sk.public_key().to_encoded_point(true).as_bytes().to_vec())
    }

    /// Get the current derivation depth (0 = master).
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the chain code (useful for extended public key export).
    #[must_use]
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the parent key fingerprint (4 bytes).
    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    /// Get the child index used in this key's derivation.
    pub fn child_index(&self) -> u32 {
        self.child_index
    }

    /// Serialize as an **xprv** Base58Check string (BIP-32).
    ///
    /// Format: `4 bytes version || 1 byte depth || 4 bytes fingerprint || 4 bytes child index || 32 bytes chain code || 1 byte 0x00 || 32 bytes key`
    ///
    /// # Security
    /// The returned String contains the private key — handle with care.
    #[must_use]
    pub fn to_xprv(&self) -> Zeroizing<String> {
        let mut data = Zeroizing::new(Vec::with_capacity(82));
        data.extend_from_slice(&[0x04, 0x88, 0xAD, 0xE4]); // xprv version
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&*self.chain_code);
        data.push(0x00); // private key prefix
        data.extend_from_slice(&*self.key);
        // Base58Check: double-SHA256 checksum
        let checksum = crypto::double_sha256(&data);
        data.extend_from_slice(&checksum[..4]);
        Zeroizing::new(bs58::encode(&*data).into_string())
    }

    /// Serialize the public key as an **xpub** Base58Check string (BIP-32).
    pub fn to_xpub(&self) -> Result<String, SignerError> {
        let pubkey = self.public_key_bytes()?;
        let mut data = Vec::with_capacity(82);
        data.extend_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&*self.chain_code);
        data.extend_from_slice(&pubkey);
        let checksum = crypto::double_sha256(&data);
        data.extend_from_slice(&checksum[..4]);
        Ok(bs58::encode(data).into_string())
    }

    /// Deserialize an **xprv** Base58Check string back into an extended private key.
    pub fn from_xprv(xprv: &str) -> Result<Self, SignerError> {
        let data = Zeroizing::new(
            bs58::decode(xprv)
                .into_vec()
                .map_err(|e| SignerError::InvalidPrivateKey(format!("invalid base58: {e}")))?,
        );
        if data.len() != 82 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "xprv must be 82 bytes, got {}", data.len()
            )));
        }
        // Verify checksum (constant-time)
        let checksum = crypto::double_sha256(&data[..78]);
        use subtle::ConstantTimeEq;
        if data[78..82].ct_eq(&checksum[..4]).unwrap_u8() != 1 {
            return Err(SignerError::InvalidPrivateKey("invalid xprv checksum".into()));
        }
        // Verify version
        if data[..4] != [0x04, 0x88, 0xAD, 0xE4] {
            return Err(SignerError::InvalidPrivateKey("not an xprv (wrong version)".into()));
        }
        let depth = data[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);
        let child_index = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
        let mut chain_code = Zeroizing::new([0u8; 32]);
        chain_code.copy_from_slice(&data[13..45]);
        // data[45] should be 0x00 (private key prefix)
        if data[45] != 0x00 {
            return Err(SignerError::InvalidPrivateKey("invalid private key prefix".into()));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&data[46..78]);
        // Validate the key
        k256::SecretKey::from_bytes((&*key).into())
            .map_err(|_| SignerError::InvalidPrivateKey("invalid xprv key".into()))?;
        Ok(Self { key, chain_code, depth, parent_fingerprint, child_index })
    }

    /// Convert to an `ExtendedPublicKey` for watch-only derivation.
    pub fn to_extended_public_key(&self) -> Result<ExtendedPublicKey, SignerError> {
        let pubkey_bytes = self.public_key_bytes()?;
        let mut key = [0u8; 33];
        key.copy_from_slice(&pubkey_bytes);
        Ok(ExtendedPublicKey {
            key,
            chain_code: *self.chain_code,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
        })
    }
}

// ─── Extended Public Key (BIP-32 Watch-Only) ────────────────────────

/// A BIP-32 extended public key for watch-only wallets.
///
/// Supports **normal** (non-hardened) child derivation only.
/// Hardened derivation requires the private key.
#[derive(Clone, Debug)]
pub struct ExtendedPublicKey {
    /// Compressed SEC1 public key (33 bytes).
    key: [u8; 33],
    /// Chain code (32 bytes).
    chain_code: [u8; 32],
    /// Derivation depth.
    depth: u8,
    /// Parent key fingerprint.
    parent_fingerprint: [u8; 4],
    /// Child index.
    child_index: u32,
}

impl ExtendedPublicKey {
    /// Get the compressed public key (33 bytes).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8; 33] {
        &self.key
    }

    /// Get the derivation depth.
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the chain code.
    #[must_use]
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Get the parent fingerprint.
    #[must_use]
    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    /// Get the child index.
    #[must_use]
    pub fn child_index(&self) -> u32 {
        self.child_index
    }

    /// Derive a **normal** (non-hardened) child public key.
    ///
    /// Only normal derivation (index < 2^31) is supported.
    /// Hardened derivation requires the private key.
    pub fn derive_child_normal(&self, index: u32) -> Result<Self, SignerError> {
        if index >= 0x8000_0000 {
            return Err(SignerError::InvalidPrivateKey(
                "hardened derivation requires private key".into(),
            ));
        }

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .map_err(|_| SignerError::InvalidPrivateKey("HMAC init failed".into()))?;

        // For normal child: HMAC-SHA512(chain_code, pubkey || index)
        mac.update(&self.key);
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        let mut il = [0u8; 32];
        il.copy_from_slice(&result[..32]);
        let mut child_chain = [0u8; 32];
        child_chain.copy_from_slice(&result[32..]);

        // Parse IL as scalar and add to parent point
        use k256::elliptic_curve::ops::Reduce;
        use k256::{ProjectivePoint, Scalar, U256};
        use k256::elliptic_curve::group::GroupEncoding;

        let il_scalar = <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(&il));
        let parent_point = k256::AffinePoint::from_bytes((&self.key).into());
        let parent_proj: ProjectivePoint = Option::from(parent_point.map(ProjectivePoint::from))
            .ok_or_else(|| SignerError::InvalidPublicKey("invalid parent public key".into()))?;

        let child_point = parent_proj + ProjectivePoint::GENERATOR * il_scalar;

        // Serialize child public key
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let child_affine = child_point.to_affine();
        let encoded = child_affine.to_encoded_point(true);
        let child_key_bytes = encoded.as_bytes();
        if child_key_bytes.len() != 33 {
            return Err(SignerError::InvalidPublicKey("child key serialization failed".into()));
        }
        let mut child_key = [0u8; 33];
        child_key.copy_from_slice(child_key_bytes);

        // Parent fingerprint = first 4 bytes of HASH160(parent_pubkey)
        let fingerprint = crypto::hash160(&self.key);
        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&fingerprint[..4]);

        // Zeroize IL
        use zeroize::Zeroize;
        il.zeroize();

        Ok(Self {
            key: child_key,
            chain_code: child_chain,
            depth: self.depth.checked_add(1).ok_or_else(|| {
                SignerError::InvalidPrivateKey("derivation depth overflow".into())
            })?,
            parent_fingerprint: parent_fp,
            child_index: index,
        })
    }

    /// Serialize as an **xpub** Base58Check string.
    #[must_use]
    pub fn to_xpub(&self) -> String {
        let mut data = Vec::with_capacity(82);
        data.extend_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&self.key);
        let checksum = crypto::double_sha256(&data);
        data.extend_from_slice(&checksum[..4]);
        bs58::encode(data).into_string()
    }

    /// Deserialize an **xpub** Base58Check string.
    pub fn from_xpub(xpub: &str) -> Result<Self, SignerError> {
        let data = bs58::decode(xpub)
            .into_vec()
            .map_err(|e| SignerError::InvalidPublicKey(format!("invalid base58: {e}")))?;
        if data.len() != 82 {
            return Err(SignerError::InvalidPublicKey(format!(
                "xpub must be 82 bytes, got {}", data.len()
            )));
        }
        let checksum = crypto::double_sha256(&data[..78]);
        use subtle::ConstantTimeEq;
        if data[78..82].ct_eq(&checksum[..4]).unwrap_u8() != 1 {
            return Err(SignerError::InvalidPublicKey("invalid xpub checksum".into()));
        }
        if data[..4] != [0x04, 0x88, 0xB2, 0x1E] {
            return Err(SignerError::InvalidPublicKey("not an xpub (wrong version)".into()));
        }
        let depth = data[4];
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);
        let child_index = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);
        let mut key = [0u8; 33];
        key.copy_from_slice(&data[45..78]);
        // Validate the public key is on the curve
        let _pt = k256::AffinePoint::from_bytes((&key).into());
        use k256::elliptic_curve::group::GroupEncoding;
        if bool::from(k256::AffinePoint::from_bytes((&key).into()).is_none()) {
            return Err(SignerError::InvalidPublicKey("invalid xpub key point".into()));
        }
        Ok(Self { key, chain_code, depth, parent_fingerprint, child_index })
    }
}

/// A single step in a BIP-32 derivation path.
#[derive(Debug, Clone)]
pub struct DerivationStep {
    /// Child index (0-based).
    pub index: u32,
    /// Whether this is a hardened derivation step.
    pub hardened: bool,
}

/// A BIP-32/BIP-44 derivation path (e.g., `m/44'/60'/0'/0/0`).
#[derive(Debug, Clone)]
pub struct DerivationPath {
    /// The steps in this path.
    pub steps: Vec<DerivationStep>,
}

impl DerivationPath {
    /// Parse a BIP-32 path string like `"m/44'/60'/0'/0/0"`.
    ///
    /// Supported formats: `44'` or `44h` for hardened.
    pub fn parse(path: &str) -> Result<Self, SignerError> {
        let path = path.trim();
        let segments: Vec<&str> = path.split('/').collect();

        if segments.is_empty() {
            return Err(SignerError::InvalidPrivateKey("empty derivation path".into()));
        }

        // First segment must be "m" or "M"
        if segments[0] != "m" && segments[0] != "M" {
            return Err(SignerError::InvalidPrivateKey(
                "derivation path must start with 'm/'".into(),
            ));
        }

        let mut steps = Vec::new();
        for seg in &segments[1..] {
            if seg.is_empty() {
                continue;
            }
            let (hardened, num_str) = if seg.ends_with('\'') || seg.ends_with('h') || seg.ends_with('H') {
                (true, &seg[..seg.len() - 1])
            } else {
                (false, *seg)
            };

            let index: u32 = num_str.parse().map_err(|_| {
                SignerError::InvalidPrivateKey(format!("invalid path segment: {seg}"))
            })?;

            if index >= 0x8000_0000 {
                return Err(SignerError::InvalidPrivateKey(format!(
                    "index {index} too large (must be < 2^31)"
                )));
            }

            steps.push(DerivationStep { index, hardened });
        }

        Ok(Self { steps })
    }

    /// BIP-44 Ethereum path: `m/44'/60'/0'/0/{index}`
    pub fn ethereum(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 60, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: false },
                DerivationStep { index, hardened: false },
            ],
        }
    }

    /// BIP-44 Bitcoin path: `m/44'/0'/0'/0/{index}`
    pub fn bitcoin(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: false },
                DerivationStep { index, hardened: false },
            ],
        }
    }

    /// BIP-84 Bitcoin Segwit path: `m/84'/0'/0'/0/{index}`
    pub fn bitcoin_segwit(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 84, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: false },
                DerivationStep { index, hardened: false },
            ],
        }
    }

    /// BIP-86 Bitcoin Taproot path: `m/86'/0'/0'/0/{index}`
    pub fn bitcoin_taproot(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 86, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: false },
                DerivationStep { index, hardened: false },
            ],
        }
    }

    /// BIP-44 Solana path: `m/44'/501'/{index}'/0'`
    pub fn solana(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 501, hardened: true },
                DerivationStep { index, hardened: true },
                DerivationStep { index: 0, hardened: true },
            ],
        }
    }

    /// BIP-44 XRP path: `m/44'/144'/0'/0/{index}`
    pub fn xrp(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 144, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: false },
                DerivationStep { index, hardened: false },
            ],
        }
    }

    /// BIP-44 NEO path: `m/44'/888'/0'/0/{index}`
    pub fn neo(index: u32) -> Self {
        Self {
            steps: vec![
                DerivationStep { index: 44, hardened: true },
                DerivationStep { index: 888, hardened: true },
                DerivationStep { index: 0, hardened: true },
                DerivationStep { index: 0, hardened: false },
                DerivationStep { index, hardened: false },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 Test Vector 1 (from BIP-32 spec)
    // Seed: 000102030405060708090a0b0c0d0e0f
    #[test]
    fn test_bip32_vector1_master() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let pk = master.public_key_bytes().unwrap();

        assert_eq!(
            hex::encode(&*master.private_key_bytes()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(&pk),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
        assert_eq!(
            hex::encode(master.chain_code()),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
    }

    #[test]
    fn test_bip32_vector1_child_0h() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let child = master.derive_child(0, true).unwrap();

        assert_eq!(
            hex::encode(&*child.private_key_bytes()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(child.depth(), 1);
    }

    #[test]
    fn test_bip32_vector1_path_m44h_60h_0h_0_0() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let child = master.derive_path(&path).unwrap();
        assert_eq!(child.depth(), 5);
        assert_eq!(child.private_key_bytes().len(), 32);
        // Ensure deterministic — derive twice
        let child2 = master.derive_path(&path).unwrap();
        assert_eq!(&*child.private_key_bytes(), &*child2.private_key_bytes());
    }

    #[test]
    fn test_bip32_vector2_seed() {
        // BIP-32 Test Vector 2
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(&*master.private_key_bytes()),
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        );
        assert_eq!(
            hex::encode(master.chain_code()),
            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"
        );
    }

    #[test]
    fn test_derivation_path_parse() {
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.steps.len(), 5);
        assert!(path.steps[0].hardened);
        assert_eq!(path.steps[0].index, 44);
        assert!(path.steps[1].hardened);
        assert_eq!(path.steps[1].index, 60);
        assert!(!path.steps[3].hardened);
        assert_eq!(path.steps[4].index, 0);
    }

    #[test]
    fn test_derivation_path_shortcuts() {
        let eth = DerivationPath::ethereum(0);
        assert_eq!(eth.steps.len(), 5);
        assert_eq!(eth.steps[1].index, 60);

        let btc = DerivationPath::bitcoin(0);
        assert_eq!(btc.steps[1].index, 0);

        let sol = DerivationPath::solana(0);
        assert_eq!(sol.steps[1].index, 501);
        assert_eq!(sol.steps.len(), 4); // Solana uses all-hardened
    }

    #[test]
    fn test_invalid_path_rejected() {
        assert!(DerivationPath::parse("").is_err());
        assert!(DerivationPath::parse("x/44'/60'").is_err());
    }

    #[test]
    fn test_seed_length_validation() {
        assert!(ExtendedPrivateKey::from_seed(&[0u8; 15]).is_err());
        assert!(ExtendedPrivateKey::from_seed(&[0u8; 65]).is_err());
        assert!(ExtendedPrivateKey::from_seed(&[0u8; 16]).is_ok());
        assert!(ExtendedPrivateKey::from_seed(&[0u8; 64]).is_ok());
    }

    #[test]
    fn test_normal_vs_hardened_different_keys() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let normal = master.derive_child(0, false).unwrap();
        let hardened = master.derive_child(0, true).unwrap();
        assert_ne!(&*normal.private_key_bytes(), &*hardened.private_key_bytes());
    }

    #[test]
    fn test_multi_account_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        let eth0 = master.derive_path(&DerivationPath::ethereum(0)).unwrap();
        let eth1 = master.derive_path(&DerivationPath::ethereum(1)).unwrap();
        let btc0 = master.derive_path(&DerivationPath::bitcoin(0)).unwrap();

        // All different keys
        assert_ne!(&*eth0.private_key_bytes(), &*eth1.private_key_bytes());
        assert_ne!(&*eth0.private_key_bytes(), &*btc0.private_key_bytes());
    }

    // ─── BIP-32 Vector 1: xprv/xpub Serialization ───────────────

    #[test]
    fn test_bip32_vector1_master_xprv() {
        // BIP-32 Test Vector 1 — Master key xprv
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(
            &*master.to_xprv(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
    }

    #[test]
    fn test_bip32_vector1_master_xpub() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(
            master.to_xpub().unwrap(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }

    #[test]
    fn test_bip32_vector1_chain_m_0h() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let child = master.derive_child(0, true).unwrap();
        assert_eq!(
            &*child.to_xprv(),
            "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        );
        assert_eq!(
            child.to_xpub().unwrap(),
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        );
    }

    #[test]
    fn test_bip32_xprv_roundtrip() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let xprv_str = master.to_xprv();
        let restored = ExtendedPrivateKey::from_xprv(&xprv_str).unwrap();
        assert_eq!(&*master.private_key_bytes(), &*restored.private_key_bytes());
        assert_eq!(master.chain_code(), restored.chain_code());
        assert_eq!(master.depth(), restored.depth());
    }

    #[test]
    fn test_bip32_from_xprv_invalid_checksum() {
        // Valid xprv but flip last character to break checksum
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHiX";
        // This should fail because the checksum is invalid (we appended 'X')
        // But the base58 decoding may also fail since length changes
        assert!(ExtendedPrivateKey::from_xprv(xprv).is_err());
    }

    // ─── BIP-32 Vector 2: Full chain ────────────────────────────

    #[test]
    fn test_bip32_vector2_master_xprv() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        assert_eq!(
            &*master.to_xprv(),
            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        );
    }

    #[test]
    fn test_bip32_vector2_chain_m_0() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let child = master.derive_child(0, false).unwrap();
        assert_eq!(
            &*child.to_xprv(),
            "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        );
    }

    // ─── Derivation Path Edge Cases ─────────────────────────────

    #[test]
    fn test_derivation_path_hardened_h_notation() {
        let path = DerivationPath::parse("m/44h/60h/0h/0/0").unwrap();
        assert_eq!(path.steps.len(), 5);
        assert!(path.steps[0].hardened);
        assert_eq!(path.steps[0].index, 44);
    }

    #[test]
    fn test_derivation_path_all_chain_presets() {
        let btc_segwit = DerivationPath::bitcoin_segwit(0);
        assert_eq!(btc_segwit.steps[0].index, 84); // BIP-84
        assert!(btc_segwit.steps[0].hardened);

        let btc_taproot = DerivationPath::bitcoin_taproot(0);
        assert_eq!(btc_taproot.steps[0].index, 86); // BIP-86
        assert!(btc_taproot.steps[0].hardened);

        let xrp = DerivationPath::xrp(0);
        assert_eq!(xrp.steps[1].index, 144); // XRP coin type

        let neo = DerivationPath::neo(0);
        assert_eq!(neo.steps[1].index, 888); // NEO coin type
    }
}
