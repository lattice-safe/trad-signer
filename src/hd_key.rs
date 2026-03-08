//! **BIP-32** Hierarchical Deterministic (HD) key derivation for secp256k1.
//!
//! Implements master key generation from seed, hardened & normal child derivation,
//! and BIP-44 path parsing (`m/44'/60'/0'/0/0`).
//!
//! # Example
//! ```ignore
//! use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};
//!
//! let seed = [0xab_u8; 64];
//! let master = ExtendedPrivateKey::from_seed(&seed)?;
//! let path = DerivationPath::parse("m/44'/60'/0'/0/0")?;
//! let child = master.derive_path(&path)?;
//! let eth_signer = child.to_ethereum_signer()?;
//! ```

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
    chain_code: [u8; 32],
    /// Derivation depth (0 = master).
    depth: u8,
    /// Parent key fingerprint (first 4 bytes of HASH160(parent_pubkey)).
    parent_fingerprint: [u8; 4],
    /// Child index used in derivation (includes hardened bit if applicable).
    child_index: u32,
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        // key is Zeroizing, chain_code is not secret but good practice
        self.chain_code = [0u8; 32];
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
        let result = mac.finalize().into_bytes();

        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&result[..32]);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&result[32..]);

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

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
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
        let mut child_chain = [0u8; 32];
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
            use sha2::Digest;
            let sk = k256::SecretKey::from_bytes((&*self.key).into())
                .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
            let pk_bytes = sk.public_key().to_encoded_point(true);
            let sha = sha2::Sha256::digest(pk_bytes.as_bytes());
            let ripe = ripemd::Ripemd160::digest(sha);
            let mut fp = [0u8; 4];
            fp.copy_from_slice(&ripe[..4]);
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
            chain_code: self.chain_code,
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
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the chain code (useful for extended public key export).
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
    pub fn to_xprv(&self) -> String {
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&[0x04, 0x88, 0xAD, 0xE4]); // xprv version
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.push(0x00); // private key prefix
        data.extend_from_slice(&*self.key);
        // Base58Check: double-SHA256 checksum
        let checksum = {
            use sha2::Digest;
            let h1 = sha2::Sha256::digest(&data);
            sha2::Sha256::digest(h1)
        };
        data.extend_from_slice(&checksum[..4]);
        bs58::encode(data).into_string()
    }

    /// Serialize the public key as an **xpub** Base58Check string (BIP-32).
    pub fn to_xpub(&self) -> Result<String, SignerError> {
        let pubkey = self.public_key_bytes()?;
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.child_index.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(&pubkey);
        let checksum = {
            use sha2::Digest;
            let h1 = sha2::Sha256::digest(&data);
            sha2::Sha256::digest(h1)
        };
        data.extend_from_slice(&checksum[..4]);
        Ok(bs58::encode(data).into_string())
    }

    /// Deserialize an **xprv** Base58Check string back into an extended private key.
    pub fn from_xprv(xprv: &str) -> Result<Self, SignerError> {
        let data = bs58::decode(xprv)
            .into_vec()
            .map_err(|e| SignerError::InvalidPrivateKey(format!("invalid base58: {e}")))?;
        if data.len() != 82 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "xprv must be 82 bytes, got {}", data.len()
            )));
        }
        // Verify checksum
        let checksum = {
            use sha2::Digest;
            let h1 = sha2::Sha256::digest(&data[..78]);
            sha2::Sha256::digest(h1)
        };
        if data[78..82] != checksum[..4] {
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
        let mut chain_code = [0u8; 32];
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
}
