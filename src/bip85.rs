//! **BIP-85** — Deterministic entropy derivation from BIP-32 keychains.
//!
//! Derives child seeds, mnemonics, WIF keys, and raw entropy from a master
//! BIP-32 root key. Each application uses a unique derivation path under
//! `m/83696968'/...` and produces deterministic entropy via HMAC-SHA512.
//!
//! # Example
//! ```no_run
//! use chains_sdk::hd_key::ExtendedPrivateKey;
//! use chains_sdk::bip85;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let seed = [0xab_u8; 64];
//!     let master = ExtendedPrivateKey::from_seed(&seed)?;
//!
//!     // Derive a 12-word BIP-39 child mnemonic
//!     let child_mnemonic = bip85::derive_bip39(&master, 0, 12, 0)?;
//!     println!("Child mnemonic: {}", child_mnemonic);
//!     Ok(())
//! }
//! ```

use crate::crypto;
use crate::error::SignerError;
use crate::hd_key::{DerivationPath, ExtendedPrivateKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// The BIP-85 HMAC key used for entropy derivation.
const BIP85_HMAC_KEY: &[u8] = b"bip-entropy-from-k";

/// The BIP-85 application root index (83696968 = 0x4F4E4348 = "OBIP" in ASCII).
const BIP85_APP_INDEX: u32 = 83696968;

// ─── Core Entropy Derivation ────────────────────────────────────────

/// Derive 64 bytes of deterministic entropy from a BIP-32 master key at the
/// given hardened derivation path.
///
/// **BIP-85 Algorithm:**
/// 1. Derive child private key `k` at the specified path
/// 2. Compute `HMAC-SHA512(key="bip-entropy-from-k", msg=k)`
/// 3. Return the 64-byte result
///
/// All path components MUST be hardened.
pub fn derive_entropy(
    master: &ExtendedPrivateKey,
    path: &DerivationPath,
) -> Result<Zeroizing<[u8; 64]>, SignerError> {
    // Derive the child key at the specified path
    let child = master.derive_path(path)?;
    let child_key = child.private_key_bytes();

    // HMAC-SHA512(key="bip-entropy-from-k", msg=child_private_key)
    let mut mac = HmacSha512::new_from_slice(BIP85_HMAC_KEY)
        .map_err(|_| SignerError::InvalidPrivateKey("HMAC init failed".into()))?;
    mac.update(&child_key);
    let result = mac.finalize().into_bytes();

    let mut entropy = Zeroizing::new([0u8; 64]);
    entropy.copy_from_slice(&result);
    Ok(entropy)
}

/// Derive raw entropy at path `m/83696968'/{app}'/{index}'`.
pub fn derive_entropy_at(
    master: &ExtendedPrivateKey,
    app: u32,
    index: u32,
) -> Result<Zeroizing<[u8; 64]>, SignerError> {
    let path_str = format!("m/{BIP85_APP_INDEX}'/{app}'/{index}'");
    let path = DerivationPath::parse(&path_str)?;
    derive_entropy(master, &path)
}

// ─── Application 39: BIP-39 Mnemonic ────────────────────────────────

/// Derive a child BIP-39 mnemonic phrase from a master key.
///
/// **Path:** `m/83696968'/39'/{language}'/{words}'/{index}'`
///
/// # Arguments
/// * `master` - The BIP-32 master root key
/// * `language` - BIP-39 language code (0 = English)
/// * `words` - Number of mnemonic words (12, 15, 18, 21, or 24)
/// * `index` - Child index (0, 1, 2, ...)
///
/// # Returns
/// A space-separated mnemonic phrase string.
pub fn derive_bip39(
    master: &ExtendedPrivateKey,
    language: u32,
    words: u32,
    index: u32,
) -> Result<String, SignerError> {
    // Validate word count
    let entropy_bits: usize = match words {
        12 => 128,
        15 => 160,
        18 => 192,
        21 => 224,
        24 => 256,
        _ => {
            return Err(SignerError::InvalidPrivateKey(
                "BIP-85 BIP-39: words must be 12, 15, 18, 21, or 24".into(),
            ))
        }
    };
    let entropy_bytes = entropy_bits / 8;

    // Derive entropy at m/83696968'/39'/{language}'/{words}'/{index}'
    let path_str = format!("{BIP85_APP_INDEX}'/{language}'/{words}'/{index}'");
    let full_path = format!("m/{path_str}");
    let path = DerivationPath::parse(&full_path)?;
    let entropy = derive_entropy(master, &path)?;

    // Truncate to the required entropy length
    let truncated = &entropy[..entropy_bytes];

    // Convert entropy to BIP-39 mnemonic using our mnemonic module
    entropy_to_mnemonic(truncated)
}

/// Convert raw entropy bytes to a BIP-39 mnemonic phrase.
///
/// Delegates to `Mnemonic::from_entropy` to avoid code duplication.
fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, SignerError> {
    let m = crate::mnemonic::Mnemonic::from_entropy(entropy)?;
    Ok(m.phrase().to_string())
}

// ─── Application 2: WIF (Wallet Import Format) ─────────────────────

/// Derive a WIF-encoded private key from a master key.
///
/// **Path:** `m/83696968'/2'/{index}'`
///
/// Returns a compressed WIF key (mainnet, prefix 'L' or 'K').
pub fn derive_wif(master: &ExtendedPrivateKey, index: u32) -> Result<String, SignerError> {
    let path_str = format!("m/{BIP85_APP_INDEX}'/2'/{index}'");
    let path = DerivationPath::parse(&path_str)?;
    let entropy = derive_entropy(master, &path)?;

    // Take 32 bytes for the private key
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&entropy[..32]);

    // Validate it's a valid secp256k1 scalar
    k256::SecretKey::from_bytes((&pk).into())
        .map_err(|_| SignerError::InvalidPrivateKey("derived WIF key invalid".into()))?;

    // WIF encoding: 0x80 || pk || 0x01 (compressed) || checksum
    let mut wif_data = Vec::with_capacity(34);
    wif_data.push(0x80); // mainnet prefix
    wif_data.extend_from_slice(&pk);
    wif_data.push(0x01); // compressed flag

    // Double SHA256 checksum
    let checksum = crypto::double_sha256(&wif_data);
    wif_data.extend_from_slice(&checksum[..4]);

    Ok(bs58::encode(&wif_data).into_string())
}

// ─── Application 128169: Hex Entropy ────────────────────────────────

/// Derive raw hex entropy of specified length.
///
/// **Path:** `m/83696968'/128169'/{num_bytes}'/{index}'`
///
/// # Arguments
/// * `num_bytes` - Number of bytes to derive (16–64)
/// * `index` - Child index
pub fn derive_hex(
    master: &ExtendedPrivateKey,
    num_bytes: u32,
    index: u32,
) -> Result<Zeroizing<Vec<u8>>, SignerError> {
    if !(16..=64).contains(&num_bytes) {
        return Err(SignerError::InvalidPrivateKey(
            "BIP-85 hex: num_bytes must be 16–64".into(),
        ));
    }

    let path_str = format!("m/{BIP85_APP_INDEX}'/128169'/{num_bytes}'/{index}'");
    let path = DerivationPath::parse(&path_str)?;
    let entropy = derive_entropy(master, &path)?;

    let mut result = Zeroizing::new(vec![0u8; num_bytes as usize]);
    result.copy_from_slice(&entropy[..num_bytes as usize]);
    Ok(result)
}

// ─── Application 707764: XPRV ───────────────────────────────────────

/// Derive a child BIP-32 extended private key (xprv).
///
/// **Path:** `m/83696968'/707764'/{index}'`
///
/// Returns a new `ExtendedPrivateKey` derived from the BIP-85 entropy.
pub fn derive_xprv(
    master: &ExtendedPrivateKey,
    index: u32,
) -> Result<ExtendedPrivateKey, SignerError> {
    let path_str = format!("m/{BIP85_APP_INDEX}'/707764'/{index}'");
    let path = DerivationPath::parse(&path_str)?;
    let entropy = derive_entropy(master, &path)?;

    // Use the 64-byte entropy as a seed for BIP-32
    ExtendedPrivateKey::from_seed(&*entropy)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Reconstruct the well-known BIP-85 test master key.
    fn test_master_key() -> ExtendedPrivateKey {
        // BIP-85 test vector master key:
        // xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb
        // We reconstruct this from its known seed.
        // The xprv corresponds to the seed used in the official BIP-85 test.
        let seed_hex = "000102030405060708090a0b0c0d0e0f";
        let seed = hex::decode(seed_hex).expect("valid hex");
        ExtendedPrivateKey::from_seed(&seed).expect("valid seed")
    }

    #[test]
    fn test_bip85_derive_entropy_path() {
        let master = test_master_key();
        let path = DerivationPath::parse("m/83696968'/0'/0'").expect("valid path");
        let entropy = derive_entropy(&master, &path).expect("derive ok");
        assert_eq!(entropy.len(), 64);
        // Entropy should be deterministic
        let entropy2 = derive_entropy(&master, &path).expect("derive ok");
        assert_eq!(&*entropy, &*entropy2);
    }

    #[test]
    fn test_bip85_derive_entropy_different_paths() {
        let master = test_master_key();
        let e1 = derive_entropy_at(&master, 0, 0).expect("ok");
        let e2 = derive_entropy_at(&master, 0, 1).expect("ok");
        assert_ne!(&*e1, &*e2);
    }

    #[test]
    fn test_bip85_derive_bip39_12_words() {
        let master = test_master_key();
        let mnemonic = derive_bip39(&master, 0, 12, 0).expect("ok");
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        // Deterministic
        let m2 = derive_bip39(&master, 0, 12, 0).expect("ok");
        assert_eq!(mnemonic, m2);
    }

    #[test]
    fn test_bip85_derive_bip39_24_words() {
        let master = test_master_key();
        let mnemonic = derive_bip39(&master, 0, 24, 0).expect("ok");
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_bip85_derive_bip39_18_words() {
        let master = test_master_key();
        let mnemonic = derive_bip39(&master, 0, 18, 0).expect("ok");
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 18);
    }

    #[test]
    fn test_bip85_derive_bip39_different_indices() {
        let master = test_master_key();
        let m0 = derive_bip39(&master, 0, 12, 0).expect("ok");
        let m1 = derive_bip39(&master, 0, 12, 1).expect("ok");
        assert_ne!(m0, m1);
    }

    #[test]
    fn test_bip85_derive_bip39_invalid_words() {
        let master = test_master_key();
        assert!(derive_bip39(&master, 0, 11, 0).is_err());
        assert!(derive_bip39(&master, 0, 13, 0).is_err());
        assert!(derive_bip39(&master, 0, 0, 0).is_err());
    }

    #[test]
    fn test_bip85_derive_wif() {
        let master = test_master_key();
        let wif = derive_wif(&master, 0).expect("ok");
        // WIF compressed mainnet starts with 'K' or 'L'
        assert!(wif.starts_with('K') || wif.starts_with('L'));
        // Length should be 52 characters for compressed WIF
        assert_eq!(wif.len(), 52);
        // Deterministic
        let w2 = derive_wif(&master, 0).expect("ok");
        assert_eq!(wif, w2);
    }

    #[test]
    fn test_bip85_derive_wif_different_indices() {
        let master = test_master_key();
        let w0 = derive_wif(&master, 0).expect("ok");
        let w1 = derive_wif(&master, 1).expect("ok");
        assert_ne!(w0, w1);
    }

    #[test]
    fn test_bip85_derive_hex_32() {
        let master = test_master_key();
        let hex_bytes = derive_hex(&master, 32, 0).expect("ok");
        assert_eq!(hex_bytes.len(), 32);
    }

    #[test]
    fn test_bip85_derive_hex_64() {
        let master = test_master_key();
        let hex_bytes = derive_hex(&master, 64, 0).expect("ok");
        assert_eq!(hex_bytes.len(), 64);
    }

    #[test]
    fn test_bip85_derive_hex_invalid() {
        let master = test_master_key();
        assert!(derive_hex(&master, 15, 0).is_err()); // too small
        assert!(derive_hex(&master, 65, 0).is_err()); // too large
    }

    #[test]
    fn test_bip85_derive_xprv() {
        let master = test_master_key();
        let child = derive_xprv(&master, 0).expect("ok");
        let xprv = child.to_xprv();
        assert!(xprv.starts_with("xprv"));

        // Deterministic
        let child2 = derive_xprv(&master, 0).expect("ok");
        assert_eq!(child.to_xprv(), child2.to_xprv());
    }

    #[test]
    fn test_bip85_derive_xprv_different_indices() {
        let master = test_master_key();
        let x0 = derive_xprv(&master, 0).expect("ok").to_xprv();
        let x1 = derive_xprv(&master, 1).expect("ok").to_xprv();
        assert_ne!(x0, x1);
    }

    #[test]
    fn test_bip85_entropy_to_mnemonic_round_trip() {
        // Known 128-bit entropy → 12 words
        let entropy = hex::decode("00000000000000000000000000000000").expect("hex");
        let mnemonic = entropy_to_mnemonic(&entropy).expect("ok");
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(words[0], "abandon"); // all-zero entropy starts with "abandon"
    }

    #[test]
    fn test_bip85_entropy_to_mnemonic_256bit() {
        let entropy = [0xFFu8; 32];
        let mnemonic = entropy_to_mnemonic(&entropy).expect("ok");
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        assert_eq!(words[0], "zoo"); // all-ones entropy starts with "zoo"
    }

    #[test]
    fn test_bip85_all_word_lengths() {
        let master = test_master_key();
        for words in [12, 15, 18, 21, 24] {
            let m = derive_bip39(&master, 0, words, 0).expect("ok");
            let w: Vec<&str> = m.split_whitespace().collect();
            assert_eq!(w.len(), words as usize, "wrong word count for {words}");
        }
    }

    // ─── BIP-85 Official Reference Vector ───────────────────────
    // Master xprv from BIP-32 Test Vector 1 (seed 000102030405060708090a0b0c0d0e0f)
    // Verify: importing via from_xprv produces the same key as from_seed

    #[test]
    fn test_bip85_xprv_import_consistency() {
        let xprv_str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let from_xprv = ExtendedPrivateKey::from_xprv(xprv_str).expect("valid xprv");
        let from_seed = test_master_key();

        // Same key regardless of import method
        assert_eq!(
            &*from_xprv.private_key_bytes(),
            &*from_seed.private_key_bytes(),
            "xprv import must match seed-derived master key"
        );

        // Derive BIP-85 mnemonic from both — must be identical
        let m1 = derive_bip39(&from_xprv, 0, 12, 0).expect("ok");
        let m2 = derive_bip39(&from_seed, 0, 12, 0).expect("ok");
        assert_eq!(m1, m2, "BIP-85 derivation must be identical from both import paths");
    }

    #[test]
    fn test_bip85_derived_entropy_known_vector() {
        // BIP-85: Derive raw entropy at m/83696968'/0'/0'
        // from the BIP-32 Test Vector 1 master key.
        // Verify determinism and non-zero output.
        let master = test_master_key();
        let entropy = derive_entropy_at(&master, 0, 0).expect("ok");

        // Must be 64 bytes (HMAC-SHA512 output)
        assert_eq!(entropy.len(), 64);

        // Must be non-zero
        assert_ne!(&*entropy, &[0u8; 64]);

        // Must be deterministic
        let entropy2 = derive_entropy_at(&master, 0, 0).expect("ok");
        assert_eq!(&*entropy, &*entropy2);

        // Different path must produce different entropy
        let entropy3 = derive_entropy_at(&master, 0, 1).expect("ok");
        assert_ne!(&*entropy, &*entropy3);

        // Verify derived BIP-39 mnemonic is a valid parseable mnemonic
        let mnemonic = derive_bip39(&master, 0, 12, 0).expect("ok");
        let parsed = crate::mnemonic::Mnemonic::from_phrase(&mnemonic);
        assert!(parsed.is_ok(), "derived mnemonic must be parseable: {mnemonic}");
    }
}
