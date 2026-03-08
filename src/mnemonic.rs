//! **BIP-39** Mnemonic seed phrase support.
//!
//! Generates 12/24-word mnemonic phrases from entropy, converts them back to
//! seeds via PBKDF2-SHA512, and integrates with the BIP-32 HD key module.
//!
//! # Example
//! ```ignore
//! use trad_signer::mnemonic::Mnemonic;
//! use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};
//!
//! let mnemonic = Mnemonic::generate(12)?; // 12-word phrase
//! let seed = mnemonic.to_seed("optional passphrase");
//! let master = ExtendedPrivateKey::from_seed(&seed)?;
//! let eth_key = master.derive_path(&DerivationPath::ethereum(0))?;
//! ```

use crate::error::SignerError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// BIP-39 English wordlist (2048 words).
const WORDLIST: &str = include_str!("bip39_english.txt");

/// A BIP-39 mnemonic phrase.
pub struct Mnemonic {
    /// The mnemonic words.
    words: Zeroizing<String>,
}

impl Mnemonic {
    /// Generate a new random mnemonic with the given word count.
    ///
    /// Supported counts: 12 (128-bit), 15 (160-bit), 18 (192-bit), 21 (224-bit), 24 (256-bit).
    pub fn generate(word_count: usize) -> Result<Self, SignerError> {
        let entropy_bits = match word_count {
            12 => 128,
            15 => 160,
            18 => 192,
            21 => 224,
            24 => 256,
            _ => {
                return Err(SignerError::InvalidPrivateKey(
                    "word count must be 12, 15, 18, 21, or 24".into(),
                ))
            }
        };

        let entropy_bytes = entropy_bits / 8;
        let mut entropy = vec![0u8; entropy_bytes];
        getrandom::getrandom(&mut entropy)
            .map_err(|_| SignerError::EntropyError)?;

        Self::from_entropy(&entropy)
    }

    /// Create a mnemonic from raw entropy bytes.
    ///
    /// Entropy length must be 16, 20, 24, 28, or 32 bytes.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, SignerError> {
        let ent_bits = entropy.len() * 8;
        if ![128, 160, 192, 224, 256].contains(&ent_bits) {
            return Err(SignerError::InvalidPrivateKey(format!(
                "entropy must be 16-32 bytes (128-256 bits), got {} bytes",
                entropy.len()
            )));
        }

        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        if wordlist.len() != 2048 {
            return Err(SignerError::InvalidPrivateKey(
                "invalid BIP-39 wordlist".into(),
            ));
        }

        // Compute checksum: first CS bits of SHA-256(entropy)
        let cs_bits = ent_bits / 32;
        let hash = Sha256::digest(entropy);

        // Build the full bit string: entropy || checksum
        let total_bits = ent_bits + cs_bits;
        let word_count = total_bits / 11;

        let mut words = Vec::with_capacity(word_count);
        for i in 0..word_count {
            let mut idx: u32 = 0;
            for j in 0..11 {
                let bit_pos = i * 11 + j;
                let bit = if bit_pos < ent_bits {
                    // From entropy
                    (entropy[bit_pos / 8] >> (7 - (bit_pos % 8))) & 1
                } else {
                    // From checksum
                    let cs_pos = bit_pos - ent_bits;
                    (hash[cs_pos / 8] >> (7 - (cs_pos % 8))) & 1
                };
                idx = (idx << 1) | u32::from(bit);
            }
            words.push(wordlist[idx as usize]);
        }

        Ok(Self {
            words: Zeroizing::new(words.join(" ")),
        })
    }

    /// Parse a mnemonic phrase from a string.
    ///
    /// Validates word count and checksum.
    pub fn from_phrase(phrase: &str) -> Result<Self, SignerError> {
        let wordlist: Vec<&str> = WORDLIST.lines().collect();
        if wordlist.len() != 2048 {
            return Err(SignerError::InvalidPrivateKey(
                "invalid BIP-39 wordlist".into(),
            ));
        }

        let words: Vec<&str> = phrase.split_whitespace().collect();
        let word_count = words.len();
        if ![12, 15, 18, 21, 24].contains(&word_count) {
            return Err(SignerError::InvalidPrivateKey(format!(
                "invalid word count: {word_count} (must be 12, 15, 18, 21, or 24)"
            )));
        }

        // Convert words to indices
        let mut indices = Vec::with_capacity(word_count);
        for word in &words {
            let idx = wordlist
                .iter()
                .position(|w| w == word)
                .ok_or_else(|| {
                    SignerError::InvalidPrivateKey(format!("unknown BIP-39 word: {word}"))
                })?;
            indices.push(idx as u32);
        }

        // Extract entropy bits
        let total_bits = word_count * 11;
        let cs_bits = word_count / 3; // CS = ENT/32, and word_count = (ENT + CS) / 11
        let ent_bits = total_bits - cs_bits;
        let ent_bytes = ent_bits / 8;

        let mut entropy = vec![0u8; ent_bytes];
        for (i, idx) in indices.iter().enumerate() {
            for j in 0..11 {
                let bit_pos = i * 11 + j;
                if bit_pos < ent_bits {
                    let bit = (idx >> (10 - j)) & 1;
                    entropy[bit_pos / 8] |= (bit as u8) << (7 - (bit_pos % 8));
                }
            }
        }

        // Validate checksum
        let hash = Sha256::digest(&entropy);
        for i in 0..cs_bits {
            let bit_pos = ent_bits + i;
            let word_idx = bit_pos / 11;
            let bit_in_word = bit_pos % 11;
            let expected_bit = (indices[word_idx] >> (10 - bit_in_word)) & 1;
            let actual_bit = u32::from((hash[i / 8] >> (7 - (i % 8))) & 1);
            if expected_bit != actual_bit {
                return Err(SignerError::InvalidPrivateKey(
                    "invalid mnemonic checksum".into(),
                ));
            }
        }

        Ok(Self {
            words: Zeroizing::new(phrase.to_string()),
        })
    }

    /// Convert the mnemonic to a 64-byte seed using PBKDF2-SHA512.
    ///
    /// The passphrase is optional (use `""` for no passphrase).
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        let salt = format!("mnemonic{passphrase}");
        let mut seed = Zeroizing::new([0u8; 64]);
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(
            self.words.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut *seed,
        );
        seed
    }

    /// Return the mnemonic phrase as a string.
    pub fn phrase(&self) -> &str {
        &self.words
    }

    /// Return the number of words in the mnemonic.
    pub fn word_count(&self) -> usize {
        self.words.split_whitespace().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-39 Test Vector 1 (from BIP-39 spec)
    // Entropy: 00000000000000000000000000000000
    #[test]
    fn test_bip39_vector1_12words() {
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(mnemonic.word_count(), 12);
    }

    // BIP-39 Test Vector 2 (24 words)
    // Entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
    #[test]
    fn test_bip39_vector2_24words() {
        let entropy =
            hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
                .unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.phrase(),
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"
        );
    }

    // BIP-39 Test Vector: seed derivation
    #[test]
    fn test_bip39_seed_vector() {
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let seed = mnemonic.to_seed("TREZOR");
        // Official BIP-39 test vector for 128-bit all-zero entropy + "TREZOR" passphrase
        let expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        assert_eq!(hex::encode(&*seed), expected);
    }

    // Round-trip: generate → phrase → parse → seed
    #[test]
    fn test_generate_parse_roundtrip_12() {
        let m1 = Mnemonic::generate(12).unwrap();
        let m2 = Mnemonic::from_phrase(m1.phrase()).unwrap();
        assert_eq!(m1.phrase(), m2.phrase());
        assert_eq!(*m1.to_seed(""), *m2.to_seed(""));
    }

    #[test]
    fn test_generate_parse_roundtrip_24() {
        let m1 = Mnemonic::generate(24).unwrap();
        let m2 = Mnemonic::from_phrase(m1.phrase()).unwrap();
        assert_eq!(m1.phrase(), m2.phrase());
    }

    #[test]
    fn test_invalid_word_count() {
        assert!(Mnemonic::generate(11).is_err());
        assert!(Mnemonic::generate(13).is_err());
    }

    #[test]
    fn test_invalid_entropy_length() {
        assert!(Mnemonic::from_entropy(&[0u8; 15]).is_err());
        assert!(Mnemonic::from_entropy(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_invalid_word_rejected() {
        assert!(Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zzzzz").is_err());
    }

    #[test]
    fn test_bad_checksum_rejected() {
        // Valid words but wrong checksum
        assert!(Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
    }

    #[test]
    fn test_passphrase_changes_seed() {
        let m = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        let s1 = m.to_seed("");
        let s2 = m.to_seed("password");
        assert_ne!(*s1, *s2);
    }

    // Integration: mnemonic → seed → HD key → ETH address
    #[test]
    fn test_mnemonic_to_eth_address() {
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let seed = mnemonic.to_seed("TREZOR");
        let master = crate::hd_key::ExtendedPrivateKey::from_seed(&*seed).unwrap();
        let child = master
            .derive_path(&crate::hd_key::DerivationPath::ethereum(0))
            .unwrap();
        assert_eq!(child.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_all_entropy_sizes() {
        for size in [16, 20, 24, 28, 32] {
            let entropy = vec![0xABu8; size];
            let m = Mnemonic::from_entropy(&entropy).unwrap();
            let expected_words = (size * 8 + size * 8 / 32) / 11;
            assert_eq!(m.word_count(), expected_words);
            // Verify round-trip
            let m2 = Mnemonic::from_phrase(m.phrase()).unwrap();
            assert_eq!(m.phrase(), m2.phrase());
        }
    }
}
