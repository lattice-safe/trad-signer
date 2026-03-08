//! **Web3 Secret Storage v3** — Encrypted JSON keystore for Ethereum wallets.
//!
//! Implements the standard keystore format used by MetaMask, Geth, and other
//! Ethereum wallets for securely storing private keys.
//!
//! Uses **scrypt** for key derivation and **AES-128-CTR** for encryption,
//! following the [Web3 Secret Storage Definition](https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/).

use crate::error::SignerError;
use aes::cipher::{KeyIvInit, StreamCipher};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// AES-128-CTR cipher type alias.
type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

/// Scrypt parameters for keystore encryption.
#[derive(Debug, Clone)]
pub struct ScryptParams {
    /// N — CPU/memory cost parameter (must be power of 2).
    pub n: u32,
    /// r — block size.
    pub r: u32,
    /// p — parallelization.
    pub p: u32,
    /// Derived key length in bytes (default: 32).
    pub dklen: u32,
}

impl Default for ScryptParams {
    /// Default scrypt parameters matching Geth/MetaMask defaults.
    fn default() -> Self {
        Self {
            n: 262144, // 2^18
            r: 8,
            p: 1,
            dklen: 32,
        }
    }
}

impl ScryptParams {
    /// Light scrypt parameters for faster encryption (testing/mobile).
    #[must_use]
    pub fn light() -> Self {
        Self {
            n: 4096, // 2^12
            r: 8,
            p: 6,
            dklen: 32,
        }
    }
}

/// An encrypted Ethereum keystore (V3 format).
///
/// Fields correspond to the JSON keystore standard.
#[derive(Debug, Clone)]
pub struct Keystore {
    /// UUID for this keystore.
    pub id: String,
    /// EIP-55 checksummed address.
    pub address: String,
    /// Scrypt parameters used.
    pub scrypt_params: ScryptParams,
    /// 32-byte random salt for scrypt.
    pub salt: [u8; 32],
    /// 16-byte IV for AES-128-CTR.
    pub iv: [u8; 16],
    /// Encrypted private key (ciphertext).
    pub ciphertext: Vec<u8>,
    /// MAC: keccak256(derived_key[16..32] || ciphertext).
    pub mac: [u8; 32],
}

impl Keystore {
    /// Encrypt a private key into a keystore.
    ///
    /// # Arguments
    /// - `private_key` — 32-byte private key
    /// - `password` — User password for encryption
    /// - `params` — Scrypt parameters (use `ScryptParams::default()` for standard)
    pub fn encrypt(
        private_key: &[u8],
        password: &[u8],
        params: &ScryptParams,
    ) -> Result<Self, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey("key must be 32 bytes".into()));
        }

        // Generate random salt and IV
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt)
            .map_err(|_| SignerError::EntropyError)?;
        let mut iv = [0u8; 16];
        getrandom::getrandom(&mut iv)
            .map_err(|_| SignerError::EntropyError)?;

        // Derive key using scrypt
        let derived = derive_scrypt_key(password, &salt, params)?;

        // Encrypt with AES-128-CTR using first 16 bytes of derived key
        let mut ciphertext = private_key.to_vec();
        let mut cipher = Aes128Ctr::new(
            derived[..16].into(),
            iv.as_ref().into(),
        );
        cipher.apply_keystream(&mut ciphertext);

        // MAC: keccak256(derived_key[16..32] || ciphertext)
        let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
        mac_input.extend_from_slice(&derived[16..32]);
        mac_input.extend_from_slice(&ciphertext);
        let mac = keccak256(&mac_input);

        // Derive address for the keystore
        use crate::traits::KeyPair;
        let signer = super::EthereumSigner::from_bytes(private_key)?;
        let address = signer.address_checksum();

        // Generate UUID
        let mut uuid_bytes = [0u8; 16];
        getrandom::getrandom(&mut uuid_bytes)
            .map_err(|_| SignerError::EntropyError)?;
        // Set version 4 and variant bits
        uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
        uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;
        let id = format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            u32::from_be_bytes([uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3]]),
            u16::from_be_bytes([uuid_bytes[4], uuid_bytes[5]]),
            u16::from_be_bytes([uuid_bytes[6], uuid_bytes[7]]),
            u16::from_be_bytes([uuid_bytes[8], uuid_bytes[9]]),
            u64::from_be_bytes([0, 0, uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]]),
        );

        Ok(Self {
            id,
            address,
            scrypt_params: params.clone(),
            salt,
            iv,
            ciphertext,
            mac,
        })
    }

    /// Decrypt the private key from this keystore.
    ///
    /// Returns the 32-byte private key wrapped in `Zeroizing`.
    pub fn decrypt(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
        // Derive key
        let derived = derive_scrypt_key(password, &self.salt, &self.scrypt_params)?;

        // Verify MAC
        let mut mac_input = Vec::with_capacity(16 + self.ciphertext.len());
        mac_input.extend_from_slice(&derived[16..32]);
        mac_input.extend_from_slice(&self.ciphertext);
        let computed_mac = keccak256(&mac_input);

        use subtle::ConstantTimeEq;
        if computed_mac.ct_eq(&self.mac).unwrap_u8() != 1 {
            return Err(SignerError::InvalidSignature(
                "keystore MAC verification failed (wrong password?)".into(),
            ));
        }

        // Decrypt with AES-128-CTR
        let mut plaintext = self.ciphertext.clone();
        let mut cipher = Aes128Ctr::new(
            derived[..16].into(),
            self.iv.as_ref().into(),
        );
        cipher.apply_keystream(&mut plaintext);

        Ok(Zeroizing::new(plaintext))
    }

    /// Serialize the keystore to JSON string.
    ///
    /// Produces standard Web3 Secret Storage v3 format.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"version":3,"id":"{}","address":"{}","crypto":{{"cipher":"aes-128-ctr","cipherparams":{{"iv":"{}"}},"ciphertext":"{}","kdf":"scrypt","kdfparams":{{"dklen":{},"n":{},"r":{},"p":{},"salt":"{}"}},"mac":"{}"}}}}"#,
            self.id,
            self.address.trim_start_matches("0x").to_lowercase(),
            hex::encode(self.iv),
            hex::encode(&self.ciphertext),
            self.scrypt_params.dklen,
            self.scrypt_params.n,
            self.scrypt_params.r,
            self.scrypt_params.p,
            hex::encode(self.salt),
            hex::encode(self.mac),
        )
    }
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn derive_scrypt_key(password: &[u8], salt: &[u8], params: &ScryptParams) -> Result<Vec<u8>, SignerError> {
    use scrypt::scrypt;
    let log_n = (params.n as f64).log2() as u8;
    let scrypt_params = scrypt::Params::new(log_n, params.r, params.p, params.dklen as usize)
        .map_err(|e| SignerError::EncodingError(format!("scrypt params: {e}")))?;
    let mut derived = vec![0u8; params.dklen as usize];
    scrypt(password, salt, &scrypt_params, &mut derived)
        .map_err(|e| SignerError::EncodingError(format!("scrypt: {e}")))?;
    Ok(derived)
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    fn light_params() -> ScryptParams {
        ScryptParams::light()
    }

    #[test]
    fn test_keystore_encrypt_decrypt_roundtrip() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let pk = signer.private_key_bytes();
        let password = b"test-password-123";

        let ks = Keystore::encrypt(&pk, password, &light_params()).unwrap();
        let decrypted = ks.decrypt(password).unwrap();
        assert_eq!(&*decrypted, &*pk);
    }

    #[test]
    fn test_keystore_wrong_password_fails() {
        let pk = [0x42u8; 32];
        let ks = Keystore::encrypt(&pk, b"correct", &light_params()).unwrap();
        let result = ks.decrypt(b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_keystore_address_matches() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let pk = signer.private_key_bytes();
        let expected_addr = signer.address_checksum();

        let ks = Keystore::encrypt(&pk, b"pw", &light_params()).unwrap();
        assert_eq!(ks.address, expected_addr);
    }

    #[test]
    fn test_keystore_to_json_format() {
        let pk = [0x42u8; 32];
        let ks = Keystore::encrypt(&pk, b"pw", &light_params()).unwrap();
        let json = ks.to_json();
        assert!(json.contains("\"version\":3"));
        assert!(json.contains("\"cipher\":\"aes-128-ctr\""));
        assert!(json.contains("\"kdf\":\"scrypt\""));
        assert!(json.contains(&format!("\"n\":{}", light_params().n)));
    }

    #[test]
    fn test_keystore_unique_salts() {
        let pk = [0x42u8; 32];
        let ks1 = Keystore::encrypt(&pk, b"pw", &light_params()).unwrap();
        let ks2 = Keystore::encrypt(&pk, b"pw", &light_params()).unwrap();
        assert_ne!(ks1.salt, ks2.salt, "salts should be unique");
        assert_ne!(ks1.iv, ks2.iv, "IVs should be unique");
    }

    #[test]
    fn test_keystore_invalid_key_length() {
        assert!(Keystore::encrypt(&[0; 16], b"pw", &light_params()).is_err());
    }
}
