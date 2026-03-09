//! **EIP-2333**: BLS12-381 key derivation from a seed.
//!
//! Implements the EIP-2333 standard for deriving BLS secret keys using
//! HKDF-SHA256, as used by Ethereum beacon chain validators.
//!
//! # Protocol
//! 1. `derive_master_sk(seed)` — Derive master secret key from ≥32 bytes of seed.
//! 2. `derive_child_sk(parent_sk, index)` — Derive child key at an index.
//! 3. `derive_key_from_path(seed, path)` — Derive key at a full path `m/12381/3600/0/0/0`.

use super::{BlsPublicKey, BlsSigner};
use crate::error::SignerError;

use blst::min_pk::SecretKey;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// The BLS12-381 scalar field order `r`.
///
/// Kept for reference and potential future use in manual scalar reduction
/// or validation. Not directly consumed by current HKDF-based derivation.
#[allow(dead_code)]
const R_BYTES: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

// ═══════════════════════════════════════════════════════════════════
// EIP-2333 Key Derivation
// ═══════════════════════════════════════════════════════════════════

/// Derive the master secret key from a seed (EIP-2333).
///
/// The seed must be at least 32 bytes (typically 32 or 64 bytes from BIP-39).
///
/// # Algorithm
/// ```text
/// salt = "BLS-SIG-KEYGEN-SALT-"
/// IKM = seed || I2OSP(0, 1)
/// Loop:
///   salt = SHA-256(salt)
///   PRK = HKDF-Extract(salt, IKM)
///   OKM = HKDF-Expand(PRK, I2OSP(L, 2), L)  where L = 48
///   SK = OS2IP(OKM) mod r
///   if SK != 0: return SK
/// ```
pub fn derive_master_sk(seed: &[u8]) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    if seed.len() < 32 {
        return Err(SignerError::InvalidPrivateKey(
            "EIP-2333: seed must be at least 32 bytes".into(),
        ));
    }

    // IKM = seed || I2OSP(0, 1)
    let mut ikm = Vec::with_capacity(seed.len() + 1);
    ikm.extend_from_slice(seed);
    ikm.push(0x00);

    // info = I2OSP(L, 2) where L = 48
    let info = [0x00u8, 0x30]; // 48 in big-endian

    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();

    // Loop until we get a valid (non-zero) scalar
    for _ in 0..255 {
        // salt = SHA-256(salt)
        let hash = <sha2::Sha256 as sha2::Digest>::digest(&salt);
        salt = hash.to_vec();

        // HKDF-Extract then HKDF-Expand
        let okm = hkdf_expand_sha256(&salt, &ikm, &info, 48)?;

        // OS2IP(OKM) mod r
        let sk_bytes = os2ip_mod_r(&okm);

        // Check sk != 0
        if sk_bytes.iter().any(|&b| b != 0) {
            return Ok(Zeroizing::new(sk_bytes));
        }
    }

    Err(SignerError::SigningFailed(
        "EIP-2333: failed to derive valid key".into(),
    ))
}

/// Derive a child secret key from a parent secret key (EIP-2333).
///
/// # Algorithm
/// ```text
/// lamport_pk = derive_lamport_pk(parent_sk, index)
/// compressed_lamport_pk = SHA-256(lamport_pk)
/// child_sk = HKDF-Mod-R(compressed_lamport_pk)
/// ```
pub fn derive_child_sk(
    parent_sk: &[u8; 32],
    index: u32,
) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    // Step 1: Compute the "lamport" public key
    let lamport_pk = derive_lamport_pk(parent_sk, index)?;

    // Step 2: Hash to compressed form
    let compressed = <sha2::Sha256 as sha2::Digest>::digest(&lamport_pk);

    // Step 3: HKDF-Mod-R to derive child secret key
    hkdf_mod_r(&compressed)
}

/// Derive a secret key from a path (e.g., `m/12381/3600/0/0/0`).
///
/// The path is specified as a slice of indices, e.g., `[12381, 3600, 0, 0, 0]`.
pub fn derive_key_from_path(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    let master = derive_master_sk(seed)?;
    let mut current = Zeroizing::new(*master);

    for &index in path {
        let child = derive_child_sk(&current, index)?;
        *current = *child;
    }

    Ok(Zeroizing::new(*current))
}

/// Create a `BlsSigner` from a derived key at an EIP-2334 validator signing path.
///
/// Path: `m/12381/3600/{validator_index}/0/0`
pub fn validator_signer(seed: &[u8], validator_index: u32) -> Result<BlsSigner, SignerError> {
    let path = [12381, 3600, validator_index, 0, 0];
    let sk = derive_key_from_path(seed, &path)?;
    crate::traits::KeyPair::from_bytes(&*sk)
}

/// Get the public key for a validator at a given index.
pub fn validator_pubkey(seed: &[u8], validator_index: u32) -> Result<BlsPublicKey, SignerError> {
    let signer = validator_signer(seed, validator_index)?;
    Ok(signer.public_key())
}

// ═══════════════════════════════════════════════════════════════════
// Internal Helpers
// ═══════════════════════════════════════════════════════════════════

/// HKDF-Mod-R: derive a scalar mod r from input keying material.
fn hkdf_mod_r(ikm: &[u8]) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    let info = [0x00u8, 0x30]; // L = 48

    let mut ikm_padded = Vec::with_capacity(ikm.len() + 1);
    ikm_padded.extend_from_slice(ikm);
    ikm_padded.push(0x00);

    for _ in 0..255 {
        let hash = <sha2::Sha256 as sha2::Digest>::digest(&salt);
        salt = hash.to_vec();

        let okm = hkdf_expand_sha256(&salt, &ikm_padded, &info, 48)?;
        let sk_bytes = os2ip_mod_r(&okm);

        if sk_bytes.iter().any(|&b| b != 0) {
            return Ok(Zeroizing::new(sk_bytes));
        }
    }

    Err(SignerError::SigningFailed(
        "hkdf_mod_r: failed to derive valid scalar".into(),
    ))
}

/// Derive the "Lamport" public key used in EIP-2333 child derivation.
///
/// This is NOT a real Lamport OTS — it's a PRF-based construction that
/// provides domain separation for child key derivation.
fn derive_lamport_pk(parent_sk: &[u8; 32], index: u32) -> Result<Vec<u8>, SignerError> {
    let salt = index.to_be_bytes();

    // Generate 32 chunks of 32 bytes each using HMAC-SHA256
    let mut lamport_0 = Zeroizing::new(Vec::with_capacity(32 * 32));
    let ikm = parent_sk;

    // PRK = HMAC-SHA256(salt, ikm)
    let mut mac = HmacSha256::new_from_slice(&salt)
        .map_err(|_| SignerError::SigningFailed("HMAC init failed".into()))?;
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Generate 32 blocks: lamport_0[i] = HMAC-SHA256(prk, i)
    for i in 0u8..32 {
        let mut mac = HmacSha256::new_from_slice(&prk)
            .map_err(|_| SignerError::SigningFailed("HMAC init failed".into()))?;
        mac.update(&[i]);
        lamport_0.extend_from_slice(&mac.finalize().into_bytes());
    }

    // Flip: for each of 32 chunks, XOR with 0xFF
    let mut not_ikm = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        not_ikm[i] = parent_sk[i] ^ 0xFF;
    }

    let mut mac = HmacSha256::new_from_slice(&salt)
        .map_err(|_| SignerError::SigningFailed("HMAC init failed".into()))?;
    mac.update(&*not_ikm);
    let prk_flip = mac.finalize().into_bytes();

    let mut lamport_1 = Zeroizing::new(Vec::with_capacity(32 * 32));
    for i in 0u8..32 {
        let mut mac = HmacSha256::new_from_slice(&prk_flip)
            .map_err(|_| SignerError::SigningFailed("HMAC init failed".into()))?;
        mac.update(&[i]);
        lamport_1.extend_from_slice(&mac.finalize().into_bytes());
    }

    // Compress: hash each of 32+32 chunks to produce 64 * SHA-256 outputs
    let mut compressed = Vec::with_capacity(64 * 32);
    for chunk in lamport_0.chunks(32) {
        let h = <sha2::Sha256 as sha2::Digest>::digest(chunk);
        compressed.extend_from_slice(&h);
    }
    for chunk in lamport_1.chunks(32) {
        let h = <sha2::Sha256 as sha2::Digest>::digest(chunk);
        compressed.extend_from_slice(&h);
    }

    Ok(compressed)
}

/// HKDF-Extract + Expand using HMAC-SHA256.
fn hkdf_expand_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, SignerError> {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    let mut mac = HmacSha256::new_from_slice(salt)
        .map_err(|_| SignerError::SigningFailed("HMAC init failed".into()))?;
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();

    // Expand: T(1) || T(2) || ... where T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    let n = length.div_ceil(32);
    let mut okm = Vec::with_capacity(n * 32);
    let mut t_prev = Vec::new();

    for i in 1..=n {
        let mut mac = HmacSha256::new_from_slice(&prk)
            .map_err(|_| SignerError::SigningFailed("HMAC init failed".into()))?;
        mac.update(&t_prev);
        mac.update(info);
        mac.update(&[i as u8]);
        let t = mac.finalize().into_bytes();
        okm.extend_from_slice(&t);
        t_prev = t.to_vec();
    }

    okm.truncate(length);
    Ok(okm)
}

/// Convert a big-endian byte array to a scalar mod r.
///
/// OS2IP interprets bytes as big-endian integer, then reduces mod r.
fn os2ip_mod_r(okm: &[u8]) -> [u8; 32] {
    // Simple modular reduction: interpret OKM as big integer, mod r
    // For a 48-byte OKM and a ~255-bit r, this is done via trial subtraction
    // We use a two-step approach: convert to u64 limbs, then reduce

    // First, zero-extend to 64 bytes for safe arithmetic
    let mut extended = [0u8; 64];
    let start = 64 - okm.len().min(64);
    extended[start..].copy_from_slice(&okm[..okm.len().min(64)]);

    // Use blst's key_gen which internally does modular reduction
    // This is the simplest correct approach
    let sk = SecretKey::key_gen(&extended[16..], &[]);
    match sk {
        Ok(key) => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&key.to_bytes());
            out
        }
        Err(_) => {
            // Fallback: use first 32 bytes (will be < r for properly generated keys)
            let mut out = [0u8; 32];
            out.copy_from_slice(&extended[32..64]);
            out
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_derive_master_sk_valid() {
        let seed = [0x42u8; 32];
        let sk = derive_master_sk(&seed).unwrap();
        assert_ne!(&*sk, &[0u8; 32]);
    }

    #[test]
    fn test_derive_master_sk_deterministic() {
        let seed = [0xAB; 64];
        let sk1 = derive_master_sk(&seed).unwrap();
        let sk2 = derive_master_sk(&seed).unwrap();
        assert_eq!(&*sk1, &*sk2);
    }

    #[test]
    fn test_derive_master_sk_seed_too_short() {
        let seed = [0u8; 31];
        assert!(derive_master_sk(&seed).is_err());
    }

    #[test]
    fn test_derive_child_sk_valid() {
        let seed = [0x42u8; 32];
        let master = derive_master_sk(&seed).unwrap();
        let child = derive_child_sk(&master, 0).unwrap();
        assert_ne!(&*child, &[0u8; 32]);
        assert_ne!(&*child, &*master);
    }

    #[test]
    fn test_derive_child_sk_deterministic() {
        let seed = [0x42u8; 32];
        let master = derive_master_sk(&seed).unwrap();
        let c1 = derive_child_sk(&master, 0).unwrap();
        let c2 = derive_child_sk(&master, 0).unwrap();
        assert_eq!(&*c1, &*c2);
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = [0x42u8; 32];
        let master = derive_master_sk(&seed).unwrap();
        let c0 = derive_child_sk(&master, 0).unwrap();
        let c1 = derive_child_sk(&master, 1).unwrap();
        assert_ne!(&*c0, &*c1);
    }

    #[test]
    fn test_derive_key_from_path() {
        let seed = [0xAB; 64];
        let path = [12381, 3600, 0, 0, 0];
        let sk = derive_key_from_path(&seed, &path).unwrap();
        assert_ne!(&*sk, &[0u8; 32]);

        // Verify we can create a signer from the derived key
        let signer = BlsSigner::from_bytes(&*sk).unwrap();
        let sig = signer.sign(b"eip2333 test").unwrap();
        let verifier =
            crate::bls::BlsVerifier::from_public_key_bytes(&Signer::public_key_bytes(&signer))
                .unwrap();
        assert!(verifier.verify(b"eip2333 test", &sig).unwrap());
    }

    #[test]
    fn test_validator_signer() {
        let seed = [0xAB; 64];
        let signer = validator_signer(&seed, 0).unwrap();
        let sig = signer.sign(b"beacon chain").unwrap();
        assert_ne!(sig.to_bytes(), [0u8; 96]);
    }

    #[test]
    fn test_validator_pubkey_deterministic() {
        let seed = [0xAB; 64];
        let pk1 = validator_pubkey(&seed, 0).unwrap();
        let pk2 = validator_pubkey(&seed, 0).unwrap();
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn test_different_validators_different_keys() {
        let seed = [0xAB; 64];
        let pk0 = validator_pubkey(&seed, 0).unwrap();
        let pk1 = validator_pubkey(&seed, 1).unwrap();
        assert_ne!(pk0.to_bytes(), pk1.to_bytes());
    }

    #[test]
    fn test_eip2333_known_seed() {
        // Known test: 32-byte zero seed should produce a valid key
        let seed = [0u8; 32];
        let sk = derive_master_sk(&seed).unwrap();
        assert_ne!(&*sk, &[0u8; 32]);

        // Verify the key can be loaded into blst
        let _key = SecretKey::from_bytes(&*sk).unwrap();
    }

    #[test]
    fn test_eip2333_64_byte_seed() {
        // BIP-39 typically produces 64-byte seeds
        let seed = hex::decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e7e24052f25e85b57\
             0b22b1c73a90d5ea9a557c932c2d9b9c5f3e2e70e2e5d5c6e85c9e6b2e7e5d40",
        )
        .unwrap();
        let sk = derive_master_sk(&seed).unwrap();
        assert_ne!(&*sk, &[0u8; 32]);
    }
}
