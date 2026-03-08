//! Shared cryptographic primitives used across all chain modules.
//!
//! Centralizes tagged hashing, double-SHA256, HASH160, and SHA256 so that
//! chain modules don't duplicate these building blocks.

use sha2::{Digest, Sha256};

/// BIP-340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data)`.
///
/// Used by BIP-340 Schnorr, BIP-341 Taproot, BIP-322 message signing, and MuSig2.
pub fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Double SHA-256: `SHA256(SHA256(data))`.
///
/// Used by Bitcoin (BIP-137, txid), XRP (account checksums), NEO, and BIP-32.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let h1 = Sha256::digest(data);
    let h2 = Sha256::digest(h1);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h2);
    out
}

/// HASH160: `RIPEMD160(SHA256(data))`.
///
/// Used by Bitcoin (P2PKH, P2WPKH, fingerprint), XRP, NEO, BIP-32, and descriptors.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::{Digest as RipeDigest, Ripemd160};
    let sha = Sha256::digest(data);
    let ripe = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&ripe);
    out
}

/// SHA-256: `SHA256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let h = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let h = sha256(b"");
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_double_sha256() {
        let h = double_sha256(b"");
        assert_ne!(h, sha256(b"")); // double != single
    }

    #[test]
    fn test_hash160() {
        let h = hash160(b"test");
        assert_eq!(h.len(), 20);
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let h1 = tagged_hash(b"TapLeaf", b"data");
        let h2 = tagged_hash(b"TapLeaf", b"data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tagged_hash_domain_separation() {
        let h1 = tagged_hash(b"TapLeaf", b"data");
        let h2 = tagged_hash(b"TapBranch", b"data");
        assert_ne!(h1, h2); // different tags → different hashes
    }

    #[test]
    fn test_bip322_message_hash_via_tagged_hash() {
        // BIP-322 official vector: empty message
        let h = tagged_hash(b"BIP0322-signed-message", b"");
        assert_eq!(
            hex::encode(h),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
        // BIP-322 official vector: "Hello World"
        let h = tagged_hash(b"BIP0322-signed-message", b"Hello World");
        assert_eq!(
            hex::encode(h),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
    }
}
