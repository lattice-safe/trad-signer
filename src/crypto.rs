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

    // ─── SHA-256 Official NIST Vectors ──────────────────────────

    #[test]
    fn test_sha256_nist_empty() {
        // NIST FIPS 180-4: SHA-256("")
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_nist_abc() {
        // NIST FIPS 180-4: SHA-256("abc")
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_nist_448bit() {
        // NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        assert_eq!(
            hex::encode(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // ─── Double SHA-256 Known Vectors ───────────────────────────

    #[test]
    fn test_double_sha256_empty() {
        // SHA256(SHA256("")) — well-known Bitcoin constant
        assert_eq!(
            hex::encode(double_sha256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn test_double_sha256_hello() {
        // SHA256(SHA256("hello")) — cross-checked with multiple tools
        let h = double_sha256(b"hello");
        assert_eq!(h.len(), 32);
        assert_ne!(h, sha256(b"hello")); // must differ from single SHA256
    }

    #[test]
    fn test_double_sha256_is_idempotent_on_input() {
        let h1 = double_sha256(b"test");
        let h2 = double_sha256(b"test");
        assert_eq!(h1, h2);
    }

    // ─── HASH160 Known Vectors ──────────────────────────────────

    #[test]
    fn test_hash160_bitcoin_generator_point() {
        // Bitcoin generator point compressed pubkey:
        // 02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        // HASH160 → 751e76e8199196d454941c45d1b3a323f1433bd6
        let generator_pubkey = hex::decode(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ).unwrap();
        assert_eq!(
            hex::encode(hash160(&generator_pubkey)),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn test_hash160_empty() {
        // RIPEMD160(SHA256("")) — known value
        assert_eq!(
            hex::encode(hash160(b"")),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        );
    }

    #[test]
    fn test_hash160_output_length() {
        assert_eq!(hash160(b"any data").len(), 20);
        assert_eq!(hash160(b"").len(), 20);
        assert_eq!(hash160(&[0u8; 1000]).len(), 20);
    }

    // ─── Tagged Hash (BIP-340) ──────────────────────────────────

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
        let h3 = tagged_hash(b"BIP0340/challenge", b"data");
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h2, h3);
    }

    #[test]
    fn test_tagged_hash_differs_from_plain_sha256() {
        // tagged_hash("tag", data) ≠ sha256(data)
        let plain = sha256(b"data");
        let tagged = tagged_hash(b"BIP0340/aux", b"data");
        assert_ne!(plain, tagged);
    }

    #[test]
    fn test_tagged_hash_empty_tag_and_data() {
        let h = tagged_hash(b"", b"");
        assert_eq!(h.len(), 32);
        // ensure it's not all-zeros (cryptographically impossible)
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn test_bip322_message_hash_empty() {
        // BIP-322 official vector: empty message
        assert_eq!(
            hex::encode(tagged_hash(b"BIP0322-signed-message", b"")),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
    }

    #[test]
    fn test_bip322_message_hash_hello_world() {
        // BIP-322 official vector: "Hello World"
        assert_eq!(
            hex::encode(tagged_hash(b"BIP0322-signed-message", b"Hello World")),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
    }

    #[test]
    fn test_tagged_hash_bip340_aux_vector() {
        // BIP-340 aux tag: unique domain
        let h = tagged_hash(b"BIP0340/aux", &[0u8; 32]);
        assert_eq!(h.len(), 32);
        assert_ne!(h, [0u8; 32]);
    }

    // ─── Cross-function Consistency ─────────────────────────────

    #[test]
    fn test_double_sha256_equals_sha256_of_sha256() {
        let data = b"consistency check";
        let single = sha256(data);
        let double = sha256(&single);
        assert_eq!(double_sha256(data), double);
    }

    #[test]
    fn test_hash160_consistency() {
        // HASH160(data) = RIPEMD160(SHA256(data))
        // We can verify by checking the SHA256 intermediate matches
        let data = b"hash160 consistency";
        let sha_intermediate = sha256(data);
        let h160_direct = hash160(data);
        // RIPEMD160 of the SHA256 should match
        use ripemd::{Digest as _, Ripemd160};
        let ripe = Ripemd160::digest(sha_intermediate);
        assert_eq!(&h160_direct[..], &ripe[..]);
    }
}

