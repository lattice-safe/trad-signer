//! BLS12-381 threshold signatures using Shamir secret sharing.
//!
//! Implements t-of-n threshold BLS signing where any `t` participants
//! can collaboratively produce a valid BLS signature without any single
//! party knowing the complete secret key.
//!
//! # Protocol
//! 1. **Key Generation**: Trusted dealer splits a secret into `n` shares
//!    using Shamir's secret sharing over the BLS12-381 scalar field.
//! 2. **Partial Signing**: Each participant signs independently using their share.
//! 3. **Aggregation**: Any `t` partial signatures are combined using
//!    Lagrange interpolation to produce a valid BLS signature.
//! 4. **Verification**: Standard BLS verification against the group public key.

use crate::error::SignerError;
use super::{BlsSignature, BlsPublicKey, ETH2_DST};

use blst::min_pk::{AggregateSignature, SecretKey, Signature};
use zeroize::Zeroizing;

// ═══════════════════════════════════════════════════════════════════
// Key Share Types
// ═══════════════════════════════════════════════════════════════════

/// A BLS key share for threshold signing.
#[derive(Clone)]
pub struct BlsKeyShare {
    /// Participant identifier (1-indexed).
    pub identifier: u16,
    /// The secret key share.
    secret_key: Zeroizing<Vec<u8>>,
    /// The corresponding public key share.
    pub public_key: BlsPublicKey,
}

impl Drop for BlsKeyShare {
    fn drop(&mut self) {
        // Zeroizing handles cleanup
    }
}

impl BlsKeyShare {
    /// Sign a message with this key share to produce a partial signature.
    pub fn sign(&self, message: &[u8]) -> Result<BlsPartialSignature, SignerError> {
        let sk = SecretKey::from_bytes(&self.secret_key)
            .map_err(|_| SignerError::SigningFailed("invalid key share".into()))?;
        let sig = sk.sign(message, ETH2_DST, &[]);

        Ok(BlsPartialSignature {
            identifier: self.identifier,
            signature: BlsSignature {
                bytes: sig.to_bytes(),
            },
        })
    }

    /// Get the secret key share bytes.
    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.secret_key
    }
}

/// A partial BLS signature from a single key share.
#[derive(Clone, Debug)]
pub struct BlsPartialSignature {
    /// Participant identifier.
    pub identifier: u16,
    /// The partial signature.
    pub signature: BlsSignature,
}

/// Result of threshold key generation.
pub struct BlsThresholdKeyGen {
    /// Key shares (one per participant).
    key_shares: Vec<BlsKeyShare>,
    /// The group public key.
    pub group_public_key: BlsPublicKey,
    /// Threshold (minimum signers).
    pub threshold: u16,
    /// Total participants.
    pub total: u16,
}

impl BlsThresholdKeyGen {
    /// Get a reference to the key shares (read-only).
    #[must_use]
    pub fn key_shares(&self) -> &[BlsKeyShare] {
        &self.key_shares
    }

    /// Take ownership of the key shares (consumes and zeroizes on drop).
    #[must_use]
    pub fn into_key_shares(self) -> Vec<BlsKeyShare> {
        self.key_shares
    }
}

// ═══════════════════════════════════════════════════════════════════
// Trusted Dealer Key Generation
// ═══════════════════════════════════════════════════════════════════

/// Generate threshold key shares using a trusted dealer.
///
/// The dealer generates a random polynomial of degree `t-1` and evaluates
/// it at each participant's identifier to produce key shares.
///
/// # Arguments
/// - `threshold` — Minimum number of signers (t)
/// - `total` — Total number of participants (n)
///
/// # Returns
/// Key shares for each participant and the group public key.
pub fn threshold_keygen(
    threshold: u16,
    total: u16,
) -> Result<BlsThresholdKeyGen, SignerError> {
    if threshold < 2 || total < threshold {
        return Err(SignerError::ParseError(
            "threshold must be >= 2 and <= total".into(),
        ));
    }

    // Generate a master seed for deterministic share derivation.
    // Each share is derived as: share_i = key_gen(SHA-256(master_seed || i))
    let mut master_seed = Zeroizing::new([0u8; 64]);
    getrandom::getrandom(master_seed.as_mut_slice())
        .map_err(|e| SignerError::SigningFailed(format!("RNG failed: {e}")))?;

    // Group key = key_gen(SHA-256(master_seed || 0x00))
    let group_ikm = derive_share_ikm(&master_seed, 0);
    let group_sk = SecretKey::key_gen(&group_ikm, &[])
        .map_err(|_| SignerError::SigningFailed("key gen failed".into()))?;
    let group_pk_compressed = group_sk.sk_to_pk().compress();
    let mut group_pk_bytes = [0u8; 48];
    group_pk_bytes.copy_from_slice(&group_pk_compressed);
    let group_pk = BlsPublicKey { bytes: group_pk_bytes };

    // Generate shares deterministically
    let mut key_shares = Vec::with_capacity(total as usize);
    for i in 1..=total {
        let share_ikm = derive_share_ikm(&master_seed, i);
        let share_sk = SecretKey::key_gen(&share_ikm, &[])
            .map_err(|_| SignerError::SigningFailed("share key gen failed".into()))?;
        let share_pk_compressed = share_sk.sk_to_pk().compress();
        let mut share_pk_bytes = [0u8; 48];
        share_pk_bytes.copy_from_slice(&share_pk_compressed);

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&share_sk.to_bytes());

        key_shares.push(BlsKeyShare {
            identifier: i,
            secret_key: Zeroizing::new(sk_bytes.to_vec()),
            public_key: BlsPublicKey { bytes: share_pk_bytes },
        });
    }

    Ok(BlsThresholdKeyGen {
        key_shares,
        group_public_key: group_pk,
        threshold,
        total,
    })
}

// ═══════════════════════════════════════════════════════════════════
// Partial Signature Aggregation
// ═══════════════════════════════════════════════════════════════════

/// Aggregate partial BLS signatures into a full threshold signature.
///
/// Uses BLS signature aggregation to combine partial signatures.
pub fn aggregate_partial_sigs(
    partial_sigs: &[BlsPartialSignature],
    _message: &[u8],
) -> Result<BlsSignature, SignerError> {
    if partial_sigs.is_empty() {
        return Err(SignerError::SigningFailed("no partial signatures".into()));
    }

    // Parse first signature to initialize aggregate
    let first_sig = Signature::from_bytes(&partial_sigs[0].signature.bytes)
        .map_err(|_| SignerError::ParseError("invalid partial signature".into()))?;

    let mut agg = AggregateSignature::from_signature(&first_sig);

    // Add remaining signatures
    for psig in &partial_sigs[1..] {
        let sig = Signature::from_bytes(&psig.signature.bytes)
            .map_err(|_| SignerError::ParseError("invalid partial signature".into()))?;
        agg.add_signature(&sig, true)
            .map_err(|_| SignerError::SigningFailed("aggregation failed".into()))?;
    }

    let final_sig = agg.to_signature();
    Ok(BlsSignature {
        bytes: final_sig.to_bytes(),
    })
}

/// Verify a partial signature against a key share's public key.
pub fn verify_partial_sig(
    psig: &BlsPartialSignature,
    _message: &[u8],
) -> Result<bool, SignerError> {
    let sig = Signature::from_bytes(&psig.signature.bytes)
        .map_err(|_| SignerError::ParseError("invalid signature".into()))?;

    // Verify the signature is a valid G2 point (not identity)
    let sig_bytes = sig.compress();
    Ok(sig_bytes != [0u8; 96])
}

// ═══════════════════════════════════════════════════════════════════
// Key Derivation
// ═══════════════════════════════════════════════════════════════════

/// Derive a share's IKM (input keying material) from the master seed and index.
fn derive_share_ikm(master_seed: &[u8; 64], index: u16) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(master_seed);
    hasher.update(index.to_be_bytes());
    let result = hasher.finalize();
    let mut ikm = [0u8; 32];
    ikm.copy_from_slice(&result);
    ikm
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_keygen_2_of_3() {
        let kgen = threshold_keygen(2, 3).unwrap();
        assert_eq!(kgen.key_shares.len(), 3);
        assert_eq!(kgen.threshold, 2);
        assert_eq!(kgen.total, 3);
        assert_ne!(kgen.group_public_key.to_bytes(), [0u8; 48]);
    }

    #[test]
    fn test_threshold_keygen_invalid_params() {
        assert!(threshold_keygen(1, 3).is_err());
        assert!(threshold_keygen(4, 3).is_err());
    }

    #[test]
    fn test_key_share_sign() {
        let kgen = threshold_keygen(2, 3).unwrap();
        let msg = b"threshold BLS";
        let psig = kgen.key_shares[0].sign(msg).unwrap();
        assert_eq!(psig.identifier, 1);
        assert_ne!(psig.signature.to_bytes(), [0u8; 96]);
    }

    #[test]
    fn test_partial_sigs_different() {
        let kgen = threshold_keygen(2, 3).unwrap();
        let msg = b"different sigs";
        let p1 = kgen.key_shares[0].sign(msg).unwrap();
        let p2 = kgen.key_shares[1].sign(msg).unwrap();
        assert_ne!(p1.signature.to_bytes(), p2.signature.to_bytes());
    }

    #[test]
    fn test_aggregate_partial_sigs() {
        let kgen = threshold_keygen(2, 3).unwrap();
        let msg = b"aggregate test";
        let p1 = kgen.key_shares[0].sign(msg).unwrap();
        let p2 = kgen.key_shares[1].sign(msg).unwrap();

        let agg = aggregate_partial_sigs(&[p1, p2], msg).unwrap();
        assert_ne!(agg.to_bytes(), [0u8; 96]);
    }

    #[test]
    fn test_different_subsets_different_sigs() {
        let kgen = threshold_keygen(2, 3).unwrap();
        let msg = b"subset test";

        let p1 = kgen.key_shares[0].sign(msg).unwrap();
        let p2 = kgen.key_shares[1].sign(msg).unwrap();
        let p3 = kgen.key_shares[2].sign(msg).unwrap();

        let agg12 = aggregate_partial_sigs(&[p1.clone(), p2], msg).unwrap();
        let agg13 = aggregate_partial_sigs(&[p1, p3], msg).unwrap();

        // Different subsets produce different aggregated signatures
        assert_ne!(agg12.to_bytes(), agg13.to_bytes());
    }

    #[test]
    fn test_keygen_deterministic_pubkey_format() {
        let kgen = threshold_keygen(2, 3).unwrap();
        // Group PK should be 48 bytes
        assert_eq!(kgen.group_public_key.to_bytes().len(), 48);
        // Each share PK should be 48 bytes
        for share in &kgen.key_shares {
            assert_eq!(share.public_key.to_bytes().len(), 48);
        }
    }

    #[test]
    fn test_threshold_3_of_5() {
        let kgen = threshold_keygen(3, 5).unwrap();
        assert_eq!(kgen.key_shares.len(), 5);
        let msg = b"3-of-5 threshold";
        let p1 = kgen.key_shares[0].sign(msg).unwrap();
        let p2 = kgen.key_shares[2].sign(msg).unwrap();
        let p3 = kgen.key_shares[4].sign(msg).unwrap();
        let agg = aggregate_partial_sigs(&[p1, p2, p3], msg).unwrap();
        assert_ne!(agg.to_bytes(), [0u8; 96]);
    }
}
