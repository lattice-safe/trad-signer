//! MuSig2 Nested Key Aggregation (Key Trees) and Partial Signature Verification.
//!
//! Supports hierarchical key aggregation where some "leaf" keys are themselves
//! MuSig2 aggregate keys. Also provides partial signature verification to
//! validate individual signer contributions before aggregation.
//!
//! # Nested Key Example
//! ```text
//!    TopLevel (Q = agg(Q_a, Q_b))
//!         /         \
//!     Q_a = agg(pk1, pk2)    Q_b = pk3
//! ```
//! The group Q_a signs internally using 2-of-2 MuSig2, then their combined
//! partial signature contributes as one signer to the top-level session.

use crate::crypto;
use crate::error::SignerError;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use super::signing::{
    self, KeyAggContext, AggNonce, PubNonce, PartialSignature,
    compute_nonce_coeff,
};

// ═══════════════════════════════════════════════════════════════════
// Partial Signature Verification
// ═══════════════════════════════════════════════════════════════════

/// Verify a partial signature from a specific signer.
///
/// Checks that the partial signature `s_i` satisfies:
/// `s_i * G == R_i + e * a_i * (g * P_i)`
///
/// where:
/// - `R_i = R_{1,i} + b * R_{2,i}` (effective signer nonce)
/// - `e` = BIP-340 challenge
/// - `a_i` = key aggregation coefficient
/// - `g` = parity correction (1 or -1)
/// - `P_i` = signer's public key
///
/// # Arguments
/// - `partial_sig` — The partial signature to verify
/// - `pub_nonce` — The signer's public nonce (from round 1)
/// - `signer_pubkey` — The signer's compressed public key (33 bytes)
/// - `key_agg_ctx` — The key aggregation context
/// - `agg_nonce` — The aggregated nonce
/// - `msg` — The signed message
pub fn verify_partial_sig(
    partial_sig: &PartialSignature,
    pub_nonce: &PubNonce,
    signer_pubkey: &[u8; 33],
    key_agg_ctx: &KeyAggContext,
    agg_nonce: &AggNonce,
    msg: &[u8],
) -> Result<bool, SignerError> {
    // Compute nonce coefficient b
    let b = compute_nonce_coeff(agg_nonce, &key_agg_ctx.x_only_pubkey, msg);

    // Effective R for the group: R = R1_agg + b * R2_agg
    let r_group = ProjectivePoint::from(agg_nonce.r1) + ProjectivePoint::from(agg_nonce.r2) * b;
    let r_affine = r_group.to_affine();
    let r_encoded = r_affine.to_encoded_point(true);
    let r_bytes = r_encoded.as_bytes();
    let nonce_negated = r_bytes[0] == 0x03;
    let mut r_x = [0u8; 32];
    r_x.copy_from_slice(&r_bytes[1..33]);

    // BIP-340 challenge
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(&r_x);
    challenge_data.extend_from_slice(&key_agg_ctx.x_only_pubkey);
    challenge_data.extend_from_slice(msg);
    let e = tagged_hash_scalar(b"BIP0340/challenge", &challenge_data);

    // Find the signer's aggregation coefficient
    let signer_idx = key_agg_ctx.pubkeys.iter().position(|pk| pk == signer_pubkey);
    let signer_idx = match signer_idx {
        Some(idx) => idx,
        None => return Err(SignerError::SigningFailed("signer not in key_agg context".into())),
    };
    let a_i = key_agg_ctx.coefficients[signer_idx];

    // Parse the signer's public key
    let pk_ct = AffinePoint::from_bytes(signer_pubkey.into());
    if !bool::from(pk_ct.is_some()) {
        return Ok(false);
    }
    #[allow(clippy::unwrap_used)]
    let pk_point = ProjectivePoint::from(pk_ct.unwrap());

    // Effective signer nonce: R_i = R_{1,i} + b * R_{2,i}
    let ri = ProjectivePoint::from(pub_nonce.r1) + ProjectivePoint::from(pub_nonce.r2) * b;
    let effective_ri = if nonce_negated { -ri } else { ri };

    // Effective public key (negate if aggregate key has odd y)
    let effective_pk = if key_agg_ctx.parity { -pk_point } else { pk_point };

    // LHS: s_i * G
    let lhs = ProjectivePoint::GENERATOR * partial_sig.s;

    // RHS: R_i + e * a_i * P_i
    let rhs = effective_ri + effective_pk * (e * a_i);

    Ok(lhs == rhs)
}

// ═══════════════════════════════════════════════════════════════════
// Nested Key Aggregation (Key Trees)
// ═══════════════════════════════════════════════════════════════════

/// A node in a MuSig2 key tree.
#[derive(Clone, Debug)]
pub enum KeyTreeNode {
    /// A leaf node: a single public key (33 bytes compressed).
    Leaf([u8; 33]),
    /// An internal node: a MuSig2 aggregation of child nodes.
    Internal(Vec<KeyTreeNode>),
}

impl KeyTreeNode {
    /// Compute the effective public key for this node.
    ///
    /// For a leaf, returns the key directly.
    /// For an internal node, recursively aggregates child keys using MuSig2.
    pub fn effective_pubkey(&self) -> Result<[u8; 33], SignerError> {
        match self {
            KeyTreeNode::Leaf(pk) => Ok(*pk),
            KeyTreeNode::Internal(children) => {
                let child_keys: Result<Vec<[u8; 33]>, _> = children
                    .iter()
                    .map(|child| child.effective_pubkey())
                    .collect();
                let child_keys = child_keys?;
                let ctx = signing::key_agg(&child_keys)?;
                // Return the aggregate key as compressed point
                let agg_enc = ctx.aggregate_key.to_encoded_point(true);
                let mut out = [0u8; 33];
                out.copy_from_slice(agg_enc.as_bytes());
                Ok(out)
            }
        }
    }

    /// Get the key aggregation context for this node (only valid for Internal nodes).
    pub fn key_agg_context(&self) -> Result<KeyAggContext, SignerError> {
        match self {
            KeyTreeNode::Leaf(_) => Err(SignerError::ParseError(
                "leaf nodes don't have a key_agg context".into(),
            )),
            KeyTreeNode::Internal(children) => {
                let child_keys: Result<Vec<[u8; 33]>, _> = children
                    .iter()
                    .map(|child| child.effective_pubkey())
                    .collect();
                signing::key_agg(&child_keys?)
            }
        }
    }

    /// Count the total number of leaf keys in the tree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        match self {
            KeyTreeNode::Leaf(_) => 1,
            KeyTreeNode::Internal(children) => children.iter().map(|c| c.leaf_count()).sum(),
        }
    }

    /// Get the depth of the tree.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            KeyTreeNode::Leaf(_) => 0,
            KeyTreeNode::Internal(children) => {
                1 + children.iter().map(|c| c.depth()).max().unwrap_or(0)
            }
        }
    }
}

/// Build a flat MuSig2 key tree from a list of public keys.
///
/// All keys are leaves under a single internal aggregation node.
pub fn flat_key_tree(pubkeys: &[[u8; 33]]) -> KeyTreeNode {
    KeyTreeNode::Internal(
        pubkeys.iter().map(|pk| KeyTreeNode::Leaf(*pk)).collect()
    )
}

/// Build a 2-level key tree where each group is a sub-aggregation.
///
/// # Example
/// ```text
/// groups = [[pk1, pk2], [pk3, pk4]]
/// Result:
///   TopLevel
///     ├── agg(pk1, pk2)
///     └── agg(pk3, pk4)
/// ```
pub fn grouped_key_tree(groups: &[Vec<[u8; 33]>]) -> KeyTreeNode {
    KeyTreeNode::Internal(
        groups
            .iter()
            .map(|group| {
                if group.len() == 1 {
                    KeyTreeNode::Leaf(group[0])
                } else {
                    KeyTreeNode::Internal(
                        group.iter().map(|pk| KeyTreeNode::Leaf(*pk)).collect()
                    )
                }
            })
            .collect()
    )
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Tagged hash to scalar (duplicated for module isolation).
fn tagged_hash_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    let hash = crypto::tagged_hash(tag, data);
    let wide = k256::U256::from_be_slice(&hash);
    <Scalar as Reduce<k256::U256>>::reduce(wide)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use super::super::signing;

    fn make_keys() -> ([u8; 32], [u8; 32], [u8; 33], [u8; 33]) {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = signing::individual_pubkey(&sk1).unwrap();
        let pk2 = signing::individual_pubkey(&sk2).unwrap();
        (sk1, sk2, pk1, pk2)
    }

    // ─── Partial Signature Verification ─────────────────────────

    #[test]
    fn test_partial_sig_verify_valid() {
        let (sk1, sk2, pk1, pk2) = make_keys();
        let ctx = signing::key_agg(&[pk1, pk2]).unwrap();
        let msg = b"partial sig verify";

        let (sec1, pub1) = signing::nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
        let (sec2, pub2) = signing::nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
        let agg_nonce = signing::nonce_agg(&[pub1.clone(), pub2]).unwrap();

        let psig1 = signing::sign(sec1, &sk1, &ctx, &agg_nonce, msg).unwrap();

        let valid = verify_partial_sig(&psig1, &pub1, &pk1, &ctx, &agg_nonce, msg).unwrap();
        assert!(valid, "valid partial sig must verify");
    }

    #[test]
    fn test_partial_sig_verify_tampered() {
        let (sk1, sk2, pk1, pk2) = make_keys();
        let ctx = signing::key_agg(&[pk1, pk2]).unwrap();
        let msg = b"tampered partial sig";

        let (sec1, pub1) = signing::nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
        let (_sec2, pub2) = signing::nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
        let agg_nonce = signing::nonce_agg(&[pub1.clone(), pub2]).unwrap();

        let psig1 = signing::sign(sec1, &sk1, &ctx, &agg_nonce, msg).unwrap();

        // Tamper
        let tampered = PartialSignature { s: psig1.s + Scalar::ONE };
        let valid = verify_partial_sig(&tampered, &pub1, &pk1, &ctx, &agg_nonce, msg).unwrap();
        assert!(!valid, "tampered partial sig must fail");
    }

    #[test]
    fn test_partial_sig_wrong_key_fails() {
        let (sk1, sk2, pk1, pk2) = make_keys();
        let ctx = signing::key_agg(&[pk1, pk2]).unwrap();
        let msg = b"wrong key";

        let (sec1, pub1) = signing::nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
        let (_sec2, pub2) = signing::nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
        let agg_nonce = signing::nonce_agg(&[pub1.clone(), pub2]).unwrap();
        let psig1 = signing::sign(sec1, &sk1, &ctx, &agg_nonce, msg).unwrap();

        // Verify with wrong key (pk2 instead of pk1)
        let valid = verify_partial_sig(&psig1, &pub1, &pk2, &ctx, &agg_nonce, msg).unwrap();
        assert!(!valid, "partial sig verified with wrong key must fail");
    }

    // ─── Key Tree Tests ─────────────────────────────────────────

    #[test]
    fn test_flat_key_tree() {
        let (_, _, pk1, pk2) = make_keys();
        let tree = flat_key_tree(&[pk1, pk2]);
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.depth(), 1);

        let effective = tree.effective_pubkey().unwrap();
        let direct_ctx = signing::key_agg(&[pk1, pk2]).unwrap();
        let direct_enc = direct_ctx.aggregate_key.to_encoded_point(true);
        let mut direct_bytes = [0u8; 33];
        direct_bytes.copy_from_slice(direct_enc.as_bytes());
        assert_eq!(effective, direct_bytes, "flat tree should match direct agg");
    }

    #[test]
    fn test_nested_key_tree() {
        let sk3 = [0x33u8; 32];
        let pk3 = signing::individual_pubkey(&sk3).unwrap();
        let (_, _, pk1, pk2) = make_keys();

        // 2-level tree: agg(agg(pk1, pk2), pk3)
        let tree = KeyTreeNode::Internal(vec![
            KeyTreeNode::Internal(vec![
                KeyTreeNode::Leaf(pk1),
                KeyTreeNode::Leaf(pk2),
            ]),
            KeyTreeNode::Leaf(pk3),
        ]);

        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.depth(), 2);

        let effective = tree.effective_pubkey().unwrap();
        assert_ne!(effective, [0u8; 33]);

        // The top-level context should exist
        let ctx = tree.key_agg_context().unwrap();
        assert_eq!(ctx.pubkeys.len(), 2); // 2 children at top level
    }

    #[test]
    fn test_grouped_key_tree() {
        let (_, _, pk1, pk2) = make_keys();
        let sk3 = [0x33u8; 32];
        let sk4 = [0x44u8; 32];
        let pk3 = signing::individual_pubkey(&sk3).unwrap();
        let pk4 = signing::individual_pubkey(&sk4).unwrap();

        let tree = grouped_key_tree(&[vec![pk1, pk2], vec![pk3, pk4]]);
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.depth(), 2);

        let effective = tree.effective_pubkey().unwrap();
        assert_ne!(effective, [0u8; 33]);
    }

    #[test]
    fn test_leaf_key_agg_context_error() {
        let (_, _, pk1, _) = make_keys();
        let leaf = KeyTreeNode::Leaf(pk1);
        assert!(leaf.key_agg_context().is_err());
    }

    #[test]
    fn test_nested_tree_deterministic() {
        let (_, _, pk1, pk2) = make_keys();
        let sk3 = [0x33u8; 32];
        let pk3 = signing::individual_pubkey(&sk3).unwrap();

        let tree1 = KeyTreeNode::Internal(vec![
            KeyTreeNode::Internal(vec![KeyTreeNode::Leaf(pk1), KeyTreeNode::Leaf(pk2)]),
            KeyTreeNode::Leaf(pk3),
        ]);
        let tree2 = KeyTreeNode::Internal(vec![
            KeyTreeNode::Internal(vec![KeyTreeNode::Leaf(pk1), KeyTreeNode::Leaf(pk2)]),
            KeyTreeNode::Leaf(pk3),
        ]);

        assert_eq!(tree1.effective_pubkey().unwrap(), tree2.effective_pubkey().unwrap());
    }
}
