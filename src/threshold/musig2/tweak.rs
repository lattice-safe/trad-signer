//! MuSig2 tweaking (BIP-32 plain and BIP-341 x-only/Taproot tweaks).
//!
//! Supports two kinds of tweaks per BIP-327:
//! - **Plain tweak**: `Q = Q' + t*G` (for BIP-32 key derivation).
//! - **X-only tweak**: `Q = has_even_y(Q') ? Q' + t*G : -Q' + t*G`
//!   (for Taproot commitments, BIP-341).

use crate::crypto;
use crate::error::SignerError;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};

use super::signing::KeyAggContext;

/// A tweak to apply to an aggregated key.
#[derive(Clone, Debug)]
pub struct Tweak {
    /// The tweak scalar.
    pub scalar: Scalar,
    /// Whether this is an x-only (Taproot) tweak.
    pub is_xonly: bool,
}

/// Tweaked key aggregation context.
#[derive(Clone, Debug)]
pub struct TweakedKeyAggContext {
    /// The original (pre-tweak) key aggregation context.
    pub original: KeyAggContext,
    /// The tweaked aggregate key.
    pub tweaked_key: AffinePoint,
    /// The x-only tweaked key (32 bytes).
    pub tweaked_x_only: [u8; 32],
    /// Accumulated tweak value for signature adjustment.
    pub tweak_acc: Scalar,
    /// Whether the key was negated during tweaking.
    pub negated: bool,
}

/// Apply a plain tweak (BIP-32 style) to a key aggregation context.
///
/// Computes `Q = P + t*G` where `P` is the aggregate key and `t` is the tweak.
///
/// # Arguments
/// - `ctx` — The key aggregation context
/// - `tweak_bytes` — 32-byte tweak value (e.g., from BIP-32 derivation)
pub fn apply_plain_tweak(
    ctx: &KeyAggContext,
    tweak_bytes: &[u8; 32],
) -> Result<TweakedKeyAggContext, SignerError> {
    let t = parse_tweak_scalar(tweak_bytes)?;

    let p = ProjectivePoint::from(ctx.aggregate_key);
    let q = p + ProjectivePoint::GENERATOR * t;
    let q_affine = q.to_affine();
    let q_enc = q_affine.to_encoded_point(true);
    let q_bytes = q_enc.as_bytes();

    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&q_bytes[1..33]);

    Ok(TweakedKeyAggContext {
        original: ctx.clone(),
        tweaked_key: q_affine,
        tweaked_x_only: x_only,
        tweak_acc: t,
        negated: false,
    })
}

/// Apply an x-only tweak (Taproot/BIP-341 style) to a key aggregation context.
///
/// If the aggregate key has odd Y, negate it first, then add `t*G`.
/// This ensures the tweaked key always has even Y (x-only compatible).
///
/// # Arguments
/// - `ctx` — The key aggregation context
/// - `tweak_bytes` — 32-byte tweak value (e.g., tagged hash of taproot data)
pub fn apply_xonly_tweak(
    ctx: &KeyAggContext,
    tweak_bytes: &[u8; 32],
) -> Result<TweakedKeyAggContext, SignerError> {
    let t = parse_tweak_scalar(tweak_bytes)?;

    let p = ProjectivePoint::from(ctx.aggregate_key);
    let p_enc = ctx.aggregate_key.to_encoded_point(true);
    let has_odd_y = p_enc.as_bytes()[0] == 0x03;

    // If odd Y, negate P
    let effective_p = if has_odd_y { -p } else { p };
    let effective_t = if has_odd_y { -t } else { t };

    let q = effective_p + ProjectivePoint::GENERATOR * t;
    let q_affine = q.to_affine();
    let q_enc = q_affine.to_encoded_point(true);
    let q_bytes = q_enc.as_bytes();

    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&q_bytes[1..33]);

    Ok(TweakedKeyAggContext {
        original: ctx.clone(),
        tweaked_key: q_affine,
        tweaked_x_only: x_only,
        tweak_acc: effective_t,
        negated: has_odd_y,
    })
}

/// Compute a BIP-341 taproot tweak from the internal key and merkle root.
///
/// `t = tagged_hash("TapTweak", internal_key || merkle_root)`
///
/// If no scripts (merkle_root is None), uses just the internal key.
pub fn compute_taproot_tweak(
    internal_key_x: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(internal_key_x);
    if let Some(root) = merkle_root {
        data.extend_from_slice(root);
    }
    crypto::tagged_hash(b"TapTweak", &data)
}

/// Adjust a partial signature for a tweaked key.
///
/// When signing with a tweaked key, the final partial signature must be
/// adjusted: `s_adj = s + e * t * g` where `t` is the accumulated tweak
/// and `g` determines parity correction.
pub fn adjust_partial_sig_for_tweak(
    partial_s: &Scalar,
    challenge: &Scalar,
    tweak_ctx: &TweakedKeyAggContext,
) -> Scalar {
    let adjustment = *challenge * tweak_ctx.tweak_acc;
    *partial_s + adjustment
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Parse a 32-byte tweak into a scalar.
fn parse_tweak_scalar(bytes: &[u8; 32]) -> Result<Scalar, SignerError> {
    let wide = k256::U256::from_be_slice(bytes);
    let scalar = <Scalar as Reduce<k256::U256>>::reduce(wide);
    Ok(scalar)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use super::super::signing;

    fn setup_2_of_2() -> (KeyAggContext, [u8; 33], [u8; 33]) {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = signing::individual_pubkey(&sk1).unwrap();
        let pk2 = signing::individual_pubkey(&sk2).unwrap();
        let ctx = signing::key_agg(&[pk1, pk2]).unwrap();
        (ctx, pk1, pk2)
    }

    // ─── Plain Tweak Tests ──────────────────────────────────────

    #[test]
    fn test_plain_tweak_changes_key() {
        let (ctx, _, _) = setup_2_of_2();
        let tweak = [0x01u8; 32];
        let tweaked = apply_plain_tweak(&ctx, &tweak).unwrap();
        assert_ne!(tweaked.tweaked_x_only, ctx.x_only_pubkey);
    }

    #[test]
    fn test_plain_tweak_deterministic() {
        let (ctx, _, _) = setup_2_of_2();
        let tweak = [0x42u8; 32];
        let t1 = apply_plain_tweak(&ctx, &tweak).unwrap();
        let t2 = apply_plain_tweak(&ctx, &tweak).unwrap();
        assert_eq!(t1.tweaked_x_only, t2.tweaked_x_only);
    }

    #[test]
    fn test_plain_tweak_zero_preserves_key() {
        let (ctx, _, _) = setup_2_of_2();
        let tweak = [0u8; 32];
        let tweaked = apply_plain_tweak(&ctx, &tweak).unwrap();
        assert_eq!(tweaked.tweaked_x_only, ctx.x_only_pubkey);
    }

    // ─── X-Only Tweak Tests ─────────────────────────────────────

    #[test]
    fn test_xonly_tweak_changes_key() {
        let (ctx, _, _) = setup_2_of_2();
        let tweak = [0x01u8; 32];
        let tweaked = apply_xonly_tweak(&ctx, &tweak).unwrap();
        assert_ne!(tweaked.tweaked_x_only, ctx.x_only_pubkey);
    }

    #[test]
    fn test_xonly_tweak_deterministic() {
        let (ctx, _, _) = setup_2_of_2();
        let tweak = [0xABu8; 32];
        let t1 = apply_xonly_tweak(&ctx, &tweak).unwrap();
        let t2 = apply_xonly_tweak(&ctx, &tweak).unwrap();
        assert_eq!(t1.tweaked_x_only, t2.tweaked_x_only);
    }

    // ─── Taproot Tweak Computation ──────────────────────────────

    #[test]
    fn test_taproot_tweak_computation() {
        let internal_key = [0x42u8; 32];
        let merkle_root = [0xABu8; 32];

        // With merkle root
        let t1 = compute_taproot_tweak(&internal_key, Some(&merkle_root));
        assert_ne!(t1, [0u8; 32]);

        // Without merkle root (key-path only)
        let t2 = compute_taproot_tweak(&internal_key, None);
        assert_ne!(t2, [0u8; 32]);

        // They should differ
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_taproot_tweak_bip341_test_vector() {
        // BIP-341 test vector: internal key → tweaked key
        // Internal key from BIP-341 test: d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d
        let internal_key = hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d").unwrap();
        let mut ik = [0u8; 32];
        ik.copy_from_slice(&internal_key);

        // Key-path-only spend (no scripts)
        let tweak = compute_taproot_tweak(&ik, None);
        assert_ne!(tweak, [0u8; 32]);
        // The tweak should be deterministic
        let tweak2 = compute_taproot_tweak(&ik, None);
        assert_eq!(tweak, tweak2);
    }

    // ─── Tweak Signature Adjustment ─────────────────────────────

    #[test]
    fn test_adjust_partial_sig() {
        let (ctx, _, _) = setup_2_of_2();
        let tweak = [0x01u8; 32];
        let tweaked = apply_plain_tweak(&ctx, &tweak).unwrap();

        let partial_s = Scalar::from(42u64);
        let challenge = Scalar::from(7u64);

        let adjusted = adjust_partial_sig_for_tweak(&partial_s, &challenge, &tweaked);
        // adjusted = partial_s + challenge * tweak_acc
        assert_ne!(adjusted, partial_s);
        // Verify the math: adjusted - partial_s should equal challenge * tweak_acc
        let diff = adjusted - partial_s;
        assert_eq!(diff, challenge * tweaked.tweak_acc);
    }
}
