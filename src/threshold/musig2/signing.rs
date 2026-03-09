//! MuSig2 key aggregation and signing (BIP-327).

use crate::crypto;
use crate::error::SignerError;
use core::fmt;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::Zeroizing;

// ─── Tagged Hash Scalar ─────────────────────────────────────────────

/// Hash to scalar using tagged hash.
fn tagged_hash_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    super::tagged_hash_scalar(tag, data)
}

// ─── Key Aggregation (BIP-327 KeyAgg) ───────────────────────────────

/// Aggregated key context from `key_agg()`.
#[derive(Clone)]
pub struct KeyAggContext {
    /// The aggregate public key `Q` (combined point).
    pub aggregate_key: AffinePoint,
    /// The x-only aggregate public key bytes (32 bytes).
    pub x_only_pubkey: [u8; 32],
    /// Per-key aggregation coefficients `a_i`.
    pub(crate) coefficients: Vec<Scalar>,
    /// The original (sorted) public keys.
    pub(crate) pubkeys: Vec<[u8; 33]>,
    /// Parity flag for the aggregate key (for x-only compatibility).
    pub(crate) parity: bool,
}

impl core::fmt::Debug for KeyAggContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyAggContext")
            .field("x_only_pubkey", &hex::encode(self.x_only_pubkey))
            .field("coefficients", &"[REDACTED]")
            .field("num_keys", &self.pubkeys.len())
            .finish()
    }
}

/// A public nonce pair (2 points, each 33 bytes SEC1 compressed).
#[derive(Clone, Debug)]
pub struct PubNonce {
    /// First public nonce `R_1 = G * k_1`.
    pub r1: AffinePoint,
    /// Second public nonce `R_2 = G * k_2`.
    pub r2: AffinePoint,
}

impl PubNonce {
    /// Encode as 66 bytes: `R1 (33) || R2 (33)`.
    pub fn to_bytes(&self) -> [u8; 66] {
        let r1_enc = ProjectivePoint::from(self.r1)
            .to_affine()
            .to_encoded_point(true);
        let r2_enc = ProjectivePoint::from(self.r2)
            .to_affine()
            .to_encoded_point(true);
        let mut out = [0u8; 66];
        out[..33].copy_from_slice(r1_enc.as_bytes());
        out[33..].copy_from_slice(r2_enc.as_bytes());
        out[33..].copy_from_slice(r2_enc.as_bytes());
        out
    }
}

/// Secret nonce pair (MUST be used exactly once).
pub struct SecNonce {
    /// First secret nonce scalar.
    k1: Zeroizing<Scalar>,
    /// Second secret nonce scalar.
    k2: Zeroizing<Scalar>,
    /// The associated public key (for safety checks).
    pub(crate) pubkey: [u8; 33],
}

impl Drop for SecNonce {
    fn drop(&mut self) {
        // k1 and k2 are Zeroizing
    }
}

/// Aggregated nonce (2 points).
#[derive(Clone, Debug)]
pub struct AggNonce {
    /// First aggregated nonce `R_1 = Σ R_{1,i}`.
    pub r1: AffinePoint,
    /// Second aggregated nonce `R_2 = Σ R_{2,i}`.
    pub r2: AffinePoint,
}

/// A partial signature scalar.
#[derive(Clone)]
pub struct PartialSignature {
    /// The partial signature scalar.
    pub s: Scalar,
}

impl fmt::Debug for PartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialSignature")
            .field("s", &"[REDACTED]")
            .finish()
    }
}

/// A final MuSig2 Schnorr signature (64 bytes: x(R) || s).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MuSig2Signature {
    /// 32-byte x-coordinate of R.
    pub r: [u8; 32],
    /// 32-byte scalar s.
    pub s: [u8; 32],
}

impl MuSig2Signature {
    /// Encode as 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }
}

// ─── Public Key Utilities ───────────────────────────────────────────

/// Compute the compressed (33-byte) public key from a 32-byte secret key.
pub fn individual_pubkey(secret_key: &[u8; 32]) -> Result<[u8; 33], SignerError> {
    let wide = k256::U256::from_be_slice(secret_key);
    let scalar = <Scalar as Reduce<k256::U256>>::reduce(wide);
    if scalar == Scalar::ZERO {
        return Err(SignerError::InvalidPrivateKey("secret key is zero".into()));
    }
    let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
    let encoded = point.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

/// Sort public keys lexicographically (BIP-327 KeySort).
pub fn key_sort(pubkeys: &[[u8; 33]]) -> Vec<[u8; 33]> {
    let mut sorted = pubkeys.to_vec();
    sorted.sort();
    sorted
}

/// Compute the hash of all public keys (used in key aggregation coefficient).
pub(crate) fn hash_keys(pubkeys: &[[u8; 33]]) -> [u8; 32] {
    let mut data = Vec::with_capacity(pubkeys.len() * 33);
    for pk in pubkeys {
        data.extend_from_slice(pk);
    }
    crypto::tagged_hash(b"KeyAgg list", &data)
}

/// Key aggregation: combine N public keys into a single aggregate key (BIP-327).
///
/// Each key gets a coefficient `a_i = H("KeyAgg coefficient", L || pk_i)`
/// where `L = H("KeyAgg list", pk_1 || ... || pk_n)`.
///
/// Exception: the "second unique key" gets coefficient 1 for efficiency.
pub fn key_agg(pubkeys: &[[u8; 33]]) -> Result<KeyAggContext, SignerError> {
    if pubkeys.is_empty() {
        return Err(SignerError::InvalidPrivateKey("empty pubkey list".into()));
    }

    // Validate all public keys
    for pk in pubkeys {
        parse_point(pk)?;
    }

    let pk_list_hash = hash_keys(pubkeys);

    // Find the "second unique key" value (first key that differs from pubkeys[0])
    let second_key: Option<&[u8; 33]> = pubkeys.iter().find(|pk| *pk != &pubkeys[0]);

    // Compute coefficients
    // Per BIP-327: a_i = 1 if pk_i == second_key, else H(L || pk_i)
    let mut coefficients = Vec::with_capacity(pubkeys.len());
    for pk in pubkeys {
        let a_i = if second_key == Some(pk) {
            // All keys equal to the second unique key get coefficient 1
            Scalar::ONE
        } else {
            let mut data = Vec::with_capacity(32 + 33);
            data.extend_from_slice(&pk_list_hash);
            data.extend_from_slice(pk);
            tagged_hash_scalar(b"KeyAgg coefficient", &data)
        };
        coefficients.push(a_i);
    }

    // Aggregate: Q = Σ a_i * P_i
    let mut q = ProjectivePoint::IDENTITY;
    for (i, pk) in pubkeys.iter().enumerate() {
        let point = parse_point(pk)?;
        q += point * coefficients[i];
    }

    let q_affine = q.to_affine();
    let q_encoded = q_affine.to_encoded_point(true);
    let q_bytes = q_encoded.as_bytes();

    // x-only pubkey (32 bytes)
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&q_bytes[1..33]);

    // Parity: if the y-coordinate is odd, we negate
    let parity = q_bytes[0] == 0x03;

    Ok(KeyAggContext {
        aggregate_key: q_affine,
        x_only_pubkey: x_only,
        coefficients,
        pubkeys: pubkeys.to_vec(),
        parity,
    })
}

// ─── Nonce Generation ───────────────────────────────────────────────

/// Generate a secret/public nonce pair for MuSig2 signing.
///
/// # Security
/// The returned `SecNonce` MUST be used exactly once and then discarded.
/// Nonce reuse across different messages leads to private key extraction.
pub fn nonce_gen(
    _secret_key: &[u8; 32],
    pubkey: &[u8; 33],
    key_agg_ctx: &KeyAggContext,
    msg: &[u8],
    extra_in: &[u8],
) -> Result<(SecNonce, PubNonce), SignerError> {
    // Generate random seed
    let mut rand_bytes = [0u8; 32];
    crate::security::secure_random(&mut rand_bytes)?;

    // k_1 = H("MuSig/nonce" || rand || pk || agg_pk || msg_prefixed || extra)
    let k1 = {
        let mut data = Vec::new();
        data.extend_from_slice(&rand_bytes);
        data.extend_from_slice(pubkey);
        data.extend_from_slice(&key_agg_ctx.x_only_pubkey);
        data.push(0x01); // nonce index
        data.extend_from_slice(msg);
        data.extend_from_slice(extra_in);
        let hash = crypto::tagged_hash(b"MuSig/nonce", &data);
        let wide = k256::U256::from_be_slice(&hash);
        let s = <Scalar as Reduce<k256::U256>>::reduce(wide);
        if s == Scalar::ZERO {
            return Err(SignerError::EntropyError);
        }
        s
    };

    // k_2 = H("MuSig/nonce" || rand || pk || agg_pk || msg_prefixed || extra) with different index
    let k2 = {
        let mut data = Vec::new();
        data.extend_from_slice(&rand_bytes);
        data.extend_from_slice(pubkey);
        data.extend_from_slice(&key_agg_ctx.x_only_pubkey);
        data.push(0x02); // nonce index
        data.extend_from_slice(msg);
        data.extend_from_slice(extra_in);
        let hash = crypto::tagged_hash(b"MuSig/nonce", &data);
        let wide = k256::U256::from_be_slice(&hash);
        let s = <Scalar as Reduce<k256::U256>>::reduce(wide);
        if s == Scalar::ZERO {
            return Err(SignerError::EntropyError);
        }
        s
    };

    let r1 = (ProjectivePoint::GENERATOR * k1).to_affine();
    let r2 = (ProjectivePoint::GENERATOR * k2).to_affine();

    let sec_nonce = SecNonce {
        k1: Zeroizing::new(k1),
        k2: Zeroizing::new(k2),
        pubkey: *pubkey,
    };

    let pub_nonce = PubNonce { r1, r2 };

    Ok((sec_nonce, pub_nonce))
}

/// Aggregate public nonces from all signers.
pub fn nonce_agg(pub_nonces: &[PubNonce]) -> Result<AggNonce, SignerError> {
    if pub_nonces.is_empty() {
        return Err(SignerError::InvalidPrivateKey("empty nonce list".into()));
    }

    let mut r1 = ProjectivePoint::IDENTITY;
    let mut r2 = ProjectivePoint::IDENTITY;

    for pn in pub_nonces {
        r1 += ProjectivePoint::from(pn.r1);
        r2 += ProjectivePoint::from(pn.r2);
    }

    Ok(AggNonce {
        r1: r1.to_affine(),
        r2: r2.to_affine(),
    })
}

// ─── Partial Signing ────────────────────────────────────────────────

/// Compute the nonce coefficient `b` from the session context.
pub(crate) fn compute_nonce_coeff(
    agg_nonce: &AggNonce,
    x_only_pubkey: &[u8; 32],
    msg: &[u8],
) -> Scalar {
    let r1_enc = ProjectivePoint::from(agg_nonce.r1)
        .to_affine()
        .to_encoded_point(true);
    let r2_enc = ProjectivePoint::from(agg_nonce.r2)
        .to_affine()
        .to_encoded_point(true);

    let mut data = Vec::new();
    data.extend_from_slice(r1_enc.as_bytes());
    data.extend_from_slice(r2_enc.as_bytes());
    data.extend_from_slice(x_only_pubkey);
    data.extend_from_slice(msg);

    tagged_hash_scalar(b"MuSig/noncecoef", &data)
}

/// Produce a partial signature.
///
/// `s_i = k1_i + b * k2_i + e * a_i * sk_i`
/// where `e` is the BIP-340 challenge and `a_i` is the key aggregation coefficient.
pub fn sign(
    sec_nonce: SecNonce,
    secret_key: &[u8; 32],
    key_agg_ctx: &KeyAggContext,
    agg_nonce: &AggNonce,
    msg: &[u8],
) -> Result<PartialSignature, SignerError> {
    let sk_wide = k256::U256::from_be_slice(secret_key);
    let sk_scalar = <Scalar as Reduce<k256::U256>>::reduce(sk_wide);

    // Compute nonce coefficient b
    let b = compute_nonce_coeff(agg_nonce, &key_agg_ctx.x_only_pubkey, msg);

    // Effective nonce: R = R1 + b * R2
    let r = ProjectivePoint::from(agg_nonce.r1) + ProjectivePoint::from(agg_nonce.r2) * b;
    let r_affine = r.to_affine();
    let r_encoded = r_affine.to_encoded_point(true);
    let r_bytes = r_encoded.as_bytes();

    // x-only R for BIP-340 compatibility
    let mut r_x = [0u8; 32];
    r_x.copy_from_slice(&r_bytes[1..33]);

    // Negate nonce if R has odd y
    let nonce_negated = r_bytes[0] == 0x03;

    // BIP-340 challenge: e = H("BIP0340/challenge", R_x || P_x || msg)
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(&r_x);
    challenge_data.extend_from_slice(&key_agg_ctx.x_only_pubkey);
    challenge_data.extend_from_slice(msg);
    let e = tagged_hash_scalar(b"BIP0340/challenge", &challenge_data);

    // Find my coefficient
    let my_idx = key_agg_ctx
        .pubkeys
        .iter()
        .position(|pk| pk == &sec_nonce.pubkey)
        .ok_or_else(|| SignerError::SigningFailed("pubkey not in key_agg context".into()))?;
    let a_i = key_agg_ctx.coefficients[my_idx];

    // Effective secret key (negate if aggregate key has odd y)
    let mut d = sk_scalar;
    if key_agg_ctx.parity {
        d = -d;
    }

    // Effective nonces (negate if R has odd y)
    let mut k1 = *sec_nonce.k1;
    let mut k2 = *sec_nonce.k2;
    if nonce_negated {
        k1 = -k1;
        k2 = -k2;
    }

    // s_i = k1 + b*k2 + e * a_i * d
    let s = k1 + b * k2 + e * a_i * d;

    Ok(PartialSignature { s })
}

/// Aggregate partial signatures into a final MuSig2 Schnorr signature.
///
/// Returns a 64-byte BIP-340 compatible signature: `x(R) || s`.
pub fn partial_sig_agg(
    partial_sigs: &[PartialSignature],
    agg_nonce: &AggNonce,
    key_agg_ctx: &KeyAggContext,
    msg: &[u8],
) -> Result<MuSig2Signature, SignerError> {
    if partial_sigs.is_empty() {
        return Err(SignerError::SigningFailed(
            "empty partial signatures".into(),
        ));
    }

    // Compute effective R
    let b = compute_nonce_coeff(agg_nonce, &key_agg_ctx.x_only_pubkey, msg);
    let r = ProjectivePoint::from(agg_nonce.r1) + ProjectivePoint::from(agg_nonce.r2) * b;
    let r_affine = r.to_affine();
    let r_encoded = r_affine.to_encoded_point(true);
    let r_bytes = r_encoded.as_bytes();

    // x-only R
    let mut r_x = [0u8; 32];
    r_x.copy_from_slice(&r_bytes[1..33]);

    // Sum partial signatures
    let mut s = Scalar::ZERO;
    for psig in partial_sigs {
        s += psig.s;
    }

    Ok(MuSig2Signature {
        r: r_x,
        s: s.to_bytes().into(),
    })
}

/// Verify a MuSig2 signature using standard BIP-340 Schnorr verification.
///
/// `s * G == R + e * P`
pub fn verify(
    sig: &MuSig2Signature,
    x_only_pubkey: &[u8; 32],
    msg: &[u8],
) -> Result<bool, SignerError> {
    // Parse R as a point with even y
    let mut r_sec1 = [0u8; 33];
    r_sec1[0] = 0x02; // even y
    r_sec1[1..].copy_from_slice(&sig.r);
    let r_point = parse_point(&r_sec1)?;

    // Parse s
    let s_wide = k256::U256::from_be_slice(&sig.s);
    let s_scalar = <Scalar as Reduce<k256::U256>>::reduce(s_wide);

    // Parse public key as point with even y
    let mut pk_sec1 = [0u8; 33];
    pk_sec1[0] = 0x02; // even y
    pk_sec1[1..].copy_from_slice(x_only_pubkey);
    let pk_point = parse_point(&pk_sec1)?;

    // Challenge: e = H("BIP0340/challenge", R_x || P_x || msg)
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(&sig.r);
    challenge_data.extend_from_slice(x_only_pubkey);
    challenge_data.extend_from_slice(msg);
    let e = tagged_hash_scalar(b"BIP0340/challenge", &challenge_data);

    // Verify: s * G == R + e * P
    let lhs = ProjectivePoint::GENERATOR * s_scalar;
    let rhs = r_point + pk_point * e;

    Ok(lhs == rhs)
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Parse a 33-byte SEC1 compressed point.
fn parse_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, SignerError> {
    // Validate prefix byte first (0x02 = even y, 0x03 = odd y)
    if bytes[0] != 0x02 && bytes[0] != 0x03 {
        return Err(SignerError::InvalidPrivateKey(
            "invalid compressed point prefix".into(),
        ));
    }
    let ct = AffinePoint::from_bytes(bytes.into());
    if !bool::from(ct.is_some()) {
        return Err(SignerError::InvalidPrivateKey(
            "invalid compressed point".into(),
        ));
    }
    // Safe: is_some() verified above. CtOption::unwrap() is constant-time.
    #[allow(clippy::unwrap_used)]
    Ok(ProjectivePoint::from(ct.unwrap()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── Individual Pubkey ──────────────────────────────────────

    #[test]
    fn test_individual_pubkey_from_known_key() {
        // Secret key = 1 → generator point G (compressed)
        let sk = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        };
        let pk = individual_pubkey(&sk).unwrap();
        // Generator point compressed: 02 79BE667E...
        assert_eq!(pk[0], 0x02);
        assert_eq!(
            hex::encode(&pk[1..]),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_individual_pubkey_zero_key_rejected() {
        let sk = [0u8; 32];
        assert!(individual_pubkey(&sk).is_err());
    }

    #[test]
    fn test_individual_pubkey_deterministic() {
        let sk = [0x42u8; 32];
        let pk1 = individual_pubkey(&sk).unwrap();
        let pk2 = individual_pubkey(&sk).unwrap();
        assert_eq!(pk1, pk2);
    }

    // ─── Key Aggregation (BIP-327 KeyAgg) ───────────────────────

    #[test]
    fn test_key_agg_two_keys() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();

        let ctx = key_agg(&[pk1, pk2]).unwrap();
        assert_eq!(ctx.x_only_pubkey.len(), 32);
        assert_eq!(ctx.pubkeys.len(), 2);
        assert_eq!(ctx.coefficients.len(), 2);
    }

    #[test]
    fn test_key_agg_deterministic() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();

        let ctx1 = key_agg(&[pk1, pk2]).unwrap();
        let ctx2 = key_agg(&[pk1, pk2]).unwrap();
        assert_eq!(ctx1.x_only_pubkey, ctx2.x_only_pubkey);
    }

    #[test]
    fn test_key_agg_empty_rejected() {
        assert!(key_agg(&[]).is_err());
    }

    #[test]
    fn test_key_agg_order_matters() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();

        let ctx_12 = key_agg(&[pk1, pk2]).unwrap();
        let ctx_21 = key_agg(&[pk2, pk1]).unwrap();
        // Different order → different aggregate key (unless sorted first)
        // This is expected BIP-327 behavior
        assert_ne!(ctx_12.x_only_pubkey, ctx_21.x_only_pubkey);
    }

    #[test]
    fn test_key_sort() {
        let sk1 = [0x01u8; 32];
        let sk2 = [0x02u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();

        let sorted = key_sort(&[pk2, pk1]);
        let sorted2 = key_sort(&[pk1, pk2]);
        assert_eq!(sorted, sorted2); // same order regardless of input
    }

    // ─── Full 2-of-2 Signing Round-Trip ─────────────────────────

    #[test]
    fn test_musig2_full_roundtrip() {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();

        // Key aggregation
        let key_agg_ctx = key_agg(&[pk1, pk2]).unwrap();

        // Nonce generation
        let msg = b"musig2 test message";
        let (sec1, pub1) = nonce_gen(&sk1, &pk1, &key_agg_ctx, msg, &[]).unwrap();
        let (sec2, pub2) = nonce_gen(&sk2, &pk2, &key_agg_ctx, msg, &[]).unwrap();

        // Nonce aggregation
        let agg_nonce = nonce_agg(&[pub1, pub2]).unwrap();

        // Partial signing
        let psig1 = sign(sec1, &sk1, &key_agg_ctx, &agg_nonce, msg).unwrap();
        let psig2 = sign(sec2, &sk2, &key_agg_ctx, &agg_nonce, msg).unwrap();

        // Aggregate
        let sig = partial_sig_agg(&[psig1, psig2], &agg_nonce, &key_agg_ctx, msg).unwrap();
        assert_eq!(sig.to_bytes().len(), 64);

        // BIP-340 verification
        let valid = verify(&sig, &key_agg_ctx.x_only_pubkey, msg).unwrap();
        assert!(valid, "MuSig2 signature must verify");
    }

    #[test]
    fn test_musig2_different_messages_different_sigs() {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();
        let ctx = key_agg(&[pk1, pk2]).unwrap();

        let msg1 = b"message one";
        let msg2 = b"message two";

        let (s1a, p1a) = nonce_gen(&sk1, &pk1, &ctx, msg1, &[]).unwrap();
        let (s2a, p2a) = nonce_gen(&sk2, &pk2, &ctx, msg1, &[]).unwrap();
        let an_a = nonce_agg(&[p1a, p2a]).unwrap();
        let ps1a = sign(s1a, &sk1, &ctx, &an_a, msg1).unwrap();
        let ps2a = sign(s2a, &sk2, &ctx, &an_a, msg1).unwrap();
        let sig1 = partial_sig_agg(&[ps1a, ps2a], &an_a, &ctx, msg1).unwrap();

        let (s1b, p1b) = nonce_gen(&sk1, &pk1, &ctx, msg2, &[]).unwrap();
        let (s2b, p2b) = nonce_gen(&sk2, &pk2, &ctx, msg2, &[]).unwrap();
        let an_b = nonce_agg(&[p1b, p2b]).unwrap();
        let ps1b = sign(s1b, &sk1, &ctx, &an_b, msg2).unwrap();
        let ps2b = sign(s2b, &sk2, &ctx, &an_b, msg2).unwrap();
        let sig2 = partial_sig_agg(&[ps1b, ps2b], &an_b, &ctx, msg2).unwrap();

        // Different messages → different signatures
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn test_musig2_wrong_message_fails_verification() {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();
        let ctx = key_agg(&[pk1, pk2]).unwrap();

        let msg = b"correct message";
        let (s1, p1) = nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
        let (s2, p2) = nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
        let an = nonce_agg(&[p1, p2]).unwrap();
        let ps1 = sign(s1, &sk1, &ctx, &an, msg).unwrap();
        let ps2 = sign(s2, &sk2, &ctx, &an, msg).unwrap();
        let sig = partial_sig_agg(&[ps1, ps2], &an, &ctx, msg).unwrap();

        // Verify with wrong message
        let valid = verify(&sig, &ctx.x_only_pubkey, b"wrong message").unwrap();
        assert!(!valid, "signature must not verify for wrong message");
    }

    #[test]
    fn test_nonce_agg_empty_rejected() {
        assert!(nonce_agg(&[]).is_err());
    }

    #[test]
    fn test_partial_sig_agg_empty_rejected() {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = individual_pubkey(&sk1).unwrap();
        let pk2 = individual_pubkey(&sk2).unwrap();
        let ctx = key_agg(&[pk1, pk2]).unwrap();
        let (_, p1) = nonce_gen(&sk1, &pk1, &ctx, b"x", &[]).unwrap();
        let (_, p2) = nonce_gen(&sk2, &pk2, &ctx, b"x", &[]).unwrap();
        let an = nonce_agg(&[p1, p2]).unwrap();
        assert!(partial_sig_agg(&[], &an, &ctx, b"x").is_err());
    }
}
