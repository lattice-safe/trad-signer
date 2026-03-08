//! MuSig2 key aggregation and signing (BIP-327).

use crate::error::SignerError;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ─── Tagged Hashes (BIP-340 style) ──────────────────────────────────

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
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

/// Hash to scalar using tagged hash.
fn tagged_hash_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    let hash = tagged_hash(tag, data);
    let wide = k256::U256::from_be_slice(&hash);
    <Scalar as Reduce<k256::U256>>::reduce(wide)
}

// ─── Key Aggregation (BIP-327 KeyAgg) ───────────────────────────────

/// Aggregated key context from `key_agg()`.
#[derive(Clone, Debug)]
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
        let r1_enc = ProjectivePoint::from(self.r1).to_affine().to_encoded_point(true);
        let r2_enc = ProjectivePoint::from(self.r2).to_affine().to_encoded_point(true);
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
#[derive(Clone, Debug)]
pub struct PartialSignature {
    /// The partial signature scalar.
    pub s: Scalar,
}

/// A final MuSig2 Schnorr signature (64 bytes: x(R) || s).
#[derive(Clone, Debug)]
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
fn hash_keys(pubkeys: &[[u8; 33]]) -> [u8; 32] {
    let mut data = Vec::with_capacity(pubkeys.len() * 33);
    for pk in pubkeys {
        data.extend_from_slice(pk);
    }
    tagged_hash(b"KeyAgg list", &data)
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
    getrandom::getrandom(&mut rand_bytes).map_err(|_| SignerError::EntropyError)?;

    // k_1 = H("MuSig/nonce" || rand || pk || agg_pk || msg_prefixed || extra)
    let k1 = {
        let mut data = Vec::new();
        data.extend_from_slice(&rand_bytes);
        data.extend_from_slice(pubkey);
        data.extend_from_slice(&key_agg_ctx.x_only_pubkey);
        data.push(0x01); // nonce index
        data.extend_from_slice(msg);
        data.extend_from_slice(extra_in);
        let hash = tagged_hash(b"MuSig/nonce", &data);
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
        let hash = tagged_hash(b"MuSig/nonce", &data);
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
        return Err(SignerError::InvalidPrivateKey(
            "empty nonce list".into(),
        ));
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
fn compute_nonce_coeff(
    agg_nonce: &AggNonce,
    x_only_pubkey: &[u8; 32],
    msg: &[u8],
) -> Scalar {
    let r1_enc = ProjectivePoint::from(agg_nonce.r1).to_affine().to_encoded_point(true);
    let r2_enc = ProjectivePoint::from(agg_nonce.r2).to_affine().to_encoded_point(true);

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
