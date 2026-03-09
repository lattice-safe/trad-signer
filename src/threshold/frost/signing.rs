//! FROST two-round signing protocol (RFC 9591 Section 5).
//!
//! Implements the FROST(secp256k1, SHA-256) ciphersuite.
//! contextString = "FROST-secp256k1-SHA256-v1"

use crate::error::SignerError;
use crate::threshold::frost::keygen::{derive_interpolating_value, KeyPackage};
// GroupEncoding import required for AffinePoint::from_bytes() trait resolution.
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Context string for FROST(secp256k1, SHA-256).
const CONTEXT_STRING: &[u8] = b"FROST-secp256k1-SHA256-v1";

// ─── Data Types ──────────────────────────────────────────────────────

/// Secret nonces generated in round 1 (MUST be used exactly once, then discarded).
pub struct SigningNonces {
    /// Hiding nonce `d_i`.
    pub(crate) hiding: Zeroizing<Scalar>,
    /// Binding nonce `e_i`.
    pub(crate) binding: Zeroizing<Scalar>,
    /// The corresponding public commitments.
    pub commitments: SigningCommitments,
}

impl Drop for SigningNonces {
    fn drop(&mut self) {
        // hiding and binding are Zeroizing<Scalar>
    }
}

/// Public commitments broadcast in round 1.
#[derive(Clone, Debug)]
pub struct SigningCommitments {
    /// Participant identifier.
    pub identifier: u16,
    /// Hiding nonce commitment `D_i = G * d_i`.
    pub hiding: AffinePoint,
    /// Binding nonce commitment `E_i = G * e_i`.
    pub binding: AffinePoint,
}

/// A partial signature share produced in round 2.
#[derive(Clone)]
pub struct SignatureShare {
    /// Participant identifier.
    pub identifier: u16,
    /// The partial signature scalar `z_i`.
    pub share: Scalar,
}

impl core::fmt::Debug for SignatureShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignatureShare")
            .field("identifier", &self.identifier)
            .field("share", &"[REDACTED]")
            .finish()
    }
}

/// A FROST Schnorr signature (compressed point R || scalar s).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrostSignature {
    /// The group commitment point R (33 bytes, SEC1 compressed).
    pub r_bytes: Vec<u8>,
    /// The signature scalar s (32 bytes).
    pub s_bytes: [u8; 32],
}

impl FrostSignature {
    /// Encode as raw bytes: `R (33 bytes) || s (32 bytes)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&self.r_bytes);
        out.extend_from_slice(&self.s_bytes);
        out
    }
}

// ─── Domain-Separated Hash Functions (RFC 9591 Section 6.5) ──────────

/// H1: Hash to scalar for nonce derivation.
fn h1(data: &[u8]) -> Scalar {
    hash_to_scalar(b"rho", data)
}

/// H2: Hash to scalar for challenge computation.
fn h2(data: &[u8]) -> Scalar {
    hash_to_scalar(b"chal", data)
}

/// H3: Hash to scalar for nonce generation.
///
/// Included for RFC 9591 spec completeness. Currently used internally
/// by the nonce generation path that takes a pre-hashed auxiliary rand.
#[allow(dead_code)]
fn h3(data: &[u8]) -> Scalar {
    hash_to_scalar(b"nonce", data)
}

/// H4: Hash for message processing.
fn h4(data: &[u8]) -> [u8; 32] {
    hash_to_bytes(b"msg", data)
}

/// H5: Hash for commitment processing.
fn h5(data: &[u8]) -> [u8; 32] {
    hash_to_bytes(b"com", data)
}

/// Hash to scalar using expand_message_xmd (RFC 9380 Section 5.2).
///
/// Uses SHA-256 with domain separation: `contextString || tag`.
fn hash_to_scalar(tag: &[u8], data: &[u8]) -> Scalar {
    // Build DST: contextString || tag
    let mut dst = Vec::with_capacity(CONTEXT_STRING.len() + tag.len());
    dst.extend_from_slice(CONTEXT_STRING);
    dst.extend_from_slice(tag);

    // expand_message_xmd with desired output length = 48 bytes (for wide reduction)
    let expanded = expand_message_xmd(data, &dst, 48);

    // Reduce 48 bytes to a scalar (mod group order)
    let mut wide = [0u8; 48];
    wide.copy_from_slice(&expanded);
    scalar_from_wide(&wide)
}

/// Hash to bytes using domain separation.
fn hash_to_bytes(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTEXT_STRING);
    h.update(tag);
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// expand_message_xmd (RFC 9380 Section 5.2) using SHA-256.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    let b_in_bytes = 32usize; // SHA-256 output
    let ell = len_in_bytes.div_ceil(b_in_bytes);

    // DST_prime = DST || I2OSP(len(DST), 1)
    let dst_prime_len = dst.len() as u8;

    // Z_pad = I2OSP(0, b_in_bytes) = 64 zero bytes for SHA-256 block size
    let z_pad = [0u8; 64];

    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let l_i_b = (len_in_bytes as u16).to_be_bytes();

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h0 = Sha256::new();
    h0.update(z_pad);
    h0.update(msg);
    h0.update(l_i_b);
    h0.update([0u8]);
    h0.update(dst);
    h0.update([dst_prime_len]);
    let b_0 = h0.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h1 = Sha256::new();
    h1.update(b_0);
    h1.update([1u8]);
    h1.update(dst);
    h1.update([dst_prime_len]);
    let mut b_vals = vec![h1.finalize()];

    for i in 2..=ell {
        // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
        let prev = &b_vals[i - 2];
        let mut xored = [0u8; 32];
        for (j, byte) in xored.iter_mut().enumerate() {
            *byte = b_0[j] ^ prev[j];
        }
        let mut hi = Sha256::new();
        hi.update(xored);
        hi.update([i as u8]);
        hi.update(dst);
        hi.update([dst_prime_len]);
        b_vals.push(hi.finalize());
    }

    let mut output = Vec::with_capacity(len_in_bytes);
    for b in &b_vals {
        output.extend_from_slice(b);
    }
    output.truncate(len_in_bytes);
    output
}

/// Reduce 48 bytes to a scalar using wide reduction (mod group order).
fn scalar_from_wide(bytes: &[u8; 48]) -> Scalar {
    // Interpret as big-endian 384-bit integer, reduce mod n
    // k256 doesn't directly support 384-bit, so we do it manually
    let mut u256_hi = [0u8; 32];
    let mut u256_lo = [0u8; 32];
    u256_hi[16..].copy_from_slice(&bytes[..16]);
    u256_lo.copy_from_slice(&bytes[16..]);

    let hi = k256::U256::from_be_slice(&u256_hi);
    let lo = k256::U256::from_be_slice(&u256_lo);

    // result = hi * 2^256 + lo (mod n)
    let hi_scalar = <Scalar as Reduce<k256::U256>>::reduce(hi);
    let lo_scalar = <Scalar as Reduce<k256::U256>>::reduce(lo);

    // 2^256 mod n
    let two_256_mod_n = {
        let _bytes = [0u8; 32];
        // 2^256 mod n = 2^256 - n = 0x14551231950B75FC4402DA1732FC9BEBF
        // Actually, the easiest way: just reduce a U256 of all zeros from the top
        let max = k256::U256::from_be_hex(
            "0000000000000000000000000000000100000000000000000000000000000000",
        );
        <Scalar as Reduce<k256::U256>>::reduce(max)
    };

    hi_scalar * two_256_mod_n + lo_scalar
}

// ─── Round 1: Commitment ────────────────────────────────────────────

/// FROST Round 1: Generate nonces and commitments.
///
/// Each participant calls this once per signing session.
/// The secret nonces MUST NOT be reused across sessions.
pub fn commit(key_package: &KeyPackage) -> Result<SigningNonces, SignerError> {
    let hiding = crate::threshold::frost::keygen::random_scalar()?;
    let binding = crate::threshold::frost::keygen::random_scalar()?;

    let hiding_commitment = (ProjectivePoint::GENERATOR * hiding).to_affine();
    let binding_commitment = (ProjectivePoint::GENERATOR * binding).to_affine();

    Ok(SigningNonces {
        hiding: Zeroizing::new(hiding),
        binding: Zeroizing::new(binding),
        commitments: SigningCommitments {
            identifier: key_package.identifier,
            hiding: hiding_commitment,
            binding: binding_commitment,
        },
    })
}

// ─── Binding Factor Computation ──────────────────────────────────────

/// Compute the binding factor for a single participant.
fn compute_binding_factor(
    group_public_key: &AffinePoint,
    commitments_list: &[SigningCommitments],
    identifier: u16,
    message: &[u8],
) -> Scalar {
    // encoded_commitments_hash = H5(encode(commitments))
    let mut commit_data = Vec::new();
    for c in commitments_list {
        let hiding_enc = ProjectivePoint::from(c.hiding)
            .to_affine()
            .to_encoded_point(true);
        let binding_enc = ProjectivePoint::from(c.binding)
            .to_affine()
            .to_encoded_point(true);
        commit_data.extend_from_slice(hiding_enc.as_bytes());
        commit_data.extend_from_slice(binding_enc.as_bytes());
    }
    let encoded_commitments_hash = h5(&commit_data);

    // msg_hash = H4(message)
    let msg_hash = h4(message);

    // binding_factor_input = group_public_key || msg_hash || encoded_commitments_hash || I2OSP(identifier, 2)
    let pk_enc = ProjectivePoint::from(*group_public_key)
        .to_affine()
        .to_encoded_point(true);
    let mut input = Vec::new();
    input.extend_from_slice(pk_enc.as_bytes());
    input.extend_from_slice(&msg_hash);
    input.extend_from_slice(&encoded_commitments_hash);

    // Participant identifier as bytes — RFC says to fill remaining with zeros to Ns (32 bytes)
    let mut id_bytes = [0u8; 32];
    let id_be = (identifier as u64).to_be_bytes();
    id_bytes[24..].copy_from_slice(&id_be);
    input.extend_from_slice(&id_bytes);

    h1(&input)
}

/// Compute the group commitment `R = Σ(D_i + ρ_i * E_i)`.
fn compute_group_commitment(
    commitments_list: &[SigningCommitments],
    binding_factors: &[(u16, Scalar)],
) -> ProjectivePoint {
    let mut r = ProjectivePoint::IDENTITY;

    for c in commitments_list {
        let rho = binding_factors
            .iter()
            .find(|(id, _)| *id == c.identifier)
            .map(|(_, bf)| *bf)
            .unwrap_or(Scalar::ZERO);

        r += ProjectivePoint::from(c.hiding) + ProjectivePoint::from(c.binding) * rho;
    }

    r
}

// ─── Round 2: Signature Share Generation ─────────────────────────────

/// FROST Round 2: Generate a partial signature share.
///
/// Each participant produces `z_i = d_i + (e_i * ρ_i) + λ_i * s_i * c`
/// where `c` is the challenge hash.
pub fn sign(
    key_package: &KeyPackage,
    nonces: SigningNonces,
    commitments_list: &[SigningCommitments],
    message: &[u8],
) -> Result<SignatureShare, SignerError> {
    // Compute binding factors for all participants
    let mut binding_factors = Vec::new();
    for c in commitments_list {
        let bf = compute_binding_factor(
            &key_package.group_public_key,
            commitments_list,
            c.identifier,
            message,
        );
        binding_factors.push((c.identifier, bf));
    }

    // Group commitment R
    let group_commitment = compute_group_commitment(commitments_list, &binding_factors);
    let r_enc = group_commitment.to_affine().to_encoded_point(true);

    // Challenge: c = H2(R || PK || message)
    let pk_enc = ProjectivePoint::from(key_package.group_public_key)
        .to_affine()
        .to_encoded_point(true);
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(r_enc.as_bytes());
    challenge_input.extend_from_slice(pk_enc.as_bytes());
    challenge_input.extend_from_slice(message);
    let challenge = h2(&challenge_input);

    // My binding factor
    let my_rho = binding_factors
        .iter()
        .find(|(id, _)| *id == key_package.identifier)
        .map(|(_, bf)| *bf)
        .ok_or_else(|| SignerError::SigningFailed("participant not in commitments list".into()))?;

    // Lagrange coefficient
    let participant_ids: Vec<Scalar> = commitments_list
        .iter()
        .map(|c| Scalar::from(u64::from(c.identifier)))
        .collect();
    let lambda = derive_interpolating_value(
        &Scalar::from(u64::from(key_package.identifier)),
        &participant_ids,
    )?;

    // z_i = d_i + (e_i * ρ_i) + λ_i * s_i * c
    let z = *nonces.hiding
        + (*nonces.binding * my_rho)
        + (lambda * *key_package.secret_share() * challenge);

    Ok(SignatureShare {
        identifier: key_package.identifier,
        share: z,
    })
}

// ─── Signature Aggregation ───────────────────────────────────────────

/// Aggregate partial signature shares into a final FROST signature.
///
/// The coordinator collects all `SignatureShare` values and produces
/// a standard Schnorr signature `(R, s)`.
pub fn aggregate(
    commitments_list: &[SigningCommitments],
    sig_shares: &[SignatureShare],
    group_public_key: &AffinePoint,
    message: &[u8],
) -> Result<FrostSignature, SignerError> {
    if sig_shares.len() < 2 {
        return Err(SignerError::SigningFailed(
            "need at least 2 signature shares".into(),
        ));
    }

    // Compute binding factors
    let mut binding_factors = Vec::new();
    for c in commitments_list {
        let bf = compute_binding_factor(group_public_key, commitments_list, c.identifier, message);
        binding_factors.push((c.identifier, bf));
    }

    // Group commitment R
    let group_commitment = compute_group_commitment(commitments_list, &binding_factors);

    // Aggregate: s = Σ z_i
    let mut s = Scalar::ZERO;
    for share in sig_shares {
        s += share.share;
    }

    let r_enc = group_commitment.to_affine().to_encoded_point(true);

    Ok(FrostSignature {
        r_bytes: r_enc.as_bytes().to_vec(),
        s_bytes: s.to_bytes().into(),
    })
}

/// Verify a FROST signature against the group public key.
///
/// Standard Schnorr verification: `s * G == R + c * PK`
pub fn verify(
    signature: &FrostSignature,
    group_public_key: &AffinePoint,
    message: &[u8],
) -> Result<bool, SignerError> {
    // Parse R
    let r_ct = AffinePoint::from_bytes(signature.r_bytes.as_slice().into());
    if !bool::from(r_ct.is_some()) {
        return Ok(false);
    }
    // Safe: is_some() verified above. CtOption::unwrap() is constant-time.
    #[allow(clippy::unwrap_used)]
    let r_point = ProjectivePoint::from(r_ct.unwrap());

    // Parse s
    let s_wide = k256::U256::from_be_slice(&signature.s_bytes);
    let s_scalar = <Scalar as Reduce<k256::U256>>::reduce(s_wide);

    // Challenge: c = H2(R || PK || message)
    let r_enc = r_point.to_affine().to_encoded_point(true);
    let pk_enc = ProjectivePoint::from(*group_public_key)
        .to_affine()
        .to_encoded_point(true);
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(r_enc.as_bytes());
    challenge_input.extend_from_slice(pk_enc.as_bytes());
    challenge_input.extend_from_slice(message);
    let challenge = h2(&challenge_input);

    // Verify: s * G == R + c * PK
    let lhs = ProjectivePoint::GENERATOR * s_scalar;
    let rhs = r_point + ProjectivePoint::from(*group_public_key) * challenge;

    Ok(lhs == rhs)
}

/// Verify a single participant's signature share (identifiable abort).
///
/// Checks: `z_i * G == D_i + ρ_i * E_i + λ_i * c * PK_i`
pub fn verify_share(
    share: &SignatureShare,
    commitment: &SigningCommitments,
    public_key_share: &AffinePoint,
    group_public_key: &AffinePoint,
    commitments_list: &[SigningCommitments],
    message: &[u8],
) -> Result<bool, SignerError> {
    // Binding factor
    let binding_factor = compute_binding_factor(
        group_public_key,
        commitments_list,
        share.identifier,
        message,
    );

    // Binding factors for group commitment
    let mut binding_factors = Vec::new();
    for c in commitments_list {
        let bf = compute_binding_factor(group_public_key, commitments_list, c.identifier, message);
        binding_factors.push((c.identifier, bf));
    }

    // Group commitment R
    let group_commitment = compute_group_commitment(commitments_list, &binding_factors);
    let r_enc = group_commitment.to_affine().to_encoded_point(true);

    // Challenge
    let pk_enc = ProjectivePoint::from(*group_public_key)
        .to_affine()
        .to_encoded_point(true);
    let mut challenge_input = Vec::new();
    challenge_input.extend_from_slice(r_enc.as_bytes());
    challenge_input.extend_from_slice(pk_enc.as_bytes());
    challenge_input.extend_from_slice(message);
    let challenge = h2(&challenge_input);

    // Lagrange coefficient
    let participant_ids: Vec<Scalar> = commitments_list
        .iter()
        .map(|c| Scalar::from(u64::from(c.identifier)))
        .collect();
    let lambda =
        derive_interpolating_value(&Scalar::from(u64::from(share.identifier)), &participant_ids)?;

    // lhs = z_i * G
    let lhs = ProjectivePoint::GENERATOR * share.share;

    // rhs = D_i + ρ_i * E_i + λ_i * c * PK_i
    let rhs = ProjectivePoint::from(commitment.hiding)
        + ProjectivePoint::from(commitment.binding) * binding_factor
        + ProjectivePoint::from(*public_key_share) * (lambda * challenge);

    Ok(lhs == rhs)
}

/// Identify misbehaving participants by verifying each signature share.
///
/// Returns a list of participant identifiers whose shares are invalid.
/// If the list is empty, all shares are valid.
///
/// This is used for **identifiable abort**: if signature aggregation fails
/// verification, the coordinator can pinpoint exactly which participant(s)
/// submitted bad shares.
///
/// # Arguments
/// - `sig_shares` — All collected signature shares
/// - `commitments_list` — All commitments from round 1
/// - `key_packages` — Key packages (needed for per-share public keys)
/// - `group_public_key` — The group public key
/// - `message` — The signed message
pub fn identify_misbehaving(
    sig_shares: &[SignatureShare],
    commitments_list: &[SigningCommitments],
    key_packages: &[KeyPackage],
    group_public_key: &AffinePoint,
    message: &[u8],
) -> Result<Vec<u16>, SignerError> {
    let mut cheaters = Vec::new();

    for share in sig_shares {
        // Find the commitment for this participant
        let commitment = commitments_list
            .iter()
            .find(|c| c.identifier == share.identifier);

        let commitment = match commitment {
            Some(c) => c,
            None => {
                cheaters.push(share.identifier);
                continue;
            }
        };

        // Find the key package for this participant
        let key_package = key_packages
            .iter()
            .find(|kp| kp.identifier == share.identifier);

        let key_package = match key_package {
            Some(kp) => kp,
            None => {
                cheaters.push(share.identifier);
                continue;
            }
        };

        let pk_share = key_package.public_key();
        let valid = verify_share(
            share,
            commitment,
            &pk_share,
            group_public_key,
            commitments_list,
            message,
        )?;

        if !valid {
            cheaters.push(share.identifier);
        }
    }

    Ok(cheaters)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::threshold::frost::keygen;

    fn setup_2_of_3() -> (keygen::KeyGenOutput, AffinePoint) {
        let secret = [0x42u8; 32];
        let output = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let group_pk = output.group_public_key;
        (output, group_pk)
    }

    // ─── Full 2-of-3 Round-Trip ────────────────────────────────

    #[test]
    fn test_frost_2_of_3_roundtrip() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"frost threshold message";

        // Round 1: participants 1 and 2 commit
        let nonce1 = commit(&kgen.key_packages[0]).unwrap();
        let nonce2 = commit(&kgen.key_packages[1]).unwrap();
        let commitments = vec![nonce1.commitments.clone(), nonce2.commitments.clone()];

        // Round 2: each signs
        let share1 = sign(&kgen.key_packages[0], nonce1, &commitments, msg).unwrap();
        let share2 = sign(&kgen.key_packages[1], nonce2, &commitments, msg).unwrap();

        // Aggregate
        let sig = aggregate(&commitments, &[share1, share2], &group_pk, msg).unwrap();
        assert_eq!(sig.to_bytes().len(), 65); // 33 (R) + 32 (s)

        // Verify
        let valid = verify(&sig, &group_pk, msg).unwrap();
        assert!(valid, "FROST 2-of-3 signature must verify");
    }

    // ─── Different Signer Subsets ────────────────────────────────

    #[test]
    fn test_frost_different_participant_subsets() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"subset test";

        // Subset {1, 3}
        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let n3 = commit(&kgen.key_packages[2]).unwrap();
        let comms = vec![n1.commitments.clone(), n3.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
        let s3 = sign(&kgen.key_packages[2], n3, &comms, msg).unwrap();
        let sig = aggregate(&comms, &[s1, s3], &group_pk, msg).unwrap();
        assert!(
            verify(&sig, &group_pk, msg).unwrap(),
            "subset {{1,3}} must verify"
        );
    }

    // ─── Share Verification (Identifiable Abort) ────────────────

    #[test]
    fn test_frost_verify_share() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"share verify test";

        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let n2 = commit(&kgen.key_packages[1]).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();

        // Verify participant 1's share
        let pk1 = kgen.key_packages[0].public_key();
        let valid = verify_share(&s1, &comms[0], &pk1, &group_pk, &comms, msg).unwrap();
        assert!(valid, "valid share must verify");
    }

    // ─── Wrong Message Fails ────────────────────────────────────

    #[test]
    fn test_frost_wrong_message_fails() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"correct msg";

        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let n2 = commit(&kgen.key_packages[1]).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
        let s2 = sign(&kgen.key_packages[1], n2, &comms, msg).unwrap();
        let sig = aggregate(&comms, &[s1, s2], &group_pk, msg).unwrap();

        let wrong = verify(&sig, &group_pk, b"wrong msg").unwrap();
        assert!(!wrong, "wrong message must fail verification");
    }

    // ─── Different Messages → Different Signatures ──────────────

    #[test]
    fn test_frost_different_messages_different_sigs() {
        let (kgen, group_pk) = setup_2_of_3();

        let make_sig = |m: &[u8]| -> Vec<u8> {
            let n1 = commit(&kgen.key_packages[0]).unwrap();
            let n2 = commit(&kgen.key_packages[1]).unwrap();
            let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
            let s1 = sign(&kgen.key_packages[0], n1, &comms, m).unwrap();
            let s2 = sign(&kgen.key_packages[1], n2, &comms, m).unwrap();
            aggregate(&comms, &[s1, s2], &group_pk, m)
                .unwrap()
                .to_bytes()
        };

        let sig_a = make_sig(b"message A");
        let sig_b = make_sig(b"message B");
        assert_ne!(sig_a, sig_b);
    }

    // ─── VSS Commitment Verification ────────────────────────────

    #[test]
    fn test_frost_vss_commitments_verify() {
        let (kgen, _) = setup_2_of_3();
        for pkg in &kgen.key_packages {
            assert!(
                kgen.vss_commitments
                    .verify_share(pkg.identifier, pkg.secret_share()),
                "VSS share must verify for participant {}",
                pkg.identifier
            );
        }
    }

    // ─── Aggregate Rejects Insufficient Shares ──────────────────

    #[test]
    fn test_frost_aggregate_rejects_single_share() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"need 2";

        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let comms = vec![n1.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();

        // Only 1 share — must fail (need at least t=2)
        assert!(aggregate(&comms, &[s1], &group_pk, msg).is_err());
    }

    // ─── Deterministic Key Generation ───────────────────────────

    #[test]
    fn test_frost_keygen_deterministic() {
        let secret = [0x42u8; 32];
        let out1 = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let out2 = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        assert_eq!(
            out1.group_public_key.to_encoded_point(true).as_bytes(),
            out2.group_public_key.to_encoded_point(true).as_bytes()
        );
    }

    // ─── Identifiable Abort Tests ───────────────────────────────

    #[test]
    fn test_identify_misbehaving_all_honest() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"identifiable abort honest";

        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let n2 = commit(&kgen.key_packages[1]).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
        let s2 = sign(&kgen.key_packages[1], n2, &comms, msg).unwrap();

        let cheaters =
            identify_misbehaving(&[s1, s2], &comms, &kgen.key_packages, &group_pk, msg).unwrap();
        assert!(cheaters.is_empty(), "no cheaters expected");
    }

    #[test]
    fn test_identify_misbehaving_tampered_share() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"identifiable abort tampered";

        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let n2 = commit(&kgen.key_packages[1]).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
        let s2 = sign(&kgen.key_packages[1], n2, &comms, msg).unwrap();

        // Tamper with participant 2's share
        let tampered_s2 = SignatureShare {
            identifier: s2.identifier,
            share: s2.share + Scalar::ONE, // corrupt!
        };

        let cheaters = identify_misbehaving(
            &[s1, tampered_s2],
            &comms,
            &kgen.key_packages,
            &group_pk,
            msg,
        )
        .unwrap();
        assert_eq!(
            cheaters,
            vec![2],
            "participant 2 should be identified as cheater"
        );
    }

    #[test]
    fn test_identify_misbehaving_both_tampered() {
        let (kgen, group_pk) = setup_2_of_3();
        let msg = b"both bad";

        let n1 = commit(&kgen.key_packages[0]).unwrap();
        let n2 = commit(&kgen.key_packages[1]).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
        let s2 = sign(&kgen.key_packages[1], n2, &comms, msg).unwrap();

        let bad1 = SignatureShare {
            identifier: s1.identifier,
            share: Scalar::ZERO,
        };
        let bad2 = SignatureShare {
            identifier: s2.identifier,
            share: Scalar::ZERO,
        };

        let cheaters =
            identify_misbehaving(&[bad1, bad2], &comms, &kgen.key_packages, &group_pk, msg)
                .unwrap();
        assert_eq!(cheaters.len(), 2, "both participants should be identified");
    }
}
