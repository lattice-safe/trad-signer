//! **BIP-352** — Silent Payments for Bitcoin.
//!
//! Privacy-enhanced payments where the sender derives a unique one-time
//! address for each transaction, and the receiver scans for outputs
//! without revealing any payment link on-chain.
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::silent_payments::*;
//!
//! let scan_key = [0x01u8; 32];
//! let spend_key = [0x02u8; 32];
//! let scan_pub = pubkey_from_secret(&scan_key).unwrap();
//! let spend_pub = pubkey_from_secret(&spend_key).unwrap();
//! let addr = create_address(&scan_pub, &spend_pub, "sp");
//! ```

use crate::crypto;
use crate::error::SignerError;
use zeroize::Zeroize;

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar};

// ═══════════════════════════════════════════════════════════════════
// Address Encoding (Bech32m with "sp" HRP)
// ═══════════════════════════════════════════════════════════════════

/// A Silent Payment address containing scan and spend public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// The scan public key (33-byte compressed SEC1).
    pub scan_pubkey: [u8; 33],
    /// The spend public key (33-byte compressed SEC1).
    pub spend_pubkey: [u8; 33],
}

/// A label for creating labeled silent payment addresses.
///
/// Labels allow a receiver to categorize incoming payments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    /// Label integer `m` used to derive the tweak.
    pub m: u32,
}

impl Label {
    /// Create a new label with the given index.
    #[must_use]
    pub const fn new(m: u32) -> Self {
        Self { m }
    }

    /// Compute the label tweak: `tagged_hash("BIP0352/Label", scan_key || ser_uint32(m))`.
    pub fn tweak(&self, scan_privkey: &[u8; 32]) -> [u8; 32] {
        let mut data = [0u8; 36];
        data[..32].copy_from_slice(scan_privkey);
        data[32..].copy_from_slice(&self.m.to_be_bytes());
        let result = crypto::tagged_hash(b"BIP0352/Label", &data);
        data.zeroize(); // scan_privkey was copied here
        result
    }
}

/// Create a Silent Payment address string from scan and spend public keys.
///
/// Encodes as `{hrp}:{version_hex}{scan_pubkey_hex}{spend_pubkey_hex}`.
#[must_use]
pub fn create_address(
    scan_pubkey: &[u8; 33],
    spend_pubkey: &[u8; 33],
    hrp: &str,
) -> String {
    let mut payload = [0u8; 67];
    payload[0] = 0x00; // version 0
    payload[1..34].copy_from_slice(scan_pubkey);
    payload[34..67].copy_from_slice(spend_pubkey);
    format!("{hrp}:{}", hex::encode(payload))
}

/// Parse a Silent Payment address.
///
/// Extracts the scan and spend public keys from the address format `{hrp}:{payload_hex}`.
pub fn parse_address(address: &str) -> Result<SilentPaymentAddress, SignerError> {
    let sep_pos = address.find(':')
        .ok_or_else(|| SignerError::ParseError("no separator in SP address".into()))?;

    let data_part = &address[sep_pos + 1..];
    let payload = hex::decode(data_part)
        .map_err(|_| SignerError::ParseError("invalid SP address hex".into()))?;

    if payload.len() < 67 {
        return Err(SignerError::ParseError(
            format!("SP payload too short: {} < 67", payload.len()),
        ));
    }

    if payload[0] != 0x00 {
        return Err(SignerError::ParseError(
            format!("unsupported SP version: {}", payload[0]),
        ));
    }

    let mut scan = [0u8; 33];
    let mut spend = [0u8; 33];
    scan.copy_from_slice(&payload[1..34]);
    spend.copy_from_slice(&payload[34..67]);

    Ok(SilentPaymentAddress {
        scan_pubkey: scan,
        spend_pubkey: spend,
    })
}

// ═══════════════════════════════════════════════════════════════════
// Key Operations
// ═══════════════════════════════════════════════════════════════════

/// Derive a compressed public key from a 32-byte secret key.
pub fn pubkey_from_secret(secret: &[u8; 32]) -> Result<[u8; 33], SignerError> {
    let scalar = parse_scalar(secret)?;
    let point = ProjectivePoint::GENERATOR * scalar;
    let encoded = point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(SignerError::ParseError("unexpected pubkey length".into()));
    }
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    Ok(result)
}

/// Compute an ECDH shared secret between a private key and a public key.
///
/// Returns `tagged_hash("BIP0352/SharedSecret", ECDH_point_x || input_hash)`.
#[must_use = "shared secret must be used"]
pub fn compute_shared_secret(
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
    input_hash: &[u8; 32],
) -> Result<[u8; 32], SignerError> {
    let scalar = parse_scalar(privkey)?;
    let point = parse_point(pubkey)?;
    let shared = (point * scalar).to_affine();
    let x_bytes = shared.to_encoded_point(false);
    let x = &x_bytes.as_bytes()[1..33]; // x-coordinate

    let mut data = [0u8; 64];
    data[..32].copy_from_slice(x);
    data[32..].copy_from_slice(input_hash);
    let result = crypto::tagged_hash(b"BIP0352/SharedSecret", &data);
    data.zeroize(); // contains ECDH x-coordinate
    Ok(result)
}

/// Derive the output public key for a Silent Payment recipient.
///
/// `output_key = spend_pubkey + tagged_hash("BIP0352/SharedSecret", ...) * G`
#[must_use = "output key must be used"]
pub fn derive_output_key(
    shared_secret: &[u8; 32],
    spend_pubkey: &[u8; 33],
    k: u32,
) -> Result<[u8; 32], SignerError> {
    // t_k = tagged_hash("BIP0352/SharedSecret", shared_secret || ser_uint32(k))
    let mut data = [0u8; 36];
    data[..32].copy_from_slice(shared_secret);
    data[32..].copy_from_slice(&k.to_be_bytes());
    let mut t_k = crypto::tagged_hash(b"BIP0352/SharedSecret", &data);
    data.zeroize();

    let tweak_scalar = parse_scalar(&t_k)?;
    t_k.zeroize();
    let spend_point = parse_point(spend_pubkey)?;
    let output = spend_point + ProjectivePoint::GENERATOR * tweak_scalar;
    let encoded = output.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();

    // Return x-only (32 bytes)
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes[1..33]);
    Ok(result)
}

/// Compute the input hash for BIP-352 from the transaction's outpoints.
///
/// `input_hash = tagged_hash("BIP0352/Inputs", smallest_outpoint || sum_input_pubkeys)`
pub fn compute_input_hash(
    outpoints: &[([u8; 32], u32)],
    sum_input_pubkeys: &[u8; 33],
) -> Result<[u8; 32], SignerError> {
    if outpoints.is_empty() {
        return Err(SignerError::ParseError("no outpoints".into()));
    }

    // Serialize an outpoint into a fixed 36-byte buffer (no heap)
    let serialize_outpoint = |txid: &[u8; 32], vout: u32| -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(txid);
        buf[32..].copy_from_slice(&vout.to_le_bytes());
        buf
    };

    // Find the lexicographically smallest outpoint
    let mut smallest = serialize_outpoint(&outpoints[0].0, outpoints[0].1);
    for op in &outpoints[1..] {
        let candidate = serialize_outpoint(&op.0, op.1);
        if candidate < smallest {
            smallest = candidate;
        }
    }

    let mut data = [0u8; 69];
    data[..36].copy_from_slice(&smallest);
    data[36..69].copy_from_slice(sum_input_pubkeys);

    Ok(crypto::tagged_hash(b"BIP0352/Inputs", &data))
}

/// Sum multiple public keys (EC point addition).
pub fn sum_pubkeys(pubkeys: &[[u8; 33]]) -> Result<[u8; 33], SignerError> {
    if pubkeys.is_empty() {
        return Err(SignerError::ParseError("no pubkeys to sum".into()));
    }

    let mut sum = parse_point(&pubkeys[0])?;
    for pk in &pubkeys[1..] {
        sum += parse_point(pk)?;
    }

    let encoded = sum.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    Ok(result)
}

/// Apply a label tweak to a spend public key.
///
/// `labeled_spend = spend_pubkey + label_tweak * G`
pub fn apply_label(
    spend_pubkey: &[u8; 33],
    label_tweak: &[u8; 32],
) -> Result<[u8; 33], SignerError> {
    let spend = parse_point(spend_pubkey)?;
    let tweak = parse_scalar(label_tweak)?;
    let labeled = spend + ProjectivePoint::GENERATOR * tweak;
    let encoded = labeled.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 33];
    result.copy_from_slice(bytes);
    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Parse a 32-byte big-endian scalar, rejecting zero and values ≥ curve order.
///
/// Unlike `Scalar::reduce()`, this does NOT silently wrap — it rejects invalid inputs.
fn parse_scalar(bytes: &[u8; 32]) -> Result<Scalar, SignerError> {
    let nz = k256::NonZeroScalar::try_from(bytes as &[u8])
        .map_err(|_| SignerError::ParseError("scalar is zero or >= curve order".into()))?;
    Ok(*nz.as_ref())
}

fn parse_point(bytes: &[u8; 33]) -> Result<ProjectivePoint, SignerError> {
    let repr = k256::EncodedPoint::from_bytes(bytes)
        .map_err(|_| SignerError::ParseError("invalid point encoding".into()))?;
    let point = AffinePoint::from_encoded_point(&repr);
    if point.is_none().into() {
        return Err(SignerError::ParseError("invalid curve point".into()));
    }
    #[allow(clippy::unwrap_used)]
    Ok(ProjectivePoint::from(point.unwrap()))
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Known test secret keys
    const SK1: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 1;
        k
    };
    const SK2: [u8; 32] = {
        let mut k = [0u8; 32];
        k[31] = 2;
        k
    };

    // ─── Key Operations ─────────────────────────────────────────

    #[test]
    fn test_pubkey_from_secret() {
        let pk = pubkey_from_secret(&SK1).unwrap();
        assert_eq!(pk.len(), 33);
        // G point: 02 79BE667E...
        assert_eq!(pk[0], 0x02);
    }

    #[test]
    fn test_pubkey_from_secret_deterministic() {
        let pk1 = pubkey_from_secret(&SK1).unwrap();
        let pk2 = pubkey_from_secret(&SK1).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_pubkey_from_secret_different_keys() {
        let pk1 = pubkey_from_secret(&SK1).unwrap();
        let pk2 = pubkey_from_secret(&SK2).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_pubkey_from_zero_fails() {
        assert!(pubkey_from_secret(&[0u8; 32]).is_err());
    }

    // ─── Address Encoding ───────────────────────────────────────

    #[test]
    fn test_create_address() {
        let scan = pubkey_from_secret(&SK1).unwrap();
        let spend = pubkey_from_secret(&SK2).unwrap();
        let addr = create_address(&scan, &spend, "sp");
        assert!(addr.starts_with("sp:"));
    }

    #[test]
    fn test_create_address_roundtrip() {
        let scan = pubkey_from_secret(&SK1).unwrap();
        let spend = pubkey_from_secret(&SK2).unwrap();
        let addr = create_address(&scan, &spend, "sp");
        let parsed = parse_address(&addr).unwrap();
        assert_eq!(parsed.scan_pubkey, scan);
        assert_eq!(parsed.spend_pubkey, spend);
    }

    #[test]
    fn test_parse_address_invalid() {
        assert!(parse_address("invalid").is_err());
    }

    #[test]
    fn test_parse_address_too_short() {
        assert!(parse_address("sp:0000").is_err());
    }

    // ─── ECDH Shared Secret ─────────────────────────────────────

    #[test]
    fn test_shared_secret_deterministic() {
        let pk2 = pubkey_from_secret(&SK2).unwrap();
        let input_hash = [0xCC; 32];
        let ss1 = compute_shared_secret(&SK1, &pk2, &input_hash).unwrap();
        let ss2 = compute_shared_secret(&SK1, &pk2, &input_hash).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_shared_secret_different_input_hashes() {
        let pk2 = pubkey_from_secret(&SK2).unwrap();
        let ss1 = compute_shared_secret(&SK1, &pk2, &[0xAA; 32]).unwrap();
        let ss2 = compute_shared_secret(&SK1, &pk2, &[0xBB; 32]).unwrap();
        assert_ne!(ss1, ss2);
    }

    // ─── Output Key Derivation ──────────────────────────────────

    #[test]
    fn test_derive_output_key() {
        let spend = pubkey_from_secret(&SK2).unwrap();
        let shared = [0xDD; 32];
        let out_key = derive_output_key(&shared, &spend, 0).unwrap();
        assert_eq!(out_key.len(), 32);
    }

    #[test]
    fn test_derive_output_key_different_k() {
        let spend = pubkey_from_secret(&SK2).unwrap();
        let shared = [0xDD; 32];
        let k0 = derive_output_key(&shared, &spend, 0).unwrap();
        let k1 = derive_output_key(&shared, &spend, 1).unwrap();
        assert_ne!(k0, k1);
    }

    // ─── Input Hash ─────────────────────────────────────────────

    #[test]
    fn test_input_hash() {
        let outpoints = vec![([0xAA; 32], 0u32)];
        let sum = pubkey_from_secret(&SK1).unwrap();
        let hash = compute_input_hash(&outpoints, &sum).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_input_hash_empty_outpoints() {
        let sum = pubkey_from_secret(&SK1).unwrap();
        assert!(compute_input_hash(&[], &sum).is_err());
    }

    #[test]
    fn test_input_hash_deterministic() {
        let outpoints = vec![([0xAA; 32], 0u32), ([0xBB; 32], 1)];
        let sum = pubkey_from_secret(&SK1).unwrap();
        let h1 = compute_input_hash(&outpoints, &sum).unwrap();
        let h2 = compute_input_hash(&outpoints, &sum).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_input_hash_selects_smallest() {
        let sum = pubkey_from_secret(&SK1).unwrap();
        // Different order, same result (smallest outpoint selected)
        let h1 = compute_input_hash(&[([0xAA; 32], 0), ([0xBB; 32], 0)], &sum).unwrap();
        let h2 = compute_input_hash(&[([0xBB; 32], 0), ([0xAA; 32], 0)], &sum).unwrap();
        assert_eq!(h1, h2);
    }

    // ─── Sum Pubkeys ────────────────────────────────────────────

    #[test]
    fn test_sum_pubkeys_single() {
        let pk = pubkey_from_secret(&SK1).unwrap();
        let sum = sum_pubkeys(&[pk]).unwrap();
        assert_eq!(sum, pk);
    }

    #[test]
    fn test_sum_pubkeys_two() {
        let pk1 = pubkey_from_secret(&SK1).unwrap();
        let pk2 = pubkey_from_secret(&SK2).unwrap();
        let sum = sum_pubkeys(&[pk1, pk2]).unwrap();
        assert_ne!(sum, pk1);
        assert_ne!(sum, pk2);
    }

    #[test]
    fn test_sum_pubkeys_empty() {
        assert!(sum_pubkeys(&[]).is_err());
    }

    // ─── Labels ─────────────────────────────────────────────────

    #[test]
    fn test_label_new() {
        let label = Label::new(0);
        assert_eq!(label.m, 0);
    }

    #[test]
    fn test_label_tweak_deterministic() {
        let label = Label::new(1);
        let t1 = label.tweak(&SK1);
        let t2 = label.tweak(&SK1);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_label_tweak_different_m() {
        let t0 = Label::new(0).tweak(&SK1);
        let t1 = Label::new(1).tweak(&SK1);
        assert_ne!(t0, t1);
    }

    #[test]
    fn test_apply_label() {
        let spend = pubkey_from_secret(&SK2).unwrap();
        let tweak = Label::new(1).tweak(&SK1);
        let labeled = apply_label(&spend, &tweak).unwrap();
        assert_ne!(labeled, spend);
        assert_eq!(labeled.len(), 33);
    }
}
