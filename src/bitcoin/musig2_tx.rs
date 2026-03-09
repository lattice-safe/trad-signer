//! MuSig2 Taproot transaction signing — bridges `threshold::musig2` with
//! Bitcoin Taproot (BIP-341) key-path spending.
//!
//! Provides an end-to-end flow:
//! 1. Aggregate N public keys via MuSig2 → aggregate key
//! 2. Apply Taproot tweak → P2TR output key
//! 3. Compute BIP-341 sighash for a transaction input
//! 4. Run MuSig2 nonce exchange and partial signing
//! 5. Aggregate partial signatures → final 64-byte Schnorr sig
//! 6. Build the witness for a P2TR key-path spend

use crate::bitcoin::sighash::taproot_key_path_sighash;
use crate::bitcoin::taproot::{taproot_tweak, TapTree};
use crate::bitcoin::tapscript::SighashType;
use crate::bitcoin::transaction::{Transaction, TxOut};
use crate::error::SignerError;
use crate::threshold::musig2;
use crate::threshold::musig2::tweak;

// ═══════════════════════════════════════════════════════════════════
// Taproot Key Aggregation
// ═══════════════════════════════════════════════════════════════════

/// Result of MuSig2 Taproot key aggregation.
#[derive(Debug, Clone)]
pub struct TaprootKeyAgg {
    /// The MuSig2 key aggregation context (untweaked).
    pub key_agg_ctx: musig2::KeyAggContext,
    /// The x-only internal key (32 bytes) — this is the MuSig2 aggregate.
    pub internal_key: [u8; 32],
    /// The Taproot output key (32 bytes, x-only).
    pub output_key: [u8; 32],
    /// Whether the output key has odd y (needed for signing).
    pub output_parity: bool,
}

/// Aggregate public keys for a MuSig2 Taproot output.
///
/// Combines N compressed public keys into a single MuSig2 aggregate,
/// then applies the BIP-341 Taproot tweak (optional script tree).
///
/// # Arguments
/// - `pubkeys` — Compressed 33-byte public keys (one per signer)
/// - `tap_tree` — Optional TapTree for script-path spending
///
/// # Returns
/// The aggregated key context and the P2TR output key.
pub fn aggregate_taproot_key(
    pubkeys: &[[u8; 33]],
    tap_tree: Option<&TapTree>,
) -> Result<TaprootKeyAgg, SignerError> {
    let key_agg_ctx = musig2::key_agg(pubkeys)?;
    let internal_key = key_agg_ctx.x_only_pubkey;

    let merkle_root = tap_tree.map(|t| t.merkle_root());
    let (output_key, parity) = taproot_tweak(
        &internal_key,
        merkle_root.as_ref(),
    )?;

    Ok(TaprootKeyAgg {
        key_agg_ctx,
        internal_key,
        output_key,
        output_parity: parity,
    })
}

// ═══════════════════════════════════════════════════════════════════
// Signing Session
// ═══════════════════════════════════════════════════════════════════

/// A MuSig2 Taproot signing session for a specific transaction input.
#[derive(Debug, Clone)]
pub struct SigningSession {
    /// The sighash to be signed (32 bytes).
    pub sighash: [u8; 32],
    /// The sighash type used.
    pub sighash_type: SighashType,
    /// The Taproot tweak bytes (for adjusting partial signatures).
    pub tweak_bytes: [u8; 32],
}

/// Create a signing session for a MuSig2 Taproot input.
///
/// Computes the BIP-341 sighash for the specified input and returns
/// a session context for the signing protocol.
pub fn create_signing_session(
    key_agg: &TaprootKeyAgg,
    tx: &Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
    sighash_type: SighashType,
    tap_tree: Option<&TapTree>,
) -> Result<SigningSession, SignerError> {
    let sighash = taproot_key_path_sighash(tx, input_idx, prevouts, sighash_type)?;

    let merkle_root = tap_tree.map(|t| t.merkle_root());
    let tweak_bytes = tweak::compute_taproot_tweak(
        &key_agg.internal_key,
        merkle_root.as_ref(),
    );

    Ok(SigningSession {
        sighash,
        sighash_type,
        tweak_bytes,
    })
}

// ═══════════════════════════════════════════════════════════════════
// Signature Building
// ═══════════════════════════════════════════════════════════════════

/// Aggregate MuSig2 partial signatures into a final Schnorr signature.
///
/// Returns a 64-byte BIP-340 Schnorr signature suitable for Taproot key-path spending.
pub fn aggregate_signatures(
    partial_sigs: &[musig2::PartialSignature],
    agg_nonce: &musig2::AggNonce,
    key_agg_ctx: &musig2::KeyAggContext,
    sighash: &[u8; 32],
) -> Result<[u8; 64], SignerError> {
    let sig = musig2::partial_sig_agg(partial_sigs, agg_nonce, key_agg_ctx, sighash)?;
    Ok(sig.to_bytes())
}

/// Build a P2TR key-path witness from a Schnorr signature.
///
/// For `SIGHASH_DEFAULT` (0x00), the witness is just the 64-byte signature.
/// For other sighash types, append the sighash byte (65 bytes total).
#[must_use]
pub fn build_key_path_witness(schnorr_sig: &[u8; 64], sighash_type: SighashType) -> Vec<Vec<u8>> {
    let sig_with_type = if sighash_type == SighashType::Default {
        schnorr_sig.to_vec() // 64 bytes only
    } else {
        let mut s = schnorr_sig.to_vec();
        s.push(sighash_type as u8);
        s // 65 bytes
    };

    vec![sig_with_type] // Single witness element
}

/// Compute the P2TR scriptPubKey for a MuSig2 aggregated output.
///
/// Returns `OP_1 PUSH32 <output_key>` (34 bytes).
#[must_use]
pub fn p2tr_script_pubkey(output_key: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x51); // OP_1 (witness v1)
    spk.push(0x20); // push 32 bytes
    spk.extend_from_slice(output_key);
    spk
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::threshold::musig2;

    const SK1: [u8; 32] = [0x11; 32];
    const SK2: [u8; 32] = [0x22; 32];

    fn setup_keys() -> ([u8; 33], [u8; 33]) {
        let pk1 = musig2::individual_pubkey(&SK1).unwrap();
        let pk2 = musig2::individual_pubkey(&SK2).unwrap();
        (pk1, pk2)
    }

    // ─── Key Aggregation ────────────────────────────────────────

    #[test]
    fn test_aggregate_taproot_key_no_scripts() {
        let (pk1, pk2) = setup_keys();
        let agg = aggregate_taproot_key(&[pk1, pk2], None).unwrap();
        assert_eq!(agg.internal_key.len(), 32);
        assert_eq!(agg.output_key.len(), 32);
        assert_ne!(agg.internal_key, agg.output_key); // tweak changes the key
    }

    #[test]
    fn test_aggregate_taproot_key_deterministic() {
        let (pk1, pk2) = setup_keys();
        let agg1 = aggregate_taproot_key(&[pk1, pk2], None).unwrap();
        let agg2 = aggregate_taproot_key(&[pk1, pk2], None).unwrap();
        assert_eq!(agg1.internal_key, agg2.internal_key);
        assert_eq!(agg1.output_key, agg2.output_key);
    }

    #[test]
    fn test_aggregate_taproot_key_with_tree() {
        use crate::bitcoin::taproot::{TapLeaf, TapTree};

        let (pk1, pk2) = setup_keys();
        let script = vec![0x51, 0x93]; // OP_1 OP_ADD — dummy script
        let leaf = TapLeaf::tapscript(script);
        let tree = TapTree::leaf(leaf);

        let agg_no_tree = aggregate_taproot_key(&[pk1, pk2], None).unwrap();
        let agg_tree = aggregate_taproot_key(&[pk1, pk2], Some(&tree)).unwrap();

        assert_eq!(agg_no_tree.internal_key, agg_tree.internal_key); // same MuSig2
        assert_ne!(agg_no_tree.output_key, agg_tree.output_key); // different tweak
    }

    #[test]
    fn test_aggregate_taproot_key_empty_fails() {
        assert!(aggregate_taproot_key(&[], None).is_err());
    }

    // ─── P2TR ScriptPubKey ──────────────────────────────────────

    #[test]
    fn test_p2tr_script_pubkey_structure() {
        let key = [0xAA; 32];
        let spk = p2tr_script_pubkey(&key);
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x51); // OP_1
        assert_eq!(spk[1], 0x20); // push 32
        assert_eq!(&spk[2..], &key);
    }

    #[test]
    fn test_p2tr_script_pubkey_from_musig2() {
        let (pk1, pk2) = setup_keys();
        let agg = aggregate_taproot_key(&[pk1, pk2], None).unwrap();
        let spk = p2tr_script_pubkey(&agg.output_key);
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x51);
    }

    // ─── Witness Building ───────────────────────────────────────

    #[test]
    fn test_witness_default_sighash() {
        let sig = [0xBB; 64];
        let witness = build_key_path_witness(&sig, SighashType::Default);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 64); // no sighash byte
    }

    #[test]
    fn test_witness_all_sighash() {
        let sig = [0xBB; 64];
        let witness = build_key_path_witness(&sig, SighashType::All);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 65); // sig + sighash byte
        assert_eq!(*witness[0].last().unwrap(), SighashType::All as u8);
    }

    #[test]
    fn test_witness_none_sighash() {
        let sig = [0xBB; 64];
        let witness = build_key_path_witness(&sig, SighashType::None);
        assert_eq!(witness[0].len(), 65);
        assert_eq!(*witness[0].last().unwrap(), SighashType::None as u8);
    }

    #[test]
    fn test_witness_single_sighash() {
        let sig = [0xBB; 64];
        let witness = build_key_path_witness(&sig, SighashType::Single);
        assert_eq!(witness[0].len(), 65);
    }

    // ─── Aggregate Signatures ───────────────────────────────────

    #[test]
    fn test_aggregate_signatures_empty_fails() {
        let (pk1, pk2) = setup_keys();
        let ctx = musig2::key_agg(&[pk1, pk2]).unwrap();
        let (_, pn1) = musig2::nonce_gen(&SK1, &pk1, &ctx, b"x", &[]).unwrap();
        let (_, pn2) = musig2::nonce_gen(&SK2, &pk2, &ctx, b"x", &[]).unwrap();
        let agg_nonce = musig2::nonce_agg(&[pn1, pn2]).unwrap();
        assert!(aggregate_signatures(&[], &agg_nonce, &ctx, &[0; 32]).is_err());
    }

    // ─── E2E: MuSig2 → Taproot Key → Sign → Verify ─────────────

    #[test]
    fn test_e2e_musig2_taproot_signing() {
        let (pk1, pk2) = setup_keys();
        let agg = aggregate_taproot_key(&[pk1, pk2], None).unwrap();

        // A dummy "sighash" to sign
        let sighash = [0xDD; 32];

        // MuSig2 nonce exchange
        let (sec1, pub1) = musig2::nonce_gen(&SK1, &pk1, &agg.key_agg_ctx, &sighash, &[]).unwrap();
        let (sec2, pub2) = musig2::nonce_gen(&SK2, &pk2, &agg.key_agg_ctx, &sighash, &[]).unwrap();
        let agg_nonce = musig2::nonce_agg(&[pub1, pub2]).unwrap();

        // Partial signing
        let ps1 = musig2::sign(sec1, &SK1, &agg.key_agg_ctx, &agg_nonce, &sighash).unwrap();
        let ps2 = musig2::sign(sec2, &SK2, &agg.key_agg_ctx, &agg_nonce, &sighash).unwrap();

        // Aggregate
        let sig_bytes = aggregate_signatures(&[ps1, ps2], &agg_nonce, &agg.key_agg_ctx, &sighash).unwrap();
        assert_eq!(sig_bytes.len(), 64);

        // Build witness
        let witness = build_key_path_witness(&sig_bytes, SighashType::Default);
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 64);

        // Build P2TR script pubkey
        let spk = p2tr_script_pubkey(&agg.output_key);
        assert_eq!(spk.len(), 34);
    }

    #[test]
    fn test_e2e_musig2_verifies_against_internal_key() {
        let (pk1, pk2) = setup_keys();
        let agg = aggregate_taproot_key(&[pk1, pk2], None).unwrap();

        let msg = b"taproot musig2 test";
        let (sec1, pub1) = musig2::nonce_gen(&SK1, &pk1, &agg.key_agg_ctx, msg, &[]).unwrap();
        let (sec2, pub2) = musig2::nonce_gen(&SK2, &pk2, &agg.key_agg_ctx, msg, &[]).unwrap();
        let agg_nonce = musig2::nonce_agg(&[pub1, pub2]).unwrap();

        let ps1 = musig2::sign(sec1, &SK1, &agg.key_agg_ctx, &agg_nonce, msg).unwrap();
        let ps2 = musig2::sign(sec2, &SK2, &agg.key_agg_ctx, &agg_nonce, msg).unwrap();

        let sig = musig2::partial_sig_agg(&[ps1, ps2], &agg_nonce, &agg.key_agg_ctx, msg).unwrap();

        // Verify against the MuSig2 aggregate key (internal key, not output key)
        let valid = musig2::verify(&sig, &agg.internal_key, msg).unwrap();
        assert!(valid, "MuSig2 signature must verify against internal key");
    }
}
