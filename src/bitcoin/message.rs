//! **BIP-322** — Generic Signed Message Format.
//!
//! Provides script-based message signing that works with all Bitcoin address types
//! (P2PKH, P2WPKH, P2SH, P2TR), replacing the limited BIP-137 format.
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::message;
//!
//! let hash = message::message_hash(b"Hello World");
//! assert_eq!(hex::encode(hash), "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a");
//! ```

use crate::crypto;
use crate::encoding;
use crate::error::SignerError;
use crate::traits::Signer;

/// BIP-322 tagged hash tag for message hashing.
const BIP322_TAG: &[u8] = b"BIP0322-signed-message";

// ─── Message Hashing ────────────────────────────────────────────────

/// Compute the BIP-322 message hash.
///
/// `SHA256(SHA256(tag) || SHA256(tag) || message)`
///
/// This is the BIP-340 tagged hash with tag `"BIP0322-signed-message"`.
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    crypto::tagged_hash(BIP322_TAG, message)
}

// ─── Virtual Transaction Construction ───────────────────────────────

/// Create the virtual "to_spend" transaction for BIP-322 signing.
///
/// This is a transaction with:
/// - Version: 0
/// - 1 input: prevout = 0000...0000:0xFFFFFFFF, scriptSig = OP_0 PUSH32(message_hash)
/// - 1 output: value = 0, scriptPubKey = the message signer's script
///
/// Returns the serialized transaction bytes.
pub fn create_to_spend_tx(script_pubkey: &[u8], message: &[u8]) -> Vec<u8> {
    let msg_hash = message_hash(message);

    let mut tx = Vec::new();

    // Version (4 bytes, little-endian)
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Input count (varint)
    tx.push(0x01);

    // Input: prevout txid (32 zero bytes)
    tx.extend_from_slice(&[0u8; 32]);
    // Input: prevout vout (0xFFFFFFFF)
    tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    // Input: scriptSig = OP_0 OP_PUSH32 message_hash
    let script_sig_len = 1 + 1 + 32; // OP_0 + OP_PUSH32 + 32 bytes
    tx.push(script_sig_len as u8); // varint length
    tx.push(0x00); // OP_0
    tx.push(0x20); // OP_PUSH32
    tx.extend_from_slice(&msg_hash);

    // Input: sequence (0)
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Output count (varint)
    tx.push(0x01);

    // Output: value (0, 8 bytes)
    tx.extend_from_slice(&0u64.to_le_bytes());

    // Output: scriptPubKey
    encoding::encode_compact_size(&mut tx, script_pubkey.len() as u64);
    tx.extend_from_slice(script_pubkey);

    // Locktime (0)
    tx.extend_from_slice(&0u32.to_le_bytes());

    tx
}

/// Create the virtual "to_sign" transaction for BIP-322 signing.
///
/// This transaction spends the "to_spend" output:
/// - Version: 0
/// - 1 input: prevout = hash(to_spend):0, empty scriptSig
/// - 1 output: value = 0, scriptPubKey = OP_RETURN
///
/// The witness is left empty (to be filled by the signer).
///
/// `to_spend_txid` must be in standard transaction serialization byte order
/// (the order used inside outpoints).
pub fn create_to_sign_tx(to_spend_txid: &[u8; 32]) -> Vec<u8> {
    let mut tx = Vec::new();

    // Version (0)
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Marker + Flag for SegWit
    tx.push(0x00); // marker
    tx.push(0x01); // flag

    // Input count
    tx.push(0x01);

    // Input: prevout txid (hash of to_spend tx)
    tx.extend_from_slice(to_spend_txid);
    // Input: prevout vout (0)
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Input: scriptSig (empty)
    tx.push(0x00);

    // Input: sequence (0)
    tx.extend_from_slice(&0u32.to_le_bytes());

    // Output count
    tx.push(0x01);

    // Output: value (0)
    tx.extend_from_slice(&0u64.to_le_bytes());

    // Output: scriptPubKey = OP_RETURN (1 byte)
    tx.push(0x01); // length
    tx.push(0x6a); // OP_RETURN

    // Witness (empty for now — 1 element of 0 bytes)
    tx.push(0x00); // number of witness items = 0

    // Locktime (0)
    tx.extend_from_slice(&0u32.to_le_bytes());

    tx
}

/// Compute the txid (double SHA256) of a raw transaction.
///
/// Returns the 32-byte hash in standard transaction serialization byte order
/// (not display-reversed hex order).
pub fn compute_txid(raw_tx: &[u8]) -> [u8; 32] {
    crypto::double_sha256(raw_tx)
}

/// Create a P2WPKH scriptPubKey from a 20-byte pubkey hash.
///
/// Format: `OP_0 OP_PUSH20 <pubkey_hash>`
pub fn p2wpkh_script_pubkey(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(22);
    script.push(0x00); // OP_0 (witness version 0)
    script.push(0x14); // OP_PUSH20
    script.extend_from_slice(pubkey_hash);
    script
}

/// Create a P2TR scriptPubKey from a 32-byte x-only pubkey.
///
/// Format: `OP_1 OP_PUSH32 <x_only_pubkey>`
pub fn p2tr_script_pubkey(x_only_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1 (witness version 1)
    script.push(0x20); // OP_PUSH32
    script.extend_from_slice(x_only_pubkey);
    script
}

/// Serialize a witness stack using Bitcoin consensus vector encoding.
fn encode_witness_stack(stack: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    encoding::encode_compact_size(&mut out, stack.len() as u64);
    for item in stack {
        encoding::encode_compact_size(&mut out, item.len() as u64);
        out.extend_from_slice(item);
    }
    out
}

/// Parse a consensus-encoded witness stack.
fn decode_witness_stack(data: &[u8]) -> Result<Vec<Vec<u8>>, SignerError> {
    let mut offset = 0usize;
    let item_count_u64 = encoding::read_compact_size(data, &mut offset)?;
    let item_count = usize::try_from(item_count_u64)
        .map_err(|_| SignerError::ParseError("witness item count exceeds platform usize".into()))?;
    let mut stack = Vec::with_capacity(item_count);

    for _ in 0..item_count {
        let item_len_u64 = encoding::read_compact_size(data, &mut offset)?;
        let item_len = usize::try_from(item_len_u64).map_err(|_| {
            SignerError::ParseError("witness item length exceeds platform usize".into())
        })?;
        let end = offset
            .checked_add(item_len)
            .ok_or_else(|| SignerError::ParseError("witness item length overflow".into()))?;
        if end > data.len() {
            return Err(SignerError::ParseError("truncated witness item".into()));
        }
        stack.push(data[offset..end].to_vec());
        offset = end;
    }

    if offset != data.len() {
        return Err(SignerError::ParseError(
            "witness stack has trailing bytes".into(),
        ));
    }

    Ok(stack)
}

// ─── BIP-322 Simple Signing ────────────────────────────────────────

/// BIP-322 "simple" message signing for P2WPKH addresses.
///
/// Builds the complete BIP-322 signing flow:
/// 1. Build `to_spend` virtual transaction
/// 2. Compute its txid
/// 3. Build `to_sign` virtual transaction spending `to_spend`
/// 4. Compute the BIP-143 sighash for the `to_sign` input
/// 5. Sign with ECDSA and return the BIP-322 "simple" witness stack bytes
///
/// Returns the consensus-encoded witness stack (`vector<vector<u8>>`).
pub fn sign_simple_p2wpkh(
    signer: &super::BitcoinSigner,
    message: &[u8],
) -> Result<Vec<u8>, crate::error::SignerError> {
    let pubkey = signer.public_key_bytes();
    let pubkey_hash = crypto::hash160(&pubkey);
    let script_pk = p2wpkh_script_pubkey(&pubkey_hash);

    // Step 1-2: Build to_spend and get its txid
    let to_spend = create_to_spend_tx(&script_pk, message);
    let to_spend_txid = compute_txid(&to_spend);

    // Step 3: Build to_sign (spending to_spend:0)
    // We need the sighash, so we build the tx structure manually
    use super::sighash;
    use super::tapscript::SighashType;
    use super::transaction::*;

    let mut tx = Transaction::new(0);
    tx.inputs.push(TxIn {
        previous_output: OutPoint {
            txid: to_spend_txid,
            vout: 0,
        },
        script_sig: vec![],
        sequence: 0,
    });
    tx.outputs.push(TxOut {
        value: 0,
        script_pubkey: vec![0x6a], // OP_RETURN
    });

    // Step 4: Compute BIP-143 sighash
    let script_code = sighash::p2wpkh_script_code(&pubkey_hash);
    let prev_out = sighash::PrevOut {
        script_code,
        value: 0, // to_spend output value is 0
    };
    let sighash_value = sighash::segwit_v0_sighash(&tx, 0, &prev_out, SighashType::All)?;

    // Step 5: Sign the sighash
    let sig = signer.sign_digest(&sighash_value)?;
    let mut sig_bytes = sig.to_bytes();
    sig_bytes.push(SighashType::All.to_byte()); // append sighash flag

    // Build witness: [signature, pubkey]
    let witness_stack = vec![sig_bytes, pubkey.to_vec()];
    Ok(encode_witness_stack(&witness_stack))
}

/// BIP-322 "simple" message signing for P2TR (Taproot) addresses.
///
/// Uses Schnorr key-path signing with BIP-341 sighash.
///
/// Returns the consensus-encoded witness stack (`vector<vector<u8>>`).
pub fn sign_simple_p2tr(
    signer: &super::schnorr::SchnorrSigner,
    message: &[u8],
) -> Result<Vec<u8>, crate::error::SignerError> {
    let x_only_pubkey_bytes = signer.public_key_bytes();
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&x_only_pubkey_bytes);
    let script_pk = p2tr_script_pubkey(&x_only);

    // Build to_spend and get txid
    let to_spend = create_to_spend_tx(&script_pk, message);
    let to_spend_txid = compute_txid(&to_spend);

    use super::sighash;
    use super::tapscript::SighashType;
    use super::transaction::*;

    let mut tx = Transaction::new(0);
    tx.inputs.push(TxIn {
        previous_output: OutPoint {
            txid: to_spend_txid,
            vout: 0,
        },
        script_sig: vec![],
        sequence: 0,
    });
    tx.outputs.push(TxOut {
        value: 0,
        script_pubkey: vec![0x6a], // OP_RETURN
    });

    // Compute BIP-341 Taproot sighash
    let prevouts = vec![TxOut {
        value: 0,
        script_pubkey: script_pk,
    }];
    let sighash_value = sighash::taproot_key_path_sighash(&tx, 0, &prevouts, SighashType::Default)?;

    // Sign with Schnorr (BIP-340 signs the raw message)
    use crate::traits::Signer;
    let sig = signer.sign(&sighash_value)?;

    // Taproot witness: [schnorr_signature] (no sighash byte for Default)
    let witness_stack = vec![sig.bytes.to_vec()];
    Ok(encode_witness_stack(&witness_stack))
}

// ─── BIP-322 Simple Verification ──────────────────────────────────

/// BIP-322 "simple" verification for P2WPKH proofs.
///
/// Verifies a BIP-322 proof by:
/// 1. Deriving the P2WPKH scriptPubKey from the provided pubkey via hash160
/// 2. Rebuilding the `to_spend` virtual transaction
/// 3. Recomputing the BIP-143 sighash for the `to_sign` input
/// 4. Verifying the ECDSA signature against the pubkey
///
/// # Arguments
/// - `pubkey` — Compressed public key (33 bytes)
/// - `message` — The original signed message
/// - `proof` — BIP-322 simple signature bytes (consensus-encoded witness stack)
pub fn verify_simple_p2wpkh(
    pubkey: &[u8; 33],
    message: &[u8],
    proof: &[u8],
) -> Result<bool, crate::error::SignerError> {
    use super::sighash;
    use super::tapscript::SighashType;
    use super::transaction::*;

    let (der_sig, sighash_type, raw_shorthand) = match decode_witness_stack(proof) {
        // Canonical BIP-322 simple proof: witness stack [sig||hashtype, pubkey]
        Ok(witness_stack) => {
            if witness_stack.len() != 2 {
                return Err(SignerError::ParseError(format!(
                    "invalid P2WPKH simple signature witness item count: {}",
                    witness_stack.len()
                )));
            }

            if witness_stack[1] != pubkey {
                return Err(SignerError::ParseError(
                    "witness pubkey does not match provided pubkey".into(),
                ));
            }

            let sig_with_hashtype = &witness_stack[0];
            if sig_with_hashtype.is_empty() {
                return Err(SignerError::ParseError("empty ECDSA signature".into()));
            }
            let (&sighash_byte, der_sig) = sig_with_hashtype
                .split_last()
                .ok_or_else(|| SignerError::ParseError("empty ECDSA signature".into()))?;
            let sighash_type = SighashType::from_byte(sighash_byte)
                .ok_or_else(|| SignerError::ParseError("invalid sighash type in witness".into()))?;
            if sighash_type == SighashType::Default {
                return Err(SignerError::ParseError(
                    "SIGHASH_DEFAULT is invalid for SegWit v0 signatures".into(),
                ));
            }
            (der_sig.to_vec(), sighash_type, false)
        }
        // Compatibility shorthand: allow raw DER signature (assume SIGHASH_ALL),
        // or DER||hashtype directly, without witness vector framing.
        Err(_) => {
            let (der, sht) = decode_raw_p2wpkh_signature(proof)?;
            (der, sht, true)
        }
    };

    let pubkey_hash = crypto::hash160(pubkey);
    let script_pk = p2wpkh_script_pubkey(&pubkey_hash);

    // Rebuild to_spend and its txid
    let to_spend = create_to_spend_tx(&script_pk, message);
    let to_spend_txid = compute_txid(&to_spend);

    let script_code = sighash::p2wpkh_script_code(&pubkey_hash);
    let verifier = super::BitcoinVerifier::from_public_key_bytes(pubkey)?;
    use crate::traits::Verifier;
    let signature = super::BitcoinSignature::from_bytes(&der_sig)?;

    let verify_with_txid = |txid: [u8; 32]| -> Result<bool, SignerError> {
        let mut tx = Transaction::new(0);
        tx.inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0,
        });
        tx.outputs.push(TxOut {
            value: 0,
            script_pubkey: vec![0x6a],
        });
        let prev_out = sighash::PrevOut {
            script_code: script_code.clone(),
            value: 0,
        };
        let sighash_value = sighash::segwit_v0_sighash(&tx, 0, &prev_out, sighash_type)?;
        verifier.verify_prehashed(&sighash_value, &signature)
    };

    let valid = verify_with_txid(to_spend_txid)?;
    if valid {
        return Ok(true);
    }

    if raw_shorthand {
        let mut reversed = to_spend_txid;
        reversed.reverse();
        return verify_with_txid(reversed);
    }

    Ok(false)
}

/// BIP-322 "simple" verification for P2TR (Taproot) proofs.
///
/// Verifies a BIP-322 proof by:
/// 1. Deriving the P2TR scriptPubKey from the x-only public key
/// 2. Rebuilding the `to_spend` virtual transaction
/// 3. Recomputing the BIP-341 Taproot sighash
/// 4. Verifying the Schnorr signature against the x-only pubkey
///
/// # Arguments
/// - `x_only_pubkey` — 32-byte x-only public key
/// - `message` — The original signed message
/// - `proof` — BIP-322 simple signature bytes (consensus-encoded witness stack)
pub fn verify_simple_p2tr(
    x_only_pubkey: &[u8; 32],
    message: &[u8],
    proof: &[u8],
) -> Result<bool, crate::error::SignerError> {
    use super::sighash;
    use super::transaction::*;

    let (signature, sighash_type, raw_shorthand) = match decode_witness_stack(proof) {
        // Canonical BIP-322 simple proof: witness stack [taproot_sig]
        Ok(witness_stack) => {
            if witness_stack.len() != 1 {
                return Err(SignerError::ParseError(format!(
                    "invalid P2TR simple signature witness item count: {}",
                    witness_stack.len()
                )));
            }
            let (sig, sht) = decode_taproot_sig_item(&witness_stack[0], "witness")?;
            (sig, sht, false)
        }
        // Compatibility shorthand: raw 64-byte Schnorr sig (or 65 with hashtype)
        Err(_) => {
            let (sig, sht) = decode_taproot_sig_item(proof, "proof")?;
            (sig, sht, true)
        }
    };

    let script_pk = p2tr_script_pubkey(x_only_pubkey);

    // Rebuild to_spend and its txid
    let to_spend = create_to_spend_tx(&script_pk, message);
    let to_spend_txid = compute_txid(&to_spend);

    let verifier = super::schnorr::SchnorrVerifier::from_public_key_bytes(x_only_pubkey)?;
    let schnorr_sig = super::schnorr::SchnorrSignature { bytes: signature };
    use crate::traits::Verifier;

    let verify_with_txid = |txid: [u8; 32]| -> Result<bool, SignerError> {
        let mut tx = Transaction::new(0);
        tx.inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: vec![],
            sequence: 0,
        });
        tx.outputs.push(TxOut {
            value: 0,
            script_pubkey: vec![0x6a],
        });
        let prevouts = vec![TxOut {
            value: 0,
            script_pubkey: script_pk.clone(),
        }];
        let sighash_value = sighash::taproot_key_path_sighash(&tx, 0, &prevouts, sighash_type)?;
        verifier.verify(&sighash_value, &schnorr_sig)
    };

    let valid = verify_with_txid(to_spend_txid)?;
    if valid {
        return Ok(true);
    }

    if raw_shorthand {
        let mut reversed = to_spend_txid;
        reversed.reverse();
        return verify_with_txid(reversed);
    }

    Ok(false)
}

fn decode_raw_p2wpkh_signature(
    proof: &[u8],
) -> Result<(Vec<u8>, super::tapscript::SighashType), SignerError> {
    use super::tapscript::SighashType;

    if proof.is_empty() {
        return Err(SignerError::ParseError("empty P2WPKH proof".into()));
    }

    // Raw DER shorthand => assume SIGHASH_ALL.
    if super::BitcoinSignature::from_bytes(proof).is_ok() {
        return Ok((proof.to_vec(), SighashType::All));
    }

    // DER || hashtype shorthand.
    if proof.len() > 1 {
        let sighash_byte = proof[proof.len() - 1];
        if let Some(sighash_type) = SighashType::from_byte(sighash_byte) {
            if sighash_type == SighashType::Default {
                return Err(SignerError::ParseError(
                    "SIGHASH_DEFAULT is invalid for SegWit v0 signatures".into(),
                ));
            }
            let der = &proof[..proof.len() - 1];
            if super::BitcoinSignature::from_bytes(der).is_ok() {
                return Ok((der.to_vec(), sighash_type));
            }
        }
    }

    Err(SignerError::ParseError(
        "invalid P2WPKH proof format".into(),
    ))
}

fn decode_taproot_sig_item(
    sig_item: &[u8],
    source: &str,
) -> Result<([u8; 64], super::tapscript::SighashType), SignerError> {
    use super::tapscript::SighashType;

    let (sig_bytes, sighash_type) = match sig_item.len() {
        64 => (sig_item, SighashType::Default),
        65 => {
            let sighash_byte = sig_item[64];
            if sighash_byte == SighashType::Default.to_byte() {
                return Err(SignerError::ParseError(
                    "taproot signature must omit SIGHASH_DEFAULT byte".into(),
                ));
            }
            let parsed = SighashType::from_byte(sighash_byte).ok_or_else(|| {
                SignerError::ParseError(format!("invalid sighash type in {source}"))
            })?;
            (&sig_item[..64], parsed)
        }
        _ => {
            return Err(SignerError::ParseError(format!(
                "invalid taproot signature length in {source}: {}",
                sig_item.len()
            )));
        }
    };

    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig_bytes);
    Ok((signature, sighash_type))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // BIP-322 official test vectors for message hashing

    #[test]
    fn test_bip322_message_hash_empty() {
        let hash = message_hash(b"");
        assert_eq!(
            hex::encode(hash),
            "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1"
        );
    }

    #[test]
    fn test_bip322_message_hash_hello_world() {
        let hash = message_hash(b"Hello World");
        assert_eq!(
            hex::encode(hash),
            "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a"
        );
    }

    #[test]
    fn test_bip322_message_hash_deterministic() {
        let h1 = message_hash(b"test message");
        let h2 = message_hash(b"test message");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_bip322_message_hash_different_messages() {
        let h1 = message_hash(b"message A");
        let h2 = message_hash(b"message B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_bip322_to_spend_tx_structure() {
        let script_pk = p2wpkh_script_pubkey(&[0xAA; 20]);
        let tx = create_to_spend_tx(&script_pk, b"test");
        // Version should be 0
        assert_eq!(&tx[0..4], &0u32.to_le_bytes());
        // Input count should be 1
        assert_eq!(tx[4], 0x01);
        // Should contain the message hash
        let msg_hash = message_hash(b"test");
        // Find the message hash in the transaction
        let found = tx.windows(32).any(|w| w == msg_hash);
        assert!(found, "message hash not found in to_spend tx");
    }

    #[test]
    fn test_bip322_to_sign_tx_structure() {
        let txid = [0xBB; 32];
        let tx = create_to_sign_tx(&txid);
        // Version should be 0
        assert_eq!(&tx[0..4], &0u32.to_le_bytes());
        // Should contain SegWit marker + flag
        assert_eq!(tx[4], 0x00);
        assert_eq!(tx[5], 0x01);
        // Should contain OP_RETURN output
        assert!(tx.contains(&0x6a), "OP_RETURN not found in to_sign tx");
    }

    #[test]
    fn test_bip322_compute_txid() {
        let tx = vec![0x01, 0x02, 0x03, 0x04];
        let txid = compute_txid(&tx);
        // Should be deterministic
        let txid2 = compute_txid(&tx);
        assert_eq!(txid, txid2);
        assert_eq!(txid.len(), 32);
    }

    #[test]
    fn test_bip322_witness_stack_roundtrip() {
        let stack = vec![vec![0xAA, 0xBB], vec![0x01], vec![]];
        let encoded = encode_witness_stack(&stack);
        let decoded = decode_witness_stack(&encoded).unwrap();
        assert_eq!(decoded, stack);
    }

    #[test]
    fn test_bip322_p2wpkh_script_pubkey() {
        let hash = [0xAA; 20];
        let script = p2wpkh_script_pubkey(&hash);
        assert_eq!(script.len(), 22);
        assert_eq!(script[0], 0x00); // OP_0
        assert_eq!(script[1], 0x14); // OP_PUSH20
        assert_eq!(&script[2..], &hash);
    }

    #[test]
    fn test_bip322_p2tr_script_pubkey() {
        let key = [0xBB; 32];
        let script = p2tr_script_pubkey(&key);
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51); // OP_1
        assert_eq!(script[1], 0x20); // OP_PUSH32
        assert_eq!(&script[2..], &key);
    }

    #[test]
    fn test_bip322_varint_encoding() {
        let mut buf = Vec::new();
        encoding::encode_compact_size(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        encoding::encode_compact_size(&mut buf, 252);
        assert_eq!(buf, vec![0xFC]);

        buf.clear();
        encoding::encode_compact_size(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        buf.clear();
        encoding::encode_compact_size(&mut buf, 0x1234);
        assert_eq!(buf, vec![0xFD, 0x34, 0x12]);
    }

    #[test]
    fn test_bip322_to_spend_to_sign_chain() {
        // End-to-end: create to_spend → get txid → create to_sign
        let script_pk = p2wpkh_script_pubkey(&[0xCC; 20]);
        let to_spend = create_to_spend_tx(&script_pk, b"chain test");
        let txid = compute_txid(&to_spend);
        let to_sign = create_to_sign_tx(&txid);
        // to_sign should reference the txid
        assert!(to_sign.windows(32).any(|w| w == txid));
    }

    #[test]
    fn test_bip322_sign_verify_p2wpkh_roundtrip() {
        use crate::traits::KeyPair;
        let signer = super::super::BitcoinSigner::generate().unwrap();
        let message = b"BIP-322 P2WPKH test";

        // Sign
        let proof = sign_simple_p2wpkh(&signer, message).unwrap();
        assert!(!proof.is_empty());

        let pubkey_bytes = signer.public_key_bytes();
        let mut pubkey33 = [0u8; 33];
        pubkey33.copy_from_slice(&pubkey_bytes);

        // Verify
        let result = verify_simple_p2wpkh(&pubkey33, message, &proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_bip322_verify_p2wpkh_wrong_message() {
        use crate::traits::KeyPair;
        let signer = super::super::BitcoinSigner::generate().unwrap();
        let pubkey_bytes = signer.public_key_bytes();
        let mut pubkey33 = [0u8; 33];
        pubkey33.copy_from_slice(&pubkey_bytes);

        let proof = sign_simple_p2wpkh(&signer, b"message A").unwrap();

        // Verify against message B — should fail
        let result = verify_simple_p2wpkh(&pubkey33, b"message B", &proof);
        // Should either be Ok(false) or Err
        if let Ok(valid) = result {
            assert!(!valid, "wrong message should not verify");
        }
    }

    #[test]
    fn test_bip322_sign_verify_p2tr_roundtrip() {
        use crate::traits::KeyPair;
        let signer = super::super::schnorr::SchnorrSigner::generate().unwrap();
        let message = b"BIP-322 P2TR test";

        let proof = sign_simple_p2tr(&signer, message).unwrap();
        assert!(!proof.is_empty());

        let pubkey_bytes = signer.public_key_bytes();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&pubkey_bytes);

        let result = verify_simple_p2tr(&x_only, message, &proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_bip322_verify_p2tr_wrong_message() {
        use crate::traits::KeyPair;
        let signer = super::super::schnorr::SchnorrSigner::generate().unwrap();
        let proof = sign_simple_p2tr(&signer, b"message A").unwrap();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&signer.public_key_bytes());

        let result = verify_simple_p2tr(&x_only, b"message B", &proof);
        if let Ok(valid) = result {
            assert!(!valid, "wrong message should not verify");
        }
    }

    #[test]
    fn test_bip322_verify_rejects_malformed_witness() {
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&[0x11; 32]);
        assert!(verify_simple_p2tr(&x_only, b"m", &[0x02, 0x01, 0xAA]).is_err());
        assert!(verify_simple_p2wpkh(&[0x02; 33], b"m", &[0x02, 0x01, 0xAA]).is_err());
    }

    #[test]
    fn test_bip322_verify_p2wpkh_accepts_raw_der_shorthand() {
        use crate::traits::KeyPair;
        let signer = super::super::BitcoinSigner::generate().unwrap();
        let pubkey = signer.public_key_bytes();
        let mut pubkey33 = [0u8; 33];
        pubkey33.copy_from_slice(&pubkey);
        let message = b"p2wpkh raw-der shorthand";

        use super::super::sighash;
        use super::super::tapscript::SighashType;
        use super::super::transaction::*;
        use crate::traits::Signer;

        let pubkey_hash = crate::crypto::hash160(&pubkey33);
        let script_pk = p2wpkh_script_pubkey(&pubkey_hash);
        let to_spend = create_to_spend_tx(&script_pk, message);
        let to_spend_txid = compute_txid(&to_spend);

        let mut tx = Transaction::new(0);
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: to_spend_txid,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0,
        });
        tx.outputs.push(TxOut {
            value: 0,
            script_pubkey: vec![0x6a],
        });

        let script_code = sighash::p2wpkh_script_code(&pubkey_hash);
        let prev_out = sighash::PrevOut {
            script_code,
            value: 0,
        };
        let sighash_value =
            sighash::segwit_v0_sighash(&tx, 0, &prev_out, SighashType::All).unwrap();
        let sig = signer.sign_prehashed(&sighash_value).unwrap();

        assert!(verify_simple_p2wpkh(&pubkey33, message, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn test_bip322_verify_p2tr_accepts_raw_sig_shorthand() {
        use crate::traits::KeyPair;
        let signer = super::super::schnorr::SchnorrSigner::generate().unwrap();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&signer.public_key_bytes());
        let message = b"p2tr raw-sig shorthand";

        use super::super::sighash;
        use super::super::tapscript::SighashType;
        use super::super::transaction::*;
        use crate::traits::Signer;

        let script_pk = p2tr_script_pubkey(&x_only);
        let to_spend = create_to_spend_tx(&script_pk, message);
        let to_spend_txid = compute_txid(&to_spend);

        let mut tx = Transaction::new(0);
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: to_spend_txid,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0,
        });
        tx.outputs.push(TxOut {
            value: 0,
            script_pubkey: vec![0x6a],
        });

        let prevouts = vec![TxOut {
            value: 0,
            script_pubkey: script_pk,
        }];
        let sighash_value =
            sighash::taproot_key_path_sighash(&tx, 0, &prevouts, SighashType::Default).unwrap();
        let sig = signer.sign(&sighash_value).unwrap();

        assert!(verify_simple_p2tr(&x_only, message, &sig.bytes).unwrap());
    }
}
