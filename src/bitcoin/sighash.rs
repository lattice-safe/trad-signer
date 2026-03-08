//! Bitcoin sighash computation for SegWit v0 (BIP-143) and Taproot (BIP-341/342).
//!
//! Provides the hash preimage construction used by signers to commit to
//! transaction data before signing.

use crate::crypto;
use crate::error::SignerError;
use sha2::{Digest, Sha256};

use super::tapscript::SighashType;
use super::transaction::{Transaction, TxOut};

// ─── SegWit v0 Sighash (BIP-143) ────────────────────────────────────

/// Previous output info needed for SegWit sighash computation.
pub struct PrevOut {
    /// The scriptCode for this input (typically P2WPKH witness program).
    pub script_code: Vec<u8>,
    /// The value of the output being spent (in satoshis).
    pub value: u64,
}

/// Compute the BIP-143 SegWit v0 sighash for a specific input.
///
/// This is the hash that is signed for P2WPKH and P2WSH inputs.
///
/// # Arguments
/// - `tx` — The unsigned transaction
/// - `input_idx` — Index of the input being signed
/// - `prev_out` — Script code and value of the output being spent
/// - `sighash_type` — Sighash flag (typically `All` = 0x01)
pub fn segwit_v0_sighash(
    tx: &Transaction,
    input_idx: usize,
    prev_out: &PrevOut,
    sighash_type: SighashType,
) -> Result<[u8; 32], SignerError> {
    if input_idx >= tx.inputs.len() {
        return Err(SignerError::SigningFailed(format!(
            "input index {} out of range ({})", input_idx, tx.inputs.len()
        )));
    }

    let sighash_u32 = sighash_type.to_byte() as u32;
    let anyone_can_pay = sighash_u32 & 0x80 != 0;
    let base_type = sighash_u32 & 0x1f;

    // hashPrevouts
    let hash_prevouts = if !anyone_can_pay {
        let mut buf = Vec::new();
        for input in &tx.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        }
        crypto::double_sha256(&buf)
    } else {
        [0u8; 32]
    };

    // hashSequence
    let hash_sequence = if !anyone_can_pay && base_type != 0x02 && base_type != 0x03 {
        let mut buf = Vec::new();
        for input in &tx.inputs {
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }
        crypto::double_sha256(&buf)
    } else {
        [0u8; 32]
    };

    // hashOutputs
    let hash_outputs = if base_type != 0x02 && base_type != 0x03 {
        // SIGHASH_ALL: hash all outputs
        let mut buf = Vec::new();
        for output in &tx.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            crate::encoding::encode_compact_size(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }
        crypto::double_sha256(&buf)
    } else if base_type == 0x03 && input_idx < tx.outputs.len() {
        // SIGHASH_SINGLE: hash only the corresponding output
        let mut buf = Vec::new();
        let output = &tx.outputs[input_idx];
        buf.extend_from_slice(&output.value.to_le_bytes());
        crate::encoding::encode_compact_size(&mut buf, output.script_pubkey.len() as u64);
        buf.extend_from_slice(&output.script_pubkey);
        crypto::double_sha256(&buf)
    } else {
        [0u8; 32]
    };

    // Build the preimage
    let input = &tx.inputs[input_idx];
    let mut preimage = Vec::with_capacity(256);
    preimage.extend_from_slice(&tx.version.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    // outpoint
    preimage.extend_from_slice(&input.previous_output.txid);
    preimage.extend_from_slice(&input.previous_output.vout.to_le_bytes());
    // scriptCode
    crate::encoding::encode_compact_size(&mut preimage, prev_out.script_code.len() as u64);
    preimage.extend_from_slice(&prev_out.script_code);
    // value
    preimage.extend_from_slice(&prev_out.value.to_le_bytes());
    // sequence
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&tx.locktime.to_le_bytes());
    preimage.extend_from_slice(&sighash_u32.to_le_bytes());

    Ok(crypto::double_sha256(&preimage))
}

// ─── Taproot Key-Path Sighash (BIP-341 §4) ─────────────────────────

/// Compute the BIP-341 Taproot key-path sighash for a specific input.
///
/// # Arguments
/// - `tx` — The unsigned transaction
/// - `input_idx` — Index of the input being signed
/// - `prevouts` — All previous outputs (values and scriptPubKeys) in input order
/// - `sighash_type` — Sighash flag (Default = 0x00 means ALL)
pub fn taproot_key_path_sighash(
    tx: &Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
    sighash_type: SighashType,
) -> Result<[u8; 32], SignerError> {
    if input_idx >= tx.inputs.len() {
        return Err(SignerError::SigningFailed(format!(
            "input index {} out of range ({})", input_idx, tx.inputs.len()
        )));
    }
    if prevouts.len() != tx.inputs.len() {
        return Err(SignerError::SigningFailed(format!(
            "prevouts length {} != inputs length {}", prevouts.len(), tx.inputs.len()
        )));
    }

    let sighash_byte = sighash_type.to_byte();
    let anyone_can_pay = sighash_byte & 0x80 != 0;
    let base_type = sighash_byte & 0x03;
    // Default (0x00) is treated as ALL
    let effective_base = if sighash_byte == 0x00 { 0x01 } else { base_type };

    // Epoch
    let mut sig_msg = Vec::with_capacity(256);
    sig_msg.push(0x00); // epoch = 0

    // hash_type
    sig_msg.push(sighash_byte);

    // nVersion
    sig_msg.extend_from_slice(&tx.version.to_le_bytes());
    // nLocktime
    sig_msg.extend_from_slice(&tx.locktime.to_le_bytes());

    // If not ANYONECANPAY:
    if !anyone_can_pay {
        // sha_prevouts (SHA256 of all outpoints)
        let mut h = Sha256::new();
        for input in &tx.inputs {
            h.update(&input.previous_output.txid);
            h.update(input.previous_output.vout.to_le_bytes());
        }
        sig_msg.extend_from_slice(&h.finalize());

        // sha_amounts (SHA256 of all input amounts)
        let mut h = Sha256::new();
        for p in prevouts {
            h.update(p.value.to_le_bytes());
        }
        sig_msg.extend_from_slice(&h.finalize());

        // sha_scriptpubkeys (SHA256 of all input scriptPubKeys)
        let mut h = Sha256::new();
        for p in prevouts {
            // compact size + scriptPubKey
            let mut tmp = Vec::new();
            crate::encoding::encode_compact_size(&mut tmp, p.script_pubkey.len() as u64);
            h.update(&tmp);
            h.update(&p.script_pubkey);
        }
        sig_msg.extend_from_slice(&h.finalize());

        // sha_sequences (SHA256 of all sequences)
        let mut h = Sha256::new();
        for input in &tx.inputs {
            h.update(input.sequence.to_le_bytes());
        }
        sig_msg.extend_from_slice(&h.finalize());
    }

    // If SIGHASH_ALL (base 0x01 or Default):
    if effective_base == 0x01 || effective_base == 0x00 {
        let mut h = Sha256::new();
        for output in &tx.outputs {
            h.update(output.value.to_le_bytes());
            let mut tmp = Vec::new();
            crate::encoding::encode_compact_size(&mut tmp, output.script_pubkey.len() as u64);
            h.update(&tmp);
            h.update(&output.script_pubkey);
        }
        sig_msg.extend_from_slice(&h.finalize());
    }

    // spend_type (key path = 0, script path = 1, + ext_flag bit 0)
    sig_msg.push(0x00); // key-path, no annex

    // If ANYONECANPAY:
    if anyone_can_pay {
        // outpoint
        let input = &tx.inputs[input_idx];
        sig_msg.extend_from_slice(&input.previous_output.txid);
        sig_msg.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        // amount
        sig_msg.extend_from_slice(&prevouts[input_idx].value.to_le_bytes());
        // scriptPubKey
        let mut tmp = Vec::new();
        crate::encoding::encode_compact_size(&mut tmp, prevouts[input_idx].script_pubkey.len() as u64);
        sig_msg.extend_from_slice(&tmp);
        sig_msg.extend_from_slice(&prevouts[input_idx].script_pubkey);
        // sequence
        sig_msg.extend_from_slice(&tx.inputs[input_idx].sequence.to_le_bytes());
    } else {
        // input_index
        sig_msg.extend_from_slice(&(input_idx as u32).to_le_bytes());
    }

    // SIGHASH_SINGLE: hash the corresponding output
    if effective_base == 0x03 && input_idx < tx.outputs.len() {
        let mut h = Sha256::new();
        let output = &tx.outputs[input_idx];
        h.update(output.value.to_le_bytes());
        let mut tmp = Vec::new();
        crate::encoding::encode_compact_size(&mut tmp, output.script_pubkey.len() as u64);
        h.update(&tmp);
        h.update(&output.script_pubkey);
        sig_msg.extend_from_slice(&h.finalize());
    }

    // Tagged hash: "TapSighash"
    Ok(crypto::tagged_hash(b"TapSighash", &sig_msg))
}

// ─── P2WPKH Script Code Helper ─────────────────────────────────────

/// Build the BIP-143 script code for a P2WPKH input.
///
/// For P2WPKH, the script code is `OP_DUP OP_HASH160 PUSH20(hash160) OP_EQUALVERIFY OP_CHECKSIG`.
#[must_use]
pub fn p2wpkh_script_code(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // PUSH 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::transaction::*;

    fn sample_segwit_tx() -> Transaction {
        let mut tx = Transaction::new(2);
        tx.inputs.push(TxIn {
            previous_output: OutPoint { txid: [0x01; 32], vout: 0 },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
        tx.outputs.push(TxOut {
            value: 49_000,
            script_pubkey: {
                let mut spk = vec![0x00, 0x14];
                spk.extend_from_slice(&[0xAA; 20]);
                spk
            },
        });
        tx
    }

    #[test]
    fn test_segwit_sighash_deterministic() {
        let tx = sample_segwit_tx();
        let prev = PrevOut {
            script_code: p2wpkh_script_code(&[0xBB; 20]),
            value: 50_000,
        };
        let h1 = segwit_v0_sighash(&tx, 0, &prev, SighashType::All).unwrap();
        let h2 = segwit_v0_sighash(&tx, 0, &prev, SighashType::All).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_segwit_sighash_different_types() {
        let tx = sample_segwit_tx();
        let prev = PrevOut {
            script_code: p2wpkh_script_code(&[0xBB; 20]),
            value: 50_000,
        };
        let h_all = segwit_v0_sighash(&tx, 0, &prev, SighashType::All).unwrap();
        let h_none = segwit_v0_sighash(&tx, 0, &prev, SighashType::None).unwrap();
        assert_ne!(h_all, h_none);
    }

    #[test]
    fn test_segwit_sighash_out_of_range() {
        let tx = sample_segwit_tx();
        let prev = PrevOut {
            script_code: p2wpkh_script_code(&[0xBB; 20]),
            value: 50_000,
        };
        assert!(segwit_v0_sighash(&tx, 5, &prev, SighashType::All).is_err());
    }

    #[test]
    fn test_taproot_sighash_deterministic() {
        let tx = sample_segwit_tx();
        let prevouts = vec![TxOut {
            value: 50_000,
            script_pubkey: {
                let mut spk = vec![0x51, 0x20];
                spk.extend_from_slice(&[0xCC; 32]);
                spk
            },
        }];
        let h1 = taproot_key_path_sighash(&tx, 0, &prevouts, SighashType::Default).unwrap();
        let h2 = taproot_key_path_sighash(&tx, 0, &prevouts, SighashType::Default).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_taproot_sighash_different_from_segwit() {
        let tx = sample_segwit_tx();
        let prev = PrevOut {
            script_code: p2wpkh_script_code(&[0xBB; 20]),
            value: 50_000,
        };
        let prevouts = vec![TxOut {
            value: 50_000,
            script_pubkey: {
                let mut spk = vec![0x51, 0x20];
                spk.extend_from_slice(&[0xCC; 32]);
                spk
            },
        }];
        let h_segwit = segwit_v0_sighash(&tx, 0, &prev, SighashType::All).unwrap();
        let h_taproot = taproot_key_path_sighash(&tx, 0, &prevouts, SighashType::Default).unwrap();
        assert_ne!(h_segwit, h_taproot);
    }

    #[test]
    fn test_taproot_sighash_mismatched_prevouts() {
        let tx = sample_segwit_tx();
        // Wrong number of prevouts
        assert!(taproot_key_path_sighash(&tx, 0, &[], SighashType::Default).is_err());
    }

    #[test]
    fn test_p2wpkh_script_code_structure() {
        let hash = [0xAA; 20];
        let code = p2wpkh_script_code(&hash);
        assert_eq!(code.len(), 25);
        assert_eq!(code[0], 0x76); // OP_DUP
        assert_eq!(code[1], 0xa9); // OP_HASH160
        assert_eq!(code[2], 0x14); // PUSH 20
        assert_eq!(&code[3..23], &hash);
        assert_eq!(code[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(code[24], 0xac); // OP_CHECKSIG
    }
}
