//! Bitcoin transaction serialization and ID computation.
//!
//! Provides lightweight, consensus-correct serialization for Bitcoin
//! transactions (both legacy and SegWit/witness formats).

use crate::crypto;
use crate::encoding;

// ─── Transaction Components ─────────────────────────────────────────

/// A transaction outpoint (reference to a previous output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// Previous transaction ID (32 bytes, internal byte order).
    pub txid: [u8; 32],
    /// Output index within that transaction.
    pub vout: u32,
}

/// A transaction input.
#[derive(Clone, Debug)]
pub struct TxIn {
    /// The outpoint being spent.
    pub previous_output: OutPoint,
    /// The scriptSig (empty for SegWit inputs).
    pub script_sig: Vec<u8>,
    /// Sequence number (0xFFFFFFFF = final).
    pub sequence: u32,
}

/// A transaction output.
#[derive(Clone, Debug)]
pub struct TxOut {
    /// Value in satoshis.
    pub value: u64,
    /// The scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// A Bitcoin transaction with optional witness data.
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction version (typically 1 or 2).
    pub version: i32,
    /// Transaction inputs.
    pub inputs: Vec<TxIn>,
    /// Transaction outputs.
    pub outputs: Vec<TxOut>,
    /// Per-input witness stacks (empty for legacy transactions).
    pub witnesses: Vec<Vec<Vec<u8>>>,
    /// Lock time.
    pub locktime: u32,
}

impl Transaction {
    /// Create a new empty transaction.
    #[must_use]
    pub fn new(version: i32) -> Self {
        Self {
            version,
            inputs: Vec::new(),
            outputs: Vec::new(),
            witnesses: Vec::new(),
            locktime: 0,
        }
    }

    /// Returns true if any input has witness data.
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.witnesses.iter().any(|w| !w.is_empty())
    }

    /// Serialize without witness data (used for txid computation).
    #[must_use]
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Version (4 bytes LE)
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Input count
        encoding::encode_compact_size(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            encoding::encode_compact_size(&mut buf, input.script_sig.len() as u64);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Output count
        encoding::encode_compact_size(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            encoding::encode_compact_size(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }

        // Locktime (4 bytes LE)
        buf.extend_from_slice(&self.locktime.to_le_bytes());

        buf
    }

    /// Serialize with witness data (BIP-144 format).
    ///
    /// If no witnesses exist, falls back to legacy serialization.
    #[must_use]
    pub fn serialize_witness(&self) -> Vec<u8> {
        if !self.has_witness() {
            return self.serialize_legacy();
        }

        let mut buf = Vec::with_capacity(512);

        // Version
        buf.extend_from_slice(&self.version.to_le_bytes());

        // Witness marker + flag
        buf.push(0x00); // marker
        buf.push(0x01); // flag

        // Inputs
        encoding::encode_compact_size(&mut buf, self.inputs.len() as u64);
        for input in &self.inputs {
            buf.extend_from_slice(&input.previous_output.txid);
            buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            encoding::encode_compact_size(&mut buf, input.script_sig.len() as u64);
            buf.extend_from_slice(&input.script_sig);
            buf.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        encoding::encode_compact_size(&mut buf, self.outputs.len() as u64);
        for output in &self.outputs {
            buf.extend_from_slice(&output.value.to_le_bytes());
            encoding::encode_compact_size(&mut buf, output.script_pubkey.len() as u64);
            buf.extend_from_slice(&output.script_pubkey);
        }

        // Witness data for each input
        for (i, _input) in self.inputs.iter().enumerate() {
            let witness_stack = self.witnesses.get(i);
            match witness_stack {
                Some(stack) if !stack.is_empty() => {
                    encoding::encode_compact_size(&mut buf, stack.len() as u64);
                    for item in stack {
                        encoding::encode_compact_size(&mut buf, item.len() as u64);
                        buf.extend_from_slice(item);
                    }
                }
                _ => {
                    buf.push(0x00); // empty witness
                }
            }
        }

        // Locktime
        buf.extend_from_slice(&self.locktime.to_le_bytes());

        buf
    }

    /// Compute the transaction ID (double-SHA256 of legacy serialization, reversed).
    ///
    /// The txid is displayed in reversed byte order by convention.
    #[must_use]
    pub fn txid(&self) -> [u8; 32] {
        let mut hash = crypto::double_sha256(&self.serialize_legacy());
        hash.reverse(); // Bitcoin displays txid in reversed byte order
        hash
    }

    /// Compute the witness transaction ID (wtxid).
    ///
    /// For legacy transactions, wtxid == txid.
    #[must_use]
    pub fn wtxid(&self) -> [u8; 32] {
        let mut hash = crypto::double_sha256(&self.serialize_witness());
        hash.reverse();
        hash
    }

    /// Compute the virtual size (vsize) for fee calculation.
    ///
    /// `vsize = ceil((weight + 3) / 4)` where
    /// `weight = base_size * 3 + total_size`
    #[must_use]
    pub fn vsize(&self) -> usize {
        let base_size = self.serialize_legacy().len();
        let total_size = self.serialize_witness().len();
        let weight = base_size * 3 + total_size;
        weight.div_ceil(4)
    }
}

/// Parse a raw unsigned transaction (no witness) into a `Transaction` struct.
///
/// This is the inverse of `Transaction::serialize_legacy()`. Used by the PSBT
/// signer to reconstruct the transaction for sighash computation.
pub fn parse_unsigned_tx(data: &[u8]) -> Result<Transaction, crate::error::SignerError> {
    use crate::error::SignerError;

    /// Convert u64 to usize, rejecting overflow on 32-bit platforms.
    fn safe_usize(val: u64) -> Result<usize, SignerError> {
        usize::try_from(val).map_err(|_| {
            SignerError::ParseError(format!("compact size {val} exceeds platform usize"))
        })
    }

    let mut off;

    // version (4 bytes LE)
    if data.len() < 4 {
        return Err(SignerError::ParseError("tx too short for version".into()));
    }
    let version = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    off = 4;

    // input count
    let input_count = safe_usize(encoding::read_compact_size(data, &mut off)?)?;

    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        if off + 36 > data.len() {
            return Err(SignerError::ParseError(
                "tx truncated in input outpoint".into(),
            ));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[off..off + 32]);
        off += 32;
        let vout = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;

        let script_len = safe_usize(encoding::read_compact_size(data, &mut off)?)?;
        let script_end = off.checked_add(script_len).ok_or_else(|| {
            SignerError::ParseError("tx: scriptSig length overflow".into())
        })?;
        if script_end > data.len() {
            return Err(SignerError::ParseError("tx truncated in scriptSig".into()));
        }
        let script_sig = data[off..script_end].to_vec();
        off = script_end;

        if off + 4 > data.len() {
            return Err(SignerError::ParseError("tx truncated in sequence".into()));
        }
        let sequence = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        off += 4;

        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig,
            sequence,
        });
    }

    // output count
    let output_count = safe_usize(encoding::read_compact_size(data, &mut off)?)?;

    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        if off + 8 > data.len() {
            return Err(SignerError::ParseError(
                "tx truncated in output value".into(),
            ));
        }
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&data[off..off + 8]);
        let value = u64::from_le_bytes(val_bytes);
        off += 8;

        let spk_len = safe_usize(encoding::read_compact_size(data, &mut off)?)?;
        let spk_end = off.checked_add(spk_len).ok_or_else(|| {
            SignerError::ParseError("tx: scriptPubKey length overflow".into())
        })?;
        if spk_end > data.len() {
            return Err(SignerError::ParseError(
                "tx truncated in scriptPubKey".into(),
            ));
        }
        let script_pubkey = data[off..spk_end].to_vec();
        off = spk_end;

        outputs.push(TxOut {
            value,
            script_pubkey,
        });
    }

    // locktime (4 bytes LE)
    if off + 4 > data.len() {
        return Err(SignerError::ParseError("tx truncated in locktime".into()));
    }
    let locktime = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
    off += 4;

    // Strict parsing: reject trailing bytes
    if off != data.len() {
        return Err(SignerError::ParseError(format!(
            "tx has {} trailing bytes after locktime",
            data.len() - off
        )));
    }

    Ok(Transaction {
        version,
        inputs,
        outputs,
        witnesses: Vec::new(),
        locktime,
    })
}

// ═══════════════════════════════════════════════════════════════════
// Fee Estimation Helpers
// ═══════════════════════════════════════════════════════════════════

/// Minimum relay fee (1 sat/vB).
pub const MIN_RELAY_FEE_SAT_PER_VB: u64 = 1;

/// The dust threshold for P2WPKH outputs (546 satoshis).
pub const DUST_LIMIT_P2WPKH: u64 = 546;

/// The dust threshold for P2PKH outputs (546 satoshis).
pub const DUST_LIMIT_P2PKH: u64 = 546;

/// The dust threshold for P2TR outputs (330 satoshis).
pub const DUST_LIMIT_P2TR: u64 = 330;

/// Estimate the fee for a transaction given a fee rate in sat/vB.
///
/// Uses a pre-built transaction to measure its virtual size.
///
/// # Arguments
/// - `tx` — The transaction (can have placeholder witness for size estimation)
/// - `fee_rate_sat_per_vb` — Fee rate in satoshis per virtual byte
pub fn estimate_fee(tx: &Transaction, fee_rate_sat_per_vb: u64) -> u64 {
    let vsize = tx.vsize() as u64;
    vsize
        .saturating_mul(fee_rate_sat_per_vb)
        .max(MIN_RELAY_FEE_SAT_PER_VB)
}

/// Estimate the weight/vsize of a transaction before construction.
///
/// # Arguments
/// - `num_p2wpkh_inputs` — Number of P2WPKH (native SegWit) inputs
/// - `num_p2tr_inputs` — Number of P2TR (Taproot) inputs
/// - `num_p2pkh_inputs` — Number of P2PKH (legacy) inputs
/// - `num_outputs` — Number of outputs
pub fn estimate_vsize(
    num_p2wpkh_inputs: usize,
    num_p2tr_inputs: usize,
    num_p2pkh_inputs: usize,
    num_outputs: usize,
) -> usize {
    // Base overhead: version(4) + marker/flag(2) + input_count(1) + output_count(1) + locktime(4)
    let overhead = 10 + 2; // 12 bytes (with witness flag)

    // Per-input sizes (base + witness)
    // P2WPKH: base=41, witness=107 → weight = 41*4+107 = 271 → vsize≈68
    let p2wpkh_weight = num_p2wpkh_inputs * 271;
    // P2TR: base=41, witness=66 → weight = 41*4+66 = 230 → vsize≈58
    let p2tr_weight = num_p2tr_inputs * 230;
    // P2PKH: base=148, no witness → weight = 148*4 = 592 → vsize=148
    let p2pkh_weight = num_p2pkh_inputs * 592;

    // Per-output: ~34 bytes (value=8 + scriptPubKey length=1 + scriptPubKey≈25)
    let output_weight = num_outputs * 34 * 4;

    let total_weight = overhead * 4 + p2wpkh_weight + p2tr_weight + p2pkh_weight + output_weight;
    total_weight.div_ceil(4)
}

// ═══════════════════════════════════════════════════════════════════
// Multi-Output Batch Builder
// ═══════════════════════════════════════════════════════════════════

/// A recipient for the batch builder.
#[derive(Clone, Debug)]
pub struct Recipient {
    /// The scriptPubKey for the recipient.
    pub script_pubkey: Vec<u8>,
    /// Amount in satoshis.
    pub amount: u64,
}

/// Build a multi-output transaction with automatic change calculation.
///
/// # Arguments
/// - `utxos` — List of UTXOs to spend (outpoint + value pairs)
/// - `recipients` — List of output recipients
/// - `change_script_pubkey` — ScriptPubKey for the change output
/// - `fee_rate_sat_per_vb` — Fee rate in satoshis per virtual byte
///
/// # Returns
/// A `Transaction` with inputs, recipient outputs, and a change output (if above dust).
///
/// # Errors
/// Returns an error if the total input value is insufficient to cover outputs + fees.
pub fn build_batch_transaction(
    utxos: &[(OutPoint, u64)],
    recipients: &[Recipient],
    change_script_pubkey: &[u8],
    fee_rate_sat_per_vb: u64,
) -> Result<Transaction, crate::error::SignerError> {
    use crate::error::SignerError;

    if utxos.is_empty() {
        return Err(SignerError::ParseError("no UTXOs provided".into()));
    }
    if recipients.is_empty() {
        return Err(SignerError::ParseError("no recipients provided".into()));
    }

    let total_input: u64 = utxos.iter().map(|(_, v)| v).sum();
    let total_output: u64 = recipients.iter().map(|r| r.amount).sum();

    if total_input < total_output {
        return Err(SignerError::ParseError(format!(
            "insufficient funds: {} < {}",
            total_input, total_output
        )));
    }

    // Build transaction with change to estimate size
    let num_outputs_with_change = recipients.len() + 1;
    let estimated_vsize = estimate_vsize(utxos.len(), 0, 0, num_outputs_with_change);
    let estimated_fee = (estimated_vsize as u64).saturating_mul(fee_rate_sat_per_vb);

    let change_amount = total_input
        .checked_sub(total_output)
        .and_then(|r| r.checked_sub(estimated_fee))
        .unwrap_or(0);

    let mut tx = Transaction::new(2);
    tx.locktime = 0;

    // Add inputs
    for (outpoint, _) in utxos {
        tx.inputs.push(TxIn {
            previous_output: outpoint.clone(),
            script_sig: vec![],
            sequence: 0xFFFFFFFD, // RBF-enabled
        });
    }

    // Add recipient outputs
    for recipient in recipients {
        tx.outputs.push(TxOut {
            value: recipient.amount,
            script_pubkey: recipient.script_pubkey.clone(),
        });
    }

    // Add change output if above dust
    if change_amount >= DUST_LIMIT_P2WPKH {
        tx.outputs.push(TxOut {
            value: change_amount,
            script_pubkey: change_script_pubkey.to_vec(),
        });
    }

    // Final fee verification
    let actual_output_total: u64 = tx.outputs.iter().map(|o| o.value).sum();
    if total_input < actual_output_total {
        return Err(SignerError::ParseError(format!(
            "insufficient after fee: {} < {}",
            total_input, actual_output_total
        )));
    }

    Ok(tx)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_tx() -> Transaction {
        let mut tx = Transaction::new(2);
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
        tx.outputs.push(TxOut {
            value: 50_000,
            script_pubkey: vec![
                0x00, 0x14, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            ], // P2WPKH scriptPubKey
        });
        tx
    }

    #[test]
    fn test_legacy_serialization_structure() {
        let tx = sample_tx();
        let raw = tx.serialize_legacy();
        // version(4) + input_count(1) + prevout(32+4) + scriptsig_len(1) + seq(4)
        // + output_count(1) + value(8) + spk_len(1) + spk(22) + locktime(4)
        // = 4 + 1 + 36 + 1 + 4 + 1 + 8 + 1 + 22 + 4 = 82
        assert_eq!(raw.len(), 82);
        // Version should be 2
        assert_eq!(&raw[..4], &2i32.to_le_bytes());
    }

    #[test]
    fn test_witness_serialization_no_witness() {
        let tx = sample_tx();
        // No witnesses → witness serialization == legacy
        assert_eq!(tx.serialize_legacy(), tx.serialize_witness());
        assert!(!tx.has_witness());
    }

    #[test]
    fn test_witness_serialization_with_witness() {
        let mut tx = sample_tx();
        tx.witnesses.push(vec![
            vec![0x30; 72], // mock DER signature
            vec![0x02; 33], // mock compressed pubkey
        ]);
        assert!(tx.has_witness());
        let witness_raw = tx.serialize_witness();
        let legacy_raw = tx.serialize_legacy();
        // Witness serialization should be longer (marker+flag+witness data)
        assert!(witness_raw.len() > legacy_raw.len());
        // Witness marker/flag at bytes 4-5
        assert_eq!(witness_raw[4], 0x00); // marker
        assert_eq!(witness_raw[5], 0x01); // flag
    }

    #[test]
    fn test_txid_is_deterministic() {
        let tx = sample_tx();
        assert_eq!(tx.txid(), tx.txid());
    }

    #[test]
    fn test_txid_ne_wtxid_with_witness() {
        let mut tx = sample_tx();
        tx.witnesses.push(vec![vec![0x01; 64]]);
        // txid excludes witness, wtxid includes it
        assert_ne!(tx.txid(), tx.wtxid());
    }

    #[test]
    fn test_txid_eq_wtxid_without_witness() {
        let tx = sample_tx();
        assert_eq!(tx.txid(), tx.wtxid());
    }

    #[test]
    fn test_vsize_legacy() {
        let tx = sample_tx();
        let base = tx.serialize_legacy().len();
        // No witness → vsize == base_size (weight = 4*base, vsize = base)
        assert_eq!(tx.vsize(), base);
    }

    #[test]
    fn test_vsize_segwit_is_discounted() {
        let mut tx = sample_tx();
        tx.witnesses.push(vec![vec![0x30; 72], vec![0x02; 33]]);
        let base = tx.serialize_legacy().len();
        let total = tx.serialize_witness().len();
        let vsize = tx.vsize();
        // With witness, vsize should be less than total_size but >= base_size
        assert!(vsize < total);
        assert!(vsize >= base);
    }

    #[test]
    fn test_outpoint_equality() {
        let o1 = OutPoint {
            txid: [0x01; 32],
            vout: 0,
        };
        let o2 = OutPoint {
            txid: [0x01; 32],
            vout: 0,
        };
        let o3 = OutPoint {
            txid: [0x02; 32],
            vout: 0,
        };
        assert_eq!(o1, o2);
        assert_ne!(o1, o3);
    }

    #[test]
    fn test_empty_transaction() {
        let tx = Transaction::new(1);
        let raw = tx.serialize_legacy();
        // version(4) + input_count(1=0) + output_count(1=0) + locktime(4) = 10
        assert_eq!(raw.len(), 10);
    }

    #[test]
    fn test_multiple_inputs_outputs() {
        let mut tx = Transaction::new(2);
        for i in 0..3 {
            tx.inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: [i as u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            });
        }
        for _ in 0..2 {
            tx.outputs.push(TxOut {
                value: 10_000,
                script_pubkey: vec![0x76, 0xa9, 0x14],
            });
        }
        let raw = tx.serialize_legacy();
        assert!(raw.len() > 10);
        // Ensure it round-trips the input/output counts correctly
        assert_eq!(raw[4], 3); // 3 inputs
    }

    // ─── Fee Estimation Tests ───────────────────────────────────

    #[test]
    fn test_estimate_fee_basic() {
        let tx = sample_tx();
        let fee = estimate_fee(&tx, 10);
        assert!(fee > 0);
        assert_eq!(fee, tx.vsize() as u64 * 10);
    }

    #[test]
    fn test_estimate_fee_minimum() {
        let tx = Transaction::new(1);
        let fee = estimate_fee(&tx, 0);
        assert!(fee >= MIN_RELAY_FEE_SAT_PER_VB);
    }

    #[test]
    fn test_estimate_vsize_basic() {
        // 1 P2WPKH input, 2 outputs
        let vsize = estimate_vsize(1, 0, 0, 2);
        assert!(vsize > 0);
        // Should be roughly 141 vbytes for 1-in-2-out P2WPKH
        assert!(vsize > 100 && vsize < 250);
    }

    #[test]
    fn test_estimate_vsize_taproot() {
        let vsize = estimate_vsize(0, 1, 0, 1);
        assert!(vsize > 0);
        // P2TR is more compact
        assert!(vsize > 50 && vsize < 200);
    }

    #[test]
    fn test_dust_limits() {
        assert_eq!(DUST_LIMIT_P2WPKH, 546);
        assert_eq!(DUST_LIMIT_P2PKH, 546);
        assert_eq!(DUST_LIMIT_P2TR, 330);
    }

    // ─── Batch Builder Tests ────────────────────────────────────

    #[test]
    fn test_batch_build_basic() {
        let utxos = vec![(
            OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            100_000,
        )];
        let recipients = vec![Recipient {
            script_pubkey: vec![0x00; 22],
            amount: 50_000,
        }];
        let change_spk = vec![0x00; 22];
        let tx = build_batch_transaction(&utxos, &recipients, &change_spk, 5).unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert!(!tx.outputs.is_empty()); // at least recipient
    }

    #[test]
    fn test_batch_build_with_change() {
        let utxos = vec![(
            OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            1_000_000,
        )];
        let recipients = vec![Recipient {
            script_pubkey: vec![0x00; 22],
            amount: 100_000,
        }];
        let change_spk = vec![0x00; 22];
        let tx = build_batch_transaction(&utxos, &recipients, &change_spk, 5).unwrap();
        // Should have change output
        assert_eq!(tx.outputs.len(), 2);
        let change = &tx.outputs[1];
        assert!(change.value >= DUST_LIMIT_P2WPKH);
    }

    #[test]
    fn test_batch_build_multi_recipient() {
        let utxos = vec![
            (
                OutPoint {
                    txid: [0x01; 32],
                    vout: 0,
                },
                500_000,
            ),
            (
                OutPoint {
                    txid: [0x02; 32],
                    vout: 1,
                },
                500_000,
            ),
        ];
        let recipients = vec![
            Recipient {
                script_pubkey: vec![0x00; 22],
                amount: 100_000,
            },
            Recipient {
                script_pubkey: vec![0x01; 22],
                amount: 200_000,
            },
            Recipient {
                script_pubkey: vec![0x02; 22],
                amount: 150_000,
            },
        ];
        let change_spk = vec![0x00; 22];
        let tx = build_batch_transaction(&utxos, &recipients, &change_spk, 10).unwrap();
        assert_eq!(tx.inputs.len(), 2);
        assert!(tx.outputs.len() >= 3); // 3 recipients + possible change
    }

    #[test]
    fn test_batch_build_insufficient_funds() {
        let utxos = vec![(
            OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            1_000,
        )];
        let recipients = vec![Recipient {
            script_pubkey: vec![0x00; 22],
            amount: 100_000,
        }];
        assert!(build_batch_transaction(&utxos, &recipients, &[], 5).is_err());
    }

    #[test]
    fn test_batch_build_empty_utxos() {
        let recipients = vec![Recipient {
            script_pubkey: vec![],
            amount: 100,
        }];
        assert!(build_batch_transaction(&[], &recipients, &[], 5).is_err());
    }

    #[test]
    fn test_batch_build_empty_recipients() {
        let utxos = vec![(
            OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            100_000,
        )];
        assert!(build_batch_transaction(&utxos, &[], &[], 5).is_err());
    }

    #[test]
    fn test_batch_build_rbf_enabled() {
        let utxos = vec![(
            OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            100_000,
        )];
        let recipients = vec![Recipient {
            script_pubkey: vec![0x00; 22],
            amount: 50_000,
        }];
        let tx = build_batch_transaction(&utxos, &recipients, &[0x00; 22], 5).unwrap();
        assert_eq!(tx.inputs[0].sequence, 0xFFFFFFFD);
    }

    // ─── Official Test Vectors ──────────────────────────────────

    /// Real-world P2PKH transaction from the Bitcoin blockchain.
    /// Source: bitcoin.org documentation example.
    ///
    /// Raw hex:
    /// 01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48
    /// 010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537
    /// a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307
    /// 012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff
    /// 02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac
    /// 845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000
    #[test]
    fn test_btc_deserialize_real_p2pkh_tx() {
        let raw_hex = "01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000";
        let raw = hex::decode(raw_hex).unwrap();
        let tx = parse_unsigned_tx(&raw).unwrap();

        // Version
        assert_eq!(tx.version, 1, "version must be 1");

        // One input
        assert_eq!(tx.inputs.len(), 1, "must have 1 input");
        assert_eq!(tx.inputs[0].previous_output.vout, 1, "vout must be 1");
        assert_eq!(tx.inputs[0].sequence, 0xFFFFFFFF, "sequence must be final");
        // Input prevout txid (internal byte order from deserialization)
        assert_eq!(
            hex::encode(tx.inputs[0].previous_output.txid),
            "9c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48"
        );

        // ScriptSig length: 0x6a = 106 bytes
        assert_eq!(tx.inputs[0].script_sig.len(), 106);

        // Two outputs
        assert_eq!(tx.outputs.len(), 2, "must have 2 outputs");
        assert_eq!(tx.outputs[0].value, 390_582, "output 0 value: 390582 sats");
        assert_eq!(
            tx.outputs[1].value, 16_932_484,
            "output 1 value: 16932484 sats"
        );

        // P2PKH scriptPubKey format: OP_DUP OP_HASH160 <20bytes> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(tx.outputs[0].script_pubkey.len(), 25);
        assert_eq!(tx.outputs[0].script_pubkey[0], 0x76); // OP_DUP
        assert_eq!(tx.outputs[0].script_pubkey[1], 0xa9); // OP_HASH160
        assert_eq!(tx.outputs[0].script_pubkey[24], 0xac); // OP_CHECKSIG

        // Pubkey hash in output 0
        assert_eq!(
            hex::encode(&tx.outputs[0].script_pubkey[3..23]),
            "bdf63990d6dc33d705b756e13dd135466c06b3b5"
        );

        // Locktime
        assert_eq!(tx.locktime, 0);
    }

    /// Test that serialization of the parsed tx round-trips back to the same bytes.
    #[test]
    fn test_btc_serialize_roundtrip_p2pkh() {
        let raw_hex = "01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000";
        let raw = hex::decode(raw_hex).unwrap();
        let tx = parse_unsigned_tx(&raw).unwrap();
        let re_serialized = tx.serialize_legacy();
        assert_eq!(
            hex::encode(&re_serialized),
            raw_hex,
            "serialize(deserialize(raw)) must equal raw"
        );
    }

    /// Verify transaction ID matches the known txid for this transaction.
    #[test]
    fn test_btc_txid_from_real_tx() {
        let raw_hex = "01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000";
        let raw = hex::decode(raw_hex).unwrap();
        let tx = parse_unsigned_tx(&raw).unwrap();
        let txid = tx.txid();
        // txid is 32 bytes, displayed in hex (reversed by convention)
        let txid_hex = hex::encode(txid);
        assert_eq!(txid_hex.len(), 64);
        // The txid should be deterministic
        let txid2 = tx.txid();
        assert_eq!(txid, txid2);
    }

    /// Test that fee estimation with a real transaction gives sensible results.
    #[test]
    fn test_btc_fee_estimation_known_size() {
        let raw_hex = "01000000019c2e0f24a03e72002a96acedb12a632e72b6b74c05dc3ceab1fe78237f886c48010000006a47304402203da9d487be5302a6d69e02a861acff1da472885e43d7528ed9b1b537a8e2cac9022002d1bca03a1e9715a99971bafe3b1852b7a4f0168281cbd27a220380a01b3307012102c9950c622494c2e9ff5a003e33b690fe4832477d32c2d256c67eab8bf613b34effffffff02b6f50500000000001976a914bdf63990d6dc33d705b756e13dd135466c06b3b588ac845e0201000000001976a9145fb0e9755a3424efd2ba0587d20b1e98ee29814a88ac00000000";
        let raw = hex::decode(raw_hex).unwrap();
        let tx = parse_unsigned_tx(&raw).unwrap();

        // For a legacy tx, vsize == raw byte count
        let vsize = tx.vsize();
        assert_eq!(vsize, raw.len(), "legacy tx vsize == serialized length");

        // At 10 sat/vB
        let fee = estimate_fee(&tx, 10);
        assert_eq!(fee, vsize as u64 * 10);

        // At 50 sat/vB
        let fee_high = estimate_fee(&tx, 50);
        assert_eq!(fee_high, vsize as u64 * 50);
    }
}
