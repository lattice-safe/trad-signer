//! Bitcoin script helpers: OP_RETURN, RBF/CPFP, and Ordinals inscription encoding.
//!
//! Provides utilities for:
//! - **OP_RETURN**: Data embedding up to 80 bytes
//! - **RBF**: Replace-by-fee signaling (BIP-125)
//! - **CPFP**: Child-pays-for-parent fee bumping
//! - **Ordinals**: Inscription envelope encoding (BIP-taproot)
//!
//! These work with the existing `transaction.rs` types.

use super::transaction::{OutPoint, Transaction, TxIn, TxOut};

// ═══════════════════════════════════════════════════════════════════
// OP_RETURN
// ═══════════════════════════════════════════════════════════════════

/// Maximum OP_RETURN data payload size (bytes).
pub const OP_RETURN_MAX_SIZE: usize = 80;

/// Build an OP_RETURN output for embedding arbitrary data.
///
/// Creates a `TxOut` with a script: `OP_RETURN <push_data>`.
/// The output is provably unspendable, so `value` is typically 0.
///
/// # Errors
/// Returns `Err` if `data` exceeds 80 bytes (standardness limit).
pub fn op_return(data: &[u8]) -> Result<TxOut, crate::error::SignerError> {
    if data.len() > OP_RETURN_MAX_SIZE {
        return Err(crate::error::SignerError::ParseError(format!(
            "OP_RETURN data exceeds {} bytes: {}",
            OP_RETURN_MAX_SIZE,
            data.len()
        )));
    }

    let mut script = Vec::with_capacity(2 + data.len());
    script.push(0x6A); // OP_RETURN

    // Push data with appropriate opcode
    if data.len() <= 75 {
        script.push(data.len() as u8); // direct length push
    } else {
        script.push(0x4C); // OP_PUSHDATA1
        script.push(data.len() as u8);
    }
    script.extend_from_slice(data);

    Ok(TxOut {
        value: 0,
        script_pubkey: script,
    })
}

/// Build a multi-push OP_RETURN with multiple data chunks.
///
/// Creates: `OP_RETURN <push1> <push2> ...`
/// Total data must not exceed 80 bytes.
pub fn op_return_multi(chunks: &[&[u8]]) -> Result<TxOut, crate::error::SignerError> {
    let total: usize = chunks.iter().map(|c| c.len()).sum();
    if total > OP_RETURN_MAX_SIZE {
        return Err(crate::error::SignerError::ParseError(format!(
            "OP_RETURN total data exceeds {} bytes: {}",
            OP_RETURN_MAX_SIZE, total
        )));
    }

    let mut script = vec![0x6A]; // OP_RETURN
    for chunk in chunks {
        if chunk.len() <= 75 {
            script.push(chunk.len() as u8);
        } else {
            script.push(0x4C); // OP_PUSHDATA1
            script.push(chunk.len() as u8);
        }
        script.extend_from_slice(chunk);
    }

    Ok(TxOut {
        value: 0,
        script_pubkey: script,
    })
}

// ═══════════════════════════════════════════════════════════════════
// RBF (Replace-by-Fee) — BIP-125
// ═══════════════════════════════════════════════════════════════════

/// BIP-125 RBF sequence value (any value < 0xFFFFFFFE signals RBF).
pub const RBF_SEQUENCE: u32 = 0xFFFFFFFD;

/// Check if a transaction input signals RBF (BIP-125).
///
/// An input is considered RBF-signaling if its sequence number is
/// less than `0xFFFFFFFE`.
#[must_use]
pub fn is_rbf_signaling(sequence: u32) -> bool {
    sequence < 0xFFFFFFFE
}

/// Mark a transaction input as RBF-enabled by setting its sequence.
pub fn enable_rbf(input: &mut TxIn) {
    input.sequence = RBF_SEQUENCE;
}

/// Mark all inputs in a transaction as RBF-enabled.
pub fn enable_rbf_all(tx: &mut Transaction) {
    for input in &mut tx.inputs {
        input.sequence = RBF_SEQUENCE;
    }
}

/// Check if any input in a transaction signals RBF.
#[must_use]
pub fn tx_signals_rbf(tx: &Transaction) -> bool {
    tx.inputs
        .iter()
        .any(|input| is_rbf_signaling(input.sequence))
}

// ═══════════════════════════════════════════════════════════════════
// CPFP (Child-Pays-for-Parent)
// ═══════════════════════════════════════════════════════════════════

/// Calculate the effective fee rate for CPFP (child-pays-for-parent).
///
/// When a low-fee parent transaction is "stuck", creating a child
/// transaction with a high enough fee can incentivize miners to
/// include both parent and child.
///
/// # Returns
/// The combined fee rate (sat/vbyte) needed for the child.
#[must_use]
pub fn cpfp_required_fee_rate(
    parent_fee_sats: u64,
    parent_vsize: usize,
    desired_fee_rate: u64, // sat/vbyte desired for the package
    child_vsize: usize,
) -> u64 {
    let package_vsize = parent_vsize as u64 + child_vsize as u64;
    let package_fee_needed = desired_fee_rate * package_vsize;
    let child_fee_needed = package_fee_needed.saturating_sub(parent_fee_sats);
    if child_vsize == 0 {
        return 0;
    }
    child_fee_needed / (child_vsize as u64)
}

/// Build a CPFP child transaction that spends a specific output
/// from the parent transaction.
///
/// Returns a minimal transaction spending `parent_txid:parent_vout`
/// to a change address with RBF enabled.
#[must_use]
pub fn cpfp_child(
    parent_txid: [u8; 32],
    parent_vout: u32,
    change_script: Vec<u8>,
    change_value: u64,
) -> Transaction {
    let mut tx = Transaction::new(2);
    tx.inputs.push(TxIn {
        previous_output: OutPoint {
            txid: parent_txid,
            vout: parent_vout,
        },
        script_sig: vec![],
        sequence: RBF_SEQUENCE, // Enable RBF on child too
    });
    tx.outputs.push(TxOut {
        value: change_value,
        script_pubkey: change_script,
    });
    tx
}

// ═══════════════════════════════════════════════════════════════════
// Ordinals Inscription Encoding
// ═══════════════════════════════════════════════════════════════════

/// Build an Ordinals inscription envelope for taproot witness.
///
/// Creates the witness script data for embedding content as an Ordinal inscription.
/// Format:
/// ```text
/// OP_FALSE OP_IF
///   OP_PUSH "ord"
///   OP_PUSH 0x01 (content type tag)
///   OP_PUSH <content_type>
///   OP_PUSH 0x00 (body tag)
///   OP_PUSH <body chunks...>
/// OP_ENDIF
/// ```
///
/// # Arguments
/// - `content_type` — MIME type (e.g., `"text/plain;charset=utf-8"`)
/// - `body` — The inscription content
///
/// # Returns
/// The raw witness script bytes for the inscription envelope.
#[must_use]
pub fn inscription_envelope(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();

    // OP_FALSE OP_IF
    script.push(0x00); // OP_FALSE / OP_0
    script.push(0x63); // OP_IF

    // Push "ord" protocol tag
    script.push(0x03); // push 3 bytes
    script.extend_from_slice(b"ord");

    // Content type tag (0x01)
    script.push(0x01); // push 1 byte
    script.push(0x01); // tag = 1 (content type)

    // Push content type string
    push_data(&mut script, content_type.as_bytes());

    // Body tag (0x00)
    script.push(0x00); // OP_0 = body tag separator

    // Push body in 520-byte chunks (tapscript max push)
    for chunk in body.chunks(520) {
        push_data(&mut script, chunk);
    }

    // OP_ENDIF
    script.push(0x68); // OP_ENDIF

    script
}

/// Helper to push data with appropriate Bitcoin script push opcodes.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00); // OP_0
        return;
    }

    if len <= 75 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(0x4C); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 0xFFFF {
        script.push(0x4D); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(0x4E); // OP_PUSHDATA4
        if len > u32::MAX as usize {
            // Slices larger than u32::MAX are not representable by script push opcodes.
            #[allow(clippy::panic)]
            {
                panic!("script push length exceeds u32::MAX");
            }
        }
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }

    script.extend_from_slice(data);
}

/// Compute the total size of an inscription for fee estimation.
#[must_use]
pub fn inscription_size(content_type: &str, body: &[u8]) -> usize {
    inscription_envelope(content_type, body).len()
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── OP_RETURN Tests ───────────────────────────────────────────

    #[test]
    fn test_op_return_basic() {
        let out = op_return(b"hello bitcoin").unwrap();
        assert_eq!(out.value, 0);
        assert_eq!(out.script_pubkey[0], 0x6A); // OP_RETURN
        assert_eq!(out.script_pubkey[1], 13); // length
        assert_eq!(&out.script_pubkey[2..], b"hello bitcoin");
    }

    #[test]
    fn test_op_return_empty() {
        let out = op_return(b"").unwrap();
        assert_eq!(out.value, 0);
        assert_eq!(out.script_pubkey[0], 0x6A);
        assert_eq!(out.script_pubkey[1], 0); // empty push
    }

    #[test]
    fn test_op_return_max_size() {
        let data = [0xAA; 80];
        let out = op_return(&data).unwrap();
        assert_eq!(out.script_pubkey[0], 0x6A);
    }

    #[test]
    fn test_op_return_too_large() {
        let data = [0xAA; 81];
        assert!(op_return(&data).is_err());
    }

    #[test]
    fn test_op_return_multi() {
        let out = op_return_multi(&[b"OMNI", b"\x00\x00\x00\x00"]).unwrap();
        assert_eq!(out.script_pubkey[0], 0x6A);
        // First push: 4 bytes "OMNI"
        assert_eq!(out.script_pubkey[1], 4);
        assert_eq!(&out.script_pubkey[2..6], b"OMNI");
    }

    // ─── RBF Tests ─────────────────────────────────────────────────

    #[test]
    fn test_rbf_sequence_value() {
        assert!(is_rbf_signaling(RBF_SEQUENCE));
        assert!(is_rbf_signaling(0));
        assert!(!is_rbf_signaling(0xFFFFFFFF));
        assert!(!is_rbf_signaling(0xFFFFFFFE));
    }

    #[test]
    fn test_enable_rbf() {
        let mut input = TxIn {
            previous_output: OutPoint {
                txid: [0; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        };
        assert!(!is_rbf_signaling(input.sequence));
        enable_rbf(&mut input);
        assert!(is_rbf_signaling(input.sequence));
        assert_eq!(input.sequence, RBF_SEQUENCE);
    }

    #[test]
    fn test_tx_signals_rbf() {
        let mut tx = Transaction::new(2);
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: [0; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
        assert!(!tx_signals_rbf(&tx));
        enable_rbf_all(&mut tx);
        assert!(tx_signals_rbf(&tx));
    }

    // ─── CPFP Tests ────────────────────────────────────────────────

    #[test]
    fn test_cpfp_fee_calculation() {
        // Parent: 200 vbytes, 200 sats fee (1 sat/vbyte)
        // Want: 10 sat/vbyte package rate
        // Child: 150 vbytes
        let rate = cpfp_required_fee_rate(200, 200, 10, 150);
        // Package needs: 10 * 350 = 3500 sats
        // Child needs: 3500 - 200 = 3300 sats
        // Child rate: 3300 / 150 = 22 sat/vbyte
        assert_eq!(rate, 22);
    }

    #[test]
    fn test_cpfp_child_construction() {
        let child = cpfp_child([0xAA; 32], 0, vec![0x76; 25], 50_000);
        assert_eq!(child.inputs.len(), 1);
        assert_eq!(child.outputs.len(), 1);
        assert_eq!(child.inputs[0].previous_output.txid, [0xAA; 32]);
        assert_eq!(child.outputs[0].value, 50_000);
        assert!(is_rbf_signaling(child.inputs[0].sequence));
    }

    // ─── Ordinals Tests ────────────────────────────────────────────

    #[test]
    fn test_inscription_envelope_structure() {
        let envelope = inscription_envelope("text/plain;charset=utf-8", b"Hello, World!");
        // Must start with OP_FALSE OP_IF
        assert_eq!(envelope[0], 0x00); // OP_FALSE
        assert_eq!(envelope[1], 0x63); // OP_IF
                                       // Must contain "ord"
        assert_eq!(&envelope[3..6], b"ord");
        // Must end with OP_ENDIF
        assert_eq!(*envelope.last().unwrap(), 0x68); // OP_ENDIF
    }

    #[test]
    fn test_inscription_envelope_contains_content_type() {
        let ct = "image/png";
        let envelope = inscription_envelope(ct, b"\x89PNG");
        // Verify the content type appears in the envelope
        let envelope_str = String::from_utf8_lossy(&envelope);
        assert!(envelope_str.contains("image/png"));
    }

    #[test]
    fn test_inscription_large_body_chunked() {
        // Body larger than 520 bytes should be chunked
        let body = vec![0xAA; 1200];
        let envelope = inscription_envelope("text/plain", &body);
        assert!(!envelope.is_empty());
        // Should end with OP_ENDIF
        assert_eq!(*envelope.last().unwrap(), 0x68);
    }

    #[test]
    fn test_inscription_size() {
        let size = inscription_size("text/plain", b"test");
        assert!(size > 0);
        assert_eq!(size, inscription_envelope("text/plain", b"test").len());
    }

    #[test]
    fn test_inscription_empty_body() {
        let envelope = inscription_envelope("text/plain", b"");
        assert_eq!(envelope[0], 0x00); // OP_FALSE
        assert_eq!(*envelope.last().unwrap(), 0x68); // OP_ENDIF
    }

    #[test]
    fn test_inscription_large_content_type_not_dropped() {
        let content_type = "a".repeat(600);
        let envelope = inscription_envelope(&content_type, b"");

        // content-type push should use OP_PUSHDATA2 with 0x0258 (600) length
        assert!(envelope.windows(3).any(|w| w == [0x4D, 0x58, 0x02]));
        assert!(envelope.windows(600).any(|w| w == content_type.as_bytes()));
    }
}
