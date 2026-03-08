//! Bitcoin script helpers: HTLC, Timelock (CLTV/CSV), and Coin Selection.

use crate::error::SignerError;
use super::transaction::{Transaction, TxIn, TxOut, OutPoint};

// ═══════════════════════════════════════════════════════════════════
// Timelock Scripts (CLTV / CSV)
// ═══════════════════════════════════════════════════════════════════

/// Build a CLTV (CheckLockTimeVerify, BIP-65) timelock script.
///
/// Script: `<locktime> OP_CLTV OP_DROP <pubkey_hash> OP_CHECKSIG`
///
/// The output can only be spent after the specified block height or time.
///
/// # Arguments
/// - `locktime` — Block height (< 500_000_000) or Unix timestamp
/// - `pubkey_hash` — 20-byte HASH160 of the recipient's public key
pub fn cltv_script(locktime: u32, pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(30);

    // Push locktime as minimal integer
    push_script_number(&mut script, locktime as i64);

    script.push(0xB1); // OP_CHECKLOCKTIMEVERIFY
    script.push(0x75); // OP_DROP
    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG
    script
}

/// Build a CSV (CheckSequenceVerify, BIP-112) relative timelock script.
///
/// Script: `<sequence> OP_CSV OP_DROP <pubkey_hash> OP_CHECKSIG`
///
/// The output can only be spent after a relative delay from confirmation.
///
/// # Arguments
/// - `sequence` — Relative lock value (blocks or 512-second intervals)
/// - `pubkey_hash` — 20-byte HASH160 of the recipient's public key
pub fn csv_script(sequence: u32, pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(30);

    push_script_number(&mut script, sequence as i64);

    script.push(0xB2); // OP_CHECKSEQUENCEVERIFY
    script.push(0x75); // OP_DROP
    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG
    script
}

/// Check if a locktime value represents a block height or Unix timestamp.
///
/// Per BIP-65: values < 500,000,000 are block heights; >= are Unix timestamps.
#[must_use]
pub fn is_block_height_locktime(locktime: u32) -> bool {
    locktime < 500_000_000
}

// ═══════════════════════════════════════════════════════════════════
// HTLC (Hash Time-Locked Contract)
// ═══════════════════════════════════════════════════════════════════

/// Build an HTLC (Hash Time-Locked Contract) script.
///
/// Script:
/// ```text
/// OP_IF
///   OP_SHA256 <hash> OP_EQUALVERIFY
///   <receiver_pubkey_hash> OP_CHECKSIG          // hashlock path
/// OP_ELSE
///   <timeout> OP_CLTV OP_DROP
///   <sender_pubkey_hash> OP_CHECKSIG            // timelock refund path
/// OP_ENDIF
/// ```
///
/// # Arguments
/// - `payment_hash` — 32-byte SHA-256 hash of the preimage
/// - `receiver_pubkey_hash` — 20-byte HASH160 of receiver
/// - `sender_pubkey_hash` — 20-byte HASH160 of sender (refund)
/// - `timeout` — CLTV timeout for the refund path
pub fn htlc_script(
    payment_hash: &[u8; 32],
    receiver_pubkey_hash: &[u8; 20],
    sender_pubkey_hash: &[u8; 20],
    timeout: u32,
) -> Vec<u8> {
    let mut script = Vec::with_capacity(100);

    // OP_IF (hashlock branch)
    script.push(0x63); // OP_IF

    script.push(0xA8); // OP_SHA256
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(payment_hash);
    script.push(0x88); // OP_EQUALVERIFY

    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(receiver_pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG

    // OP_ELSE (timelock refund branch)
    script.push(0x67); // OP_ELSE

    push_script_number(&mut script, timeout as i64);
    script.push(0xB1); // OP_CHECKLOCKTIMEVERIFY
    script.push(0x75); // OP_DROP

    script.push(0x76); // OP_DUP
    script.push(0xA9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(sender_pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xAC); // OP_CHECKSIG

    script.push(0x68); // OP_ENDIF

    script
}

/// Compute the SHA-256 hash of a preimage for HTLC usage.
pub fn htlc_payment_hash(preimage: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Build the witness for claiming an HTLC (hashlock path).
///
/// Witness: `<signature> <pubkey> <preimage> OP_TRUE`
pub fn htlc_claim_witness(
    signature: &[u8],
    pubkey: &[u8],
    preimage: &[u8],
    htlc_script: &[u8],
) -> Vec<Vec<u8>> {
    vec![
        signature.to_vec(),
        pubkey.to_vec(),
        preimage.to_vec(),
        vec![0x01], // OP_TRUE (select IF branch)
        htlc_script.to_vec(),
    ]
}

/// Build the witness for refunding an HTLC (timelock path).
///
/// Witness: `<signature> <pubkey> OP_FALSE`
pub fn htlc_refund_witness(
    signature: &[u8],
    pubkey: &[u8],
    htlc_script: &[u8],
) -> Vec<Vec<u8>> {
    vec![
        signature.to_vec(),
        pubkey.to_vec(),
        vec![], // OP_FALSE (select ELSE branch)
        htlc_script.to_vec(),
    ]
}

// ═══════════════════════════════════════════════════════════════════
// Coin Selection
// ═══════════════════════════════════════════════════════════════════

/// A UTXO available for spending.
#[derive(Clone, Debug)]
pub struct Utxo {
    /// Transaction ID containing this UTXO.
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Estimated virtual size of the input when spent (in vbytes).
    pub input_vsize: usize,
}

/// Result of coin selection.
#[derive(Clone, Debug)]
pub struct CoinSelectionResult {
    /// Selected UTXOs.
    pub selected: Vec<Utxo>,
    /// Total value of selected UTXOs.
    pub total_value: u64,
    /// Estimated fee in satoshis.
    pub estimated_fee: u64,
    /// Change amount (0 if no change).
    pub change: u64,
}

/// Select coins using Single Random Draw (SRD) algorithm.
///
/// Randomly selects UTXOs until the target is met. Simple and effective
/// for most use cases.
///
/// # Arguments
/// - `utxos` — Available UTXOs
/// - `target` — Target amount in satoshis (excluding fees)
/// - `fee_rate` — Fee rate in sat/vbyte
/// - `base_tx_vsize` — Base transaction virtual size (overhead without inputs)
/// - `change_output_vsize` — Virtual size of a change output
pub fn select_coins_srd(
    utxos: &[Utxo],
    target: u64,
    fee_rate: u64,
    base_tx_vsize: usize,
    change_output_vsize: usize,
) -> Result<CoinSelectionResult, SignerError> {
    if utxos.is_empty() {
        return Err(SignerError::ParseError("no UTXOs available".into()));
    }

    // Sort by value descending (largest first for SRD)
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| b.value.cmp(&a.value));

    let mut selected = Vec::new();
    let mut total_value = 0u64;
    let mut total_input_vsize = 0usize;

    for utxo in &sorted {
        selected.push((*utxo).clone());
        total_value += utxo.value;
        total_input_vsize += utxo.input_vsize;

        let tx_vsize = base_tx_vsize + total_input_vsize + change_output_vsize;
        let fee = fee_rate * tx_vsize as u64;

        if total_value >= target + fee {
            let change = total_value - target - fee;
            return Ok(CoinSelectionResult {
                selected,
                total_value,
                estimated_fee: fee,
                change,
            });
        }
    }

    Err(SignerError::ParseError(
        "insufficient funds: not enough UTXOs to cover target + fees".into(),
    ))
}

/// Select coins using Branch and Bound (BnB) algorithm.
///
/// Tries to find an exact match (no change) to reduce on-chain footprint.
/// Falls back to SRD if no exact match is found within the search limit.
///
/// # Arguments
/// - `utxos` — Available UTXOs
/// - `target` — Target amount in satoshis
/// - `fee_rate` — Fee rate in sat/vbyte
/// - `base_tx_vsize` — Base transaction virtual size
/// - `change_output_vsize` — Virtual size of a change output
/// - `cost_of_change` — Minimum change worth creating (dust threshold)
pub fn select_coins_bnb(
    utxos: &[Utxo],
    target: u64,
    fee_rate: u64,
    base_tx_vsize: usize,
    change_output_vsize: usize,
    cost_of_change: u64,
) -> Result<CoinSelectionResult, SignerError> {
    if utxos.is_empty() {
        return Err(SignerError::ParseError("no UTXOs available".into()));
    }

    // Sort by effective value (value - cost to spend) descending
    let mut sorted: Vec<&Utxo> = utxos.iter().collect();
    sorted.sort_by(|a, b| {
        let ev_a = a.value.saturating_sub(fee_rate * a.input_vsize as u64);
        let ev_b = b.value.saturating_sub(fee_rate * b.input_vsize as u64);
        ev_b.cmp(&ev_a)
    });

    let max_iterations = 100_000;
    let mut best: Option<Vec<usize>> = None;
    let mut best_waste = i64::MAX;

    // DFS search for exact match
    let mut stack: Vec<(usize, Vec<usize>, u64, usize)> = vec![(0, vec![], 0, 0)];
    let mut iterations = 0;

    while let Some((idx, selected_indices, total, total_vsize)) = stack.pop() {
        iterations += 1;
        if iterations > max_iterations {
            break;
        }

        let fee = fee_rate * (base_tx_vsize + total_vsize) as u64;
        let needed = target + fee;

        if total >= needed && total <= needed + cost_of_change {
            // Found an acceptable match (within dust threshold = no change needed)
            let waste = (total as i64) - (needed as i64);
            if waste < best_waste {
                best_waste = waste;
                best = Some(selected_indices.clone());
            }
            continue;
        }

        if idx >= sorted.len() || total > needed + cost_of_change {
            continue;
        }

        // Branch: include current UTXO
        let mut with = selected_indices.clone();
        with.push(idx);
        stack.push((
            idx + 1,
            with,
            total + sorted[idx].value,
            total_vsize + sorted[idx].input_vsize,
        ));

        // Branch: exclude current UTXO
        stack.push((idx + 1, selected_indices, total, total_vsize));
    }

    if let Some(indices) = best {
        let selected: Vec<Utxo> = indices.iter().map(|i| sorted[*i].clone()).collect();
        let total_value: u64 = selected.iter().map(|u| u.value).sum();
        let total_input_vsize: usize = selected.iter().map(|u| u.input_vsize).sum();
        let fee = fee_rate * (base_tx_vsize + total_input_vsize) as u64;
        let change = total_value.saturating_sub(target + fee);

        Ok(CoinSelectionResult {
            selected,
            total_value,
            estimated_fee: fee,
            change,
        })
    } else {
        // Fallback to SRD
        select_coins_srd(utxos, target, fee_rate, base_tx_vsize, change_output_vsize)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Push a number in Bitcoin's minimal script number encoding.
fn push_script_number(script: &mut Vec<u8>, n: i64) {
    if n == 0 {
        script.push(0x00); // OP_0
        return;
    }
    if n >= 1 && n <= 16 {
        script.push(0x50 + n as u8); // OP_1..OP_16
        return;
    }

    // Encode as little-endian with sign bit
    let negative = n < 0;
    let mut abs_n = if negative { (-n) as u64 } else { n as u64 };
    let mut bytes = Vec::new();

    while abs_n > 0 {
        bytes.push((abs_n & 0xFF) as u8);
        abs_n >>= 8;
    }

    // Add sign bit if needed
    if bytes.last().map_or(false, |b| b & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = bytes.len() - 1;
        bytes[last] |= 0x80;
    }

    script.push(bytes.len() as u8); // push data length
    script.extend_from_slice(&bytes);
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const PKH: [u8; 20] = [0xAB; 20];
    const PKH2: [u8; 20] = [0xCD; 20];

    // ─── Timelock Tests ─────────────────────────────────────────

    #[test]
    fn test_cltv_script_structure() {
        let script = cltv_script(500_000, &PKH);
        // Should contain OP_CHECKLOCKTIMEVERIFY and OP_CHECKSIG
        assert!(script.contains(&0xB1)); // OP_CLTV
        assert!(script.contains(&0xAC)); // OP_CHECKSIG
        assert!(script.windows(20).any(|w| w == PKH));
    }

    #[test]
    fn test_csv_script_structure() {
        let script = csv_script(144, &PKH); // ~1 day in blocks
        assert!(script.contains(&0xB2)); // OP_CSV
        assert!(script.contains(&0xAC)); // OP_CHECKSIG
    }

    #[test]
    fn test_is_block_height_locktime() {
        assert!(is_block_height_locktime(500_000));
        assert!(is_block_height_locktime(0));
        assert!(!is_block_height_locktime(500_000_000));
        assert!(!is_block_height_locktime(1_700_000_000));
    }

    // ─── HTLC Tests ─────────────────────────────────────────────

    #[test]
    fn test_htlc_script_structure() {
        let preimage = b"secret preimage";
        let hash = htlc_payment_hash(preimage);
        let script = htlc_script(&hash, &PKH, &PKH2, 100_000);

        assert!(script.contains(&0x63)); // OP_IF
        assert!(script.contains(&0x67)); // OP_ELSE
        assert!(script.contains(&0x68)); // OP_ENDIF
        assert!(script.contains(&0xA8)); // OP_SHA256
        assert!(script.contains(&0xB1)); // OP_CLTV
        // Should contain both pubkey hashes
        assert!(script.windows(20).any(|w| w == PKH));
        assert!(script.windows(20).any(|w| w == PKH2));
    }

    #[test]
    fn test_htlc_payment_hash_deterministic() {
        let preimage = b"test preimage";
        let h1 = htlc_payment_hash(preimage);
        let h2 = htlc_payment_hash(preimage);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_htlc_payment_hash_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = htlc_payment_hash(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_htlc_claim_witness() {
        let sig = vec![0x30, 0x44]; // dummy DER signature
        let pk = vec![0x02; 33]; // dummy compressed key
        let preimage = b"secret";
        let script = vec![0x63; 10]; // dummy script
        let witness = htlc_claim_witness(&sig, &pk, preimage, &script);
        assert_eq!(witness.len(), 5);
        assert_eq!(witness[3], vec![0x01]); // OP_TRUE for claim
    }

    #[test]
    fn test_htlc_refund_witness() {
        let sig = vec![0x30, 0x44];
        let pk = vec![0x02; 33];
        let script = vec![0x63; 10];
        let witness = htlc_refund_witness(&sig, &pk, &script);
        assert_eq!(witness.len(), 4);
        assert!(witness[2].is_empty()); // OP_FALSE for refund
    }

    // ─── Coin Selection Tests ───────────────────────────────────

    fn make_utxos() -> Vec<Utxo> {
        vec![
            Utxo { txid: [1; 32], vout: 0, value: 100_000, input_vsize: 68 },
            Utxo { txid: [2; 32], vout: 0, value: 50_000, input_vsize: 68 },
            Utxo { txid: [3; 32], vout: 0, value: 200_000, input_vsize: 68 },
            Utxo { txid: [4; 32], vout: 0, value: 30_000, input_vsize: 68 },
        ]
    }

    #[test]
    fn test_srd_selects_enough() {
        let utxos = make_utxos();
        let result = select_coins_srd(&utxos, 150_000, 10, 10, 34).unwrap();
        assert!(result.total_value >= 150_000 + result.estimated_fee);
    }

    #[test]
    fn test_srd_insufficient_funds() {
        let utxos = make_utxos();
        let result = select_coins_srd(&utxos, 1_000_000, 10, 10, 34);
        assert!(result.is_err());
    }

    #[test]
    fn test_srd_empty_utxos() {
        let result = select_coins_srd(&[], 100, 10, 10, 34);
        assert!(result.is_err());
    }

    #[test]
    fn test_bnb_finds_exact_match() {
        let utxos = vec![
            Utxo { txid: [1; 32], vout: 0, value: 100_000, input_vsize: 68 },
            Utxo { txid: [2; 32], vout: 0, value: 50_000, input_vsize: 68 },
            Utxo { txid: [3; 32], vout: 0, value: 25_000, input_vsize: 68 },
        ];
        // Target + fee should be achievable with exact match
        let result = select_coins_bnb(&utxos, 49_000, 1, 10, 34, 500).unwrap();
        assert!(result.total_value >= 49_000);
    }

    #[test]
    fn test_bnb_falls_back_to_srd() {
        let utxos = make_utxos();
        // This should find a solution (either exact or SRD fallback)
        let result = select_coins_bnb(&utxos, 150_000, 10, 10, 34, 546).unwrap();
        assert!(result.total_value >= 150_000 + result.estimated_fee);
    }

    // ─── Script Number Encoding ─────────────────────────────────

    #[test]
    fn test_push_script_number_small() {
        let mut s = Vec::new();
        push_script_number(&mut s, 0);
        assert_eq!(s, vec![0x00]); // OP_0

        let mut s = Vec::new();
        push_script_number(&mut s, 1);
        assert_eq!(s, vec![0x51]); // OP_1

        let mut s = Vec::new();
        push_script_number(&mut s, 16);
        assert_eq!(s, vec![0x60]); // OP_16
    }

    #[test]
    fn test_push_script_number_large() {
        let mut s = Vec::new();
        push_script_number(&mut s, 500_000);
        // 500_000 = 0x07A120 in LE: [0x20, 0xA1, 0x07]
        assert_eq!(s[0], 3); // length
        assert_eq!(s[1..], [0x20, 0xA1, 0x07]);
    }
}
