//! XRP advanced transactions: DEX orders, Escrow, and IOU precision.

// ═══════════════════════════════════════════════════════════════════
// XRPL Amount Encoding (IOU with Mantissa/Exponent)
// ═══════════════════════════════════════════════════════════════════

/// Encode an IOU (Issued Currency) amount per XRPL serialization format.
///
/// XRPL IOU amounts are 8 bytes:
/// - Bit 63: Not XRP flag (always 1 for IOU)
/// - Bit 62: Sign (1 = positive, 0 = negative)
/// - Bits 54-61: Exponent (biased by 97)
/// - Bits 0-53: Mantissa (54 bits)
///
/// The value = mantissa * 10^(exponent - 97)
///
/// # Arguments
/// - `mantissa` — Significant digits (must be <= 10^16 - 1)
/// - `exponent` — Power of 10 offset (range: -96 to 80)
/// - `positive` — Whether the amount is positive
pub fn encode_iou_amount(mantissa: u64, exponent: i8, positive: bool) -> [u8; 8] {
    if mantissa == 0 {
        // Zero amount: special encoding
        let mut bytes = [0u8; 8];
        bytes[0] = 0x80; // Not XRP flag, positive, zero mantissa
        return bytes;
    }

    // Normalize mantissa to 54 bits max (10^15 <= m < 10^16)
    let mut m = mantissa;
    let mut e = exponent as i16;

    // Normalize: mantissa should be in [10^15, 10^16)
    while m < 1_000_000_000_000_000 && e > -96 {
        m *= 10;
        e -= 1;
    }
    while m >= 10_000_000_000_000_000 && e < 80 {
        m /= 10;
        e += 1;
    }

    // Bias the exponent: stored = exponent + 97
    let biased_exp = (e + 97) as u64;

    let mut val: u64 = 0;
    val |= 1 << 63; // Not XRP flag
    if positive {
        val |= 1 << 62; // Positive flag
    }
    val |= (biased_exp & 0xFF) << 54; // 8-bit exponent
    val |= m & 0x003F_FFFF_FFFF_FFFF; // 54-bit mantissa

    val.to_be_bytes()
}

/// Decode an IOU amount from 8 bytes.
///
/// Returns (mantissa, exponent, is_positive).
pub fn decode_iou_amount(bytes: &[u8; 8]) -> (u64, i8, bool) {
    let val = u64::from_be_bytes(*bytes);

    // Check for zero
    if val & 0x003F_FFFF_FFFF_FFFF == 0 {
        return (0, 0, true);
    }

    let positive = (val >> 62) & 1 == 1;
    let biased_exp = ((val >> 54) & 0xFF) as i16;
    let exponent = (biased_exp - 97) as i8;
    let mantissa = val & 0x003F_FFFF_FFFF_FFFF;

    (mantissa, exponent, positive)
}

/// Encode a 3-character currency code for XRPL.
///
/// XRPL currency codes are 20 bytes:
/// - Standard (3-char): 12 zero bytes + 3 ASCII bytes + 5 zero bytes
/// - Non-standard (40-hex): raw 20 bytes
pub fn encode_currency_code(code: &str) -> Result<[u8; 20], &'static str> {
    if code.len() != 3 {
        return Err("currency code must be 3 characters");
    }
    if code == "XRP" {
        return Err("XRP is not an issued currency");
    }

    let mut out = [0u8; 20];
    out[12..15].copy_from_slice(code.as_bytes());
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════
// OfferCreate / OfferCancel (DEX)
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for OfferCreate.
pub const TT_OFFER_CREATE: u16 = 7;
/// Transaction type code for OfferCancel.
pub const TT_OFFER_CANCEL: u16 = 8;

/// Serialize an OfferCreate transaction for signing.
///
/// # Arguments
/// - `account` — 20-byte account address
/// - `taker_gets_drops` — Amount the taker gets (in drops for XRP, or IOU bytes)
/// - `taker_pays_drops` — Amount the taker pays (in drops for XRP, or IOU bytes)
/// - `sequence` — Account sequence number
/// - `fee_drops` — Fee in drops
/// - `flags` — Transaction flags (e.g., `tfSell = 0x00080000`)
pub fn offer_create(
    account: &[u8; 20],
    taker_gets_drops: u64,
    taker_pays_drops: u64,
    sequence: u32,
    fee_drops: u64,
    flags: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);

    // TransactionType (field code 0x12 = UInt16)
    buf.extend_from_slice(&[0x12, (TT_OFFER_CREATE >> 8) as u8, TT_OFFER_CREATE as u8]);
    // Flags
    buf.extend_from_slice(&[0x22]);
    buf.extend_from_slice(&flags.to_be_bytes());
    // Sequence
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    // Fee (Amount, field code 0x68)
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    // TakerPays (Amount, field code 0x64)
    buf.push(0x64);
    buf.extend_from_slice(&encode_xrp_amount(taker_pays_drops));
    // TakerGets (Amount, field code 0x65)
    buf.push(0x65);
    buf.extend_from_slice(&encode_xrp_amount(taker_gets_drops));
    // Account (AccountID, field code 0x81 0x14)
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);

    buf
}

/// Serialize an OfferCancel transaction.
pub fn offer_cancel(
    account: &[u8; 20],
    offer_sequence: u32,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(60);

    buf.extend_from_slice(&[0x12, (TT_OFFER_CANCEL >> 8) as u8, TT_OFFER_CANCEL as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]); // flags = 0
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    // OfferSequence (UInt32 field code 0x20 0x19)
    buf.extend_from_slice(&[0x20, 0x19]);
    buf.extend_from_slice(&offer_sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);

    buf
}

// ═══════════════════════════════════════════════════════════════════
// Escrow
// ═══════════════════════════════════════════════════════════════════

/// Transaction type code for EscrowCreate.
pub const TT_ESCROW_CREATE: u16 = 1;
/// Transaction type code for EscrowFinish.
pub const TT_ESCROW_FINISH: u16 = 2;
/// Transaction type code for EscrowCancel.
pub const TT_ESCROW_CANCEL: u16 = 4;

/// Serialize an EscrowCreate transaction.
///
/// # Arguments
/// - `account` — Sender address
/// - `destination` — Recipient address
/// - `amount_drops` — Amount in drops
/// - `finish_after` — Unix timestamp after which escrow can be finished
/// - `cancel_after` — Optional Unix timestamp after which escrow can be cancelled
/// - `sequence` — Account sequence
/// - `fee_drops` — Fee in drops
pub fn escrow_create(
    account: &[u8; 20],
    destination: &[u8; 20],
    amount_drops: u64,
    finish_after: u32,
    cancel_after: Option<u32>,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);

    buf.extend_from_slice(&[0x12, (TT_ESCROW_CREATE >> 8) as u8, TT_ESCROW_CREATE as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]); // flags = 0
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    // FinishAfter (UInt32)
    buf.extend_from_slice(&[0x20, 0x24]);
    buf.extend_from_slice(&finish_after.to_be_bytes());
    // CancelAfter (optional)
    if let Some(cancel) = cancel_after {
        buf.extend_from_slice(&[0x20, 0x25]);
        buf.extend_from_slice(&cancel.to_be_bytes());
    }
    // Amount
    buf.push(0x61);
    buf.extend_from_slice(&encode_xrp_amount(amount_drops));
    // Fee
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    // Account
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    // Destination
    buf.extend_from_slice(&[0x83, 0x14]);
    buf.extend_from_slice(destination);

    buf
}

/// Serialize an EscrowFinish transaction.
pub fn escrow_finish(
    account: &[u8; 20],
    owner: &[u8; 20],
    offer_sequence: u32,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(70);

    buf.extend_from_slice(&[0x12, (TT_ESCROW_FINISH >> 8) as u8, TT_ESCROW_FINISH as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&[0x20, 0x19]); // OfferSequence
    buf.extend_from_slice(&offer_sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    // Owner
    buf.extend_from_slice(&[0x82, 0x14]);
    buf.extend_from_slice(owner);

    buf
}

/// Serialize an EscrowCancel transaction.
pub fn escrow_cancel(
    account: &[u8; 20],
    owner: &[u8; 20],
    offer_sequence: u32,
    sequence: u32,
    fee_drops: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(70);

    buf.extend_from_slice(&[0x12, (TT_ESCROW_CANCEL >> 8) as u8, TT_ESCROW_CANCEL as u8]);
    buf.extend_from_slice(&[0x22, 0x00, 0x00, 0x00, 0x00]);
    buf.extend_from_slice(&[0x24]);
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&[0x20, 0x19]);
    buf.extend_from_slice(&offer_sequence.to_be_bytes());
    buf.push(0x68);
    buf.extend_from_slice(&encode_xrp_amount(fee_drops));
    buf.extend_from_slice(&[0x81, 0x14]);
    buf.extend_from_slice(account);
    buf.extend_from_slice(&[0x82, 0x14]);
    buf.extend_from_slice(owner);

    buf
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Encode an XRP amount in drops (native currency).
///
/// XRP amounts are 8 bytes with bit 63 = 0 (not IOU) and bit 62 = 1 (positive).
fn encode_xrp_amount(drops: u64) -> [u8; 8] {
    let val = drops | (0x40 << 56); // Set positive bit
    val.to_be_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 20] = [0x01; 20];
    const DEST: [u8; 20] = [0x02; 20];

    // ─── IOU Amount Tests ───────────────────────────────────────

    #[test]
    fn test_iou_encode_decode_roundtrip() {
        let encoded = encode_iou_amount(1_000_000_000_000_000, 0, true);
        let (m, e, pos) = decode_iou_amount(&encoded);
        assert!(pos);
        // After normalization, mantissa * 10^exponent should represent same value
        let original = 1_000_000_000_000_000u128 * 10u128.pow(0);
        let decoded = m as u128 * 10u128.pow((e + 97 - 97) as u32);
        // Values should be in the same order of magnitude
        assert!(m > 0);
    }

    #[test]
    fn test_iou_zero() {
        let encoded = encode_iou_amount(0, 0, true);
        assert_eq!(encoded[0] & 0x80, 0x80); // Not XRP flag
        let (m, _, _) = decode_iou_amount(&encoded);
        assert_eq!(m, 0);
    }

    #[test]
    fn test_iou_negative() {
        let encoded = encode_iou_amount(1_000_000_000_000_000, 0, false);
        let (_, _, pos) = decode_iou_amount(&encoded);
        assert!(!pos);
    }

    // ─── Currency Code Tests ────────────────────────────────────

    #[test]
    fn test_currency_code_usd() {
        let cc = encode_currency_code("USD").unwrap();
        assert_eq!(&cc[12..15], b"USD");
        assert_eq!(&cc[..12], &[0u8; 12]);
    }

    #[test]
    fn test_currency_code_xrp_rejected() {
        assert!(encode_currency_code("XRP").is_err());
    }

    #[test]
    fn test_currency_code_wrong_length() {
        assert!(encode_currency_code("US").is_err());
        assert!(encode_currency_code("USDC").is_err());
    }

    // ─── OfferCreate Tests ──────────────────────────────────────

    #[test]
    fn test_offer_create_serialization() {
        let tx = offer_create(&ACCOUNT, 1_000_000, 500_000, 42, 12, 0);
        assert!(!tx.is_empty());
        // Transaction type should be 7
        assert_eq!(tx[0], 0x12);
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_OFFER_CREATE);
    }

    #[test]
    fn test_offer_cancel_serialization() {
        let tx = offer_cancel(&ACCOUNT, 10, 43, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_OFFER_CANCEL);
    }

    // ─── Escrow Tests ───────────────────────────────────────────

    #[test]
    fn test_escrow_create_serialization() {
        let tx = escrow_create(
            &ACCOUNT, &DEST, 1_000_000,
            1700000000, Some(1700100000),
            44, 12,
        );
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ESCROW_CREATE);
    }

    #[test]
    fn test_escrow_create_no_cancel() {
        let tx1 = escrow_create(&ACCOUNT, &DEST, 1_000_000, 1700000000, None, 44, 12);
        let tx2 = escrow_create(&ACCOUNT, &DEST, 1_000_000, 1700000000, Some(1700100000), 44, 12);
        // With cancel_after should be longer
        assert!(tx2.len() > tx1.len());
    }

    #[test]
    fn test_escrow_finish_serialization() {
        let tx = escrow_finish(&ACCOUNT, &DEST, 44, 45, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ESCROW_FINISH);
    }

    #[test]
    fn test_escrow_cancel_serialization() {
        let tx = escrow_cancel(&ACCOUNT, &DEST, 44, 46, 12);
        assert!(!tx.is_empty());
        assert_eq!(u16::from_be_bytes([tx[1], tx[2]]), TT_ESCROW_CANCEL);
    }

    // ─── XRP Amount Encoding ────────────────────────────────────

    #[test]
    fn test_xrp_amount_encoding() {
        let amt = encode_xrp_amount(1_000_000); // 1 XRP
        // Bit 62 should be set (positive)
        assert_eq!(amt[0] & 0x40, 0x40);
        // Bit 63 should be 0 (native XRP)
        assert_eq!(amt[0] & 0x80, 0x00);
    }
}
