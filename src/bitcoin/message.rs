//! **BIP-322** — Generic Signed Message Format.
//!
//! Provides script-based message signing that works with all Bitcoin address types
//! (P2PKH, P2WPKH, P2SH, P2TR), replacing the limited BIP-137 format.
//!
//! # Example
//! ```ignore
//! use trad_signer::bitcoin::message;
//!
//! let hash = message::message_hash(b"Hello World");
//! assert_eq!(hex::encode(hash), "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a");
//! ```

use crate::crypto;
use crate::encoding;

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

/// Compute the txid (double SHA256, reversed) of a raw transaction.
pub fn compute_txid(raw_tx: &[u8]) -> [u8; 32] {
    let mut txid = crypto::double_sha256(raw_tx);
    // txid is displayed reversed (little-endian)
    txid.reverse();
    txid
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

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
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
}
