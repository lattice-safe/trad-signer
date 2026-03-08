//! **BIP-342** — Tapscript: validation rules for Taproot script-path spends.
//!
//! Provides a script builder and validator for Tapscript, which uses BIP-340
//! Schnorr signatures instead of legacy ECDSA.
//!
//! # Example
//! ```ignore
//! use trad_signer::bitcoin::tapscript::{Script, Opcode};
//!
//! // Simple "check signature" script
//! let script = Script::new()
//!     .push_key(&pubkey)
//!     .push_opcode(Opcode::OP_CHECKSIG);
//! ```

use sha2::{Digest, Sha256};

// ─── Opcodes ────────────────────────────────────────────────────────

/// Bitcoin/Tapscript opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Opcode {
    /// Push empty byte vector.
    OP_0 = 0x00,
    /// Push the number 1 (OP_TRUE).
    OP_1 = 0x51,
    /// Push the number 2.
    OP_2 = 0x52,
    /// Push the number 3.
    OP_3 = 0x53,
    /// Push the number 16.
    OP_16 = 0x60,
    /// Return immediately (marks output as unspendable/data carrier).
    OP_RETURN = 0x6a,
    /// Duplicate the top stack item.
    OP_DUP = 0x76,
    /// Pop and check equality.
    OP_EQUAL = 0x87,
    /// OP_EQUAL + OP_VERIFY.
    OP_EQUALVERIFY = 0x88,
    /// Verify top stack item is nonzero, fail if not.
    OP_VERIFY = 0x69,
    /// Pop two items, fail if not equal.
    OP_HASH160 = 0xa9,
    /// BIP-340 Schnorr signature check (replaces legacy OP_CHECKSIG).
    OP_CHECKSIG = 0xac,
    /// BIP-342: Schnorr sig check + accumulate counter.
    OP_CHECKSIGADD = 0xba,
    /// Check that the top stack item equals the required number of signatures.
    OP_NUMEQUAL = 0x9c,
    /// OP_NUMEQUAL + OP_VERIFY.
    OP_NUMEQUALVERIFY = 0x9d,
    /// Check locktime.
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    /// Check sequence.
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    /// Mark remaining script as always-succeeding (BIP-342).
    OP_SUCCESS = 0x50,
    /// No operation.
    OP_NOP = 0x61,
    /// Drop top stack item.
    OP_DROP = 0x75,
    /// Swap top two stack items.
    OP_SWAP = 0x7c,
    /// If top stack item is true, execute following script.
    OP_IF = 0x63,
    /// Else branch for OP_IF.
    OP_ELSE = 0x67,
    /// End if block.
    OP_ENDIF = 0x68,
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> u8 {
        op as u8
    }
}

// ─── Script Builder ─────────────────────────────────────────────────

/// A Tapscript builder for constructing Bitcoin scripts.
#[derive(Clone, Debug)]
pub struct Script {
    /// The raw script bytes.
    bytes: Vec<u8>,
}

impl Script {
    /// Create a new empty script.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Push an opcode onto the script.
    pub fn push_opcode(mut self, opcode: Opcode) -> Self {
        self.bytes.push(opcode as u8);
        self
    }

    /// Push raw data onto the script with appropriate push opcode.
    ///
    /// Automatically selects the correct push operation based on data length:
    /// - 1-75 bytes: `OP_PUSHBYTESn`
    /// - 76-255 bytes: `OP_PUSHDATA1`
    /// - 256-65535 bytes: `OP_PUSHDATA2`
    pub fn push_data(mut self, data: &[u8]) -> Self {
        let len = data.len();
        if len == 0 {
            self.bytes.push(0x00); // OP_0
        } else if len <= 75 {
            self.bytes.push(len as u8); // OP_PUSHBYTESn
            self.bytes.extend_from_slice(data);
        } else if len <= 255 {
            self.bytes.push(0x4c); // OP_PUSHDATA1
            self.bytes.push(len as u8);
            self.bytes.extend_from_slice(data);
        } else if len <= 65535 {
            self.bytes.push(0x4d); // OP_PUSHDATA2
            self.bytes.extend_from_slice(&(len as u16).to_le_bytes());
            self.bytes.extend_from_slice(data);
        }
        self
    }

    /// Push a 32-byte x-only public key (BIP-340 Schnorr key).
    pub fn push_key(self, x_only_pubkey: &[u8; 32]) -> Self {
        self.push_data(x_only_pubkey)
    }

    /// Push a raw byte.
    pub fn push_byte(mut self, byte: u8) -> Self {
        self.bytes.push(byte);
        self
    }

    /// Push an integer (as minimal script encoding).
    pub fn push_int(mut self, value: i64) -> Self {
        if value == 0 {
            self.bytes.push(0x00); // OP_0
        } else if value == -1 {
            self.bytes.push(0x4f); // OP_1NEGATE
        } else if (1..=16).contains(&value) {
            self.bytes.push(0x50 + value as u8); // OP_1 through OP_16
        } else {
            // Encode as minimal-length byte sequence
            let mut v = value.unsigned_abs();
            let negative = value < 0;
            let mut encoded = Vec::new();
            while v > 0 {
                encoded.push((v & 0xFF) as u8);
                v >>= 8;
            }
            // Add sign bit
            if encoded.last().is_some_and(|b| b & 0x80 != 0) {
                encoded.push(if negative { 0x80 } else { 0x00 });
            } else if negative {
                if let Some(last) = encoded.last_mut() {
                    *last |= 0x80;
                }
            }
            self = self.push_data(&encoded);
        }
        self
    }

    /// Get the raw script bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return the raw script bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the script length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the script is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Compute the script hash (SHA256).
    pub fn script_hash(&self) -> [u8; 32] {
        let result = Sha256::digest(&self.bytes);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Common Script Templates ────────────────────────────────────────

/// Create a simple 1-of-1 Tapscript key-spend script.
///
/// `<pubkey> OP_CHECKSIG`
pub fn checksig_script(x_only_pubkey: &[u8; 32]) -> Script {
    Script::new()
        .push_key(x_only_pubkey)
        .push_opcode(Opcode::OP_CHECKSIG)
}

/// Create a Tapscript multisig script using OP_CHECKSIGADD.
///
/// BIP-342 replaces OP_CHECKMULTISIG with OP_CHECKSIGADD:
/// ```text
/// <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <keyN> OP_CHECKSIGADD <M> OP_NUMEQUALVERIFY
/// ```
pub fn multisig_script(keys: &[[u8; 32]], threshold: u32) -> Script {
    let mut script = Script::new();

    for (i, key) in keys.iter().enumerate() {
        script = script.push_key(key);
        if i == 0 {
            script = script.push_opcode(Opcode::OP_CHECKSIG);
        } else {
            script = script.push_opcode(Opcode::OP_CHECKSIGADD);
        }
    }

    script = script.push_int(threshold as i64);
    script.push_opcode(Opcode::OP_NUMEQUALVERIFY)
}

/// Create a timelocked script.
///
/// `<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG`
pub fn timelocked_script(x_only_pubkey: &[u8; 32], locktime: u32) -> Script {
    Script::new()
        .push_int(locktime as i64)
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_key(x_only_pubkey)
        .push_opcode(Opcode::OP_CHECKSIG)
}

// ─── Annex ──────────────────────────────────────────────────────────

/// Check if a witness item is an annex (BIP-341).
///
/// An annex is identified by a `0x50` prefix byte.
pub fn is_annex(data: &[u8]) -> bool {
    data.first() == Some(&0x50)
}

/// Create an annex field from data.
///
/// Prefixes the data with `0x50`.
pub fn create_annex(data: &[u8]) -> Vec<u8> {
    let mut annex = Vec::with_capacity(1 + data.len());
    annex.push(0x50);
    annex.extend_from_slice(data);
    annex
}

// ─── Signature Hash (Sighash) ──────────────────────────────────────

/// Tapscript signature hash types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SighashType {
    /// Default (same as ALL for Taproot).
    Default = 0x00,
    /// Sign all inputs and outputs.
    All = 0x01,
    /// Sign all inputs, no outputs.
    None = 0x02,
    /// Sign all inputs, only the output at same index.
    Single = 0x03,
    /// AnyoneCanPay modifier (can be combined with above).
    AllAnyoneCanPay = 0x81,
    /// AnyoneCanPay + None.
    NoneAnyoneCanPay = 0x82,
    /// AnyoneCanPay + Single.
    SingleAnyoneCanPay = 0x83,
}

impl SighashType {
    /// Parse a sighash type byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(SighashType::Default),
            0x01 => Some(SighashType::All),
            0x02 => Some(SighashType::None),
            0x03 => Some(SighashType::Single),
            0x81 => Some(SighashType::AllAnyoneCanPay),
            0x82 => Some(SighashType::NoneAnyoneCanPay),
            0x83 => Some(SighashType::SingleAnyoneCanPay),
            _ => None,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_builder_empty() {
        let script = Script::new();
        assert!(script.is_empty());
        assert_eq!(script.len(), 0);
    }

    #[test]
    fn test_script_builder_opcode() {
        let script = Script::new()
            .push_opcode(Opcode::OP_CHECKSIG);
        assert_eq!(script.to_bytes(), &[0xac]);
    }

    #[test]
    fn test_script_builder_key_checksig() {
        let key = [0xAA; 32];
        let script = checksig_script(&key);
        let bytes = script.to_bytes();
        assert_eq!(bytes[0], 32); // push 32 bytes
        assert_eq!(&bytes[1..33], &key);
        assert_eq!(bytes[33], 0xac); // OP_CHECKSIG
        assert_eq!(bytes.len(), 34);
    }

    #[test]
    fn test_script_builder_push_data_small() {
        let data = vec![0x01, 0x02, 0x03];
        let script = Script::new().push_data(&data);
        assert_eq!(script.to_bytes()[0], 3); // length prefix
        assert_eq!(&script.to_bytes()[1..], &data);
    }

    #[test]
    fn test_script_builder_push_data_76() {
        let data = vec![0xFF; 76];
        let script = Script::new().push_data(&data);
        assert_eq!(script.to_bytes()[0], 0x4c); // OP_PUSHDATA1
        assert_eq!(script.to_bytes()[1], 76); // length
        assert_eq!(&script.to_bytes()[2..], &data[..]);
    }

    #[test]
    fn test_script_builder_push_int_small() {
        let s0 = Script::new().push_int(0);
        assert_eq!(s0.to_bytes(), &[0x00]); // OP_0

        let s1 = Script::new().push_int(1);
        assert_eq!(s1.to_bytes(), &[0x51]); // OP_1

        let s16 = Script::new().push_int(16);
        assert_eq!(s16.to_bytes(), &[0x60]); // OP_16
    }

    #[test]
    fn test_script_builder_push_int_negative() {
        let s = Script::new().push_int(-1);
        assert_eq!(s.to_bytes(), &[0x4f]); // OP_1NEGATE
    }

    #[test]
    fn test_multisig_script_2_of_3() {
        let k1 = [0x01; 32];
        let k2 = [0x02; 32];
        let k3 = [0x03; 32];
        let script = multisig_script(&[k1, k2, k3], 2);
        let bytes = script.to_bytes();

        // Should contain all 3 keys
        assert!(!bytes.is_empty());
        // First key push: 32 bytes + OP_CHECKSIG
        assert_eq!(bytes[0], 32); // push 32
        // Should end with 2 OP_NUMEQUALVERIFY (push 2 + 0x9d)
        let last = bytes[bytes.len() - 1];
        assert_eq!(last, 0x9d); // OP_NUMEQUALVERIFY
    }

    #[test]
    fn test_timelocked_script() {
        let key = [0xAA; 32];
        let script = timelocked_script(&key, 500000);
        let bytes = script.to_bytes();
        assert!(!bytes.is_empty());
        // Should contain OP_CHECKLOCKTIMEVERIFY
        assert!(bytes.contains(&0xb1));
        // Should contain OP_DROP
        assert!(bytes.contains(&0x75));
        // Should contain OP_CHECKSIG
        assert!(bytes.contains(&0xac));
    }

    #[test]
    fn test_annex_identification() {
        assert!(is_annex(&[0x50, 0x01, 0x02]));
        assert!(!is_annex(&[0x51, 0x01]));
        assert!(!is_annex(&[]));
    }

    #[test]
    fn test_create_annex() {
        let annex = create_annex(&[0x01, 0x02]);
        assert_eq!(annex, vec![0x50, 0x01, 0x02]);
        assert!(is_annex(&annex));
    }

    #[test]
    fn test_sighash_type_parsing() {
        assert_eq!(SighashType::from_byte(0x00), Some(SighashType::Default));
        assert_eq!(SighashType::from_byte(0x01), Some(SighashType::All));
        assert_eq!(SighashType::from_byte(0x81), Some(SighashType::AllAnyoneCanPay));
        assert_eq!(SighashType::from_byte(0xFF), None);
    }

    #[test]
    fn test_script_hash() {
        let s1 = Script::new().push_opcode(Opcode::OP_CHECKSIG);
        let s2 = Script::new().push_opcode(Opcode::OP_CHECKSIG);
        assert_eq!(s1.script_hash(), s2.script_hash());

        let s3 = Script::new().push_opcode(Opcode::OP_RETURN);
        assert_ne!(s1.script_hash(), s3.script_hash());
    }

    #[test]
    fn test_script_into_bytes() {
        let script = Script::new()
            .push_opcode(Opcode::OP_1)
            .push_opcode(Opcode::OP_CHECKSIG);
        let bytes = script.into_bytes();
        assert_eq!(bytes, vec![0x51, 0xac]);
    }

    #[test]
    fn test_checksig_script_template() {
        let key = [0xBB; 32];
        let script = checksig_script(&key);
        // 32 (push len) + 32 (key) + 1 (OP_CHECKSIG) = 34 + 1 = depends on encoding
        assert_eq!(script.len(), 34);
    }
}
