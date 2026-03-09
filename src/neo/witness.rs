//! NEO N3 Witness serialization, NEP-11 (NFT), and GAS claim helpers.

use crate::crypto::hash160;
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════════
// Witness Serialization
// ═══════════════════════════════════════════════════════════════════

/// A NEO N3 witness consisting of invocation and verification scripts.
#[derive(Clone, Debug)]
pub struct Witness {
    /// Invocation script (signature push).
    pub invocation_script: Vec<u8>,
    /// Verification script (public key + CHECKSIG).
    pub verification_script: Vec<u8>,
}

impl Witness {
    /// Create a witness from a ECDSA signature and public key.
    ///
    /// # Arguments
    /// - `signature` — 64-byte ECDSA signature (r || s)
    /// - `public_key` — 33-byte compressed public key (SEC1)
    pub fn from_signature(signature: &[u8; 64], public_key: &[u8; 33]) -> Self {
        // Invocation script: PUSHDATA1 0x40 <signature_64_bytes>
        let mut inv = Vec::with_capacity(66);
        inv.push(0x0C); // PUSHDATA1 opcode (NeoVM)
        inv.push(64); // length
        inv.extend_from_slice(signature);

        // Verification script: PUSHDATA1 0x21 <pubkey_33_bytes> SYSCALL Neo.Crypto.CheckSig
        let mut ver = Vec::with_capacity(40);
        ver.push(0x0C); // PUSHDATA1
        ver.push(33); // length
        ver.extend_from_slice(public_key);
        // SYSCALL with hash of "Neo.Crypto.CheckSig"
        ver.push(0x41); // SYSCALL opcode
        let syscall_hash = neo_crypto_checksig_hash();
        ver.extend_from_slice(&syscall_hash);

        Self {
            invocation_script: inv,
            verification_script: ver,
        }
    }

    /// Create a multi-signature witness.
    ///
    /// # Arguments
    /// - `signatures` — List of 64-byte signatures
    /// - `public_keys` — List of 33-byte compressed public keys
    /// - `threshold` — Minimum number of signatures required (m)
    ///
    /// # Errors
    /// Returns error if threshold is 0, threshold > n, or n > 1024.
    pub fn from_multisig(
        signatures: &[[u8; 64]],
        public_keys: &[[u8; 33]],
        threshold: u8,
    ) -> Result<Self, crate::error::SignerError> {
        let n = public_keys.len();
        if threshold == 0 {
            return Err(crate::error::SignerError::ParseError(
                "multisig: threshold must be >= 1".into(),
            ));
        }
        if (threshold as usize) > n {
            return Err(crate::error::SignerError::ParseError(format!(
                "multisig: threshold {} exceeds key count {}",
                threshold, n
            )));
        }
        if n > 1024 {
            return Err(crate::error::SignerError::ParseError(format!(
                "multisig: key count {} exceeds maximum 1024",
                n
            )));
        }
        if signatures.len() < threshold as usize {
            return Err(crate::error::SignerError::ParseError(format!(
                "multisig: signature count {} below threshold {}",
                signatures.len(),
                threshold
            )));
        }
        if signatures.len() > n {
            return Err(crate::error::SignerError::ParseError(format!(
                "multisig: signature count {} exceeds key count {}",
                signatures.len(),
                n
            )));
        }

        // Invocation: push each signature
        let mut inv = Vec::new();
        for sig in signatures {
            inv.push(0x0C); // PUSHDATA1
            inv.push(64);
            inv.extend_from_slice(sig);
        }

        // Verification: PUSH_M <pk1> <pk2> ... PUSH_N SYSCALL CheckMultiSig
        let mut ver = Vec::new();

        // Push M (threshold)
        push_small_integer(&mut ver, threshold as u16);

        // Push each public key
        for pk in public_keys {
            ver.push(0x0C); // PUSHDATA1
            ver.push(33);
            ver.extend_from_slice(pk);
        }

        // Push N (total keys)
        push_small_integer(&mut ver, n as u16);

        // SYSCALL Neo.Crypto.CheckMultisig
        ver.push(0x41);
        let syscall_hash = neo_crypto_checkmultisig_hash();
        ver.extend_from_slice(&syscall_hash);

        Ok(Self {
            invocation_script: inv,
            verification_script: ver,
        })
    }

    /// Serialize the witness for inclusion in a transaction.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Invocation script length (varint) + data
        write_var_int(&mut out, self.invocation_script.len() as u64);
        out.extend_from_slice(&self.invocation_script);
        // Verification script length (varint) + data
        write_var_int(&mut out, self.verification_script.len() as u64);
        out.extend_from_slice(&self.verification_script);
        out
    }

    /// Compute the script hash (address) from the verification script.
    ///
    /// ScriptHash = RIPEMD160(SHA256(verification_script))
    pub fn script_hash(&self) -> [u8; 20] {
        hash160(&self.verification_script)
    }
}

// ═══════════════════════════════════════════════════════════════════
// NEP-11 (NFT) Helpers
// ═══════════════════════════════════════════════════════════════════

/// NEP-11 token operations.
pub mod nep11 {
    use super::super::transaction::ScriptBuilder;

    /// Build a NEP-11 transfer script for a divisible NFT.
    ///
    /// Invokes `transfer(from, to, amount, tokenId)` on the NFT contract.
    pub fn transfer(
        script_hash: &[u8; 20],
        from: &[u8; 20],
        to: &[u8; 20],
        amount: u64,
        token_id: &[u8],
    ) -> Vec<u8> {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_bytes(token_id);
        sb.emit_push_integer(amount as i64);
        sb.emit_push_hash160(to);
        sb.emit_push_hash160(from);
        sb.emit_contract_call(script_hash, "transfer", 4);
        sb.to_bytes()
    }

    /// Build a NEP-11 ownerOf query script.
    pub fn owner_of(script_hash: &[u8; 20], token_id: &[u8]) -> Vec<u8> {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_bytes(token_id);
        sb.emit_contract_call(script_hash, "ownerOf", 1);
        sb.to_bytes()
    }

    /// Build a NEP-11 properties query script.
    pub fn properties(script_hash: &[u8; 20], token_id: &[u8]) -> Vec<u8> {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_bytes(token_id);
        sb.emit_contract_call(script_hash, "properties", 1);
        sb.to_bytes()
    }

    /// Build a NEP-11 tokensOf query script.
    pub fn tokens_of(script_hash: &[u8; 20], owner: &[u8; 20]) -> Vec<u8> {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_hash160(owner);
        sb.emit_contract_call(script_hash, "tokensOf", 1);
        sb.to_bytes()
    }
}

// ═══════════════════════════════════════════════════════════════════
// GAS Claim
// ═══════════════════════════════════════════════════════════════════

/// GAS contract script hash on Neo N3 mainnet.
pub const GAS_CONTRACT_HASH: [u8; 20] = [
    0xd2, 0xa4, 0xcf, 0xe7, 0xc5, 0xa1, 0xc5, 0x42, 0x05, 0x40, 0xe2, 0x0a, 0xd8, 0x58, 0x2b, 0x48,
    0xd2, 0xfb, 0x95, 0x57,
];

/// NEO contract script hash on Neo N3 mainnet.
pub const NEO_CONTRACT_HASH: [u8; 20] = [
    0xef, 0x4f, 0x02, 0x6f, 0xcd, 0x3c, 0x3b, 0x14, 0x5c, 0x58, 0x3f, 0x61, 0x70, 0xa6, 0x9e, 0xe9,
    0x7d, 0x1c, 0x5d, 0xb3,
];

/// Build a GAS claim script.
///
/// Transfers unclaimed GAS to the specified address by calling
/// `transfer(from, to, amount)` on the GAS contract.
pub fn gas_claim_script(from: &[u8; 20], to: &[u8; 20], amount: u64) -> Vec<u8> {
    use super::transaction::ScriptBuilder;

    let mut sb = ScriptBuilder::new();
    sb.emit_push_integer(amount as i64);
    sb.emit_push_hash160(to);
    sb.emit_push_hash160(from);
    sb.emit_contract_call(&GAS_CONTRACT_HASH, "transfer", 3);
    sb.to_bytes()
}

// ─── Helpers ────────────────────────────────────────────────────────

/// Compute the 4-byte SYSCALL hash for "Neo.Crypto.CheckSig".
fn neo_crypto_checksig_hash() -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"Neo.Crypto.CheckSig");
    let result = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&result[..4]);
    out
}

/// Compute the 4-byte SYSCALL hash for "Neo.Crypto.CheckMultisig".
fn neo_crypto_checkmultisig_hash() -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(b"Neo.Crypto.CheckMultisig");
    let result = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&result[..4]);
    out
}

/// Push a small integer (0–65535) onto the NeoVM stack.
///
/// - 0 → PUSH0 (0x10 is PUSH1, so 0 uses opcode 0x0F)
/// - 1–16 → PUSH1..PUSH16 (0x11..0x20)
/// - 17–255 → PUSHINT8 (0x00) + 1-byte value
/// - 256–65535 → PUSHINT16 (0x01) + 2-byte LE value
fn push_small_integer(buf: &mut Vec<u8>, value: u16) {
    match value {
        0 => buf.push(0x0F),                    // PUSH0
        1..=16 => buf.push(0x10 + value as u8), // PUSH1..PUSH16
        17..=255 => {
            buf.push(0x00); // PUSHINT8
            buf.push(value as u8);
        }
        256.. => {
            buf.push(0x01); // PUSHINT16
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Write a variable-length integer (NEO format).
fn write_var_int(out: &mut Vec<u8>, val: u64) {
    if val < 0xFD {
        out.push(val as u8);
    } else if val <= 0xFFFF {
        out.push(0xFD);
        out.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xFFFF_FFFF {
        out.push(0xFE);
        out.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        out.push(0xFF);
        out.extend_from_slice(&val.to_le_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const PUBKEY: [u8; 33] = [0x02; 33];
    const SIG: [u8; 64] = [0xAB; 64];
    const SCRIPT_HASH: [u8; 20] = [0x01; 20];
    const FROM: [u8; 20] = [0x02; 20];
    const TO: [u8; 20] = [0x03; 20];

    // ─── Witness Tests ──────────────────────────────────────────

    #[test]
    fn test_witness_from_signature() {
        let w = Witness::from_signature(&SIG, &PUBKEY);
        // Invocation: 0x0C + 64 + sig = 66 bytes
        assert_eq!(w.invocation_script.len(), 66);
        assert_eq!(w.invocation_script[0], 0x0C);
        assert_eq!(w.invocation_script[1], 64);
        // Verification: 0x0C + 33 + pk + SYSCALL + 4 = 39 bytes
        assert_eq!(w.verification_script[0], 0x0C);
        assert_eq!(w.verification_script[1], 33);
    }

    #[test]
    fn test_witness_serialize() {
        let w = Witness::from_signature(&SIG, &PUBKEY);
        let serialized = w.serialize();
        assert!(!serialized.is_empty());
        // First byte should be length of invocation script
        assert_eq!(serialized[0], 66); // 66 bytes
    }

    #[test]
    fn test_witness_script_hash() {
        let w = Witness::from_signature(&SIG, &PUBKEY);
        let hash = w.script_hash();
        assert_ne!(hash, [0u8; 20]);
    }

    #[test]
    fn test_multisig_witness() {
        let sigs = [SIG, SIG]; // 2 signatures
        let pks = [PUBKEY, [0x03; 33]]; // 2 keys
        let w = Witness::from_multisig(&sigs, &pks, 2).unwrap();
        // Invocation should have 2 signature pushes
        // Each: 1 + 1 + 64 = 66, total = 132
        assert_eq!(w.invocation_script.len(), 132);
    }

    #[test]
    fn test_multisig_witness_supports_threshold_above_16() {
        let sigs = [[0xAB; 64]; 17];
        let mut pks = [[0u8; 33]; 17];
        for (i, pk) in pks.iter_mut().enumerate() {
            pk[0] = 0x02;
            pk[32] = i as u8;
        }

        let w = Witness::from_multisig(&sigs, &pks, 17).unwrap();

        // Threshold 17 should be explicitly encoded as PUSHINT8 (0x00) + 0x11.
        assert_eq!(w.verification_script[0], 0x00);
        assert_eq!(w.verification_script[1], 17);

        // After 17 public key pushes (17 * (PUSHDATA1 + len + 33 bytes)),
        // key count N should also be explicitly encoded as 17.
        let n_offset = 2 + 17 * 35;
        assert_eq!(w.verification_script[n_offset], 0x00);
        assert_eq!(w.verification_script[n_offset + 1], 17);
        assert_eq!(w.verification_script[n_offset + 2], 0x41); // SYSCALL
    }

    #[test]
    fn test_multisig_witness_rejects_signature_count_mismatch() {
        let sigs = [SIG]; // only 1 signature
        let pks = [PUBKEY, [0x03; 33]];
        assert!(Witness::from_multisig(&sigs, &pks, 2).is_err());
    }

    // ─── NEP-11 Tests ───────────────────────────────────────────

    #[test]
    fn test_nep11_transfer() {
        let script = nep11::transfer(&SCRIPT_HASH, &FROM, &TO, 1, b"token123");
        assert!(!script.is_empty());
    }

    #[test]
    fn test_nep11_owner_of() {
        let script = nep11::owner_of(&SCRIPT_HASH, b"token123");
        assert!(!script.is_empty());
    }

    #[test]
    fn test_nep11_properties() {
        let script = nep11::properties(&SCRIPT_HASH, b"token456");
        assert!(!script.is_empty());
    }

    #[test]
    fn test_nep11_tokens_of() {
        let script = nep11::tokens_of(&SCRIPT_HASH, &FROM);
        assert!(!script.is_empty());
    }

    // ─── GAS Claim Tests ────────────────────────────────────────

    #[test]
    fn test_gas_claim_script() {
        let script = gas_claim_script(&FROM, &TO, 10_000_000);
        assert!(!script.is_empty());
    }

    // ─── Var Int Tests ──────────────────────────────────────────

    #[test]
    fn test_var_int_small() {
        let mut buf = Vec::new();
        write_var_int(&mut buf, 100);
        assert_eq!(buf, vec![100]);
    }

    #[test]
    fn test_var_int_medium() {
        let mut buf = Vec::new();
        write_var_int(&mut buf, 0xFD);
        assert_eq!(buf[0], 0xFD);
        assert_eq!(buf.len(), 3);
    }
}
