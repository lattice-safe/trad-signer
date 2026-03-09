//! NEO N3 transaction building, NEP-17 token helpers, and contract invocation.
//!
//! Provides:
//! - **NEP-17**: Standard token transfer/balanceOf encoding
//! - **Transaction builder**: NEO N3 transaction construction
//! - **Script builder**: NeoVM opcode encoding for contract calls

use crate::error::SignerError;

// ═══════════════════════════════════════════════════════════════════
// NeoVM Script Builder
// ═══════════════════════════════════════════════════════════════════

/// NeoVM opcode constants.
pub mod opcode {
    /// Push zero onto the stack.
    pub const PUSH0: u8 = 0x00;
    /// Push data with 1-byte length prefix.
    pub const PUSHDATA1: u8 = 0x0C;
    /// Push integer 1.
    pub const PUSH1: u8 = 0x11;
    /// Push integer 2.
    pub const PUSH2: u8 = 0x12;
    /// Push integer 3.
    pub const PUSH3: u8 = 0x13;
    /// Push integer 4.
    pub const PUSH4: u8 = 0x14;
    /// Push integer 5.
    pub const PUSH5: u8 = 0x15;
    /// Push integer 8.
    pub const PUSH8: u8 = 0x18;
    /// Push integer 16.
    pub const PUSH16: u8 = 0x20;
    /// No operation.
    pub const NOP: u8 = 0x21;
    /// Create a new array.
    pub const NEWARRAY: u8 = 0xC5;
    /// Pack stack items into an array.
    pub const PACK: u8 = 0xC1;
    /// System call opcode.
    pub const SYSCALL: u8 = 0x41;
}

/// Build a NeoVM invocation script.
#[derive(Debug, Clone, Default)]
pub struct ScriptBuilder {
    data: Vec<u8>,
}

impl ScriptBuilder {
    /// Create a new empty script builder.
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Push a raw byte (opcode).
    pub fn emit(&mut self, op: u8) -> &mut Self {
        self.data.push(op);
        self
    }

    /// Push an integer onto the stack.
    pub fn emit_push_integer(&mut self, value: i64) -> &mut Self {
        if value == -1 {
            self.data.push(0x0F); // PUSHM1
        } else if value == 0 {
            self.data.push(opcode::PUSH0);
        } else if (1..=16).contains(&value) {
            self.data.push(opcode::PUSH1 + (value as u8 - 1));
        } else {
            // Encode as variable-length integer
            let bytes = int_to_bytes(value);
            self.emit_push_bytes(&bytes);
        }
        self
    }

    /// Push bytes onto the stack.
    pub fn emit_push_bytes(&mut self, data: &[u8]) -> &mut Self {
        let len = data.len();
        if len <= 0xFF {
            self.data.push(opcode::PUSHDATA1);
            self.data.push(len as u8);
        } else if len <= 0xFFFF {
            self.data.push(0x0D); // PUSHDATA2
            self.data.extend_from_slice(&(len as u16).to_le_bytes());
        } else {
            self.data.push(0x0E); // PUSHDATA4
            self.data.extend_from_slice(&(len as u32).to_le_bytes());
        }
        self.data.extend_from_slice(data);
        self
    }

    /// Push a 20-byte script hash.
    pub fn emit_push_hash160(&mut self, hash: &[u8; 20]) -> &mut Self {
        self.emit_push_bytes(hash)
    }

    /// Emit a syscall by its 4-byte hash.
    pub fn emit_syscall(&mut self, method_hash: u32) -> &mut Self {
        self.data.push(opcode::SYSCALL);
        self.data.extend_from_slice(&method_hash.to_le_bytes());
        self
    }

    /// Emit a contract call: `System.Contract.Call`.
    ///
    /// Hash of `System.Contract.Call` = `0x627d5b52`
    pub fn emit_contract_call(
        &mut self,
        contract_hash: &[u8; 20],
        method: &str,
        args_count: usize,
    ) -> &mut Self {
        // Push args count onto stack for PACK
        self.emit_push_integer(args_count as i64);
        self.emit(opcode::PACK);
        // Push method name
        self.emit_push_bytes(method.as_bytes());
        // Push contract hash (little-endian)
        self.emit_push_hash160(contract_hash);
        // Syscall System.Contract.Call
        self.emit_syscall(0x627d5b52);
        self
    }

    /// Get the built script bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

fn int_to_bytes(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut val = value;
    let mut bytes = Vec::new();
    let negative = val < 0;
    while val != 0 && val != -1 {
        bytes.push(val as u8);
        val >>= 8;
    }
    // Sign bit handling
    if !negative && (bytes.last().is_some_and(|b| b & 0x80 != 0)) {
        bytes.push(0);
    }
    if negative && (bytes.last().is_some_and(|b| b & 0x80 == 0)) {
        bytes.push(0xFF);
    }
    bytes
}

// ═══════════════════════════════════════════════════════════════════
// NEP-17 Token Helpers
// ═══════════════════════════════════════════════════════════════════

/// Well-known NEO N3 contract hashes (little-endian).
pub mod contracts {
    /// NEO native token script hash.
    pub const NEO_TOKEN: [u8; 20] = [
        0xf5, 0x63, 0xea, 0x40, 0xbc, 0x28, 0x3d, 0x4d, 0x0e, 0x05, 0xc4, 0x8e, 0xa3, 0x05, 0xb3,
        0xf2, 0xa0, 0x73, 0x40, 0xef,
    ];

    /// GAS native token script hash.
    pub const GAS_TOKEN: [u8; 20] = [
        0xcf, 0x76, 0xe2, 0x8b, 0xd0, 0x06, 0x2c, 0x4a, 0x47, 0x8e, 0xe3, 0x55, 0x61, 0x01, 0x13,
        0x19, 0xf3, 0xcf, 0xa4, 0xd2,
    ];
}

/// Build a NEP-17 `transfer` invocation script.
///
/// # Arguments
/// - `token_hash` — Contract script hash (20 bytes, little-endian)
/// - `from` — Sender script hash
/// - `to` — Recipient script hash
/// - `amount` — Transfer amount (in token's smallest unit)
pub fn nep17_transfer(
    token_hash: &[u8; 20],
    from: &[u8; 20],
    to: &[u8; 20],
    amount: i64,
) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    // Push arguments in reverse order for NeoVM
    sb.emit(opcode::PUSH0); // data (null for simple transfer)
    sb.emit_push_integer(amount);
    sb.emit_push_hash160(to);
    sb.emit_push_hash160(from);
    sb.emit_contract_call(token_hash, "transfer", 4);
    sb.to_bytes()
}

/// Build a NEP-17 `balanceOf` invocation script.
pub fn nep17_balance_of(token_hash: &[u8; 20], account: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_hash160(account);
    sb.emit_contract_call(token_hash, "balanceOf", 1);
    sb.to_bytes()
}

/// Build a NEP-17 `symbol` invocation script.
pub fn nep17_symbol(token_hash: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(token_hash, "symbol", 0);
    sb.to_bytes()
}

/// Build a NEP-17 `decimals` invocation script.
pub fn nep17_decimals(token_hash: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(token_hash, "decimals", 0);
    sb.to_bytes()
}

/// Build a NEP-17 `totalSupply` invocation script.
pub fn nep17_total_supply(token_hash: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(token_hash, "totalSupply", 0);
    sb.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// Transaction Builder
// ═══════════════════════════════════════════════════════════════════

/// NEO N3 transaction.
#[derive(Debug, Clone)]
pub struct NeoTransaction {
    /// Transaction version (currently 0).
    pub version: u8,
    /// Nonce for uniqueness.
    pub nonce: u32,
    /// System fee in fractions of GAS.
    pub system_fee: i64,
    /// Network fee in fractions of GAS.
    pub network_fee: i64,
    /// Valid until this block height.
    pub valid_until_block: u32,
    /// Transaction signers.
    pub signers: Vec<TransactionSigner>,
    /// Transaction attributes.
    pub attributes: Vec<TransactionAttribute>,
    /// The invocation script.
    pub script: Vec<u8>,
}

/// A transaction signer.
#[derive(Debug, Clone)]
pub struct TransactionSigner {
    /// Account script hash.
    pub account: [u8; 20],
    /// Witness scope.
    pub scope: WitnessScope,
    /// Allowed contracts (for CustomContracts scope).
    pub allowed_contracts: Vec<[u8; 20]>,
}

/// Witness scope for transaction signers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WitnessScope {
    /// No restrictions.
    None = 0x00,
    /// Only the entry contract.
    CalledByEntry = 0x01,
    /// Custom contracts list.
    CustomContracts = 0x10,
    /// Global scope.
    Global = 0x80,
}

/// Transaction attribute (extensible).
#[derive(Debug, Clone)]
pub struct TransactionAttribute {
    /// Attribute type.
    pub attr_type: u8,
    /// Attribute data.
    pub data: Vec<u8>,
}

impl NeoTransaction {
    /// Create a new transaction with default values.
    #[must_use]
    pub fn new(script: Vec<u8>) -> Self {
        Self {
            version: 0,
            nonce: 0,
            system_fee: 0,
            network_fee: 0,
            valid_until_block: 0,
            signers: vec![],
            attributes: vec![],
            script,
        }
    }

    /// Serialize the transaction for signing (without witnesses).
    #[must_use]
    pub fn serialize_unsigned(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.version);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.system_fee.to_le_bytes());
        buf.extend_from_slice(&self.network_fee.to_le_bytes());
        buf.extend_from_slice(&self.valid_until_block.to_le_bytes());

        // Signers
        write_var_int(&mut buf, self.signers.len() as u64);
        for signer in &self.signers {
            buf.extend_from_slice(&signer.account);
            buf.push(signer.scope as u8);
            if signer.scope == WitnessScope::CustomContracts {
                write_var_int(&mut buf, signer.allowed_contracts.len() as u64);
                for c in &signer.allowed_contracts {
                    buf.extend_from_slice(c);
                }
            }
        }

        // Attributes
        write_var_int(&mut buf, self.attributes.len() as u64);
        for attr in &self.attributes {
            buf.push(attr.attr_type);
            write_var_int(&mut buf, attr.data.len() as u64);
            buf.extend_from_slice(&attr.data);
        }

        // Script
        write_var_int(&mut buf, self.script.len() as u64);
        buf.extend_from_slice(&self.script);

        buf
    }

    /// Compute the transaction hash (SHA-256 of serialized unsigned tx).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let data = self.serialize_unsigned();
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(data));
        out
    }

    /// Sign the transaction with a NEO signer.
    pub fn sign(&self, signer: &super::NeoSigner) -> Result<super::NeoSignature, SignerError> {
        let hash = self.hash();
        signer.sign_digest(&hash)
    }
}

fn write_var_int(buf: &mut Vec<u8>, val: u64) {
    if val < 0xFD {
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transaction Deserialization
// ═══════════════════════════════════════════════════════════════════

/// Read a variable-length integer from a byte slice.
///
/// Returns `(value, bytes_consumed)`.
pub fn read_var_int(data: &[u8]) -> Result<(u64, usize), SignerError> {
    if data.is_empty() {
        return Err(SignerError::ParseError("read_var_int: empty".into()));
    }
    match data[0] {
        0..=0xFC => Ok((u64::from(data[0]), 1)),
        0xFD => {
            if data.len() < 3 {
                return Err(SignerError::ParseError(
                    "read_var_int: truncated u16".into(),
                ));
            }
            Ok((u64::from(u16::from_le_bytes([data[1], data[2]])), 3))
        }
        0xFE => {
            if data.len() < 5 {
                return Err(SignerError::ParseError(
                    "read_var_int: truncated u32".into(),
                ));
            }
            Ok((
                u64::from(u32::from_le_bytes([data[1], data[2], data[3], data[4]])),
                5,
            ))
        }
        0xFF => {
            if data.len() < 9 {
                return Err(SignerError::ParseError(
                    "read_var_int: truncated u64".into(),
                ));
            }
            let val = u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]);
            Ok((val, 9))
        }
    }
}

impl NeoTransaction {
    /// Deserialize a NEO N3 transaction from its unsigned byte representation.
    ///
    /// Parses version, nonce, fees, signers, attributes, and script.
    pub fn deserialize(data: &[u8]) -> Result<Self, SignerError> {
        if data.len() < 25 {
            return Err(SignerError::ParseError("neo tx: too short".into()));
        }
        let mut pos = 0;

        let version = data[pos];
        pos += 1;

        let nonce = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| SignerError::ParseError("neo tx: nonce".into()))?,
        );
        pos += 4;

        let system_fee = i64::from_le_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| SignerError::ParseError("neo tx: system_fee".into()))?,
        );
        pos += 8;

        let network_fee = i64::from_le_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| SignerError::ParseError("neo tx: network_fee".into()))?,
        );
        pos += 8;

        let valid_until_block = u32::from_le_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| SignerError::ParseError("neo tx: valid_until".into()))?,
        );
        pos += 4;

        // Signers
        let (num_signers, consumed) = read_var_int(&data[pos..])?;
        pos += consumed;
        let mut signers = Vec::new();
        for _ in 0..num_signers {
            if pos + 21 > data.len() {
                return Err(SignerError::ParseError("neo tx: truncated signer".into()));
            }
            let mut account = [0u8; 20];
            account.copy_from_slice(&data[pos..pos + 20]);
            pos += 20;
            let scope_byte = data[pos];
            pos += 1;
            let scope = match scope_byte {
                0x00 => WitnessScope::None,
                0x01 => WitnessScope::CalledByEntry,
                0x10 => WitnessScope::CustomContracts,
                0x80 => WitnessScope::Global,
                _ => {
                    return Err(SignerError::ParseError(format!(
                        "neo tx: unknown witness scope 0x{scope_byte:02x}"
                    )))
                }
            };
            let mut allowed_contracts = Vec::new();
            if scope == WitnessScope::CustomContracts {
                let (num_contracts, c) = read_var_int(&data[pos..])?;
                pos += c;
                for _ in 0..num_contracts {
                    if pos + 20 > data.len() {
                        return Err(SignerError::ParseError(
                            "neo tx: truncated allowed contract".into(),
                        ));
                    }
                    let mut contract = [0u8; 20];
                    contract.copy_from_slice(&data[pos..pos + 20]);
                    pos += 20;
                    allowed_contracts.push(contract);
                }
            }
            signers.push(TransactionSigner {
                account,
                scope,
                allowed_contracts,
            });
        }

        // Attributes
        let (num_attrs, consumed) = read_var_int(&data[pos..])?;
        pos += consumed;
        let mut attributes = Vec::new();
        for _ in 0..num_attrs {
            if pos >= data.len() {
                return Err(SignerError::ParseError("neo tx: truncated attr".into()));
            }
            let attr_type = data[pos];
            pos += 1;
            let (attr_len, c) = read_var_int(&data[pos..])?;
            pos += c;
            let attr_len_usize = usize::try_from(attr_len).map_err(|_| {
                SignerError::ParseError("neo tx: attr length exceeds usize".into())
            })?;
            let attr_end = pos.checked_add(attr_len_usize).ok_or_else(|| {
                SignerError::ParseError("neo tx: attr length overflow".into())
            })?;
            if attr_end > data.len() {
                return Err(SignerError::ParseError(
                    "neo tx: truncated attr data".into(),
                ));
            }
            let attr_data = data[pos..attr_end].to_vec();
            pos = attr_end;
            attributes.push(TransactionAttribute {
                attr_type,
                data: attr_data,
            });
        }

        // Script
        let (script_len, consumed) = read_var_int(&data[pos..])?;
        pos += consumed;
        let script_len_usize = usize::try_from(script_len).map_err(|_| {
            SignerError::ParseError("neo tx: script length exceeds usize".into())
        })?;
        let script_end = pos.checked_add(script_len_usize).ok_or_else(|| {
            SignerError::ParseError("neo tx: script length overflow".into())
        })?;
        if script_end > data.len() {
            return Err(SignerError::ParseError("neo tx: truncated script".into()));
        }
        let script = data[pos..script_end].to_vec();
        pos = script_end;

        // Reject trailing bytes
        if pos != data.len() {
            return Err(SignerError::ParseError(format!(
                "neo tx: {} trailing bytes",
                data.len() - pos
            )));
        }

        Ok(Self {
            version,
            nonce,
            system_fee,
            network_fee,
            valid_until_block,
            signers,
            attributes,
            script,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// NEP-17 Extended Operations
// ═══════════════════════════════════════════════════════════════════

/// Build a NEP-17 `approve` invocation script.
///
/// Allows `spender` to transfer up to `amount` tokens on behalf of `owner`.
/// Note: Not all NEP-17 tokens support approve — only extended implementations.
pub fn nep17_approve(
    token_hash: &[u8; 20],
    owner: &[u8; 20],
    spender: &[u8; 20],
    amount: i64,
) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_integer(amount)
        .emit_push_hash160(spender)
        .emit_push_hash160(owner)
        .emit_contract_call(token_hash, "approve", 3);
    sb.to_bytes()
}

/// Build a NEP-17 `allowance` query script.
///
/// Returns the remaining amount that `spender` is allowed to transfer from `owner`.
pub fn nep17_allowance(token_hash: &[u8; 20], owner: &[u8; 20], spender: &[u8; 20]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_hash160(spender)
        .emit_push_hash160(owner)
        .emit_contract_call(token_hash, "allowance", 2);
    sb.to_bytes()
}

/// Build a NEP-17 `transferFrom` invocation script.
///
/// Transfers `amount` from `from` to `to` using an approved allowance.
pub fn nep17_transfer_from(
    token_hash: &[u8; 20],
    spender: &[u8; 20],
    from: &[u8; 20],
    to: &[u8; 20],
    amount: i64,
) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_integer(amount)
        .emit_push_hash160(to)
        .emit_push_hash160(from)
        .emit_push_hash160(spender)
        .emit_contract_call(token_hash, "transferFrom", 4);
    sb.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// Contract Deployment
// ═══════════════════════════════════════════════════════════════════

/// ContractManagement native contract hash.
pub const CONTRACT_MANAGEMENT_HASH: [u8; 20] = [
    0xfd, 0xa3, 0xfa, 0x43, 0x34, 0x6b, 0x9d, 0x6b, 0x51, 0xd3, 0x3c, 0x64, 0xb2, 0x1c, 0x68, 0x24,
    0x38, 0x97, 0x28, 0xe6,
];

/// Build a contract deployment invocation script.
///
/// # Arguments
/// - `nef_bytes` — Compiled NEF (NEO Executable Format) bytes
/// - `manifest_json` — Contract manifest JSON string
pub fn contract_deploy(nef_bytes: &[u8], manifest_json: &str) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_bytes(manifest_json.as_bytes())
        .emit_push_bytes(nef_bytes)
        .emit_contract_call(&CONTRACT_MANAGEMENT_HASH, "deploy", 2);
    sb.to_bytes()
}

/// Build a contract update invocation script.
pub fn contract_update(nef_bytes: &[u8], manifest_json: &str) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_bytes(manifest_json.as_bytes())
        .emit_push_bytes(nef_bytes)
        .emit_contract_call(&CONTRACT_MANAGEMENT_HASH, "update", 2);
    sb.to_bytes()
}

/// Build a contract destroy invocation script.
pub fn contract_destroy() -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(&CONTRACT_MANAGEMENT_HASH, "destroy", 0);
    sb.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// Governance / Voting
// ═══════════════════════════════════════════════════════════════════

/// Build a governance `vote` script.
///
/// Votes for a consensus node with the given public key.
///
/// # Arguments
/// - `voter` — Script hash of the voter
/// - `candidate_pubkey` — 33-byte compressed public key of the candidate (or empty to cancel vote)
pub fn neo_vote(voter: &[u8; 20], candidate_pubkey: Option<&[u8; 33]>) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    match candidate_pubkey {
        Some(pk) => sb.emit_push_bytes(pk),
        None => sb.emit(opcode::PUSH0), // null = cancel vote
    };
    sb.emit_push_hash160(voter)
        .emit_contract_call(&contracts::NEO_TOKEN, "vote", 2);
    sb.to_bytes()
}

/// Build a script to query unclaimed GAS for an account.
pub fn neo_unclaimed_gas(account: &[u8; 20], end_height: u32) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_integer(i64::from(end_height))
        .emit_push_hash160(account)
        .emit_contract_call(&contracts::NEO_TOKEN, "unclaimedGas", 2);
    sb.to_bytes()
}

/// Build a script to register as a consensus candidate.
pub fn neo_register_candidate(pubkey: &[u8; 33]) -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_push_bytes(pubkey)
        .emit_contract_call(&contracts::NEO_TOKEN, "registerCandidate", 1);
    sb.to_bytes()
}

/// Build a script to query the list of registered candidates.
pub fn neo_get_candidates() -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(&contracts::NEO_TOKEN, "getCandidates", 0);
    sb.to_bytes()
}

/// Build a script to get the current committee members.
pub fn neo_get_committee() -> Vec<u8> {
    let mut sb = ScriptBuilder::new();
    sb.emit_contract_call(&contracts::NEO_TOKEN, "getCommittee", 0);
    sb.to_bytes()
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    // ─── Script Builder Tests ──────────────────────────────────────

    #[test]
    fn test_script_builder_push_integer() {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_integer(0);
        assert_eq!(sb.to_bytes(), vec![opcode::PUSH0]);
    }

    #[test]
    fn test_script_builder_push_integer_range() {
        for i in 1..=16 {
            let mut sb = ScriptBuilder::new();
            sb.emit_push_integer(i);
            let bytes = sb.to_bytes();
            assert_eq!(bytes.len(), 1);
            assert_eq!(bytes[0], opcode::PUSH1 + (i as u8 - 1));
        }
    }

    #[test]
    fn test_script_builder_push_bytes() {
        let mut sb = ScriptBuilder::new();
        sb.emit_push_bytes(b"hello");
        let bytes = sb.to_bytes();
        assert_eq!(bytes[0], opcode::PUSHDATA1);
        assert_eq!(bytes[1], 5);
        assert_eq!(&bytes[2..], b"hello");
    }

    #[test]
    fn test_script_builder_syscall() {
        let mut sb = ScriptBuilder::new();
        sb.emit_syscall(0x627d5b52);
        let bytes = sb.to_bytes();
        assert_eq!(bytes[0], opcode::SYSCALL);
        assert_eq!(&bytes[1..5], &0x627d5b52u32.to_le_bytes());
    }

    // ─── NEP-17 Tests ──────────────────────────────────────────────

    #[test]
    fn test_nep17_transfer_script() {
        let from = [0xAA; 20];
        let to = [0xBB; 20];
        let script = nep17_transfer(&contracts::NEO_TOKEN, &from, &to, 10);
        assert!(!script.is_empty());
        // Should contain "transfer" method name
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("transfer"));
    }

    #[test]
    fn test_nep17_balance_of_script() {
        let account = [0xCC; 20];
        let script = nep17_balance_of(&contracts::GAS_TOKEN, &account);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("balanceOf"));
    }

    #[test]
    fn test_nep17_symbol() {
        let script = nep17_symbol(&contracts::NEO_TOKEN);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("symbol"));
    }

    #[test]
    fn test_nep17_decimals() {
        let script = nep17_decimals(&contracts::GAS_TOKEN);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("decimals"));
    }

    #[test]
    fn test_nep17_total_supply() {
        let script = nep17_total_supply(&contracts::NEO_TOKEN);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("totalSupply"));
    }

    // ─── Transaction Tests ─────────────────────────────────────────

    #[test]
    fn test_neo_transaction_serialization() {
        let script = nep17_transfer(&contracts::NEO_TOKEN, &[0xAA; 20], &[0xBB; 20], 1);
        let tx = NeoTransaction {
            version: 0,
            nonce: 12345,
            system_fee: 100_000,
            network_fee: 50_000,
            valid_until_block: 1000,
            signers: vec![TransactionSigner {
                account: [0xAA; 20],
                scope: WitnessScope::CalledByEntry,
                allowed_contracts: vec![],
            }],
            attributes: vec![],
            script,
        };
        let serialized = tx.serialize_unsigned();
        assert!(!serialized.is_empty());
        assert_eq!(serialized[0], 0); // version 0
    }

    #[test]
    fn test_neo_transaction_hash_deterministic() {
        let script = nep17_transfer(&contracts::GAS_TOKEN, &[0xAA; 20], &[0xBB; 20], 100);
        let tx = NeoTransaction::new(script);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn test_neo_transaction_sign() {
        let signer = super::super::NeoSigner::generate().unwrap();
        let script_hash = signer.script_hash();
        let script = nep17_transfer(&contracts::NEO_TOKEN, &script_hash, &[0xBB; 20], 1);
        let tx = NeoTransaction::new(script);
        let sig = tx.sign(&signer).unwrap();
        assert_eq!(sig.to_bytes().len(), 64);
    }

    #[test]
    fn test_neo_transaction_different_nonce_different_hash() {
        let script = vec![0x00];
        let mut tx1 = NeoTransaction::new(script.clone());
        tx1.nonce = 1;
        let mut tx2 = NeoTransaction::new(script);
        tx2.nonce = 2;
        assert_ne!(tx1.hash(), tx2.hash());
    }

    // ─── Deserialization Tests ─────────────────────────────────────

    #[test]
    fn test_neo_tx_serialize_deserialize_roundtrip() {
        let script = nep17_transfer(&contracts::NEO_TOKEN, &[0xAA; 20], &[0xBB; 20], 10);
        let tx = NeoTransaction {
            version: 0,
            nonce: 42,
            system_fee: 100_000,
            network_fee: 50_000,
            valid_until_block: 999,
            signers: vec![TransactionSigner {
                account: [0xAA; 20],
                scope: WitnessScope::CalledByEntry,
                allowed_contracts: vec![],
            }],
            attributes: vec![],
            script,
        };
        let bytes = tx.serialize_unsigned();
        let restored = NeoTransaction::deserialize(&bytes).unwrap();
        assert_eq!(restored.version, tx.version);
        assert_eq!(restored.nonce, tx.nonce);
        assert_eq!(restored.system_fee, tx.system_fee);
        assert_eq!(restored.network_fee, tx.network_fee);
        assert_eq!(restored.valid_until_block, tx.valid_until_block);
        assert_eq!(restored.signers.len(), 1);
        assert_eq!(restored.signers[0].account, [0xAA; 20]);
        assert_eq!(restored.script, tx.script);
    }

    #[test]
    fn test_neo_tx_deserialize_empty_fails() {
        assert!(NeoTransaction::deserialize(&[]).is_err());
        assert!(NeoTransaction::deserialize(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_read_var_int() {
        assert_eq!(read_var_int(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_var_int(&[0xFC]).unwrap(), (252, 1));
        assert_eq!(read_var_int(&[0xFD, 0x01, 0x00]).unwrap(), (1, 3));
        assert_eq!(
            read_var_int(&[0xFE, 0x01, 0x00, 0x00, 0x00]).unwrap(),
            (1, 5)
        );
    }

    // ─── NEP-17 Extended Tests ────────────────────────────────────

    #[test]
    fn test_nep17_approve_script() {
        let script = nep17_approve(&contracts::GAS_TOKEN, &[0xAA; 20], &[0xBB; 20], 1000);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("approve"));
    }

    #[test]
    fn test_nep17_allowance_script() {
        let script = nep17_allowance(&contracts::GAS_TOKEN, &[0xAA; 20], &[0xBB; 20]);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("allowance"));
    }

    #[test]
    fn test_nep17_transfer_from_script() {
        let script = nep17_transfer_from(
            &contracts::GAS_TOKEN,
            &[0xAA; 20],
            &[0xBB; 20],
            &[0xCC; 20],
            500,
        );
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("transferFrom"));
    }

    // ─── Contract Deployment Tests ────────────────────────────────

    #[test]
    fn test_contract_deploy_script() {
        let nef = b"\x4e\x45\x46\x33"; // NEF magic
        let manifest = r#"{"name":"test"}"#;
        let script = contract_deploy(nef, manifest);
        assert!(!script.is_empty());
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("deploy"));
    }

    #[test]
    fn test_contract_update_script() {
        let script = contract_update(b"\x00", r#"{}"#);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("update"));
    }

    #[test]
    fn test_contract_destroy_script() {
        let script = contract_destroy();
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("destroy"));
    }

    // ─── Governance Tests ─────────────────────────────────────────

    #[test]
    fn test_neo_vote_script() {
        let voter = [0xAA; 20];
        let pubkey = [0x02; 33];
        let script = neo_vote(&voter, Some(&pubkey));
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("vote"));
    }

    #[test]
    fn test_neo_vote_cancel() {
        let voter = [0xAA; 20];
        let script = neo_vote(&voter, None);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("vote"));
    }

    #[test]
    fn test_neo_unclaimed_gas() {
        let script = neo_unclaimed_gas(&[0xAA; 20], 100_000);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("unclaimedGas"));
    }

    #[test]
    fn test_neo_register_candidate() {
        let script = neo_register_candidate(&[0x02; 33]);
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("registerCandidate"));
    }

    #[test]
    fn test_neo_get_candidates() {
        let script = neo_get_candidates();
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("getCandidates"));
    }

    #[test]
    fn test_neo_get_committee() {
        let script = neo_get_committee();
        let s = String::from_utf8_lossy(&script);
        assert!(s.contains("getCommittee"));
    }
}
