//! **Ethereum ABI** encoding, decoding, and contract interaction helpers.
//!
//! Implements the Solidity ABI spec for encoding function calls, decoding return values,
//! computing function selectors, and building contract deployment transactions.
//!
//! # Supported Types
//! - `uint8` through `uint256` (by 8-bit increments)
//! - `int8` through `int256`
//! - `address` (20 bytes, left-padded to 32)
//! - `bool`
//! - `bytes` (dynamic)
//! - `bytes1` through `bytes32` (fixed)
//! - `string` (dynamic, UTF-8)
//! - `T[]` (dynamic array) — via `AbiValue::Array`
//! - `(T1, T2, ...)` (tuple) — via `AbiValue::Tuple`
//!
//! # Example
//! ```no_run
//! use trad_signer::ethereum::abi::{Function, AbiValue};
//!
//! let func = Function::new("transfer(address,uint256)");
//! let calldata = func.encode(&[
//!     AbiValue::Address([0xAA; 20]),
//!     AbiValue::Uint256([0; 32]),  // amount as 32-byte big-endian
//! ]);
//! ```

use crate::error::SignerError;
use sha3::{Digest, Keccak256};

// ─── ABI Values ────────────────────────────────────────────────────

/// An ABI-encoded value.
#[derive(Debug, Clone, PartialEq)]
pub enum AbiValue {
    /// `uint<N>` — stored as 32-byte big-endian, zero-padded on the left.
    Uint256([u8; 32]),
    /// `int<N>` — stored as 32-byte big-endian, sign-extended.
    Int256([u8; 32]),
    /// `address` — 20 bytes.
    Address([u8; 20]),
    /// `bool` — true or false.
    Bool(bool),
    /// `bytes<N>` (1–32) — fixed-size, right-padded.
    FixedBytes(Vec<u8>),
    /// `bytes` — dynamic byte array.
    Bytes(Vec<u8>),
    /// `string` — dynamic UTF-8 string.
    String(String),
    /// `T[]` — dynamic array of values.
    Array(Vec<AbiValue>),
    /// `(T1, T2, ...)` — tuple of values.
    Tuple(Vec<AbiValue>),
}

impl AbiValue {
    /// Create a `uint256` from a `u64`.
    #[must_use]
    pub fn from_u64(val: u64) -> Self {
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&val.to_be_bytes());
        AbiValue::Uint256(buf)
    }

    /// Create a `uint256` from a `u128`.
    #[must_use]
    pub fn from_u128(val: u128) -> Self {
        let mut buf = [0u8; 32];
        buf[16..].copy_from_slice(&val.to_be_bytes());
        AbiValue::Uint256(buf)
    }

    /// Whether this type is dynamic in the ABI encoding sense.
    fn is_dynamic(&self) -> bool {
        matches!(self, AbiValue::Bytes(_) | AbiValue::String(_) | AbiValue::Array(_))
            || matches!(self, AbiValue::Tuple(items) if items.iter().any(|i| i.is_dynamic()))
    }

    /// Encode this value into the head (fixed) part.
    fn encode_head(&self) -> Vec<u8> {
        match self {
            AbiValue::Uint256(val) => val.to_vec(),
            AbiValue::Int256(val) => val.to_vec(),
            AbiValue::Address(addr) => {
                let mut buf = [0u8; 32];
                buf[12..].copy_from_slice(addr);
                buf.to_vec()
            }
            AbiValue::Bool(b) => {
                let mut buf = [0u8; 32];
                buf[31] = if *b { 1 } else { 0 };
                buf.to_vec()
            }
            AbiValue::FixedBytes(data) => {
                let mut buf = [0u8; 32];
                let len = data.len().min(32);
                buf[..len].copy_from_slice(&data[..len]);
                buf.to_vec()
            }
            // Dynamic types: head is a placeholder offset (filled by caller)
            _ => vec![0u8; 32],
        }
    }

    /// Encode this value into the tail (dynamic) part.
    fn encode_tail(&self) -> Vec<u8> {
        match self {
            AbiValue::Bytes(data) => encode_dynamic_bytes(data),
            AbiValue::String(s) => encode_dynamic_bytes(s.as_bytes()),
            AbiValue::Array(items) => {
                let mut buf = Vec::new();
                // Length prefix
                let mut len = [0u8; 32];
                len[24..].copy_from_slice(&(items.len() as u64).to_be_bytes());
                buf.extend_from_slice(&len);
                // Encode items as a tuple
                buf.extend_from_slice(&encode_tuple(items));
                buf
            }
            AbiValue::Tuple(items) => encode_tuple(items),
            _ => vec![], // static types have no tail
        }
    }
}

// ─── Core Encoding ─────────────────────────────────────────────────

/// ABI-encode a list of values (as a tuple).
///
/// This is equivalent to Solidity's `abi.encode(v1, v2, ...)`.
pub fn encode(values: &[AbiValue]) -> Vec<u8> {
    encode_tuple(values)
}

/// ABI-encode values with packed encoding (no padding).
///
/// This is equivalent to Solidity's `abi.encodePacked(v1, v2, ...)`.
/// Warning: packed encoding is **not** decodable and should only be used for hashing.
pub fn encode_packed(values: &[AbiValue]) -> Vec<u8> {
    let mut buf = Vec::new();
    for v in values {
        match v {
            AbiValue::Uint256(val) => {
                // Strip leading zeros for packed
                let start = val.iter().position(|b| *b != 0).unwrap_or(31);
                buf.extend_from_slice(&val[start..]);
            }
            AbiValue::Int256(val) => buf.extend_from_slice(val),
            AbiValue::Address(addr) => buf.extend_from_slice(addr),
            AbiValue::Bool(b) => buf.push(if *b { 1 } else { 0 }),
            AbiValue::FixedBytes(data) => buf.extend_from_slice(data),
            AbiValue::Bytes(data) => buf.extend_from_slice(data),
            AbiValue::String(s) => buf.extend_from_slice(s.as_bytes()),
            AbiValue::Array(items) => {
                for item in items {
                    buf.extend_from_slice(&encode_packed(&[item.clone()]));
                }
            }
            AbiValue::Tuple(items) => {
                buf.extend_from_slice(&encode_packed(items));
            }
        }
    }
    buf
}

/// Compute the keccak256 of the ABI-encoded values.
pub fn encode_and_hash(values: &[AbiValue]) -> [u8; 32] {
    keccak256(&encode(values))
}

/// Compute the keccak256 of the packed ABI-encoded values.
///
/// Commonly used for `keccak256(abi.encodePacked(...))` in Solidity.
pub fn encode_packed_and_hash(values: &[AbiValue]) -> [u8; 32] {
    keccak256(&encode_packed(values))
}

// ─── Function Call ─────────────────────────────────────────────────

/// An Ethereum contract function for ABI-encoding calls and decoding results.
///
/// # Example
/// ```no_run
/// use trad_signer::ethereum::abi::{Function, AbiValue};
///
/// let transfer = Function::new("transfer(address,uint256)");
/// assert_eq!(hex::encode(transfer.selector()), "a9059cbb");
///
/// let calldata = transfer.encode(&[
///     AbiValue::Address([0xBB; 20]),
///     AbiValue::from_u128(1_000_000_000_000_000_000), // 1 token (18 decimals)
/// ]);
/// ```
pub struct Function {
    /// The full function signature (e.g., `"transfer(address,uint256)"`).
    signature: String,
    /// The 4-byte function selector.
    selector_bytes: [u8; 4],
}

impl Function {
    /// Create a new function from its Solidity signature.
    ///
    /// The signature must follow the canonical format: `name(type1,type2,...)`
    #[must_use]
    pub fn new(signature: &str) -> Self {
        let hash = keccak256(signature.as_bytes());
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&hash[..4]);
        Self {
            signature: signature.to_string(),
            selector_bytes: selector,
        }
    }

    /// Return the 4-byte function selector.
    #[must_use]
    pub fn selector(&self) -> [u8; 4] {
        self.selector_bytes
    }

    /// Return the function signature string.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Encode a function call with the given arguments.
    ///
    /// Returns `selector || abi.encode(args...)`.
    #[must_use]
    pub fn encode(&self, args: &[AbiValue]) -> Vec<u8> {
        let mut calldata = Vec::with_capacity(4 + args.len() * 32);
        calldata.extend_from_slice(&self.selector_bytes);
        calldata.extend_from_slice(&encode(args));
        calldata
    }
}

/// Compute the 4-byte function selector from a Solidity signature.
///
/// `keccak256("transfer(address,uint256)")[..4]`
#[must_use]
pub fn function_selector(signature: &str) -> [u8; 4] {
    Function::new(signature).selector()
}

/// Compute the 32-byte event topic from a Solidity event signature.
///
/// `keccak256("Transfer(address,address,uint256)")`
#[must_use]
pub fn event_topic(signature: &str) -> [u8; 32] {
    keccak256(signature.as_bytes())
}

// ─── ABI Decoding ──────────────────────────────────────────────────

/// Decode a single `uint256` from 32 bytes.
pub fn decode_uint256(data: &[u8]) -> Result<[u8; 32], SignerError> {
    if data.len() < 32 {
        return Err(SignerError::ParseError("ABI: need 32 bytes for uint256".into()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&data[..32]);
    Ok(buf)
}

/// Decode a `uint256` as `u64` (fails if value > u64::MAX).
pub fn decode_uint256_as_u64(data: &[u8]) -> Result<u64, SignerError> {
    let raw = decode_uint256(data)?;
    // Check that the first 24 bytes are zero
    if raw[..24].iter().any(|b| *b != 0) {
        return Err(SignerError::ParseError("ABI: uint256 overflow for u64".into()));
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&raw[24..32]);
    Ok(u64::from_be_bytes(buf))
}

/// Decode an `address` from 32 padded bytes.
pub fn decode_address(data: &[u8]) -> Result<[u8; 20], SignerError> {
    if data.len() < 32 {
        return Err(SignerError::ParseError("ABI: need 32 bytes for address".into()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&data[12..32]);
    Ok(addr)
}

/// Decode a `bool` from 32 padded bytes.
pub fn decode_bool(data: &[u8]) -> Result<bool, SignerError> {
    if data.len() < 32 {
        return Err(SignerError::ParseError("ABI: need 32 bytes for bool".into()));
    }
    Ok(data[31] != 0)
}

/// Decode dynamic `bytes` from ABI-encoded data at a given offset.
///
/// Reads the offset pointer, then the length-prefixed data.
pub fn decode_bytes(data: &[u8], param_offset: usize) -> Result<Vec<u8>, SignerError> {
    // Read the offset (big-endian u64 in 32 bytes)
    let offset = decode_uint256_as_u64(&data[param_offset..])? as usize;
    // At `offset`: length (32 bytes) + data
    if offset + 32 > data.len() {
        return Err(SignerError::ParseError("ABI: bytes offset out of range".into()));
    }
    let len = decode_uint256_as_u64(&data[offset..])? as usize;
    let start = offset + 32;
    if start + len > data.len() {
        return Err(SignerError::ParseError("ABI: bytes data truncated".into()));
    }
    Ok(data[start..start + len].to_vec())
}

/// Decode a dynamic `string` from ABI-encoded data at a given offset.
pub fn decode_string(data: &[u8], param_offset: usize) -> Result<String, SignerError> {
    let bytes = decode_bytes(data, param_offset)?;
    String::from_utf8(bytes).map_err(|e| SignerError::ParseError(format!("ABI: invalid UTF-8: {e}")))
}

// ─── Contract Deployment ───────────────────────────────────────────

/// Build contract deployment calldata: `bytecode || abi.encode(constructor_args)`.
///
/// # Arguments
/// - `bytecode` — The compiled contract bytecode
/// - `constructor_args` — Constructor arguments (empty if none)
///
/// Use this as the `data` field in a transaction with `to: None`.
#[must_use]
pub fn encode_constructor(bytecode: &[u8], constructor_args: &[AbiValue]) -> Vec<u8> {
    let mut data = bytecode.to_vec();
    if !constructor_args.is_empty() {
        data.extend_from_slice(&encode(constructor_args));
    }
    data
}

/// Build and sign a contract deployment transaction (EIP-1559).
pub fn deploy_contract(
    signer: &super::EthereumSigner,
    bytecode: &[u8],
    constructor_args: &[AbiValue],
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    gas_limit: u64,
) -> Result<super::transaction::SignedTransaction, SignerError> {
    let tx = super::transaction::EIP1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to: None, // contract creation
        value: 0,
        data: encode_constructor(bytecode, constructor_args),
        access_list: vec![],
    };
    tx.sign(signer)
}

// ─── Contract Call Builder ─────────────────────────────────────────

/// A builder for encoding and signing contract calls.
///
/// # Example
/// ```no_run
/// use trad_signer::ethereum::abi::{ContractCall, AbiValue};
///
/// let call = ContractCall::new([0xAA; 20], "transfer(address,uint256)")
///     .args(&[AbiValue::Address([0xBB; 20]), AbiValue::from_u128(1_000_000)])
///     .value(0);
///
/// // For eth_call (read-only):
/// let calldata = call.calldata();
///
/// // For eth_sendTransaction (state-changing):
/// // let signed = call.sign(&signer, chain_id, nonce, fees...)?;
/// ```
pub struct ContractCall {
    /// Target contract address.
    contract: [u8; 20],
    /// Function being called.
    function: Function,
    /// Encoded arguments.
    args: Vec<AbiValue>,
    /// ETH value to send (in wei).
    value_wei: u128,
}

impl ContractCall {
    /// Create a new contract call.
    #[must_use]
    pub fn new(contract: [u8; 20], function_signature: &str) -> Self {
        Self {
            contract,
            function: Function::new(function_signature),
            args: Vec::new(),
            value_wei: 0,
        }
    }

    /// Set the function arguments.
    #[must_use]
    pub fn args(mut self, args: &[AbiValue]) -> Self {
        self.args = args.to_vec();
        self
    }

    /// Set the ETH value to send with this call.
    #[must_use]
    pub fn value(mut self, value_wei: u128) -> Self {
        self.value_wei = value_wei;
        self
    }

    /// Get the encoded calldata (selector + encoded args).
    ///
    /// Use this for `eth_call` (read-only queries).
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        self.function.encode(&self.args)
    }

    /// Build and sign an EIP-1559 transaction for this contract call.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> Result<super::transaction::SignedTransaction, SignerError> {
        let tx = super::transaction::EIP1559Transaction {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: Some(self.contract),
            value: self.value_wei,
            data: self.calldata(),
            access_list: vec![],
        };
        tx.sign(signer)
    }
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

fn encode_dynamic_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Length (32 bytes, big-endian)
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(data.len() as u64).to_be_bytes());
    buf.extend_from_slice(&len);
    // Data (padded to 32-byte boundary)
    buf.extend_from_slice(data);
    let padding = (32 - (data.len() % 32)) % 32;
    buf.extend_from_slice(&vec![0u8; padding]);
    buf
}

fn encode_tuple(values: &[AbiValue]) -> Vec<u8> {
    let head_size = values.len() * 32;
    let mut heads = Vec::with_capacity(head_size);
    let mut tails = Vec::new();

    for v in values {
        if v.is_dynamic() {
            // Head = offset to tail data
            let offset = head_size + tails.len();
            let mut offset_bytes = [0u8; 32];
            offset_bytes[24..].copy_from_slice(&(offset as u64).to_be_bytes());
            heads.extend_from_slice(&offset_bytes);
            tails.extend_from_slice(&v.encode_tail());
        } else {
            heads.extend_from_slice(&v.encode_head());
        }
    }

    let mut result = Vec::with_capacity(heads.len() + tails.len());
    result.extend_from_slice(&heads);
    result.extend_from_slice(&tails);
    result
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    // ─── Function Selector Tests ───────────────────────────────────

    #[test]
    fn test_selector_transfer() {
        // transfer(address,uint256) → 0xa9059cbb
        let sel = function_selector("transfer(address,uint256)");
        assert_eq!(hex::encode(sel), "a9059cbb");
    }

    #[test]
    fn test_selector_approve() {
        // approve(address,uint256) → 0x095ea7b3
        let sel = function_selector("approve(address,uint256)");
        assert_eq!(hex::encode(sel), "095ea7b3");
    }

    #[test]
    fn test_selector_balance_of() {
        // balanceOf(address) → 0x70a08231
        let sel = function_selector("balanceOf(address)");
        assert_eq!(hex::encode(sel), "70a08231");
    }

    #[test]
    fn test_selector_total_supply() {
        // totalSupply() → 0x18160ddd
        let sel = function_selector("totalSupply()");
        assert_eq!(hex::encode(sel), "18160ddd");
    }

    #[test]
    fn test_event_topic_transfer() {
        // Transfer(address,address,uint256) → known topic
        let topic = event_topic("Transfer(address,address,uint256)");
        assert_eq!(
            hex::encode(topic),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn test_event_topic_approval() {
        let topic = event_topic("Approval(address,address,uint256)");
        assert_eq!(
            hex::encode(topic),
            "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
        );
    }

    // ─── ABI Encoding Tests ────────────────────────────────────────

    #[test]
    fn test_encode_uint256() {
        let val = AbiValue::from_u64(42);
        let encoded = encode(&[val]);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 42);
        assert!(encoded[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_encode_address() {
        let addr = [0xAA; 20];
        let encoded = encode(&[AbiValue::Address(addr)]);
        assert_eq!(encoded.len(), 32);
        assert!(encoded[..12].iter().all(|b| *b == 0)); // left-padded
        assert_eq!(&encoded[12..], &[0xAA; 20]);
    }

    #[test]
    fn test_encode_bool() {
        let encoded_true = encode(&[AbiValue::Bool(true)]);
        assert_eq!(encoded_true[31], 1);
        let encoded_false = encode(&[AbiValue::Bool(false)]);
        assert_eq!(encoded_false[31], 0);
    }

    #[test]
    fn test_encode_dynamic_bytes() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = encode(&[AbiValue::Bytes(data.clone())]);
        // Head: offset (32 bytes) → 0x20 = 32
        assert_eq!(encoded[31], 32);
        // Tail: length (32 bytes) + padded data (32 bytes)
        assert_eq!(encoded[63], 4); // length = 4
        assert_eq!(&encoded[64..68], &data);
    }

    #[test]
    fn test_encode_string() {
        let s = "hello";
        let encoded = encode(&[AbiValue::String(s.to_string())]);
        assert_eq!(encoded[31], 32); // offset
        assert_eq!(encoded[63], 5);  // length
        assert_eq!(&encoded[64..69], b"hello");
    }

    #[test]
    fn test_encode_multiple_static() {
        // abi.encode(address, uint256)
        let encoded = encode(&[
            AbiValue::Address([0xBB; 20]),
            AbiValue::from_u64(100),
        ]);
        assert_eq!(encoded.len(), 64); // 2 × 32
        assert_eq!(&encoded[12..32], &[0xBB; 20]);
        assert_eq!(encoded[63], 100);
    }

    #[test]
    fn test_function_encode_transfer() {
        let transfer = Function::new("transfer(address,uint256)");
        let calldata = transfer.encode(&[
            AbiValue::Address([0xCC; 20]),
            AbiValue::from_u64(1000),
        ]);
        assert_eq!(&calldata[..4], &hex::decode("a9059cbb").unwrap());
        assert_eq!(calldata.len(), 4 + 64);
    }

    // ─── encode_packed Tests ───────────────────────────────────────

    #[test]
    fn test_encode_packed_address_uint() {
        let packed = encode_packed(&[
            AbiValue::Address([0xAA; 20]),
            AbiValue::from_u64(1),
        ]);
        // address = 20 bytes + uint = 1 byte (stripped)
        assert_eq!(&packed[..20], &[0xAA; 20]);
        assert_eq!(packed[20], 1);
    }

    #[test]
    fn test_encode_packed_and_hash() {
        let hash = encode_packed_and_hash(&[
            AbiValue::String("hello".to_string()),
            AbiValue::String("world".to_string()),
        ]);
        // keccak256("helloworld")
        let expected = keccak256(b"helloworld");
        assert_eq!(hash, expected);
    }

    // ─── ABI Decoding Tests ────────────────────────────────────────

    #[test]
    fn test_decode_uint256_roundtrip() {
        let val = AbiValue::from_u64(12345);
        let encoded = encode(&[val]);
        let decoded = decode_uint256_as_u64(&encoded).unwrap();
        assert_eq!(decoded, 12345);
    }

    #[test]
    fn test_decode_address_roundtrip() {
        let addr = [0xDD; 20];
        let encoded = encode(&[AbiValue::Address(addr)]);
        let decoded = decode_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_decode_bool_roundtrip() {
        let encoded = encode(&[AbiValue::Bool(true)]);
        assert!(decode_bool(&encoded).unwrap());
        let encoded = encode(&[AbiValue::Bool(false)]);
        assert!(!decode_bool(&encoded).unwrap());
    }

    #[test]
    fn test_decode_bytes_roundtrip() {
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let encoded = encode(&[AbiValue::Bytes(data.clone())]);
        let decoded = decode_bytes(&encoded, 0).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_string_roundtrip() {
        let s = "Hello, Ethereum!";
        let encoded = encode(&[AbiValue::String(s.to_string())]);
        let decoded = decode_string(&encoded, 0).unwrap();
        assert_eq!(decoded, s);
    }

    // ─── Contract Deploy Tests ─────────────────────────────────────

    #[test]
    fn test_encode_constructor_no_args() {
        let bytecode = vec![0x60, 0x00, 0x60, 0x00]; // minimal
        let data = encode_constructor(&bytecode, &[]);
        assert_eq!(data, bytecode);
    }

    #[test]
    fn test_encode_constructor_with_args() {
        let bytecode = vec![0x60, 0x00];
        let data = encode_constructor(&bytecode, &[AbiValue::from_u64(42)]);
        assert_eq!(&data[..2], &bytecode);
        assert_eq!(data.len(), 2 + 32);
        assert_eq!(data[33], 42);
    }

    #[test]
    fn test_deploy_contract_signs() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let signed = deploy_contract(
            &signer,
            &[0x60, 0x00],
            &[],
            1, 0,
            2_000_000_000, 100_000_000_000,
            1_000_000,
        ).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x02); // EIP-1559
    }

    // ─── Contract Call Tests ───────────────────────────────────────

    #[test]
    fn test_contract_call_calldata() {
        let call = ContractCall::new([0xAA; 20], "transfer(address,uint256)")
            .args(&[AbiValue::Address([0xBB; 20]), AbiValue::from_u64(1000)]);
        let cd = call.calldata();
        assert_eq!(&cd[..4], &hex::decode("a9059cbb").unwrap());
    }

    #[test]
    fn test_contract_call_sign() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let call = ContractCall::new([0xAA; 20], "transfer(address,uint256)")
            .args(&[AbiValue::Address([0xBB; 20]), AbiValue::from_u64(1000)])
            .value(0);
        let signed = call.sign(&signer, 1, 0, 2_000_000_000, 100_000_000_000, 100_000).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x02);
    }

    // ─── Fixed Bytes Tests ─────────────────────────────────────────

    #[test]
    fn test_encode_fixed_bytes() {
        let val = AbiValue::FixedBytes(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let encoded = encode(&[val]);
        assert_eq!(encoded.len(), 32);
        assert_eq!(&encoded[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert!(encoded[4..].iter().all(|b| *b == 0)); // right-padded
    }

    // ─── Array Tests ───────────────────────────────────────────────

    #[test]
    fn test_encode_array() {
        let arr = AbiValue::Array(vec![
            AbiValue::from_u64(1),
            AbiValue::from_u64(2),
            AbiValue::from_u64(3),
        ]);
        let encoded = encode(&[arr]);
        // Head: offset (32 bytes)
        // Tail: length (32 bytes) + 3 × 32 bytes
        assert_eq!(encoded.len(), 32 + 32 + 3 * 32); // = 192
    }
}
