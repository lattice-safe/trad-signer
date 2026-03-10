//! **Smart Wallet** and **Account Abstraction (EIP-4337 v0.7)** encoding/decoding.
//!
//! Provides:
//! - `PackedUserOperation` — EIP-4337 v0.7 packed format
//! - `handleOps` calldata encoding for the EntryPoint v0.7
//! - Smart wallet `execute`/`executeBatch` encoding
//! - ERC-1271 `isValidSignature` encoding and decoding
//! - Paymaster data encoding
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::smart_wallet::{
//!     PackedUserOperation, encode_execute, encode_execute_batch, ExecuteCall,
//!     encode_is_valid_signature, is_valid_signature_magic,
//!     uint256_from_u64,
//! };
//!
//! // Encode a smart wallet execute call
//! let calldata = encode_execute([0xBB; 20], uint256_from_u64(0), &[]);
//!
//! // Batch execution
//! let calls = vec![
//!     ExecuteCall { target: [0xAA; 20], value: uint256_from_u64(0), data: vec![0x01] },
//!     ExecuteCall { target: [0xBB; 20], value: uint256_from_u64(100), data: vec![0x02] },
//! ];
//! let batch = encode_execute_batch(&calls);
//! ```

use crate::error::SignerError;
use crate::ethereum::abi::{self, AbiValue};

/// A raw uint256 value encoded as 32-byte big-endian.
pub type Uint256 = [u8; 32];

// ─── EIP-4337 v0.7 Packed User Operation ───────────────────────────

/// A packed user operation for EIP-4337 v0.7 (EntryPoint v0.7).
///
/// This is the "packed" format introduced in ERC-4337 v0.7 where gas fields
/// are combined into `bytes32` for more efficient calldata.
#[derive(Debug, Clone)]
pub struct PackedUserOperation {
    /// The account making the operation.
    pub sender: [u8; 20],
    /// Anti-replay parameter (nonce from the entrypoint, includes key).
    pub nonce: [u8; 32],
    /// Account initCode (needed if account is not yet deployed).
    pub init_code: Vec<u8>,
    /// The calldata to execute on the account.
    pub call_data: Vec<u8>,
    /// Packed gas limits: `verificationGasLimit (16 bytes) || callGasLimit (16 bytes)`.
    pub account_gas_limits: [u8; 32],
    /// Pre-verification gas.
    pub pre_verification_gas: [u8; 32],
    /// Packed gas fees: `maxPriorityFeePerGas (16 bytes) || maxFeePerGas (16 bytes)`.
    pub gas_fees: [u8; 32],
    /// Paymaster data: `paymaster (20 bytes) || paymasterVerificationGasLimit (16 bytes) || paymasterPostOpGasLimit (16 bytes) || paymasterData`.
    pub paymaster_and_data: Vec<u8>,
    /// The signature for this operation.
    pub signature: Vec<u8>,
}

impl PackedUserOperation {
    /// Pack the user operation for hashing (excludes the signature).
    ///
    /// Returns the ABI-encoded struct for computing the user operation hash.
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(11 * 32);

        // Pack as: sender, nonce, keccak256(initCode), keccak256(callData),
        // accountGasLimits, preVerificationGas, gasFees, keccak256(paymasterAndData)
        buf.extend_from_slice(&pad_address(&self.sender));
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&keccak256(&self.init_code));
        buf.extend_from_slice(&keccak256(&self.call_data));
        buf.extend_from_slice(&self.account_gas_limits);
        buf.extend_from_slice(&self.pre_verification_gas);
        buf.extend_from_slice(&self.gas_fees);
        buf.extend_from_slice(&keccak256(&self.paymaster_and_data));

        buf
    }

    /// Compute the user operation hash.
    ///
    /// `keccak256(abi.encode(pack(userOp), entryPoint, chainId))`
    #[must_use]
    pub fn hash(&self, entry_point: &[u8; 20], chain_id: Uint256) -> [u8; 32] {
        let packed_hash = keccak256(&self.pack());
        let mut buf = Vec::with_capacity(3 * 32);
        buf.extend_from_slice(&packed_hash);
        buf.extend_from_slice(&pad_address(entry_point));
        buf.extend_from_slice(&chain_id);
        keccak256(&buf)
    }

    /// Sign this packed user operation.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
        entry_point: &[u8; 20],
        chain_id: Uint256,
    ) -> Result<super::EthereumSignature, SignerError> {
        let hash = self.hash(entry_point, chain_id);
        signer.sign_digest(&hash)
    }

    /// Pack gas limits into the `accountGasLimits` field.
    ///
    /// `verificationGasLimit (16 bytes) || callGasLimit (16 bytes)`
    #[must_use]
    pub fn pack_account_gas_limits(verification_gas_limit: u128, call_gas_limit: u128) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&verification_gas_limit.to_be_bytes());
        buf[16..].copy_from_slice(&call_gas_limit.to_be_bytes());
        buf
    }

    /// Unpack gas limits from the `accountGasLimits` field.
    #[must_use]
    pub fn unpack_account_gas_limits(packed: &[u8; 32]) -> (u128, u128) {
        let mut vgl = [0u8; 16];
        let mut cgl = [0u8; 16];
        vgl.copy_from_slice(&packed[..16]);
        cgl.copy_from_slice(&packed[16..]);
        (u128::from_be_bytes(vgl), u128::from_be_bytes(cgl))
    }

    /// Pack gas fees into the `gasFees` field.
    ///
    /// `maxPriorityFeePerGas (16 bytes) || maxFeePerGas (16 bytes)`
    #[must_use]
    pub fn pack_gas_fees(max_priority_fee: u128, max_fee: u128) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&max_priority_fee.to_be_bytes());
        buf[16..].copy_from_slice(&max_fee.to_be_bytes());
        buf
    }

    /// Unpack gas fees from the `gasFees` field.
    #[must_use]
    pub fn unpack_gas_fees(packed: &[u8; 32]) -> (u128, u128) {
        let mut mpf = [0u8; 16];
        let mut mf = [0u8; 16];
        mpf.copy_from_slice(&packed[..16]);
        mf.copy_from_slice(&packed[16..]);
        (u128::from_be_bytes(mpf), u128::from_be_bytes(mf))
    }
}

// ─── EntryPoint handleOps ──────────────────────────────────────────

/// The EntryPoint v0.7 contract address.
///
/// Deployed at the same address on all EVM chains.
pub const ENTRY_POINT_V07: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x71, 0x72, 0x7d, 0xe2, 0x2e, 0x5e, 0x9d, 0x8b, 0xaf, 0x0e, 0xda, 0xc6,
    0xf3, 0x7d, 0xa0, 0x32,
];

/// ABI-encode `handleOps(PackedUserOperation[], address beneficiary)` for EntryPoint v0.7.
///
/// This is the function called by bundlers to submit user operations.
#[must_use]
pub fn encode_handle_ops(ops: &[PackedUserOperation], beneficiary: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new(
        "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)",
    );

    let op_tuples: Vec<AbiValue> = ops
        .iter()
        .map(|op| {
            AbiValue::Tuple(vec![
                AbiValue::Address(op.sender),
                AbiValue::Uint256(op.nonce),
                AbiValue::Bytes(op.init_code.clone()),
                AbiValue::Bytes(op.call_data.clone()),
                AbiValue::Uint256(op.account_gas_limits),
                AbiValue::Uint256(op.pre_verification_gas),
                AbiValue::Uint256(op.gas_fees),
                AbiValue::Bytes(op.paymaster_and_data.clone()),
                AbiValue::Bytes(op.signature.clone()),
            ])
        })
        .collect();

    func.encode(&[AbiValue::Array(op_tuples), AbiValue::Address(beneficiary)])
}

// ─── Paymaster Data ────────────────────────────────────────────────

/// Encode paymaster data for the `paymasterAndData` field.
///
/// Format: `paymaster (20 bytes) || verificationGasLimit (16 bytes) || postOpGasLimit (16 bytes) || data`
#[must_use]
pub fn encode_paymaster_data(
    paymaster: [u8; 20],
    verification_gas_limit: u128,
    post_op_gas_limit: u128,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 16 + 16 + data.len());
    buf.extend_from_slice(&paymaster);
    buf.extend_from_slice(&verification_gas_limit.to_be_bytes());
    buf.extend_from_slice(&post_op_gas_limit.to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Decode paymaster data from the `paymasterAndData` field.
///
/// Returns `(paymaster, verificationGasLimit, postOpGasLimit, data)`.
pub fn decode_paymaster_data(
    encoded: &[u8],
) -> Result<([u8; 20], u128, u128, Vec<u8>), SignerError> {
    if encoded.len() < 52 {
        return Err(SignerError::EncodingError(format!(
            "paymasterAndData too short: {} bytes, need at least 52",
            encoded.len()
        )));
    }
    let mut paymaster = [0u8; 20];
    paymaster.copy_from_slice(&encoded[..20]);

    let mut vgl_bytes = [0u8; 16];
    vgl_bytes.copy_from_slice(&encoded[20..36]);
    let verification_gas_limit = u128::from_be_bytes(vgl_bytes);

    let mut pogl_bytes = [0u8; 16];
    pogl_bytes.copy_from_slice(&encoded[36..52]);
    let post_op_gas_limit = u128::from_be_bytes(pogl_bytes);

    let data = encoded[52..].to_vec();

    Ok((paymaster, verification_gas_limit, post_op_gas_limit, data))
}

// ─── Smart Wallet execute ──────────────────────────────────────────

/// ABI-encode `execute(address dest, uint256 value, bytes func)`.
///
/// Standard smart wallet execution function (e.g. SimpleAccount, Kernel, etc.).
#[must_use]
pub fn encode_execute(dest: [u8; 20], value: Uint256, func: &[u8]) -> Vec<u8> {
    let f = abi::Function::new("execute(address,uint256,bytes)");
    f.encode(&[
        AbiValue::Address(dest),
        AbiValue::Uint256(value),
        AbiValue::Bytes(func.to_vec()),
    ])
}

/// A call entry for batch execution.
#[derive(Debug, Clone)]
pub struct ExecuteCall {
    /// Target contract address.
    pub target: [u8; 20],
    /// ETH value in wei.
    pub value: Uint256,
    /// Calldata to execute.
    pub data: Vec<u8>,
}

/// ABI-encode `executeBatch(address[] dest, uint256[] values, bytes[] func)`.
///
/// Standard batched execution for smart wallets.
#[must_use]
pub fn encode_execute_batch(calls: &[ExecuteCall]) -> Vec<u8> {
    let f = abi::Function::new("executeBatch(address[],uint256[],bytes[])");
    let dests: Vec<AbiValue> = calls.iter().map(|c| AbiValue::Address(c.target)).collect();
    let values: Vec<AbiValue> = calls.iter().map(|c| AbiValue::Uint256(c.value)).collect();
    let funcs: Vec<AbiValue> = calls
        .iter()
        .map(|c| AbiValue::Bytes(c.data.clone()))
        .collect();
    f.encode(&[
        AbiValue::Array(dests),
        AbiValue::Array(values),
        AbiValue::Array(funcs),
    ])
}

// ─── ERC-1271 Signature Validation ─────────────────────────────────

/// The ERC-1271 magic value indicating a valid signature.
///
/// `bytes4(keccak256("isValidSignature(bytes32,bytes)"))` = `0x1626ba7e`
pub const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// ABI-encode `isValidSignature(bytes32 hash, bytes signature)`.
///
/// ERC-1271 standard for smart contract signature validation.
#[must_use]
pub fn encode_is_valid_signature(hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let f = abi::Function::new("isValidSignature(bytes32,bytes)");
    f.encode(&[
        AbiValue::Uint256(*hash),
        AbiValue::Bytes(signature.to_vec()),
    ])
}

/// Check if the return value from `isValidSignature` indicates a valid signature.
///
/// Returns `true` if the first 4 bytes match `0x1626ba7e`.
#[must_use]
pub fn is_valid_signature_magic(return_data: &[u8]) -> bool {
    if return_data.len() < 32 {
        return false;
    }
    // The return value is a bytes4 left-padded to 32 bytes
    return_data[..4] == [0u8; 4]
        && return_data[4..28] == [0u8; 24]
        && return_data[28..32] == ERC1271_MAGIC
}

/// Check if the return value from `isValidSignature` indicates a valid signature
/// (non-padded, just the raw 4 bytes).
#[must_use]
pub fn is_valid_signature_magic_raw(return_data: &[u8]) -> bool {
    if return_data.len() < 4 {
        return false;
    }
    return_data[..4] == ERC1271_MAGIC
}

// ─── Account Factory ───────────────────────────────────────────────

/// ABI-encode `createAccount(address owner, uint256 salt)`.
///
/// Standard account factory for deploying new smart accounts.
#[must_use]
pub fn encode_create_account(owner: [u8; 20], salt: Uint256) -> Vec<u8> {
    let f = abi::Function::new("createAccount(address,uint256)");
    f.encode(&[AbiValue::Address(owner), AbiValue::Uint256(salt)])
}

/// ABI-encode `getAddress(address owner, uint256 salt)`.
///
/// Query the counterfactual address of a smart account.
#[must_use]
pub fn encode_get_address(owner: [u8; 20], salt: Uint256) -> Vec<u8> {
    let f = abi::Function::new("getAddress(address,uint256)");
    f.encode(&[AbiValue::Address(owner), AbiValue::Uint256(salt)])
}

// ─── Nonce Management ──────────────────────────────────────────────

/// ABI-encode `getNonce(address sender, uint192 key)` for EntryPoint nonce query.
#[must_use]
pub fn encode_get_nonce(sender: [u8; 20], key: Uint256) -> Vec<u8> {
    let f = abi::Function::new("getNonce(address,uint192)");
    f.encode(&[AbiValue::Address(sender), AbiValue::Uint256(key)])
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    super::keccak256(data)
}

fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr);
    buf
}

/// Convert a u64 value into canonical uint256 encoding.
#[must_use]
pub fn uint256_from_u64(value: u64) -> Uint256 {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    fn sample_op() -> PackedUserOperation {
        PackedUserOperation {
            sender: [0xAA; 20],
            nonce: [0u8; 32],
            init_code: vec![],
            call_data: vec![0x01, 0x02],
            account_gas_limits: PackedUserOperation::pack_account_gas_limits(100_000, 200_000),
            pre_verification_gas: {
                let mut buf = [0u8; 32];
                buf[24..32].copy_from_slice(&50_000u64.to_be_bytes());
                buf
            },
            gas_fees: PackedUserOperation::pack_gas_fees(1_000_000_000, 2_000_000_000),
            paymaster_and_data: vec![],
            signature: vec![],
        }
    }

    // ─── Pack/Hash ────────────────────────────────────────────

    #[test]
    fn test_pack_deterministic() {
        let op = sample_op();
        assert_eq!(op.pack(), op.pack());
    }

    #[test]
    fn test_pack_length() {
        let op = sample_op();
        // 8 fields × 32 bytes = 256
        assert_eq!(op.pack().len(), 256);
    }

    #[test]
    fn test_hash_deterministic() {
        let op = sample_op();
        let ep = [0xFF; 20];
        assert_eq!(
            op.hash(&ep, uint256_from_u64(1)),
            op.hash(&ep, uint256_from_u64(1))
        );
    }

    #[test]
    fn test_hash_changes_with_chain_id() {
        let op = sample_op();
        let ep = [0xFF; 20];
        assert_ne!(
            op.hash(&ep, uint256_from_u64(1)),
            op.hash(&ep, uint256_from_u64(137))
        );
    }

    #[test]
    fn test_hash_changes_with_entry_point() {
        let op = sample_op();
        assert_ne!(
            op.hash(&[0xAA; 20], uint256_from_u64(1)),
            op.hash(&[0xBB; 20], uint256_from_u64(1))
        );
    }

    #[test]
    fn test_entry_point_v07_canonical_value() {
        assert_eq!(
            ENTRY_POINT_V07,
            [
                0x00, 0x00, 0x00, 0x00, 0x71, 0x72, 0x7d, 0xe2, 0x2e, 0x5e, 0x9d, 0x8b, 0xaf, 0x0e,
                0xda, 0xc6, 0xf3, 0x7d, 0xa0, 0x32,
            ]
        );
    }

    #[test]
    fn test_hash_changes_with_calldata() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.call_data = vec![0x03, 0x04];
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }

    #[test]
    fn test_hash_changes_with_sender() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.sender = [0xBB; 20];
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }

    #[test]
    fn test_hash_changes_with_nonce() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.nonce[31] = 1;
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }

    // ─── Sign ─────────────────────────────────────────────────

    #[test]
    fn test_sign_produces_valid_signature() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let op = sample_op();
        let sig = op.sign(&signer, &[0xFF; 20], uint256_from_u64(1)).unwrap();
        assert!(sig.v == 27 || sig.v == 28);
        assert_ne!(sig.r, [0u8; 32]);
    }

    #[test]
    fn test_sign_recovers_correct_address() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let op = sample_op();
        let sig = op.sign(&signer, &[0xFF; 20], uint256_from_u64(1)).unwrap();
        let hash = op.hash(&[0xFF; 20], uint256_from_u64(1));
        let recovered = super::super::ecrecover_digest(&hash, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    // ─── Gas Packing ──────────────────────────────────────────

    #[test]
    fn test_pack_account_gas_limits_roundtrip() {
        let packed = PackedUserOperation::pack_account_gas_limits(100_000, 200_000);
        let (vgl, cgl) = PackedUserOperation::unpack_account_gas_limits(&packed);
        assert_eq!(vgl, 100_000);
        assert_eq!(cgl, 200_000);
    }

    #[test]
    fn test_pack_gas_fees_roundtrip() {
        let packed = PackedUserOperation::pack_gas_fees(1_000_000_000, 2_000_000_000);
        let (mpf, mf) = PackedUserOperation::unpack_gas_fees(&packed);
        assert_eq!(mpf, 1_000_000_000);
        assert_eq!(mf, 2_000_000_000);
    }

    #[test]
    fn test_pack_gas_limits_zero() {
        let packed = PackedUserOperation::pack_account_gas_limits(0, 0);
        assert_eq!(packed, [0u8; 32]);
        let (vgl, cgl) = PackedUserOperation::unpack_account_gas_limits(&packed);
        assert_eq!(vgl, 0);
        assert_eq!(cgl, 0);
    }

    #[test]
    fn test_pack_gas_fees_max() {
        let max = u128::MAX;
        let packed = PackedUserOperation::pack_gas_fees(max, max);
        let (mpf, mf) = PackedUserOperation::unpack_gas_fees(&packed);
        assert_eq!(mpf, max);
        assert_eq!(mf, max);
    }

    // ─── handleOps ────────────────────────────────────────────

    #[test]
    fn test_encode_handle_ops_selector() {
        let ops = vec![sample_op()];
        let calldata = encode_handle_ops(&ops, [0xFF; 20]);
        let expected = abi::function_selector(
            "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)",
        );
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_handle_ops_empty() {
        let calldata = encode_handle_ops(&[], [0xFF; 20]);
        assert!(calldata.len() > 4);
    }

    // ─── Paymaster Data ───────────────────────────────────────

    #[test]
    fn test_paymaster_data_roundtrip() {
        let paymaster = [0xAA; 20];
        let vgl = 100_000u128;
        let pogl = 50_000u128;
        let data = vec![0xDE, 0xAD];

        let encoded = encode_paymaster_data(paymaster, vgl, pogl, &data);
        let (dec_pm, dec_vgl, dec_pogl, dec_data) = decode_paymaster_data(&encoded).unwrap();

        assert_eq!(dec_pm, paymaster);
        assert_eq!(dec_vgl, vgl);
        assert_eq!(dec_pogl, pogl);
        assert_eq!(dec_data, data);
    }

    #[test]
    fn test_paymaster_data_empty_extra_data() {
        let encoded = encode_paymaster_data([0xAA; 20], 100, 200, &[]);
        let (_, _, _, data) = decode_paymaster_data(&encoded).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_paymaster_data_too_short() {
        assert!(decode_paymaster_data(&[0u8; 51]).is_err());
        assert!(decode_paymaster_data(&[]).is_err());
    }

    #[test]
    fn test_paymaster_data_minimum_length() {
        let encoded = encode_paymaster_data([0xBB; 20], 0, 0, &[]);
        assert_eq!(encoded.len(), 52);
        assert!(decode_paymaster_data(&encoded).is_ok());
    }

    // ─── Smart Wallet Execute ─────────────────────────────────

    #[test]
    fn test_encode_execute_selector() {
        let calldata = encode_execute([0xBB; 20], uint256_from_u64(0), &[]);
        let expected = abi::function_selector("execute(address,uint256,bytes)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_execute_with_value() {
        let calldata = encode_execute([0xBB; 20], uint256_from_u64(1_000_000), &[0xDE, 0xAD]);
        assert!(calldata.len() > 4 + 3 * 32);
    }

    #[test]
    fn test_encode_execute_batch_selector() {
        let calls = vec![ExecuteCall {
            target: [0xAA; 20],
            value: uint256_from_u64(0),
            data: vec![],
        }];
        let calldata = encode_execute_batch(&calls);
        let expected = abi::function_selector("executeBatch(address[],uint256[],bytes[])");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_execute_batch_multiple() {
        let calls = vec![
            ExecuteCall {
                target: [0xAA; 20],
                value: uint256_from_u64(100),
                data: vec![0x01],
            },
            ExecuteCall {
                target: [0xBB; 20],
                value: uint256_from_u64(200),
                data: vec![0x02],
            },
        ];
        let calldata = encode_execute_batch(&calls);
        assert!(calldata.len() > 4);
    }

    #[test]
    fn test_encode_execute_batch_empty() {
        let calldata = encode_execute_batch(&[]);
        let expected = abi::function_selector("executeBatch(address[],uint256[],bytes[])");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── ERC-1271 ─────────────────────────────────────────────

    #[test]
    fn test_erc1271_magic_value() {
        assert_eq!(ERC1271_MAGIC, [0x16, 0x26, 0xba, 0x7e]);
    }

    #[test]
    fn test_encode_is_valid_signature_selector() {
        let calldata = encode_is_valid_signature(&[0xAA; 32], &[0xBB; 65]);
        let expected = abi::function_selector("isValidSignature(bytes32,bytes)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_is_valid_signature_magic_true() {
        // ABI-encoded: left-padded bytes4 0x1626ba7e to 32 bytes
        let mut result = [0u8; 32];
        result[28] = 0x16;
        result[29] = 0x26;
        result[30] = 0xba;
        result[31] = 0x7e;
        assert!(is_valid_signature_magic(&result));
    }

    #[test]
    fn test_is_valid_signature_magic_false() {
        let result = [0u8; 32]; // all zeros = invalid
        assert!(!is_valid_signature_magic(&result));
    }

    #[test]
    fn test_is_valid_signature_magic_too_short() {
        assert!(!is_valid_signature_magic(&[0u8; 31]));
    }

    #[test]
    fn test_is_valid_signature_magic_raw_true() {
        assert!(is_valid_signature_magic_raw(&[0x16, 0x26, 0xba, 0x7e]));
    }

    #[test]
    fn test_is_valid_signature_magic_raw_false() {
        assert!(!is_valid_signature_magic_raw(&[0x00, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_is_valid_signature_magic_raw_too_short() {
        assert!(!is_valid_signature_magic_raw(&[0x16, 0x26, 0xba]));
    }

    // ─── Account Factory ──────────────────────────────────────

    #[test]
    fn test_encode_create_account_selector() {
        let calldata = encode_create_account([0xAA; 20], uint256_from_u64(0));
        let expected = abi::function_selector("createAccount(address,uint256)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_get_address_selector() {
        let calldata = encode_get_address([0xAA; 20], uint256_from_u64(0));
        let expected = abi::function_selector("getAddress(address,uint256)");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Nonce Management ─────────────────────────────────────

    #[test]
    fn test_encode_get_nonce_selector() {
        let calldata = encode_get_nonce([0xAA; 20], uint256_from_u64(0));
        let expected = abi::function_selector("getNonce(address,uint192)");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Internal Helpers ─────────────────────────────────────

    #[test]
    fn test_pad_address() {
        let addr = [0xAA; 20];
        let padded = pad_address(&addr);
        assert_eq!(&padded[..12], &[0u8; 12]);
        assert_eq!(&padded[12..], &[0xAA; 20]);
    }

    #[test]
    fn test_uint256_from_u64() {
        let padded = uint256_from_u64(256);
        assert_eq!(&padded[..24], &[0u8; 24]);
        assert_eq!(&padded[24..], &256u64.to_be_bytes());
    }

    // ─── Init Code ────────────────────────────────────────────

    #[test]
    fn test_hash_changes_with_init_code() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.init_code = vec![0xFF; 20];
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }

    #[test]
    fn test_hash_changes_with_paymaster_data() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.paymaster_and_data = vec![0xAA; 52];
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }

    #[test]
    fn test_hash_changes_with_gas_limits() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.account_gas_limits = PackedUserOperation::pack_account_gas_limits(999, 888);
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }

    #[test]
    fn test_hash_changes_with_gas_fees() {
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.gas_fees = PackedUserOperation::pack_gas_fees(999, 888);
        assert_ne!(
            op1.hash(&[0xFF; 20], uint256_from_u64(1)),
            op2.hash(&[0xFF; 20], uint256_from_u64(1))
        );
    }
}
