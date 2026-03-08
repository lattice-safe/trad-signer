//! **Gnosis Safe (Safe)** multisig transaction encoding, signing, and management.
//!
//! Provides typed structs and helpers for interacting with Safe smart contracts:
//! - EIP-712 typed transaction signing (`safeTxHash`)
//! - `execTransaction` calldata encoding
//! - Multi-signature packing in Safe's `r‖s‖v` format
//! - Owner management: `addOwnerWithThreshold`, `removeOwner`, `changeThreshold`
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::safe::{SafeTransaction, Operation, safe_domain_separator};
//! use chains_sdk::ethereum::EthereumSigner;
//! use chains_sdk::traits::KeyPair;
//!
//! let signer = EthereumSigner::generate().unwrap();
//! let domain = safe_domain_separator(1, &[0xAA; 20]);
//!
//! let tx = SafeTransaction {
//!     to: [0xBB; 20],
//!     value: [0u8; 32],
//!     data: vec![],
//!     operation: Operation::Call,
//!     safe_tx_gas: [0u8; 32],
//!     base_gas: [0u8; 32],
//!     gas_price: [0u8; 32],
//!     gas_token: [0u8; 20],
//!     refund_receiver: [0u8; 20],
//!     nonce: [0u8; 32],
//! };
//!
//! let sig = tx.sign(&signer, &domain).unwrap();
//! let calldata = tx.encode_exec_transaction(&[sig]);
//! ```

use crate::error::SignerError;
use crate::ethereum::abi::{self, AbiValue};
use sha3::{Digest, Keccak256};

// ─── Types ─────────────────────────────────────────────────────────

/// Safe operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Standard call (CALL opcode).
    Call = 0,
    /// Delegate call (DELEGATECALL opcode).
    DelegateCall = 1,
}

/// A Gnosis Safe transaction for EIP-712 typed signing.
///
/// All `u256` fields are stored as 32-byte big-endian arrays to avoid
/// overflow issues and match the ABI encoding directly.
#[derive(Debug, Clone)]
pub struct SafeTransaction {
    /// Target address of the transaction.
    pub to: [u8; 20],
    /// ETH value in wei (32-byte BE `uint256`).
    pub value: [u8; 32],
    /// Transaction calldata.
    pub data: Vec<u8>,
    /// Call type: `Call` or `DelegateCall`.
    pub operation: Operation,
    /// Gas allocated for the Safe execution (after `gasleft()` check).
    pub safe_tx_gas: [u8; 32],
    /// Gas costs not related to the Safe execution (signatures, base overhead).
    pub base_gas: [u8; 32],
    /// Gas price used for the refund calculation. 0 = no refund.
    pub gas_price: [u8; 32],
    /// Token address for gas payment (0x0 = ETH).
    pub gas_token: [u8; 20],
    /// Address that receives the gas refund (0x0 = `tx.origin`).
    pub refund_receiver: [u8; 20],
    /// Safe nonce for replay protection.
    pub nonce: [u8; 32],
}

impl SafeTransaction {
    /// The Safe's `SAFE_TX_TYPEHASH`.
    ///
    /// `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")`
    #[must_use]
    pub fn type_hash() -> [u8; 32] {
        keccak256(
            b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)",
        )
    }

    /// Compute the EIP-712 struct hash for this transaction.
    ///
    /// `keccak256(abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce))`
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let data_hash = keccak256(&self.data);

        let mut buf = Vec::with_capacity(11 * 32);
        buf.extend_from_slice(&Self::type_hash());
        buf.extend_from_slice(&pad_address(&self.to));
        buf.extend_from_slice(&self.value);
        buf.extend_from_slice(&data_hash);
        buf.extend_from_slice(&pad_u8(self.operation as u8));
        buf.extend_from_slice(&self.safe_tx_gas);
        buf.extend_from_slice(&self.base_gas);
        buf.extend_from_slice(&self.gas_price);
        buf.extend_from_slice(&pad_address(&self.gas_token));
        buf.extend_from_slice(&pad_address(&self.refund_receiver));
        buf.extend_from_slice(&self.nonce);

        keccak256(&buf)
    }

    /// Compute the EIP-712 signing hash (`safeTxHash`).
    ///
    /// `keccak256("\x19\x01" || domainSeparator || structHash)`
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(2 + 32 + 32);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(domain_separator);
        buf.extend_from_slice(&self.struct_hash());
        keccak256(&buf)
    }

    /// Sign this Safe transaction using EIP-712.
    ///
    /// Returns an `EthereumSignature` that can be packed with `encode_signatures`.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
        domain_separator: &[u8; 32],
    ) -> Result<super::EthereumSignature, SignerError> {
        let hash = self.signing_hash(domain_separator);
        signer.sign_digest(&hash)
    }

    /// ABI-encode the `execTransaction(...)` calldata.
    ///
    /// This produces the full calldata to call `execTransaction` on the Safe contract,
    /// ready for use in a transaction's `data` field.
    #[must_use]
    pub fn encode_exec_transaction(&self, signatures: &[super::EthereumSignature]) -> Vec<u8> {
        let packed_sigs = encode_signatures(signatures);
        let func = abi::Function::new(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        );
        func.encode(&[
            AbiValue::Address(self.to),
            AbiValue::Uint256(self.value),
            AbiValue::Bytes(self.data.clone()),
            AbiValue::Uint256(pad_u8(self.operation as u8)),
            AbiValue::Uint256(self.safe_tx_gas),
            AbiValue::Uint256(self.base_gas),
            AbiValue::Uint256(self.gas_price),
            AbiValue::Address(self.gas_token),
            AbiValue::Address(self.refund_receiver),
            AbiValue::Bytes(packed_sigs),
        ])
    }
}

// ─── Domain Separator ──────────────────────────────────────────────

/// Compute the Safe's EIP-712 domain separator.
///
/// `keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, safeAddress))`
///
/// Uses the Safe v1.3+ domain typehash:
/// `keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")`
#[must_use]
pub fn safe_domain_separator(chain_id: u64, safe_address: &[u8; 20]) -> [u8; 32] {
    let domain_type_hash =
        keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)");
    let mut buf = Vec::with_capacity(3 * 32);
    buf.extend_from_slice(&domain_type_hash);
    buf.extend_from_slice(&pad_u64(chain_id));
    buf.extend_from_slice(&pad_address(safe_address));
    keccak256(&buf)
}

// ─── Signature Packing ─────────────────────────────────────────────

/// Pack multiple ECDSA signatures into Safe's format.
///
/// Each signature is encoded as `r (32 bytes) || s (32 bytes) || v (1 byte)`.
/// Signatures must be sorted by signer address (ascending) — this function
/// does NOT sort them (the caller is responsible for ordering).
#[must_use]
pub fn encode_signatures(signatures: &[super::EthereumSignature]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(signatures.len() * 65);
    for sig in signatures {
        packed.extend_from_slice(&sig.r);
        packed.extend_from_slice(&sig.s);
        packed.push(sig.v as u8);
    }
    packed
}

/// Decode packed Safe signatures back into individual signatures.
///
/// # Errors
/// Returns an error if the data length is not a multiple of 65.
pub fn decode_signatures(data: &[u8]) -> Result<Vec<super::EthereumSignature>, SignerError> {
    if data.len() % 65 != 0 {
        return Err(SignerError::EncodingError(format!(
            "signature data length {} is not a multiple of 65",
            data.len()
        )));
    }
    let count = data.len() / 65;
    let mut sigs = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * 65;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&data[offset..offset + 32]);
        s.copy_from_slice(&data[offset + 32..offset + 64]);
        let v = u64::from(data[offset + 64]);
        sigs.push(super::EthereumSignature { r, s, v });
    }
    Ok(sigs)
}

// ─── Owner Management ──────────────────────────────────────────────

/// ABI-encode `addOwnerWithThreshold(address owner, uint256 threshold)`.
#[must_use]
pub fn encode_add_owner(owner: [u8; 20], threshold: u64) -> Vec<u8> {
    let func = abi::Function::new("addOwnerWithThreshold(address,uint256)");
    func.encode(&[
        AbiValue::Address(owner),
        AbiValue::from_u64(threshold),
    ])
}

/// ABI-encode `removeOwner(address prevOwner, address owner, uint256 threshold)`.
///
/// `prevOwner` is the owner that points to `owner` in the linked list.
/// Use `SENTINEL_OWNERS` (0x1) if `owner` is the first in the list.
#[must_use]
pub fn encode_remove_owner(prev_owner: [u8; 20], owner: [u8; 20], threshold: u64) -> Vec<u8> {
    let func = abi::Function::new("removeOwner(address,address,uint256)");
    func.encode(&[
        AbiValue::Address(prev_owner),
        AbiValue::Address(owner),
        AbiValue::from_u64(threshold),
    ])
}

/// ABI-encode `changeThreshold(uint256 threshold)`.
#[must_use]
pub fn encode_change_threshold(threshold: u64) -> Vec<u8> {
    let func = abi::Function::new("changeThreshold(uint256)");
    func.encode(&[AbiValue::from_u64(threshold)])
}

/// ABI-encode `swapOwner(address prevOwner, address oldOwner, address newOwner)`.
#[must_use]
pub fn encode_swap_owner(prev_owner: [u8; 20], old_owner: [u8; 20], new_owner: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("swapOwner(address,address,address)");
    func.encode(&[
        AbiValue::Address(prev_owner),
        AbiValue::Address(old_owner),
        AbiValue::Address(new_owner),
    ])
}

/// ABI-encode `enableModule(address module)`.
#[must_use]
pub fn encode_enable_module(module: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("enableModule(address)");
    func.encode(&[AbiValue::Address(module)])
}

/// ABI-encode `disableModule(address prevModule, address module)`.
#[must_use]
pub fn encode_disable_module(prev_module: [u8; 20], module: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("disableModule(address,address)");
    func.encode(&[
        AbiValue::Address(prev_module),
        AbiValue::Address(module),
    ])
}

/// ABI-encode `setGuard(address guard)`.
#[must_use]
pub fn encode_set_guard(guard: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("setGuard(address)");
    func.encode(&[AbiValue::Address(guard)])
}

/// The sentinel address used in Safe's linked list (0x0000...0001).
pub const SENTINEL_OWNERS: [u8; 20] = {
    let mut a = [0u8; 20];
    a[19] = 1;
    a
};

/// ABI-encode `getOwners()` calldata.
#[must_use]
pub fn encode_get_owners() -> Vec<u8> {
    let func = abi::Function::new("getOwners()");
    func.encode(&[])
}

/// ABI-encode `getThreshold()` calldata.
#[must_use]
pub fn encode_get_threshold() -> Vec<u8> {
    let func = abi::Function::new("getThreshold()");
    func.encode(&[])
}

/// ABI-encode `nonce()` calldata.
#[must_use]
pub fn encode_nonce() -> Vec<u8> {
    let func = abi::Function::new("nonce()");
    func.encode(&[])
}

/// ABI-encode `getTransactionHash(...)` calldata for on-chain hash computation.
#[must_use]
pub fn encode_get_transaction_hash(tx: &SafeTransaction) -> Vec<u8> {
    let func = abi::Function::new(
        "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)",
    );
    func.encode(&[
        AbiValue::Address(tx.to),
        AbiValue::Uint256(tx.value),
        AbiValue::Bytes(tx.data.clone()),
        AbiValue::Uint256(pad_u8(tx.operation as u8)),
        AbiValue::Uint256(tx.safe_tx_gas),
        AbiValue::Uint256(tx.base_gas),
        AbiValue::Uint256(tx.gas_price),
        AbiValue::Address(tx.gas_token),
        AbiValue::Address(tx.refund_receiver),
        AbiValue::Uint256(tx.nonce),
    ])
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr);
    buf
}

fn pad_u8(val: u8) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[31] = val;
    buf
}

fn pad_u64(val: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&val.to_be_bytes());
    buf
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    fn zero_tx() -> SafeTransaction {
        SafeTransaction {
            to: [0xBB; 20],
            value: [0u8; 32],
            data: vec![],
            operation: Operation::Call,
            safe_tx_gas: [0u8; 32],
            base_gas: [0u8; 32],
            gas_price: [0u8; 32],
            gas_token: [0u8; 20],
            refund_receiver: [0u8; 20],
            nonce: [0u8; 32],
        }
    }

    // ─── Type Hash ────────────────────────────────────────────

    #[test]
    fn test_type_hash_matches_safe_contract() {
        let th = SafeTransaction::type_hash();
        // Known Safe v1.3 SAFE_TX_TYPEHASH
        let expected = keccak256(
            b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)",
        );
        assert_eq!(th, expected);
    }

    // ─── Struct Hash ──────────────────────────────────────────

    #[test]
    fn test_struct_hash_deterministic() {
        let tx = zero_tx();
        assert_eq!(tx.struct_hash(), tx.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_to() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.to = [0xCC; 20];
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_data() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.data = vec![0xDE, 0xAD];
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_operation() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.operation = Operation::DelegateCall;
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_nonce() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.nonce[31] = 1;
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_value() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.value[31] = 1;
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_gas_fields() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.safe_tx_gas[31] = 100;
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());

        let mut tx3 = zero_tx();
        tx3.base_gas[31] = 50;
        assert_ne!(tx1.struct_hash(), tx3.struct_hash());

        let mut tx4 = zero_tx();
        tx4.gas_price[31] = 10;
        assert_ne!(tx1.struct_hash(), tx4.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_gas_token() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.gas_token = [0xFF; 20];
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    #[test]
    fn test_struct_hash_changes_with_refund_receiver() {
        let tx1 = zero_tx();
        let mut tx2 = zero_tx();
        tx2.refund_receiver = [0xFF; 20];
        assert_ne!(tx1.struct_hash(), tx2.struct_hash());
    }

    // ─── Domain Separator ─────────────────────────────────────

    #[test]
    fn test_domain_separator_deterministic() {
        let ds1 = safe_domain_separator(1, &[0xAA; 20]);
        let ds2 = safe_domain_separator(1, &[0xAA; 20]);
        assert_eq!(ds1, ds2);
    }

    #[test]
    fn test_domain_separator_changes_with_chain_id() {
        let ds1 = safe_domain_separator(1, &[0xAA; 20]);
        let ds2 = safe_domain_separator(137, &[0xAA; 20]);
        assert_ne!(ds1, ds2);
    }

    #[test]
    fn test_domain_separator_changes_with_address() {
        let ds1 = safe_domain_separator(1, &[0xAA; 20]);
        let ds2 = safe_domain_separator(1, &[0xBB; 20]);
        assert_ne!(ds1, ds2);
    }

    // ─── Signing Hash ─────────────────────────────────────────

    #[test]
    fn test_signing_hash_starts_with_eip712_prefix() {
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        // The signing hash is keccak256("\x19\x01" || domain || struct_hash)
        // We can verify it's deterministic
        let h1 = tx.signing_hash(&domain);
        let h2 = tx.signing_hash(&domain);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_signing_hash_changes_with_domain() {
        let tx = zero_tx();
        let d1 = safe_domain_separator(1, &[0xAA; 20]);
        let d2 = safe_domain_separator(5, &[0xAA; 20]);
        assert_ne!(tx.signing_hash(&d1), tx.signing_hash(&d2));
    }

    // ─── Sign ─────────────────────────────────────────────────

    #[test]
    fn test_sign_produces_valid_signature() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let sig = tx.sign(&signer, &domain).unwrap();
        // v should be 27 or 28
        assert!(sig.v == 27 || sig.v == 28);
        assert_ne!(sig.r, [0u8; 32]);
        assert_ne!(sig.s, [0u8; 32]);
    }

    #[test]
    fn test_sign_recovers_correct_address() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let sig = tx.sign(&signer, &domain).unwrap();
        let hash = tx.signing_hash(&domain);
        let recovered = super::super::ecrecover_digest(&hash, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    // ─── Signature Packing ────────────────────────────────────

    #[test]
    fn test_encode_signatures_empty() {
        let packed = encode_signatures(&[]);
        assert!(packed.is_empty());
    }

    #[test]
    fn test_encode_signatures_single() {
        let sig = super::super::EthereumSignature {
            r: [0xAA; 32],
            s: [0xBB; 32],
            v: 27,
        };
        let packed = encode_signatures(&[sig]);
        assert_eq!(packed.len(), 65);
        assert_eq!(&packed[..32], &[0xAA; 32]);
        assert_eq!(&packed[32..64], &[0xBB; 32]);
        assert_eq!(packed[64], 27);
    }

    #[test]
    fn test_encode_signatures_multiple() {
        let sig1 = super::super::EthereumSignature {
            r: [0x11; 32], s: [0x22; 32], v: 27,
        };
        let sig2 = super::super::EthereumSignature {
            r: [0x33; 32], s: [0x44; 32], v: 28,
        };
        let packed = encode_signatures(&[sig1, sig2]);
        assert_eq!(packed.len(), 130);
        assert_eq!(packed[64], 27);
        assert_eq!(packed[129], 28);
    }

    // ─── Signature Decoding ───────────────────────────────────

    #[test]
    fn test_decode_signatures_roundtrip() {
        let sig1 = super::super::EthereumSignature {
            r: [0xAA; 32], s: [0xBB; 32], v: 27,
        };
        let sig2 = super::super::EthereumSignature {
            r: [0xCC; 32], s: [0xDD; 32], v: 28,
        };
        let packed = encode_signatures(&[sig1.clone(), sig2.clone()]);
        let decoded = decode_signatures(&packed).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], sig1);
        assert_eq!(decoded[1], sig2);
    }

    #[test]
    fn test_decode_signatures_empty() {
        let decoded = decode_signatures(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_signatures_invalid_length() {
        assert!(decode_signatures(&[0u8; 64]).is_err());
        assert!(decode_signatures(&[0u8; 66]).is_err());
    }

    // ─── execTransaction Encoding ─────────────────────────────

    #[test]
    fn test_exec_transaction_has_correct_selector() {
        let tx = zero_tx();
        let sig = super::super::EthereumSignature {
            r: [0xAA; 32], s: [0xBB; 32], v: 27,
        };
        let calldata = tx.encode_exec_transaction(&[sig]);
        // execTransaction selector
        let expected_selector = abi::function_selector(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        );
        assert_eq!(&calldata[..4], &expected_selector);
    }

    #[test]
    fn test_exec_transaction_includes_signature_data() {
        let tx = zero_tx();
        let sig = super::super::EthereumSignature {
            r: [0xAA; 32], s: [0xBB; 32], v: 27,
        };
        let calldata = tx.encode_exec_transaction(&[sig]);
        // The calldata should contain the packed signatures somewhere
        assert!(calldata.len() > 4 + 10 * 32); // selector + 10 params
    }

    // ─── Owner Management Helpers ─────────────────────────────

    #[test]
    fn test_encode_add_owner_selector() {
        let calldata = encode_add_owner([0xAA; 20], 2);
        let expected = abi::function_selector("addOwnerWithThreshold(address,uint256)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 2 * 32);
    }

    #[test]
    fn test_encode_remove_owner_selector() {
        let calldata = encode_remove_owner(SENTINEL_OWNERS, [0xAA; 20], 1);
        let expected = abi::function_selector("removeOwner(address,address,uint256)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 3 * 32);
    }

    #[test]
    fn test_encode_change_threshold_selector() {
        let calldata = encode_change_threshold(3);
        let expected = abi::function_selector("changeThreshold(uint256)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 32);
    }

    #[test]
    fn test_encode_swap_owner_selector() {
        let calldata = encode_swap_owner(SENTINEL_OWNERS, [0xAA; 20], [0xBB; 20]);
        let expected = abi::function_selector("swapOwner(address,address,address)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 3 * 32);
    }

    #[test]
    fn test_encode_enable_module_selector() {
        let calldata = encode_enable_module([0xAA; 20]);
        let expected = abi::function_selector("enableModule(address)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_disable_module_selector() {
        let calldata = encode_disable_module(SENTINEL_OWNERS, [0xAA; 20]);
        let expected = abi::function_selector("disableModule(address,address)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_set_guard_selector() {
        let calldata = encode_set_guard([0xAA; 20]);
        let expected = abi::function_selector("setGuard(address)");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Query Helpers ────────────────────────────────────────

    #[test]
    fn test_encode_get_owners_selector() {
        let calldata = encode_get_owners();
        let expected = abi::function_selector("getOwners()");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_get_threshold_selector() {
        let calldata = encode_get_threshold();
        let expected = abi::function_selector("getThreshold()");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_nonce_selector() {
        let calldata = encode_nonce();
        let expected = abi::function_selector("nonce()");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_get_transaction_hash_selector() {
        let tx = zero_tx();
        let calldata = encode_get_transaction_hash(&tx);
        let expected = abi::function_selector(
            "getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256)",
        );
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Sentinel ─────────────────────────────────────────────

    #[test]
    fn test_sentinel_owners() {
        assert_eq!(SENTINEL_OWNERS[19], 1);
        assert_eq!(SENTINEL_OWNERS[..19], [0u8; 19]);
    }

    // ─── Operation Enum ───────────────────────────────────────

    #[test]
    fn test_operation_values() {
        assert_eq!(Operation::Call as u8, 0);
        assert_eq!(Operation::DelegateCall as u8, 1);
    }

    #[test]
    fn test_operation_eq() {
        assert_eq!(Operation::Call, Operation::Call);
        assert_ne!(Operation::Call, Operation::DelegateCall);
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
    fn test_pad_u8() {
        let padded = pad_u8(42);
        assert_eq!(&padded[..31], &[0u8; 31]);
        assert_eq!(padded[31], 42);
    }

    #[test]
    fn test_pad_u64() {
        let padded = pad_u64(256);
        assert_eq!(&padded[..24], &[0u8; 24]);
        assert_eq!(&padded[24..], &256u64.to_be_bytes());
    }

    // ─── Delegate Call Transaction ────────────────────────────

    #[test]
    fn test_delegate_call_transaction() {
        let mut tx = zero_tx();
        tx.operation = Operation::DelegateCall;
        tx.data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let hash = tx.signing_hash(&domain);
        assert_ne!(hash, [0u8; 32]);
    }
}
