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

// ─── Sorted Signature Packing ──────────────────────────────────────

/// A signer-signature pair for auto-sorting.
///
/// The Safe contract requires signatures sorted by signer address (ascending).
/// Use [`sign_and_sort`] to automatically handle this.
#[derive(Debug, Clone)]
pub struct SignerSignature {
    /// The signer's 20-byte Ethereum address.
    pub signer: [u8; 20],
    /// The ECDSA signature.
    pub signature: super::EthereumSignature,
}

/// Sign a Safe transaction with multiple signers and auto-sort by address.
///
/// This is the recommended high-level API for multi-owner signing.
/// Signatures are returned sorted by signer address (ascending), ready
/// for `encode_exec_transaction`.
///
/// # Example
/// ```no_run
/// use chains_sdk::ethereum::safe::*;
/// use chains_sdk::ethereum::EthereumSigner;
/// use chains_sdk::traits::KeyPair;
///
/// let owner1 = EthereumSigner::generate().unwrap();
/// let owner2 = EthereumSigner::generate().unwrap();
/// let domain = safe_domain_separator(1, &[0xAA; 20]);
/// let tx = SafeTransaction {
///     to: [0xBB; 20], value: [0u8; 32], data: vec![],
///     operation: Operation::Call,
///     safe_tx_gas: [0u8; 32], base_gas: [0u8; 32], gas_price: [0u8; 32],
///     gas_token: [0u8; 20], refund_receiver: [0u8; 20], nonce: [0u8; 32],
/// };
/// let sorted_sigs = sign_and_sort(&tx, &[&owner1, &owner2], &domain).unwrap();
/// let calldata = tx.encode_exec_transaction(&sorted_sigs);
/// ```
pub fn sign_and_sort(
    tx: &SafeTransaction,
    signers: &[&super::EthereumSigner],
    domain_separator: &[u8; 32],
) -> Result<Vec<super::EthereumSignature>, SignerError> {
    let mut pairs: Vec<SignerSignature> = Vec::with_capacity(signers.len());
    for signer in signers {
        let sig = tx.sign(signer, domain_separator)?;
        pairs.push(SignerSignature {
            signer: signer.address(),
            signature: sig,
        });
    }
    // Sort by signer address (ascending) — required by Safe contract
    pairs.sort_by(|a, b| a.signer.cmp(&b.signer));
    Ok(pairs.into_iter().map(|p| p.signature).collect())
}

/// Encode signatures auto-sorted by recovering their addresses from the hash.
///
/// This is the safest approach — it recovers each signer address via `ecrecover`
/// and sorts automatically. Requires the `safeTxHash` to recover addresses.
pub fn encode_signatures_sorted(
    signatures: &[super::EthereumSignature],
    safe_tx_hash: &[u8; 32],
) -> Result<Vec<u8>, SignerError> {
    let mut pairs: Vec<([u8; 20], &super::EthereumSignature)> =
        Vec::with_capacity(signatures.len());
    for sig in signatures {
        let addr = super::ecrecover_digest(safe_tx_hash, sig)?;
        pairs.push((addr, sig));
    }
    // Sort by recovered address (ascending)
    pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut packed = Vec::with_capacity(pairs.len() * 65);
    for (_, sig) in &pairs {
        packed.extend_from_slice(&sig.r);
        packed.extend_from_slice(&sig.s);
        packed.push(sig.v as u8);
    }
    Ok(packed)
}

// ─── On-Chain Approval (approveHash) ───────────────────────────────

/// ABI-encode `approveHash(bytes32 hashToApprove)`.
///
/// Alternative to off-chain signing: an owner sends a transaction to the Safe
/// calling `approveHash` to register their approval on-chain.
/// Then `execTransaction` is called with a pre-validated signature type (v=1).
#[must_use]
pub fn encode_approve_hash(hash: &[u8; 32]) -> Vec<u8> {
    let func = abi::Function::new("approveHash(bytes32)");
    func.encode(&[AbiValue::Uint256(*hash)])
}

/// Create a pre-validated signature for an owner who approved the hash on-chain.
///
/// In Safe's signature format, `v=1` means "approval-based":
/// - `r` = owner address (left-padded to 32 bytes)
/// - `s` = zero
/// - `v` = 1
pub fn pre_validated_signature(owner: [u8; 20]) -> super::EthereumSignature {
    super::EthereumSignature {
        r: pad_address(&owner),
        s: [0u8; 32],
        v: 1,
    }
}

/// ABI-encode `approvedHashes(address owner, bytes32 hash)`.
///
/// Query whether an owner has approved a specific hash.
/// Returns uint256(1) if approved, 0 if not.
#[must_use]
pub fn encode_approved_hashes(owner: [u8; 20], hash: &[u8; 32]) -> Vec<u8> {
    let func = abi::Function::new("approvedHashes(address,bytes32)");
    func.encode(&[AbiValue::Address(owner), AbiValue::Uint256(*hash)])
}

// ─── Contract Signature (EIP-1271) ─────────────────────────────────

/// Create a contract signature for a smart-contract owner (EIP-1271).
///
/// In Safe's signature format, `v=0` means "contract signature":
/// - `r` = contract address (left-padded to 32 bytes)
/// - `s` = offset into the signatures where the contract sig data starts
/// - `v` = 0
///
/// The actual contract signature data is appended after the fixed-size
/// signature block.
pub fn contract_signature(contract_owner: [u8; 20], data_offset: u32) -> super::EthereumSignature {
    let mut s = [0u8; 32];
    s[28..32].copy_from_slice(&data_offset.to_be_bytes());
    super::EthereumSignature {
        r: pad_address(&contract_owner),
        s,
        v: 0,
    }
}

// ─── Module Execution ──────────────────────────────────────────────

/// ABI-encode `execTransactionFromModule(address to, uint256 value, bytes data, uint8 operation)`.
///
/// Called by an enabled module to execute a transaction without signatures.
#[must_use]
pub fn encode_exec_from_module(
    to: [u8; 20],
    value: &[u8; 32],
    data: &[u8],
    operation: Operation,
) -> Vec<u8> {
    let func = abi::Function::new("execTransactionFromModule(address,uint256,bytes,uint8)");
    func.encode(&[
        AbiValue::Address(to),
        AbiValue::Uint256(*value),
        AbiValue::Bytes(data.to_vec()),
        AbiValue::Uint256(pad_u8(operation as u8)),
    ])
}

/// ABI-encode `execTransactionFromModuleReturnData(...)`.
///
/// Same as `execTransactionFromModule` but returns `(bool success, bytes returnData)`.
#[must_use]
pub fn encode_exec_from_module_return_data(
    to: [u8; 20],
    value: &[u8; 32],
    data: &[u8],
    operation: Operation,
) -> Vec<u8> {
    let func = abi::Function::new(
        "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
    );
    func.encode(&[
        AbiValue::Address(to),
        AbiValue::Uint256(*value),
        AbiValue::Bytes(data.to_vec()),
        AbiValue::Uint256(pad_u8(operation as u8)),
    ])
}

// ─── Additional Queries ────────────────────────────────────────────

/// ABI-encode `isOwner(address owner)` calldata.
#[must_use]
pub fn encode_is_owner(owner: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("isOwner(address)");
    func.encode(&[AbiValue::Address(owner)])
}

/// ABI-encode `domainSeparator()` calldata.
///
/// Query the Safe's on-chain domain separator (useful when chain_id is unknown).
#[must_use]
pub fn encode_domain_separator() -> Vec<u8> {
    let func = abi::Function::new("domainSeparator()");
    func.encode(&[])
}

/// ABI-encode `isModuleEnabled(address module)` calldata.
#[must_use]
pub fn encode_is_module_enabled(module: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("isModuleEnabled(address)");
    func.encode(&[AbiValue::Address(module)])
}

/// ABI-encode `getModulesPaginated(address start, uint256 pageSize)` calldata.
#[must_use]
pub fn encode_get_modules_paginated(start: [u8; 20], page_size: u64) -> Vec<u8> {
    let func = abi::Function::new("getModulesPaginated(address,uint256)");
    func.encode(&[
        AbiValue::Address(start),
        AbiValue::from_u64(page_size),
    ])
}

// ─── Safe Deployment ───────────────────────────────────────────────

/// ABI-encode `setup(address[] calldata _owners, uint256 _threshold, ...)`.
///
/// The initializer called when deploying a new Safe proxy.
#[allow(clippy::too_many_arguments)]
pub fn encode_setup(
    owners: &[[u8; 20]],
    threshold: u64,
    to: [u8; 20],
    data: &[u8],
    fallback_handler: [u8; 20],
    payment_token: [u8; 20],
    payment: u128,
    payment_receiver: [u8; 20],
) -> Vec<u8> {
    let func = abi::Function::new(
        "setup(address[],uint256,address,bytes,address,address,uint256,address)",
    );
    let owner_values: Vec<AbiValue> = owners.iter().map(|o| AbiValue::Address(*o)).collect();
    func.encode(&[
        AbiValue::Array(owner_values),
        AbiValue::from_u64(threshold),
        AbiValue::Address(to),
        AbiValue::Bytes(data.to_vec()),
        AbiValue::Address(fallback_handler),
        AbiValue::Address(payment_token),
        AbiValue::from_u128(payment),
        AbiValue::Address(payment_receiver),
    ])
}

/// ABI-encode `createProxyWithNonce(address singleton, bytes initializer, uint256 saltNonce)`.
///
/// Deploy a new Safe via the ProxyFactory.
#[must_use]
pub fn encode_create_proxy_with_nonce(
    singleton: [u8; 20],
    initializer: &[u8],
    salt_nonce: u64,
) -> Vec<u8> {
    let func = abi::Function::new("createProxyWithNonce(address,bytes,uint256)");
    func.encode(&[
        AbiValue::Address(singleton),
        AbiValue::Bytes(initializer.to_vec()),
        AbiValue::from_u64(salt_nonce),
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
    fn test_signing_hash_deterministic() {
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        assert_eq!(tx.signing_hash(&domain), tx.signing_hash(&domain));
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

    // ─── sign_and_sort ────────────────────────────────────────

    #[test]
    fn test_sign_and_sort_signatures_ordered_by_address() {
        let s1 = super::super::EthereumSigner::generate().unwrap();
        let s2 = super::super::EthereumSigner::generate().unwrap();
        let s3 = super::super::EthereumSigner::generate().unwrap();
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let sigs = sign_and_sort(&tx, &[&s1, &s2, &s3], &domain).unwrap();
        assert_eq!(sigs.len(), 3);

        // Verify addresses are sorted
        let hash = tx.signing_hash(&domain);
        let a1 = super::super::ecrecover_digest(&hash, &sigs[0]).unwrap();
        let a2 = super::super::ecrecover_digest(&hash, &sigs[1]).unwrap();
        let a3 = super::super::ecrecover_digest(&hash, &sigs[2]).unwrap();
        assert!(a1 < a2);
        assert!(a2 < a3);
    }

    #[test]
    fn test_sign_and_sort_single_signer() {
        let s1 = super::super::EthereumSigner::generate().unwrap();
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let sigs = sign_and_sort(&tx, &[&s1], &domain).unwrap();
        assert_eq!(sigs.len(), 1);
    }

    // ─── encode_signatures_sorted ─────────────────────────────

    #[test]
    fn test_encode_signatures_sorted_ecrecover() {
        let s1 = super::super::EthereumSigner::generate().unwrap();
        let s2 = super::super::EthereumSigner::generate().unwrap();
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let hash = tx.signing_hash(&domain);
        let sig1 = tx.sign(&s1, &domain).unwrap();
        let sig2 = tx.sign(&s2, &domain).unwrap();

        let packed = encode_signatures_sorted(&[sig1, sig2], &hash).unwrap();
        assert_eq!(packed.len(), 130);

        // Decode and verify sorted
        let decoded = decode_signatures(&packed).unwrap();
        let a1 = super::super::ecrecover_digest(&hash, &decoded[0]).unwrap();
        let a2 = super::super::ecrecover_digest(&hash, &decoded[1]).unwrap();
        assert!(a1 < a2);
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
            r: [0xAA; 32], s: [0xBB; 32], v: 27,
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
        assert!(calldata.len() > 4 + 10 * 32);
    }

    // ─── approveHash ──────────────────────────────────────────

    #[test]
    fn test_encode_approve_hash_selector() {
        let calldata = encode_approve_hash(&[0xAA; 32]);
        let expected = abi::function_selector("approveHash(bytes32)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 32);
    }

    #[test]
    fn test_encode_approved_hashes_selector() {
        let calldata = encode_approved_hashes([0xBB; 20], &[0xAA; 32]);
        let expected = abi::function_selector("approvedHashes(address,bytes32)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 2 * 32);
    }

    #[test]
    fn test_pre_validated_signature() {
        let owner = [0xAA; 20];
        let sig = pre_validated_signature(owner);
        assert_eq!(sig.v, 1);
        assert_eq!(&sig.r[12..32], &owner);
        assert_eq!(&sig.r[..12], &[0u8; 12]);
        assert_eq!(sig.s, [0u8; 32]);
    }

    // ─── Contract Signature ───────────────────────────────────

    #[test]
    fn test_contract_signature() {
        let contract = [0xCC; 20];
        let sig = contract_signature(contract, 130);
        assert_eq!(sig.v, 0);
        assert_eq!(&sig.r[12..32], &contract);
        assert_eq!(sig.s[28..32], 130u32.to_be_bytes());
    }

    // ─── Module Execution ─────────────────────────────────────

    #[test]
    fn test_encode_exec_from_module_selector() {
        let calldata = encode_exec_from_module(
            [0xBB; 20], &[0u8; 32], &[0xDE, 0xAD], Operation::Call,
        );
        let expected = abi::function_selector(
            "execTransactionFromModule(address,uint256,bytes,uint8)",
        );
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_exec_from_module_delegate_call() {
        let calldata = encode_exec_from_module(
            [0xBB; 20], &[0u8; 32], &[], Operation::DelegateCall,
        );
        assert!(calldata.len() > 4);
    }

    #[test]
    fn test_encode_exec_from_module_return_data_selector() {
        let calldata = encode_exec_from_module_return_data(
            [0xBB; 20], &[0u8; 32], &[], Operation::Call,
        );
        let expected = abi::function_selector(
            "execTransactionFromModuleReturnData(address,uint256,bytes,uint8)",
        );
        assert_eq!(&calldata[..4], &expected);
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

    #[test]
    fn test_encode_is_owner_selector() {
        let calldata = encode_is_owner([0xAA; 20]);
        let expected = abi::function_selector("isOwner(address)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_domain_separator_selector() {
        let calldata = encode_domain_separator();
        let expected = abi::function_selector("domainSeparator()");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_is_module_enabled_selector() {
        let calldata = encode_is_module_enabled([0xAA; 20]);
        let expected = abi::function_selector("isModuleEnabled(address)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_get_modules_paginated_selector() {
        let calldata = encode_get_modules_paginated(SENTINEL_OWNERS, 10);
        let expected = abi::function_selector("getModulesPaginated(address,uint256)");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Deployment ───────────────────────────────────────────

    #[test]
    fn test_encode_setup_selector() {
        let calldata = encode_setup(
            &[[0xAA; 20], [0xBB; 20]],
            2,
            [0u8; 20],
            &[],
            [0xCC; 20],
            [0u8; 20],
            0,
            [0u8; 20],
        );
        let expected = abi::function_selector(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
        );
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_create_proxy_with_nonce_selector() {
        let calldata = encode_create_proxy_with_nonce([0xAA; 20], &[0x01, 0x02], 42);
        let expected = abi::function_selector("createProxyWithNonce(address,bytes,uint256)");
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

    // ─── Delegate Call ────────────────────────────────────────

    #[test]
    fn test_delegate_call_transaction() {
        let mut tx = zero_tx();
        tx.operation = Operation::DelegateCall;
        tx.data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let hash = tx.signing_hash(&domain);
        assert_ne!(hash, [0u8; 32]);
    }

    // ─── Full Multi-Owner Flow ────────────────────────────────

    #[test]
    fn test_full_2_of_3_signing_flow() {
        // 3 owners, 2-of-3 threshold
        let o1 = super::super::EthereumSigner::generate().unwrap();
        let o2 = super::super::EthereumSigner::generate().unwrap();
        let o3 = super::super::EthereumSigner::generate().unwrap();

        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let tx = zero_tx();

        // Only 2 sign
        let sorted = sign_and_sort(&tx, &[&o1, &o3], &domain).unwrap();
        assert_eq!(sorted.len(), 2);

        // Build exec calldata
        let calldata = tx.encode_exec_transaction(&sorted);
        assert!(calldata.len() > 4 + 10 * 32 + 2 * 65);
    }

    // ─── Mixed Signature Types ────────────────────────────────

    #[test]
    fn test_mixed_ecdsa_and_prevalidated() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let tx = zero_tx();
        let domain = safe_domain_separator(1, &[0xAA; 20]);
        let ecdsa_sig = tx.sign(&signer, &domain).unwrap();
        let pre_sig = pre_validated_signature([0x01; 20]);

        let packed = encode_signatures(&[pre_sig, ecdsa_sig]);
        assert_eq!(packed.len(), 2 * 65);

        // First sig should be v=1 (pre-validated)
        assert_eq!(packed[64], 1);
    }
}
