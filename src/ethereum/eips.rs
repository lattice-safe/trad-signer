//! Additional Ethereum EIP helpers for signing-related standards.
//!
//! Provides encoding helpers for EIPs that involve message construction
//! or data formatting at the signing layer:
//!
//! - **EIP-2612**: ERC-20 Permit (gasless approve via EIP-712)
//! - **EIP-4337**: Account Abstraction UserOperation
//! - **EIP-7702**: Set EOA Account Code authorization
//! - **EIP-3074**: AUTH/AUTHCALL message digest
//! - **EIP-6492**: Pre-deploy contract signature wrapping
//! - **EIP-5267**: EIP-712 domain query calldata
//! - **EIP-2335**: BLS12-381 keystore path constants

use crate::error::SignerError;
use sha3::{Digest, Keccak256};

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

// ═══════════════════════════════════════════════════════════════════
// EIP-2612: Permit (ERC-20 Gasless Approve)
// ═══════════════════════════════════════════════════════════════════

/// EIP-2612 Permit message for gasless ERC-20 token approvals.
///
/// This constructs the EIP-712 typed data that the token holder signs,
/// allowing a third party to call `permit()` on the ERC-20 contract.
#[derive(Debug, Clone)]
pub struct Permit {
    /// Token holder granting approval.
    pub owner: [u8; 20],
    /// Address being approved to spend tokens.
    pub spender: [u8; 20],
    /// Amount of tokens to approve (as 32-byte big-endian uint256).
    pub value: [u8; 32],
    /// Current nonce of the owner on the token contract.
    pub nonce: u64,
    /// Unix timestamp deadline for the permit signature.
    pub deadline: u64,
}

impl Permit {
    /// Compute the EIP-712 `PERMIT_TYPEHASH`.
    ///
    /// `keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")`
    #[must_use]
    pub fn type_hash() -> [u8; 32] {
        keccak256(b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    }

    /// Compute the struct hash for this permit.
    ///
    /// `keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline))`
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(6 * 32);
        data.extend_from_slice(&Self::type_hash());

        // owner (left-padded to 32)
        let mut owner_padded = [0u8; 32];
        owner_padded[12..].copy_from_slice(&self.owner);
        data.extend_from_slice(&owner_padded);

        // spender (left-padded to 32)
        let mut spender_padded = [0u8; 32];
        spender_padded[12..].copy_from_slice(&self.spender);
        data.extend_from_slice(&spender_padded);

        // value (already 32 bytes)
        data.extend_from_slice(&self.value);

        // nonce
        let mut nonce_buf = [0u8; 32];
        nonce_buf[24..].copy_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&nonce_buf);

        // deadline
        let mut deadline_buf = [0u8; 32];
        deadline_buf[24..].copy_from_slice(&self.deadline.to_be_bytes());
        data.extend_from_slice(&deadline_buf);

        keccak256(&data)
    }

    /// Compute the EIP-712 signing hash for this permit.
    ///
    /// `keccak256("\x19\x01" || domain_separator || struct_hash)`
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(2 + 32 + 32);
        buf.push(0x19);
        buf.push(0x01);
        buf.extend_from_slice(domain_separator);
        buf.extend_from_slice(&self.struct_hash());
        keccak256(&buf)
    }

    /// Sign this permit with the given signer.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
        domain_separator: &[u8; 32],
    ) -> Result<super::EthereumSignature, SignerError> {
        let hash = self.signing_hash(domain_separator);
        signer.sign_digest(&hash)
    }
}

// ═══════════════════════════════════════════════════════════════════
// EIP-4337: Account Abstraction UserOperation
// ═══════════════════════════════════════════════════════════════════

/// EIP-4337 UserOperation for account abstraction wallets.
///
/// This struct represents a user operation that gets submitted to a bundler
/// instead of a regular transaction.
#[derive(Debug, Clone)]
pub struct UserOperation {
    /// The account making the operation.
    pub sender: [u8; 20],
    /// Anti-replay nonce.
    pub nonce: [u8; 32],
    /// Contract creation code + calldata (for new accounts).
    pub init_code: Vec<u8>,
    /// The calldata to execute on the sender account.
    pub call_data: Vec<u8>,
    /// Gas limit for the execution phase.
    pub call_gas_limit: [u8; 32],
    /// Gas limit for verification.
    pub verification_gas_limit: [u8; 32],
    /// Gas for pre-verification (bundler overhead).
    pub pre_verification_gas: [u8; 32],
    /// Maximum fee per gas.
    pub max_fee_per_gas: [u8; 32],
    /// Maximum priority fee per gas.
    pub max_priority_fee_per_gas: [u8; 32],
    /// Paymaster address + data (empty if self-paying).
    pub paymaster_and_data: Vec<u8>,
}

impl UserOperation {
    /// Pack the UserOperation for hashing (without signature).
    ///
    /// Returns the ABI-encoded hash input as specified in EIP-4337.
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(320);

        // sender (left-padded to 32)
        let mut sender_buf = [0u8; 32];
        sender_buf[12..].copy_from_slice(&self.sender);
        data.extend_from_slice(&sender_buf);

        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&keccak256(&self.init_code));
        data.extend_from_slice(&keccak256(&self.call_data));
        data.extend_from_slice(&self.call_gas_limit);
        data.extend_from_slice(&self.verification_gas_limit);
        data.extend_from_slice(&self.pre_verification_gas);
        data.extend_from_slice(&self.max_fee_per_gas);
        data.extend_from_slice(&self.max_priority_fee_per_gas);
        data.extend_from_slice(&keccak256(&self.paymaster_and_data));

        data
    }

    /// Compute the UserOperation hash.
    ///
    /// `keccak256(abi.encode(pack(userOp), entryPoint, chainId))`
    #[must_use]
    pub fn hash(&self, entry_point: &[u8; 20], chain_id: u64) -> [u8; 32] {
        let packed_hash = keccak256(&self.pack());
        let mut data = Vec::with_capacity(3 * 32);
        data.extend_from_slice(&packed_hash);

        let mut ep_buf = [0u8; 32];
        ep_buf[12..].copy_from_slice(entry_point);
        data.extend_from_slice(&ep_buf);

        let mut chain_buf = [0u8; 32];
        chain_buf[24..].copy_from_slice(&chain_id.to_be_bytes());
        data.extend_from_slice(&chain_buf);

        keccak256(&data)
    }

    /// Sign this UserOperation.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
        entry_point: &[u8; 20],
        chain_id: u64,
    ) -> Result<super::EthereumSignature, SignerError> {
        let hash = self.hash(entry_point, chain_id);
        // EIP-191 personal_sign style hashing for the final signature
        let eth_hash = eth_signed_message_hash(&hash);
        signer.sign_digest(&eth_hash)
    }
}

fn eth_signed_message_hash(hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(28 + 32);
    buf.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    buf.extend_from_slice(hash);
    keccak256(&buf)
}

// ═══════════════════════════════════════════════════════════════════
// EIP-7702: Set EOA Account Code
// ═══════════════════════════════════════════════════════════════════

/// EIP-7702 authorization for setting EOA account code.
///
/// An EOA signs an authorization allowing its account to be temporarily
/// delegated to a contract implementation.
#[derive(Debug, Clone)]
pub struct Eip7702Authorization {
    /// Chain ID this authorization is valid for (0 = any chain).
    pub chain_id: u64,
    /// Contract address to delegate to.
    pub address: [u8; 20],
    /// Authorization nonce.
    pub nonce: u64,
}

impl Eip7702Authorization {
    /// The EIP-7702 authorization magic.
    pub const MAGIC: u8 = 0x05;

    /// Compute the signing hash for this authorization.
    ///
    /// `keccak256(MAGIC || RLP([chain_id, address, nonce]))`
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        use super::rlp;
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_bytes(&self.address));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        let rlp_data = rlp::encode_list(&items);

        let mut payload = vec![Self::MAGIC];
        payload.extend_from_slice(&rlp_data);
        keccak256(&payload)
    }

    /// Sign this authorization.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
    ) -> Result<super::EthereumSignature, SignerError> {
        let hash = self.signing_hash();
        signer.sign_digest(&hash)
    }
}

// ═══════════════════════════════════════════════════════════════════
// EIP-3074: AUTH Message Hash
// ═══════════════════════════════════════════════════════════════════

/// EIP-3074 AUTH message for authorizing an invoker contract.
///
/// The AUTH opcode verifies this signature to authorize the invoker
/// to act on behalf of the signer.
#[derive(Debug, Clone)]
pub struct AuthMessage {
    /// The invoker contract address.
    pub invoker: [u8; 20],
    /// Commit hash (application-specific commitment).
    pub commit: [u8; 32],
}

impl AuthMessage {
    /// The EIP-3074 AUTH magic byte.
    pub const MAGIC: u8 = 0x04;

    /// Compute the AUTH signing hash.
    ///
    /// `keccak256(MAGIC || pad32(chainId) || pad32(nonce) || pad32(invoker) || commit)`
    ///
    /// Note: In production, `chain_id` and `nonce` come from the EVM context.
    /// This method accepts them as parameters for flexibility.
    #[must_use]
    pub fn signing_hash(&self, chain_id: u64, nonce: u64) -> [u8; 32] {
        let mut buf = Vec::with_capacity(1 + 4 * 32);
        buf.push(Self::MAGIC);

        // chain_id padded to 32 bytes
        let mut chain_buf = [0u8; 32];
        chain_buf[24..].copy_from_slice(&chain_id.to_be_bytes());
        buf.extend_from_slice(&chain_buf);

        // nonce padded to 32 bytes
        let mut nonce_buf = [0u8; 32];
        nonce_buf[24..].copy_from_slice(&nonce.to_be_bytes());
        buf.extend_from_slice(&nonce_buf);

        // invoker padded to 32 bytes
        let mut invoker_buf = [0u8; 32];
        invoker_buf[12..].copy_from_slice(&self.invoker);
        buf.extend_from_slice(&invoker_buf);

        // commit (32 bytes)
        buf.extend_from_slice(&self.commit);

        keccak256(&buf)
    }

    /// Sign the AUTH message.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
        chain_id: u64,
        nonce: u64,
    ) -> Result<super::EthereumSignature, SignerError> {
        let hash = self.signing_hash(chain_id, nonce);
        signer.sign_digest(&hash)
    }
}

// ═══════════════════════════════════════════════════════════════════
// EIP-6492: Pre-deploy Contract Signatures
// ═══════════════════════════════════════════════════════════════════

/// EIP-6492 magic suffix bytes appended to wrapped signatures.
pub const EIP6492_MAGIC: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

/// Wrap a signature with EIP-6492 format for pre-deploy contract wallets.
///
/// Format: `abi.encode(create2Factory, factoryCalldata, originalSig) ++ magicBytes`
///
/// This allows verification of signatures from smart contract wallets
/// that haven't been deployed yet (counterfactual wallets).
#[must_use]
pub fn wrap_eip6492_signature(
    create2_factory: &[u8; 20],
    factory_calldata: &[u8],
    original_signature: &[u8],
) -> Vec<u8> {
    use super::abi::{self, AbiValue};
    let mut encoded = abi::encode(&[
        AbiValue::Address(*create2_factory),
        AbiValue::Bytes(factory_calldata.to_vec()),
        AbiValue::Bytes(original_signature.to_vec()),
    ]);
    encoded.extend_from_slice(&EIP6492_MAGIC);
    encoded
}

/// Check if a signature is EIP-6492 wrapped.
#[must_use]
pub fn is_eip6492_signature(signature: &[u8]) -> bool {
    signature.len() > 32 && signature[signature.len() - 32..] == EIP6492_MAGIC
}

/// Unwrap an EIP-6492 signature, returning the inner data without the magic suffix.
///
/// The caller is responsible for ABI-decoding the result to extract
/// `(address factory, bytes factoryCalldata, bytes originalSig)`.
pub fn unwrap_eip6492_signature(signature: &[u8]) -> Result<&[u8], SignerError> {
    if !is_eip6492_signature(signature) {
        return Err(SignerError::ParseError("not an EIP-6492 signature".into()));
    }
    Ok(&signature[..signature.len() - 32])
}

// ═══════════════════════════════════════════════════════════════════
// EIP-5267: EIP-712 Domain Retrieval
// ═══════════════════════════════════════════════════════════════════

/// Encode the `eip712Domain()` function call for EIP-5267.
///
/// Returns the ABI-encoded calldata to query a contract's EIP-712 domain.
/// The response contains: `(bytes1 fields, string name, string version,
/// uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)`.
#[must_use]
pub fn encode_eip712_domain_call() -> Vec<u8> {
    // Function selector: keccak256("eip712Domain()")[..4] = 0x84b0196e
    let selector = &keccak256(b"eip712Domain()")[..4];
    selector.to_vec()
}

/// The function selector for `eip712Domain()` (EIP-5267).
pub const EIP5267_SELECTOR: [u8; 4] = [0x84, 0xb0, 0x19, 0x6e];

// ═══════════════════════════════════════════════════════════════════
// EIP-2335: BLS12-381 Keystore Constants
// ═══════════════════════════════════════════════════════════════════

/// Standard BLS12-381 key derivation paths (EIP-2334).
pub mod bls_paths {
    /// Withdrawal key path: `m/12381/3600/{validator_index}/0`
    pub fn withdrawal(validator_index: u32) -> Vec<u32> {
        vec![12381, 3600, validator_index, 0]
    }

    /// Signing key path: `m/12381/3600/{validator_index}/0/0`
    pub fn signing(validator_index: u32) -> Vec<u32> {
        vec![12381, 3600, validator_index, 0, 0]
    }
}

/// EIP-2335 keystore version constant.
pub const EIP2335_VERSION: u32 = 4;

/// EIP-2335 keystore description type.
pub const EIP2335_KDF: &str = "scrypt";
pub const EIP2335_CIPHER: &str = "aes-128-ctr";
pub const EIP2335_CHECKSUM: &str = "sha256";

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    // ─── EIP-2612 Permit ───────────────────────────────────────────

    #[test]
    fn test_permit_type_hash() {
        let hash = Permit::type_hash();
        assert_eq!(
            hex::encode(hash),
            "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9"
        );
    }

    #[test]
    fn test_permit_struct_hash_deterministic() {
        let permit = Permit {
            owner: [0xAA; 20],
            spender: [0xBB; 20],
            value: [0; 32],
            nonce: 0,
            deadline: u64::MAX,
        };
        assert_eq!(permit.struct_hash(), permit.struct_hash());
    }

    #[test]
    fn test_permit_sign_roundtrip() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let permit = Permit {
            owner: signer.address(),
            spender: [0xBB; 20],
            value: {
                let mut v = [0u8; 32];
                v[31] = 100;
                v
            },
            nonce: 0,
            deadline: u64::MAX,
        };
        let domain = [0xCC; 32]; // mock domain separator
        let sig = permit.sign(&signer, &domain).unwrap();
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
    }

    // ─── EIP-4337 UserOperation ────────────────────────────────────

    #[test]
    fn test_user_op_hash_deterministic() {
        let op = UserOperation {
            sender: [0xAA; 20],
            nonce: [0; 32],
            init_code: vec![],
            call_data: vec![0x01, 0x02],
            call_gas_limit: [0; 32],
            verification_gas_limit: [0; 32],
            pre_verification_gas: [0; 32],
            max_fee_per_gas: [0; 32],
            max_priority_fee_per_gas: [0; 32],
            paymaster_and_data: vec![],
        };
        let entry_point = [0xBB; 20];
        let h1 = op.hash(&entry_point, 1);
        let h2 = op.hash(&entry_point, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_user_op_different_chain_different_hash() {
        let op = UserOperation {
            sender: [0xAA; 20],
            nonce: [0; 32],
            init_code: vec![],
            call_data: vec![],
            call_gas_limit: [0; 32],
            verification_gas_limit: [0; 32],
            pre_verification_gas: [0; 32],
            max_fee_per_gas: [0; 32],
            max_priority_fee_per_gas: [0; 32],
            paymaster_and_data: vec![],
        };
        let ep = [0xBB; 20];
        assert_ne!(op.hash(&ep, 1), op.hash(&ep, 5));
    }

    #[test]
    fn test_user_op_sign() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let op = UserOperation {
            sender: signer.address(),
            nonce: [0; 32],
            init_code: vec![],
            call_data: vec![],
            call_gas_limit: [0; 32],
            verification_gas_limit: [0; 32],
            pre_verification_gas: [0; 32],
            max_fee_per_gas: [0; 32],
            max_priority_fee_per_gas: [0; 32],
            paymaster_and_data: vec![],
        };
        let sig = op.sign(&signer, &[0x55; 20], 1).unwrap();
        assert_eq!(sig.r.len(), 32);
    }

    // ─── EIP-7702 Authorization ────────────────────────────────────

    #[test]
    fn test_eip7702_signing_hash_deterministic() {
        let auth = Eip7702Authorization {
            chain_id: 1,
            address: [0xCC; 20],
            nonce: 0,
        };
        assert_eq!(auth.signing_hash(), auth.signing_hash());
    }

    #[test]
    fn test_eip7702_different_chain_different_hash() {
        let auth1 = Eip7702Authorization { chain_id: 1, address: [0xCC; 20], nonce: 0 };
        let auth2 = Eip7702Authorization { chain_id: 5, address: [0xCC; 20], nonce: 0 };
        assert_ne!(auth1.signing_hash(), auth2.signing_hash());
    }

    #[test]
    fn test_eip7702_sign() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let auth = Eip7702Authorization {
            chain_id: 1,
            address: [0xDD; 20],
            nonce: 42,
        };
        let sig = auth.sign(&signer).unwrap();
        assert!(sig.v == 27 || sig.v == 28);
    }

    // ─── EIP-3074 AUTH ─────────────────────────────────────────────

    #[test]
    fn test_auth_message_hash_deterministic() {
        let msg = AuthMessage {
            invoker: [0xEE; 20],
            commit: [0xFF; 32],
        };
        assert_eq!(msg.signing_hash(1, 0), msg.signing_hash(1, 0));
    }

    #[test]
    fn test_auth_message_different_nonce() {
        let msg = AuthMessage { invoker: [0xEE; 20], commit: [0xFF; 32] };
        assert_ne!(msg.signing_hash(1, 0), msg.signing_hash(1, 1));
    }

    #[test]
    fn test_auth_message_sign() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let msg = AuthMessage { invoker: [0xAA; 20], commit: [0xBB; 32] };
        let sig = msg.sign(&signer, 1, 0).unwrap();
        assert!(sig.v == 27 || sig.v == 28);
    }

    // ─── EIP-6492 ──────────────────────────────────────────────────

    #[test]
    fn test_eip6492_wrap_unwrap() {
        let factory = [0xAA; 20];
        let calldata = vec![0xBB; 64];
        let sig = vec![0xCC; 65];
        let wrapped = wrap_eip6492_signature(&factory, &calldata, &sig);
        assert!(is_eip6492_signature(&wrapped));
        let inner = unwrap_eip6492_signature(&wrapped).unwrap();
        assert!(!inner.is_empty());
    }

    #[test]
    fn test_eip6492_not_wrapped() {
        let plain_sig = vec![0x00; 65];
        assert!(!is_eip6492_signature(&plain_sig));
    }

    // ─── EIP-5267 ──────────────────────────────────────────────────

    #[test]
    fn test_eip5267_selector() {
        let calldata = encode_eip712_domain_call();
        assert_eq!(calldata, EIP5267_SELECTOR);
    }

    // ─── EIP-2335 BLS Paths ────────────────────────────────────────

    #[test]
    fn test_bls_signing_path() {
        let path = bls_paths::signing(0);
        assert_eq!(path, vec![12381, 3600, 0, 0, 0]);
    }

    #[test]
    fn test_bls_withdrawal_path() {
        let path = bls_paths::withdrawal(5);
        assert_eq!(path, vec![12381, 3600, 5, 0]);
    }
}
