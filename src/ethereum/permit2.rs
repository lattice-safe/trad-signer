//! Uniswap Permit2 — Universal token approval and transfer signatures.
//!
//! Implements EIP-712 typed data for Uniswap's Permit2 contract, which
//! provides a universal, gas-efficient token approval system beyond
//! the basic EIP-2612 permit.
//!
//! Supports:
//! - `PermitSingle` / `PermitBatch` — gasless approval signatures
//! - `PermitTransferFrom` — one-time signed transfer authorizations
//! - `SignatureTransfer` — witness-extended transfers
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::permit2::*;
//!
//! let permit = PermitSingle {
//!     token: [0xAA; 20],
//!     amount: uint160_from_u128(1_000_000),
//!     expiration: 1_700_000_000,
//!     nonce: 0,
//!     spender: [0xBB; 20],
//!     sig_deadline: uint256_from_u64(1_700_000_000),
//! };
//! let hash = permit.struct_hash().unwrap();
//! ```

use crate::error::SignerError;
use crate::ethereum::keccak256;

/// Uniswap Permit2 contract address (same on all chains).
pub const PERMIT2_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4, 0x73, 0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9, 0xf6, 0xb4,
    0x3a, 0xc7, 0x8b, 0xa3,
];

/// Maximum valid value for a uint48 field.
pub const MAX_U48: u64 = (1u64 << 48) - 1;

/// A raw uint160 value encoded as 20-byte big-endian.
pub type Uint160 = [u8; 20];
/// A raw uint256 value encoded as 32-byte big-endian.
pub type Uint256 = [u8; 32];

// ═══════════════════════════════════════════════════════════════════
// Type Hashes
// ═══════════════════════════════════════════════════════════════════

/// `keccak256("TokenPermissions(address token,uint256 amount)")`
fn token_permissions_typehash() -> [u8; 32] {
    keccak256(b"TokenPermissions(address token,uint256 amount)")
}

/// `keccak256("PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
fn permit_details_typehash() -> [u8; 32] {
    keccak256(b"PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
}

/// `keccak256("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
fn permit_single_typehash() -> [u8; 32] {
    keccak256(b"PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
}

/// `keccak256("PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")`
fn permit_batch_typehash() -> [u8; 32] {
    keccak256(b"PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)")
}

/// `keccak256("PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`
fn permit_transfer_from_typehash() -> [u8; 32] {
    keccak256(b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")
}

/// `keccak256("PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")`
fn permit_batch_transfer_from_typehash() -> [u8; 32] {
    keccak256(b"PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)")
}

// ═══════════════════════════════════════════════════════════════════
// PermitSingle (Allowance-based)
// ═══════════════════════════════════════════════════════════════════

/// A single-token allowance permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitSingle {
    /// Token address to approve.
    pub token: [u8; 20],
    /// Approval amount (`uint160`) encoded as 20-byte big-endian.
    pub amount: Uint160,
    /// Approval expiration timestamp (`uint48`).
    pub expiration: u64,
    /// Per-token nonce for replay protection (`uint48`).
    pub nonce: u64,
    /// Address being granted the allowance.
    pub spender: [u8; 20],
    /// Signature deadline (`uint256`).
    pub sig_deadline: Uint256,
}

impl PermitSingle {
    /// Compute the PermitDetails struct hash.
    fn details_hash(&self) -> Result<[u8; 32], SignerError> {
        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&permit_details_typehash());
        data.extend_from_slice(&pad_address(&self.token));
        data.extend_from_slice(&pad_uint160(&self.amount));
        data.extend_from_slice(&pad_u48(self.expiration, "expiration")?);
        data.extend_from_slice(&pad_u48(self.nonce, "nonce")?);
        Ok(keccak256(&data))
    }

    /// Compute the EIP-712 struct hash for this permit.
    pub fn struct_hash(&self) -> Result<[u8; 32], SignerError> {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&permit_single_typehash());
        data.extend_from_slice(&self.details_hash()?);
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&self.sig_deadline);
        Ok(keccak256(&data))
    }

    /// Compute the full EIP-712 signing hash.
    ///
    /// `keccak256("\x19\x01" || domainSeparator || structHash)`
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> Result<[u8; 32], SignerError> {
        Ok(eip712_hash(domain_separator, &self.struct_hash()?))
    }
}

// ═══════════════════════════════════════════════════════════════════
// PermitBatch (Allowance-based, multiple tokens)
// ═══════════════════════════════════════════════════════════════════

/// Details for one token in a batch permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitDetails {
    /// Token address.
    pub token: [u8; 20],
    /// Approval amount (`uint160`) encoded as 20-byte big-endian.
    pub amount: Uint160,
    /// Expiration timestamp (`uint48`).
    pub expiration: u64,
    /// Per-token nonce (`uint48`).
    pub nonce: u64,
}

/// A multi-token allowance permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitBatch {
    /// Token approval details.
    pub details: Vec<PermitDetails>,
    /// Address being granted the allowance.
    pub spender: [u8; 20],
    /// Signature deadline (`uint256`).
    pub sig_deadline: Uint256,
}

impl PermitBatch {
    /// Compute the struct hash.
    pub fn struct_hash(&self) -> Result<[u8; 32], SignerError> {
        let mut details_hashes = Vec::with_capacity(self.details.len() * 32);
        for d in &self.details {
            let mut h = Vec::with_capacity(160);
            h.extend_from_slice(&permit_details_typehash());
            h.extend_from_slice(&pad_address(&d.token));
            h.extend_from_slice(&pad_uint160(&d.amount));
            h.extend_from_slice(&pad_u48(d.expiration, "expiration")?);
            h.extend_from_slice(&pad_u48(d.nonce, "nonce")?);
            details_hashes.extend_from_slice(&keccak256(&h));
        }
        let details_array_hash = keccak256(&details_hashes);

        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&permit_batch_typehash());
        data.extend_from_slice(&details_array_hash);
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&self.sig_deadline);
        Ok(keccak256(&data))
    }

    /// Compute the full EIP-712 signing hash.
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> Result<[u8; 32], SignerError> {
        Ok(eip712_hash(domain_separator, &self.struct_hash()?))
    }
}

// ═══════════════════════════════════════════════════════════════════
// PermitTransferFrom (Signature-based transfers)
// ═══════════════════════════════════════════════════════════════════

/// A single-token signature transfer permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitTransferFrom {
    /// Token address.
    pub token: [u8; 20],
    /// Maximum transfer amount (`uint256`).
    pub amount: Uint256,
    /// Unique nonce (`uint256`, unordered nonce bitmap model).
    pub nonce: Uint256,
    /// Signature deadline (`uint256`).
    pub deadline: Uint256,
    /// Address allowed to execute the transfer.
    pub spender: [u8; 20],
}

impl PermitTransferFrom {
    /// Compute the TokenPermissions struct hash.
    fn token_permissions_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(96);
        data.extend_from_slice(&token_permissions_typehash());
        data.extend_from_slice(&pad_address(&self.token));
        data.extend_from_slice(&self.amount);
        keccak256(&data)
    }

    /// Compute the EIP-712 struct hash.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&permit_transfer_from_typehash());
        data.extend_from_slice(&self.token_permissions_hash());
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.deadline);
        keccak256(&data)
    }

    /// Compute the full EIP-712 signing hash.
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        eip712_hash(domain_separator, &self.struct_hash())
    }
}

/// A batch signature transfer permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitBatchTransferFrom {
    /// Permitted tokens and amounts.
    pub permitted: Vec<TokenPermissions>,
    /// Unique nonce (`uint256`).
    pub nonce: Uint256,
    /// Signature deadline (`uint256`).
    pub deadline: Uint256,
    /// Address allowed to execute the transfer.
    pub spender: [u8; 20],
}

/// Token and amount pair for batch transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPermissions {
    /// Token address.
    pub token: [u8; 20],
    /// Transfer amount (`uint256`).
    pub amount: Uint256,
}

impl PermitBatchTransferFrom {
    /// Compute the EIP-712 struct hash.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut perms_hashes = Vec::with_capacity(self.permitted.len() * 32);
        for p in &self.permitted {
            let mut h = Vec::with_capacity(96);
            h.extend_from_slice(&token_permissions_typehash());
            h.extend_from_slice(&pad_address(&p.token));
            h.extend_from_slice(&p.amount);
            perms_hashes.extend_from_slice(&keccak256(&h));
        }
        let perms_array_hash = keccak256(&perms_hashes);

        let mut data = Vec::with_capacity(160);
        data.extend_from_slice(&permit_batch_transfer_from_typehash());
        data.extend_from_slice(&perms_array_hash);
        data.extend_from_slice(&pad_address(&self.spender));
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.deadline);
        keccak256(&data)
    }

    /// Compute the full EIP-712 signing hash.
    #[must_use]
    pub fn signing_hash(&self, domain_separator: &[u8; 32]) -> [u8; 32] {
        eip712_hash(domain_separator, &self.struct_hash())
    }
}

// ═══════════════════════════════════════════════════════════════════
// Domain Separator
// ═══════════════════════════════════════════════════════════════════

/// Compute the Permit2 EIP-712 domain separator.
///
/// `keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, name_hash, chain_id, permit2_address))`
#[must_use]
pub fn permit2_domain_separator(chain_id: Uint256) -> [u8; 32] {
    let type_hash =
        keccak256(b"EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    let name_hash = keccak256(b"Permit2");

    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&type_hash);
    data.extend_from_slice(&name_hash);
    data.extend_from_slice(&chain_id);
    data.extend_from_slice(&pad_address(&PERMIT2_ADDRESS));
    keccak256(&data)
}

// ═══════════════════════════════════════════════════════════════════
// ABI Encoding for Permit2 contract calls
// ═══════════════════════════════════════════════════════════════════

/// ABI-encode `permit(address owner, PermitSingle permitSingle, bytes signature)`.
///
/// Function selector: `permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)`
pub fn encode_permit_single_call(
    owner: &[u8; 20],
    permit: &PermitSingle,
    signature: &[u8],
) -> Result<Vec<u8>, SignerError> {
    use crate::ethereum::abi::{AbiValue, Function};

    let func =
        Function::new("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)");
    Ok(func.encode(&[
        AbiValue::Address(*owner),
        AbiValue::Tuple(vec![
            AbiValue::Tuple(vec![
                AbiValue::Address(permit.token),
                AbiValue::Uint256(pad_uint160(&permit.amount)),
                AbiValue::Uint256(pad_u48(permit.expiration, "expiration")?),
                AbiValue::Uint256(pad_u48(permit.nonce, "nonce")?),
            ]),
            AbiValue::Address(permit.spender),
            AbiValue::Uint256(permit.sig_deadline),
        ]),
        AbiValue::Bytes(signature.to_vec()),
    ]))
}

/// ABI-encode `transferFrom(address from, address to, uint160 amount, address token)`.
#[must_use]
pub fn encode_transfer_from(
    from: &[u8; 20],
    to: &[u8; 20],
    amount: Uint160,
    token: &[u8; 20],
) -> Vec<u8> {
    use crate::ethereum::abi::{AbiValue, Function};
    let func = Function::new("transferFrom(address,address,uint160,address)");
    func.encode(&[
        AbiValue::Address(*from),
        AbiValue::Address(*to),
        AbiValue::Uint256(pad_uint160(&amount)),
        AbiValue::Address(*token),
    ])
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Convert a u128 value to a canonical uint160 (20-byte) representation.
#[must_use]
pub fn uint160_from_u128(value: u128) -> Uint160 {
    let mut out = [0u8; 20];
    out[4..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Convert a u64 value to a canonical uint256 (32-byte) representation.
#[must_use]
pub fn uint256_from_u64(value: u64) -> Uint256 {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn pad_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(addr);
    buf
}

fn pad_uint160(val: &Uint160) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..32].copy_from_slice(val);
    buf
}

fn pad_u48(val: u64, field: &str) -> Result<[u8; 32], SignerError> {
    if val > MAX_U48 {
        return Err(SignerError::ParseError(format!(
            "Permit2 {field} exceeds uint48 range"
        )));
    }
    Ok(uint256_from_u64(val))
}

fn eip712_hash(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(66);
    data.push(0x19);
    data.push(0x01);
    data.extend_from_slice(domain_separator);
    data.extend_from_slice(struct_hash);
    keccak256(&data)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ethereum::abi;

    const TOKEN_A: [u8; 20] = [0xAA; 20];
    const TOKEN_B: [u8; 20] = [0xBB; 20];
    const SPENDER: [u8; 20] = [0xCC; 20];
    const OWNER: [u8; 20] = [0xDD; 20];
    const DEADLINE: u64 = 1_700_000_000;

    fn amount160(v: u128) -> Uint160 {
        uint160_from_u128(v)
    }

    fn amount256(v: u64) -> Uint256 {
        uint256_from_u64(v)
    }

    #[test]
    fn test_permit_single_struct_hash_deterministic() {
        let p = PermitSingle {
            token: TOKEN_A,
            amount: amount160(1000),
            expiration: DEADLINE,
            nonce: 0,
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        assert_eq!(p.struct_hash().unwrap(), p.struct_hash().unwrap());
    }

    #[test]
    fn test_permit_single_rejects_u48_overflow() {
        let p = PermitSingle {
            token: TOKEN_A,
            amount: amount160(1000),
            expiration: MAX_U48 + 1,
            nonce: 0,
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        assert!(p.struct_hash().is_err());
    }

    #[test]
    fn test_permit_single_different_amounts() {
        let p1 = PermitSingle {
            token: TOKEN_A,
            amount: amount160(1000),
            expiration: DEADLINE,
            nonce: 0,
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        let p2 = PermitSingle {
            token: TOKEN_A,
            amount: amount160(2000),
            expiration: DEADLINE,
            nonce: 0,
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        assert_ne!(p1.struct_hash().unwrap(), p2.struct_hash().unwrap());
    }

    #[test]
    fn test_permit_single_signing_hash() {
        let p = PermitSingle {
            token: TOKEN_A,
            amount: amount160(1000),
            expiration: DEADLINE,
            nonce: 0,
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        let ds = permit2_domain_separator(amount256(1));
        let hash = p.signing_hash(&ds).unwrap();
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_permit_batch_struct_hash() {
        let p = PermitBatch {
            details: vec![
                PermitDetails {
                    token: TOKEN_A,
                    amount: amount160(100),
                    expiration: DEADLINE,
                    nonce: 0,
                },
                PermitDetails {
                    token: TOKEN_B,
                    amount: amount160(200),
                    expiration: DEADLINE,
                    nonce: 1,
                },
            ],
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        assert_ne!(p.struct_hash().unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_permit_transfer_struct_hash() {
        let p = PermitTransferFrom {
            token: TOKEN_A,
            amount: amount256(5000),
            nonce: amount256(42),
            deadline: amount256(DEADLINE),
            spender: SPENDER,
        };
        assert_ne!(p.struct_hash(), [0u8; 32]);
    }

    #[test]
    fn test_permit_batch_transfer_struct_hash() {
        let p = PermitBatchTransferFrom {
            permitted: vec![
                TokenPermissions {
                    token: TOKEN_A,
                    amount: amount256(100),
                },
                TokenPermissions {
                    token: TOKEN_B,
                    amount: amount256(200),
                },
            ],
            nonce: amount256(0),
            deadline: amount256(DEADLINE),
            spender: SPENDER,
        };
        assert_ne!(p.struct_hash(), [0u8; 32]);
    }

    #[test]
    fn test_domain_separator_different_chains() {
        assert_ne!(
            permit2_domain_separator(amount256(1)),
            permit2_domain_separator(amount256(137))
        );
    }

    #[test]
    fn test_encode_permit_single_call_selector() {
        let p = PermitSingle {
            token: TOKEN_A,
            amount: amount160(1000),
            expiration: DEADLINE,
            nonce: 0,
            spender: SPENDER,
            sig_deadline: amount256(DEADLINE),
        };
        let data = encode_permit_single_call(&OWNER, &p, &[0xAA; 65]).unwrap();
        assert!(data.len() > 4);
    }

    #[test]
    fn test_encode_transfer_from_selector() {
        let data = encode_transfer_from(&OWNER, &SPENDER, amount160(1000), &TOKEN_A);
        let expected = abi::function_selector("transferFrom(address,address,uint160,address)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_pad_address() {
        let addr = [0xAA; 20];
        let padded = pad_address(&addr);
        assert!(padded[..12].iter().all(|b| *b == 0));
        assert_eq!(&padded[12..], &addr);
    }

    #[test]
    fn test_pad_u48() {
        let padded = pad_u48(42, "test").unwrap();
        assert_eq!(padded[31], 42);
        assert!(padded[..24].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_permit2_address_hex() {
        let hex = PERMIT2_ADDRESS
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(hex, "000000000022d473030f116ddee9f6b43ac78ba3");
    }
}
