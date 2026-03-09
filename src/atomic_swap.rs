//! Cross-chain Atomic Swap primitives using Hash Time-Locked Contracts (HTLC).
//!
//! Provides the building blocks for trustless cross-chain swaps:
//! - Swap secret generation and verification
//! - Bitcoin HTLC redeem scripts (P2WSH-compatible)
//! - Ethereum HTLC ABI-encoded function calls
//! - Timelock management
//!
//! # Example
//! ```no_run
//! use chains_sdk::atomic_swap::*;
//!
//! let secret = SwapSecret::generate();
//! let params = HtlcParams {
//!     hash_lock: secret.hash,
//!     time_lock: 1_700_000_000,
//!     sender: [0xAA; 20],
//!     receiver: [0xBB; 20],
//! };
//!
//! // Bitcoin side
//! let btc_script = build_bitcoin_htlc_script(&secret.hash, 500_000, &[0x02; 33], &[0x03; 33]);
//!
//! // Ethereum side
//! let lock_data = encode_eth_htlc_lock(&params);
//! let claim_data = encode_eth_htlc_claim(&secret.preimage);
//! ```

use crate::crypto;
use crate::error::SignerError;
use crate::ethereum::abi::{self, AbiValue};
use crate::security;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ═══════════════════════════════════════════════════════════════════
// Bitcoin Script Opcodes (HTLC subset)
// ═══════════════════════════════════════════════════════════════════

const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_SHA256: u8 = 0xa8;
const OP_CHECKSIG: u8 = 0xac;
const OP_CLTV: u8 = 0xb1; // OP_CHECKLOCKTIMEVERIFY
const OP_CSV: u8 = 0xb2;  // OP_CHECKSEQUENCEVERIFY

// ═══════════════════════════════════════════════════════════════════
// Swap Secret
// ═══════════════════════════════════════════════════════════════════

/// A swap secret: 32-byte preimage and its SHA-256 hash.
///
/// The preimage is zeroized from memory when this struct is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SwapSecret {
    /// The 32-byte secret preimage (keep private until claiming).
    pub preimage: [u8; 32],
    /// SHA-256 hash of the preimage (publicly shared as the hash lock).
    #[zeroize(skip)]
    pub hash: [u8; 32],
}

impl SwapSecret {
    /// Generate a new cryptographically secure swap secret.
    ///
    /// # Errors
    /// Returns `SignerError` if the system RNG fails (e.g., entropy exhaustion).
    pub fn generate() -> Result<Self, SignerError> {
        let mut preimage = [0u8; 32];
        security::secure_random(&mut preimage)?;
        let hash = crypto::sha256(&preimage);
        Ok(Self { preimage, hash })
    }

    /// Create a swap secret from a known preimage.
    #[must_use]
    pub fn from_preimage(preimage: [u8; 32]) -> Self {
        let hash = crypto::sha256(&preimage);
        Self { preimage, hash }
    }

    /// Verify that a preimage matches the expected hash.
    #[must_use]
    pub fn verify(preimage: &[u8; 32], expected_hash: &[u8; 32]) -> bool {
        let computed = crypto::sha256(preimage);
        // Use constant-time comparison to avoid timing attacks
        ct_eq(&computed, expected_hash)
    }
}

/// Constant-time byte comparison.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ═══════════════════════════════════════════════════════════════════
// HTLC Parameters
// ═══════════════════════════════════════════════════════════════════

/// Parameters for an HTLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HtlcParams {
    /// SHA-256 hash lock (32 bytes).
    pub hash_lock: [u8; 32],
    /// Absolute timelock (Unix timestamp or block height).
    pub time_lock: u64,
    /// Sender address (refund path).
    pub sender: [u8; 20],
    /// Receiver address (claim path).
    pub receiver: [u8; 20],
}

/// Check if a timelock has expired.
///
/// Returns `true` if `current_time >= time_lock`.
#[must_use]
pub fn is_expired(time_lock: u64, current_time: u64) -> bool {
    current_time >= time_lock
}

// ═══════════════════════════════════════════════════════════════════
// Bitcoin HTLC Script
// ═══════════════════════════════════════════════════════════════════

/// Build a Bitcoin HTLC redeem script (P2WSH-compatible).
///
/// ```text
/// OP_IF
///   OP_SHA256 <hash_lock> OP_EQUALVERIFY
///   <receiver_pubkey> OP_CHECKSIG
/// OP_ELSE
///   <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
///   <sender_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
///
/// The claim path (OP_IF) requires the preimage + receiver signature.
/// The refund path (OP_ELSE) requires the timelock to expire + sender signature.
#[must_use]
pub fn build_bitcoin_htlc_script(
    hash_lock: &[u8; 32],
    locktime: u32,
    receiver_pubkey: &[u8; 33],
    sender_pubkey: &[u8; 33],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(128);

    // Claim path
    script.push(OP_IF);
    script.push(OP_SHA256);
    script.push(32); // push 32 bytes
    script.extend_from_slice(hash_lock);
    script.push(OP_EQUALVERIFY);
    script.push(33); // push 33 bytes
    script.extend_from_slice(receiver_pubkey);
    script.push(OP_CHECKSIG);

    // Refund path
    script.push(OP_ELSE);
    push_script_number(&mut script, locktime as i64);
    script.push(OP_CLTV);
    script.push(OP_DROP);
    script.push(33);
    script.extend_from_slice(sender_pubkey);
    script.push(OP_CHECKSIG);

    script.push(OP_ENDIF);

    script
}

/// Build a Bitcoin HTLC script using relative timelock (CSV).
///
/// Similar to the CLTV version but uses `OP_CHECKSEQUENCEVERIFY`
/// for relative timelocks (number of blocks since confirmation).
#[must_use]
pub fn build_bitcoin_htlc_csv_script(
    hash_lock: &[u8; 32],
    sequence: u32,
    receiver_pubkey: &[u8; 33],
    sender_pubkey: &[u8; 33],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(128);

    script.push(OP_IF);
    script.push(OP_SHA256);
    script.push(32);
    script.extend_from_slice(hash_lock);
    script.push(OP_EQUALVERIFY);
    script.push(33);
    script.extend_from_slice(receiver_pubkey);
    script.push(OP_CHECKSIG);

    script.push(OP_ELSE);
    push_script_number(&mut script, sequence as i64);
    script.push(OP_CSV);
    script.push(OP_DROP);
    script.push(33);
    script.extend_from_slice(sender_pubkey);
    script.push(OP_CHECKSIG);

    script.push(OP_ENDIF);

    script
}

/// Build the claim witness for a Bitcoin HTLC.
///
/// Returns `[signature, preimage, OP_TRUE, redeem_script]`.
#[must_use]
pub fn build_btc_claim_witness(
    signature: &[u8],
    preimage: &[u8; 32],
    redeem_script: &[u8],
) -> Vec<Vec<u8>> {
    vec![
        signature.to_vec(),
        preimage.to_vec(),
        vec![0x01], // OP_TRUE — select the IF branch
        redeem_script.to_vec(),
    ]
}

/// Build the refund witness for a Bitcoin HTLC.
///
/// Returns `[signature, OP_FALSE, redeem_script]`.
#[must_use]
pub fn build_btc_refund_witness(
    signature: &[u8],
    redeem_script: &[u8],
) -> Vec<Vec<u8>> {
    vec![
        signature.to_vec(),
        vec![], // empty = OP_FALSE — select the ELSE branch
        redeem_script.to_vec(),
    ]
}

/// Compute the P2WSH script hash for an HTLC redeem script.
///
/// `OP_0 <SHA256(redeem_script)>` — the scriptPubKey for P2WSH.
#[must_use]
pub fn htlc_script_pubkey(redeem_script: &[u8]) -> Vec<u8> {
    let hash = crypto::sha256(redeem_script);
    let mut spk = Vec::with_capacity(34);
    spk.push(0x00); // witness version 0
    spk.push(32);   // push 32 bytes
    spk.extend_from_slice(&hash);
    spk
}

// ═══════════════════════════════════════════════════════════════════
// Ethereum HTLC ABI Encoding
// ═══════════════════════════════════════════════════════════════════

/// ABI-encode an Ethereum HTLC `lock(bytes32 hashLock, uint256 timelock, address receiver)`.
#[must_use]
pub fn encode_eth_htlc_lock(params: &HtlcParams) -> Vec<u8> {
    let lock_fn = abi::Function::new("lock(bytes32,uint256,address)");
    lock_fn.encode(&[
        AbiValue::Uint256(params.hash_lock),
        AbiValue::from_u64(params.time_lock),
        AbiValue::Address(params.receiver),
    ])
}

/// ABI-encode an Ethereum HTLC `claim(bytes32 preimage)`.
#[must_use]
pub fn encode_eth_htlc_claim(preimage: &[u8; 32]) -> Vec<u8> {
    let claim_fn = abi::Function::new("claim(bytes32)");
    claim_fn.encode(&[AbiValue::Uint256(*preimage)])
}

/// ABI-encode an Ethereum HTLC `refund(bytes32 hashLock)`.
#[must_use]
pub fn encode_eth_htlc_refund(hash_lock: &[u8; 32]) -> Vec<u8> {
    let refund_fn = abi::Function::new("refund(bytes32)");
    refund_fn.encode(&[AbiValue::Uint256(*hash_lock)])
}

/// ABI-encode an ERC-20 HTLC `lockTokens(address token, bytes32 hashLock, uint256 timelock, address receiver, uint256 amount)`.
#[must_use]
pub fn encode_eth_htlc_lock_tokens(
    token: &[u8; 20],
    params: &HtlcParams,
    amount: u64,
) -> Vec<u8> {
    let lock_fn = abi::Function::new("lockTokens(address,bytes32,uint256,address,uint256)");
    lock_fn.encode(&[
        AbiValue::Address(*token),
        AbiValue::Uint256(params.hash_lock),
        AbiValue::from_u64(params.time_lock),
        AbiValue::Address(params.receiver),
        AbiValue::from_u64(amount),
    ])
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Push a number in Bitcoin's minimal script number encoding.
fn push_script_number(script: &mut Vec<u8>, n: i64) {
    if n == 0 {
        script.push(0x00);
        return;
    }
    if (1..=16).contains(&n) {
        script.push(0x50 + n as u8);
        return;
    }

    let negative = n < 0;
    let mut abs_n = if negative { (-n) as u64 } else { n as u64 };
    let mut bytes = Vec::new();

    while abs_n > 0 {
        bytes.push((abs_n & 0xFF) as u8);
        abs_n >>= 8;
    }

    if bytes.last().is_some_and(|b| b & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = bytes.len() - 1;
        bytes[last] |= 0x80;
    }

    script.push(bytes.len() as u8);
    script.extend_from_slice(&bytes);
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const RECEIVER_PK: [u8; 33] = [0x02; 33];
    const SENDER_PK: [u8; 33] = [0x03; 33];
    const RECEIVER_ADDR: [u8; 20] = [0xBB; 20];
    const SENDER_ADDR: [u8; 20] = [0xAA; 20];

    fn sample_params() -> HtlcParams {
        let secret = SwapSecret::from_preimage([0xDD; 32]);
        HtlcParams {
            hash_lock: secret.hash,
            time_lock: 1_700_000_000,
            sender: SENDER_ADDR,
            receiver: RECEIVER_ADDR,
        }
    }

    // ─── SwapSecret ─────────────────────────────────────────────

    #[test]
    fn test_generate_secret_unique() {
        let s1 = SwapSecret::generate().unwrap();
        let s2 = SwapSecret::generate().unwrap();
        assert_ne!(s1.preimage, s2.preimage);
        assert_ne!(s1.hash, s2.hash);
    }

    #[test]
    fn test_secret_hash_matches() {
        let secret = SwapSecret::generate().unwrap();
        assert_eq!(crypto::sha256(&secret.preimage), secret.hash);
    }

    #[test]
    fn test_from_preimage() {
        let preimage = [0xAB; 32];
        let secret = SwapSecret::from_preimage(preimage);
        assert_eq!(secret.preimage, preimage);
        assert_eq!(secret.hash, crypto::sha256(&preimage));
    }

    #[test]
    fn test_verify_preimage_correct() {
        let secret = SwapSecret::generate().unwrap();
        assert!(SwapSecret::verify(&secret.preimage, &secret.hash));
    }

    #[test]
    fn test_verify_preimage_incorrect() {
        let secret = SwapSecret::generate().unwrap();
        let wrong = [0xFF; 32];
        assert!(!SwapSecret::verify(&wrong, &secret.hash));
    }

    #[test]
    fn test_verify_constant_time() {
        // This is a functional test — we verify ct_eq works correctly
        let a = [0xAA; 32];
        let b = [0xAA; 32];
        let c = [0xBB; 32];
        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
    }

    // ─── Timelock ───────────────────────────────────────────────

    #[test]
    fn test_not_expired() {
        assert!(!is_expired(1_700_000_000, 1_699_999_999));
    }

    #[test]
    fn test_exactly_expired() {
        assert!(is_expired(1_700_000_000, 1_700_000_000));
    }

    #[test]
    fn test_past_expired() {
        assert!(is_expired(1_700_000_000, 1_800_000_000));
    }

    // ─── Bitcoin HTLC Script ────────────────────────────────────

    #[test]
    fn test_btc_htlc_script_contains_sha256() {
        let hash = [0xAA; 32];
        let script = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        assert!(script.contains(&OP_SHA256));
    }

    #[test]
    fn test_btc_htlc_script_contains_cltv() {
        let hash = [0xAA; 32];
        let script = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        assert!(script.contains(&OP_CLTV));
    }

    #[test]
    fn test_btc_htlc_script_structure() {
        let hash = [0xAA; 32];
        let script = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        assert_eq!(script[0], OP_IF);
        assert_eq!(*script.last().unwrap(), OP_ENDIF);
        assert!(script.contains(&OP_ELSE));
    }

    #[test]
    fn test_btc_htlc_script_contains_hash_lock() {
        let hash = [0xAA; 32];
        let script = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        let has_hash = script.windows(32).any(|w| w == hash);
        assert!(has_hash, "script must contain hash lock");
    }

    #[test]
    fn test_btc_htlc_script_contains_pubkeys() {
        let hash = [0xAA; 32];
        let script = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        let has_receiver = script.windows(33).any(|w| w == RECEIVER_PK);
        let has_sender = script.windows(33).any(|w| w == SENDER_PK);
        assert!(has_receiver);
        assert!(has_sender);
    }

    #[test]
    fn test_btc_htlc_csv_contains_csv() {
        let hash = [0xAA; 32];
        let script = build_bitcoin_htlc_csv_script(&hash, 144, &RECEIVER_PK, &SENDER_PK);
        assert!(script.contains(&OP_CSV));
        assert!(!script.contains(&OP_CLTV)); // should use CSV, not CLTV
    }

    #[test]
    fn test_btc_htlc_deterministic() {
        let hash = [0xAA; 32];
        let s1 = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        let s2 = build_bitcoin_htlc_script(&hash, 500_000, &RECEIVER_PK, &SENDER_PK);
        assert_eq!(s1, s2);
    }

    // ─── Bitcoin HTLC Witnesses ─────────────────────────────────

    #[test]
    fn test_btc_claim_witness_structure() {
        let preimage = [0xBB; 32];
        let sig = vec![0xCC; 64];
        let script = vec![0xDD; 100];
        let witness = build_btc_claim_witness(&sig, &preimage, &script);
        assert_eq!(witness.len(), 4);
        assert_eq!(witness[0], sig);
        assert_eq!(witness[1].as_slice(), &preimage);
        assert_eq!(witness[2], vec![0x01]); // TRUE
        assert_eq!(witness[3], script);
    }

    #[test]
    fn test_btc_refund_witness_structure() {
        let sig = vec![0xCC; 64];
        let script = vec![0xDD; 100];
        let witness = build_btc_refund_witness(&sig, &script);
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], sig);
        assert!(witness[1].is_empty()); // FALSE
        assert_eq!(witness[2], script);
    }

    // ─── P2WSH Script Pubkey ────────────────────────────────────

    #[test]
    fn test_htlc_script_pubkey_length() {
        let script = vec![0xAA; 50];
        let spk = htlc_script_pubkey(&script);
        assert_eq!(spk.len(), 34); // OP_0 + push32 + hash
    }

    #[test]
    fn test_htlc_script_pubkey_witness_v0() {
        let script = vec![0xAA; 50];
        let spk = htlc_script_pubkey(&script);
        assert_eq!(spk[0], 0x00); // witness v0
        assert_eq!(spk[1], 32);   // push 32 bytes
    }

    // ─── Ethereum HTLC ABI ──────────────────────────────────────

    #[test]
    fn test_eth_htlc_lock_selector() {
        let params = sample_params();
        let data = encode_eth_htlc_lock(&params);
        let expected = abi::function_selector("lock(bytes32,uint256,address)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_eth_htlc_lock_length() {
        let params = sample_params();
        let data = encode_eth_htlc_lock(&params);
        // 4 (selector) + 32*3 (bytes32, uint256, address) = 100
        assert_eq!(data.len(), 100);
    }

    #[test]
    fn test_eth_htlc_claim_selector() {
        let data = encode_eth_htlc_claim(&[0xAA; 32]);
        let expected = abi::function_selector("claim(bytes32)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_eth_htlc_claim_length() {
        let data = encode_eth_htlc_claim(&[0xAA; 32]);
        assert_eq!(data.len(), 36); // selector + bytes32
    }

    #[test]
    fn test_eth_htlc_refund_selector() {
        let data = encode_eth_htlc_refund(&[0xAA; 32]);
        let expected = abi::function_selector("refund(bytes32)");
        assert_eq!(&data[..4], &expected);
    }

    #[test]
    fn test_eth_htlc_lock_tokens_selector() {
        let params = sample_params();
        let data = encode_eth_htlc_lock_tokens(&[0xFF; 20], &params, 1000);
        let expected = abi::function_selector("lockTokens(address,bytes32,uint256,address,uint256)");
        assert_eq!(&data[..4], &expected);
    }

    // ─── End-to-End ─────────────────────────────────────────────

    #[test]
    fn test_e2e_swap_flow() {
        // 1. Alice generates secret
        let secret = SwapSecret::generate().unwrap();

        // 2. Bob verifies the hash on-chain
        assert!(SwapSecret::verify(&secret.preimage, &secret.hash));

        // 3. Build Bitcoin HTLC
        let btc_script = build_bitcoin_htlc_script(
            &secret.hash, 500_000, &RECEIVER_PK, &SENDER_PK,
        );
        assert!(!btc_script.is_empty());

        // 4. Build Ethereum HTLC
        let params = HtlcParams {
            hash_lock: secret.hash,
            time_lock: 1_700_000_000,
            sender: SENDER_ADDR,
            receiver: RECEIVER_ADDR,
        };
        let eth_lock = encode_eth_htlc_lock(&params);
        assert!(!eth_lock.is_empty());

        // 5. Alice claims with preimage
        let eth_claim = encode_eth_htlc_claim(&secret.preimage);
        assert!(!eth_claim.is_empty());

        // 6. Verify P2WSH output
        let spk = htlc_script_pubkey(&btc_script);
        assert_eq!(spk.len(), 34);
    }

    #[test]
    fn test_e2e_expired_refund() {
        let secret = SwapSecret::generate().unwrap();
        let time_lock = 1_700_000_000u64;

        // Not expired yet
        assert!(!is_expired(time_lock, 1_699_000_000));

        // Expired — can refund
        assert!(is_expired(time_lock, 1_700_000_001));

        // Build refund
        let eth_refund = encode_eth_htlc_refund(&secret.hash);
        assert!(!eth_refund.is_empty());
    }
}
