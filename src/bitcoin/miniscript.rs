//! Miniscript — A structured representation of Bitcoin Script spending conditions.
//!
//! Provides types for expressing spending policies and compiling them to
//! Bitcoin Script. Supports satisfaction analysis (witness size estimation).
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::miniscript::*;
//!
//! let key1 = [0x02u8; 33];
//! let key2 = [0x03u8; 33];
//!
//! // 2-of-2 multisig policy
//! let policy = Policy::Threshold(2, vec![
//!     Policy::Key(key1),
//!     Policy::Key(key2),
//! ]);
//! let ms = policy.compile().unwrap();
//! let script = ms.encode();
//! ```

use crate::error::SignerError;

// ═══════════════════════════════════════════════════════════════════
// Opcodes
// ═══════════════════════════════════════════════════════════════════

#[allow(dead_code)]
mod op {
    pub const OP_0: u8 = 0x00;
    pub const OP_IF: u8 = 0x63;
    pub const OP_NOTIF: u8 = 0x64;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_RETURN: u8 = 0x6A;
    pub const OP_TOALTSTACK: u8 = 0x6B;
    pub const OP_FROMALTSTACK: u8 = 0x6C;
    pub const OP_IFDUP: u8 = 0x73;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_SWAP: u8 = 0x7C;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_SIZE: u8 = 0x82;
    pub const OP_BOOLOR: u8 = 0x9B;
    pub const OP_ADD: u8 = 0x93;
    pub const OP_HASH160: u8 = 0xA9;
    pub const OP_SHA256: u8 = 0xA8;
    pub const OP_RIPEMD160: u8 = 0xA6;
    pub const OP_HASH256: u8 = 0xAA;
    pub const OP_CHECKSIG: u8 = 0xAC;
    pub const OP_CHECKSIGVERIFY: u8 = 0xAD;
    pub const OP_CHECKMULTISIG: u8 = 0xAE;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xAF;
    pub const OP_CLTV: u8 = 0xB1;
    pub const OP_CSV: u8 = 0xB2;
}

// ═══════════════════════════════════════════════════════════════════
// Policy — Human-readable spending conditions
// ═══════════════════════════════════════════════════════════════════

/// A high-level spending policy.
///
/// Policies describe *what* conditions must be satisfied, without specifying
/// *how* they are encoded in Bitcoin Script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// Require a signature for this public key (33-byte compressed).
    Key([u8; 33]),
    /// Absolute timelock (BIP-65 CLTV).
    After(u32),
    /// Relative timelock (BIP-112 CSV).
    Older(u32),
    /// SHA-256 hash preimage lock.
    Sha256([u8; 32]),
    /// RIPEMD-160 hash preimage lock.
    Ripemd160([u8; 20]),
    /// HASH-160 (SHA-256 → RIPEMD-160) preimage lock.
    Hash160([u8; 20]),
    /// All sub-policies must be satisfied (AND).
    And(Vec<Policy>),
    /// Any one sub-policy must be satisfied (OR with equal weights).
    Or(Vec<Policy>),
    /// k-of-n threshold: at least `k` sub-policies must be satisfied.
    Threshold(usize, Vec<Policy>),
    /// Always fails (un-spendable).
    Unsatisfiable,
    /// Always succeeds (trivially satisfiable).
    Trivial,
}

#[allow(clippy::expect_used)]
impl Policy {
    /// Compile this policy to a Miniscript fragment.
    ///
    /// Returns `Err` if the policy is malformed (e.g., empty threshold,
    /// threshold k > n, or empty AND/OR).
    pub fn compile(&self) -> Result<Miniscript, SignerError> {
        match self {
            Policy::Key(pk) => Ok(Miniscript::Pk(*pk)),
            Policy::After(n) => Ok(Miniscript::After(*n)),
            Policy::Older(n) => Ok(Miniscript::Older(*n)),
            Policy::Sha256(h) => Ok(Miniscript::Sha256(*h)),
            Policy::Ripemd160(h) => Ok(Miniscript::Ripemd160(*h)),
            Policy::Hash160(h) => Ok(Miniscript::Hash160(*h)),
            Policy::Unsatisfiable => Ok(Miniscript::False),
            Policy::Trivial => Ok(Miniscript::True),

            Policy::And(subs) => {
                if subs.is_empty() {
                    return Err(SignerError::ParseError("empty AND policy".into()));
                }
                let compiled: Vec<Miniscript> = subs
                    .iter()
                    .map(|p| p.compile())
                    .collect::<Result<Vec<_>, _>>()?;
                let mut iter = compiled.into_iter();
                let first = iter.next().expect("non-empty");
                Ok(iter.fold(first, |acc, ms| {
                    Miniscript::AndV(Box::new(acc), Box::new(ms))
                }))
            }

            Policy::Or(subs) => {
                if subs.is_empty() {
                    return Err(SignerError::ParseError("empty OR policy".into()));
                }
                let compiled: Vec<Miniscript> = subs
                    .iter()
                    .map(|p| p.compile())
                    .collect::<Result<Vec<_>, _>>()?;
                let mut iter = compiled.into_iter();
                let first = iter.next().expect("non-empty");
                Ok(iter.fold(first, |acc, ms| {
                    Miniscript::OrB(Box::new(acc), Box::new(ms))
                }))
            }

            Policy::Threshold(k, subs) => {
                let k = *k;
                if subs.is_empty() {
                    return Err(SignerError::ParseError("empty threshold".into()));
                }
                if k == 0 || k > subs.len() {
                    return Err(SignerError::ParseError(
                        format!("invalid threshold {k} of {}", subs.len()),
                    ));
                }

                // Special cases: all keys → OP_CHECKMULTISIG
                let all_keys = subs.iter().all(|p| matches!(p, Policy::Key(_)));
                if all_keys && subs.len() <= 20 {
                    let keys: Vec<[u8; 33]> = subs
                        .iter()
                        .map(|p| match p {
                            Policy::Key(k) => *k,
                            _ => unreachable!(),
                        })
                        .collect();
                    return Ok(Miniscript::ThreshM(k, keys));
                }

                // General threshold compiled as and_v / or_b chains
                if k == subs.len() {
                    // All required → AND
                    Policy::And(subs.clone()).compile()
                } else if k == 1 {
                    // Any one → OR
                    Policy::Or(subs.clone()).compile()
                } else {
                    // General k-of-n: compile each sub and use Thresh
                    let compiled: Vec<Miniscript> = subs
                        .iter()
                        .map(|p| p.compile())
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(Miniscript::Thresh(k, compiled))
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Miniscript — Script-level fragments
// ═══════════════════════════════════════════════════════════════════

/// A Miniscript fragment that maps directly to Bitcoin Script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Miniscript {
    /// `<key> OP_CHECKSIG`
    Pk([u8; 33]),
    /// `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`
    PkH([u8; 20]),
    /// `<n> OP_CSV OP_VERIFY`
    Older(u32),
    /// `<n> OP_CLTV OP_VERIFY`
    After(u32),
    /// `OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL`
    Sha256([u8; 32]),
    /// `OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL`
    Ripemd160([u8; 20]),
    /// `OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL`
    Hash160([u8; 20]),
    /// `[X] [Y] OP_VERIFY` — both must succeed
    AndV(Box<Miniscript>, Box<Miniscript>),
    /// `[X] [Y] OP_BOOLOR` — either may succeed
    OrB(Box<Miniscript>, Box<Miniscript>),
    /// `OP_IF [X] OP_ELSE [Y] OP_ENDIF` — branching OR
    OrI(Box<Miniscript>, Box<Miniscript>),
    /// `<k> <key1> ... <keyn> <n> OP_CHECKMULTISIG`
    ThreshM(usize, Vec<[u8; 33]>),
    /// General threshold of sub-fragments with OP_ADD
    Thresh(usize, Vec<Miniscript>),
    /// `OP_1` — always true
    True,
    /// `OP_0` — always false
    False,
}

impl Miniscript {
    /// Encode this fragment to Bitcoin Script bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut script = Vec::new();
        self.encode_into(&mut script);
        script
    }

    /// Encode into an existing buffer.
    fn encode_into(&self, s: &mut Vec<u8>) {
        match self {
            Miniscript::Pk(key) => {
                s.push(33); // push 33 bytes
                s.extend_from_slice(key);
                s.push(op::OP_CHECKSIG);
            }

            Miniscript::PkH(hash) => {
                s.push(op::OP_DUP);
                s.push(op::OP_HASH160);
                s.push(20);
                s.extend_from_slice(hash);
                s.push(op::OP_EQUALVERIFY);
                s.push(op::OP_CHECKSIG);
            }

            Miniscript::Older(n) => {
                push_script_number(s, *n as i64);
                s.push(op::OP_CSV);
                s.push(op::OP_VERIFY);
            }

            Miniscript::After(n) => {
                push_script_number(s, *n as i64);
                s.push(op::OP_CLTV);
                s.push(op::OP_VERIFY);
            }

            Miniscript::Sha256(hash) => {
                s.push(op::OP_SIZE);
                push_script_number(s, 32);
                s.push(op::OP_EQUALVERIFY);
                s.push(op::OP_SHA256);
                s.push(32);
                s.extend_from_slice(hash);
                s.push(op::OP_EQUAL);
            }

            Miniscript::Ripemd160(hash) => {
                s.push(op::OP_SIZE);
                push_script_number(s, 32);
                s.push(op::OP_EQUALVERIFY);
                s.push(op::OP_RIPEMD160);
                s.push(20);
                s.extend_from_slice(hash);
                s.push(op::OP_EQUAL);
            }

            Miniscript::Hash160(hash) => {
                s.push(op::OP_SIZE);
                push_script_number(s, 32);
                s.push(op::OP_EQUALVERIFY);
                s.push(op::OP_HASH160);
                s.push(20);
                s.extend_from_slice(hash);
                s.push(op::OP_EQUAL);
            }

            Miniscript::AndV(left, right) => {
                left.encode_into(s);
                right.encode_into(s);
            }

            Miniscript::OrB(left, right) => {
                left.encode_into(s);
                right.encode_into(s);
                s.push(op::OP_BOOLOR);
            }

            Miniscript::OrI(left, right) => {
                s.push(op::OP_IF);
                left.encode_into(s);
                s.push(op::OP_ELSE);
                right.encode_into(s);
                s.push(op::OP_ENDIF);
            }

            Miniscript::ThreshM(k, keys) => {
                push_script_number(s, *k as i64);
                for key in keys {
                    s.push(33);
                    s.extend_from_slice(key);
                }
                push_script_number(s, keys.len() as i64);
                s.push(op::OP_CHECKMULTISIG);
            }

            Miniscript::Thresh(k, subs) => {
                if let Some((first, rest)) = subs.split_first() {
                    first.encode_into(s);
                    for sub in rest {
                        sub.encode_into(s);
                        s.push(op::OP_ADD);
                    }
                    push_script_number(s, *k as i64);
                    s.push(op::OP_EQUAL);
                }
            }

            Miniscript::True => {
                s.push(0x51); // OP_1
            }

            Miniscript::False => {
                s.push(op::OP_0);
            }
        }
    }

    /// Estimate the script size in bytes.
    pub fn script_size(&self) -> usize {
        self.encode().len()
    }

    /// Maximum number of witness stack elements needed to satisfy this fragment.
    pub fn max_satisfaction_witness_elements(&self) -> usize {
        match self {
            Miniscript::Pk(_) => 1,         // signature
            Miniscript::PkH(_) => 2,        // sig + pubkey
            Miniscript::Older(_) | Miniscript::After(_) => 0, // sequence/locktime
            Miniscript::Sha256(_) | Miniscript::Ripemd160(_) | Miniscript::Hash160(_) => 1, // preimage
            Miniscript::AndV(l, r) => {
                l.max_satisfaction_witness_elements() + r.max_satisfaction_witness_elements()
            }
            Miniscript::OrB(l, r) | Miniscript::OrI(l, r) => {
                l.max_satisfaction_witness_elements()
                    .max(r.max_satisfaction_witness_elements())
                    + 1 // branch selector
            }
            Miniscript::ThreshM(k, _) => k + 1, // k sigs + dummy OP_0
            Miniscript::Thresh(_, subs) => {
                subs.iter()
                    .map(|s| s.max_satisfaction_witness_elements())
                    .sum::<usize>()
            }
            Miniscript::True | Miniscript::False => 0,
        }
    }

    /// Maximum witness size in bytes (approximate).
    pub fn max_satisfaction_size(&self) -> usize {
        match self {
            Miniscript::Pk(_) => 73,        // DER sig (72 max) + sighash byte
            Miniscript::PkH(_) => 73 + 34,  // sig + compact-push + pubkey
            Miniscript::Older(_) | Miniscript::After(_) => 0,
            Miniscript::Sha256(_) => 33,    // 32-byte preimage + push
            Miniscript::Ripemd160(_) | Miniscript::Hash160(_) => 33,
            Miniscript::AndV(l, r) => {
                l.max_satisfaction_size() + r.max_satisfaction_size()
            }
            Miniscript::OrB(l, r) | Miniscript::OrI(l, r) => {
                l.max_satisfaction_size().max(r.max_satisfaction_size()) + 1
            }
            Miniscript::ThreshM(k, _) => 1 + k * 73, // OP_0 + k signatures
            Miniscript::Thresh(_, subs) => {
                subs.iter()
                    .map(|s| s.max_satisfaction_size())
                    .sum::<usize>()
            }
            Miniscript::True | Miniscript::False => 0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Push a number in Bitcoin's minimal script number encoding.
fn push_script_number(script: &mut Vec<u8>, n: i64) {
    if n == 0 {
        script.push(0x00); // OP_0
        return;
    }
    if (1..=16).contains(&n) {
        script.push(0x50 + n as u8); // OP_1..OP_16
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

    const KEY1: [u8; 33] = [0x02; 33];
    const KEY2: [u8; 33] = [0x03; 33];
    const KEY3: [u8; 33] = [0x04; 33];
    const HASH32: [u8; 32] = [0xAA; 32];
    const HASH20: [u8; 20] = [0xBB; 20];

    // ─── Policy Compilation ─────────────────────────────────────

    #[test]
    fn test_policy_key_compiles() {
        let ms = Policy::Key(KEY1).compile().unwrap();
        assert!(matches!(ms, Miniscript::Pk(_)));
    }

    #[test]
    fn test_policy_after_compiles() {
        let ms = Policy::After(500_000).compile().unwrap();
        assert!(matches!(ms, Miniscript::After(500_000)));
    }

    #[test]
    fn test_policy_older_compiles() {
        let ms = Policy::Older(144).compile().unwrap();
        assert!(matches!(ms, Miniscript::Older(144)));
    }

    #[test]
    fn test_policy_sha256_compiles() {
        let ms = Policy::Sha256(HASH32).compile().unwrap();
        assert!(matches!(ms, Miniscript::Sha256(_)));
    }

    #[test]
    fn test_policy_ripemd160_compiles() {
        let ms = Policy::Ripemd160(HASH20).compile().unwrap();
        assert!(matches!(ms, Miniscript::Ripemd160(_)));
    }

    #[test]
    fn test_policy_hash160_compiles() {
        let ms = Policy::Hash160(HASH20).compile().unwrap();
        assert!(matches!(ms, Miniscript::Hash160(_)));
    }

    #[test]
    fn test_policy_trivial() {
        let ms = Policy::Trivial.compile().unwrap();
        assert!(matches!(ms, Miniscript::True));
    }

    #[test]
    fn test_policy_unsatisfiable() {
        let ms = Policy::Unsatisfiable.compile().unwrap();
        assert!(matches!(ms, Miniscript::False));
    }

    #[test]
    fn test_policy_and_two_keys() {
        let policy = Policy::And(vec![Policy::Key(KEY1), Policy::Key(KEY2)]);
        let ms = policy.compile().unwrap();
        assert!(matches!(ms, Miniscript::AndV(_, _)));
    }

    #[test]
    fn test_policy_or_two_keys() {
        let policy = Policy::Or(vec![Policy::Key(KEY1), Policy::Key(KEY2)]);
        let ms = policy.compile().unwrap();
        assert!(matches!(ms, Miniscript::OrB(_, _)));
    }

    #[test]
    fn test_policy_threshold_all_keys() {
        let policy = Policy::Threshold(2, vec![
            Policy::Key(KEY1), Policy::Key(KEY2), Policy::Key(KEY3),
        ]);
        let ms = policy.compile().unwrap();
        assert!(matches!(ms, Miniscript::ThreshM(2, _)));
    }

    #[test]
    fn test_policy_threshold_n_of_n() {
        let policy = Policy::Threshold(2, vec![Policy::Key(KEY1), Policy::Key(KEY2)]);
        let ms = policy.compile().unwrap();
        // 2-of-2 all keys → ThreshM
        assert!(matches!(ms, Miniscript::ThreshM(2, _)));
    }

    // ─── Policy Errors ──────────────────────────────────────────

    #[test]
    fn test_policy_empty_and_errors() {
        assert!(Policy::And(vec![]).compile().is_err());
    }

    #[test]
    fn test_policy_empty_or_errors() {
        assert!(Policy::Or(vec![]).compile().is_err());
    }

    #[test]
    fn test_policy_empty_threshold_errors() {
        assert!(Policy::Threshold(1, vec![]).compile().is_err());
    }

    #[test]
    fn test_policy_threshold_k_zero_errors() {
        assert!(Policy::Threshold(0, vec![Policy::Key(KEY1)]).compile().is_err());
    }

    #[test]
    fn test_policy_threshold_k_exceeds_n_errors() {
        assert!(Policy::Threshold(3, vec![Policy::Key(KEY1), Policy::Key(KEY2)]).compile().is_err());
    }

    // ─── Script Encoding ────────────────────────────────────────

    #[test]
    fn test_pk_script_structure() {
        let script = Miniscript::Pk(KEY1).encode();
        assert_eq!(script[0], 33); // push 33
        assert_eq!(&script[1..34], &KEY1);
        assert_eq!(script[34], op::OP_CHECKSIG);
        assert_eq!(script.len(), 35);
    }

    #[test]
    fn test_pkh_script_structure() {
        let script = Miniscript::PkH(HASH20).encode();
        assert_eq!(script[0], op::OP_DUP);
        assert_eq!(script[1], op::OP_HASH160);
        assert_eq!(script[2], 20);
        assert_eq!(&script[3..23], &HASH20);
        assert_eq!(script[23], op::OP_EQUALVERIFY);
        assert_eq!(script[24], op::OP_CHECKSIG);
    }

    #[test]
    fn test_after_script_contains_cltv() {
        let script = Miniscript::After(500_000).encode();
        assert!(script.contains(&op::OP_CLTV));
        assert!(script.contains(&op::OP_VERIFY));
    }

    #[test]
    fn test_older_script_contains_csv() {
        let script = Miniscript::Older(144).encode();
        assert!(script.contains(&op::OP_CSV));
        assert!(script.contains(&op::OP_VERIFY));
    }

    #[test]
    fn test_sha256_script_contains_hash_op() {
        let script = Miniscript::Sha256(HASH32).encode();
        assert!(script.contains(&op::OP_SHA256));
        assert!(script.contains(&op::OP_EQUAL));
        assert!(script.contains(&op::OP_SIZE));
    }

    #[test]
    fn test_ripemd160_script_contains_hash_op() {
        let script = Miniscript::Ripemd160(HASH20).encode();
        assert!(script.contains(&op::OP_RIPEMD160));
    }

    #[test]
    fn test_hash160_script_contains_hash_op() {
        let script = Miniscript::Hash160(HASH20).encode();
        assert!(script.contains(&op::OP_HASH160));
    }

    #[test]
    fn test_thresh_m_2_of_3_script() {
        let script = Miniscript::ThreshM(2, vec![KEY1, KEY2, KEY3]).encode();
        assert_eq!(script[0], 0x52); // OP_2
        // 3 keys × (1 push + 33 bytes)
        assert_eq!(script[1], 33);
        assert_eq!(script[1 + 34], 33);
        assert_eq!(script[1 + 68], 33);
        // OP_3
        assert_eq!(script[1 + 102], 0x53);
        // OP_CHECKMULTISIG
        assert_eq!(script[1 + 103], op::OP_CHECKMULTISIG);
    }

    #[test]
    fn test_and_v_combines_scripts() {
        let ms = Miniscript::AndV(
            Box::new(Miniscript::Pk(KEY1)),
            Box::new(Miniscript::Pk(KEY2)),
        );
        let script = ms.encode();
        // Two pk scripts concatenated
        assert_eq!(script.len(), 35 + 35); // 2 × pk script
    }

    #[test]
    fn test_or_b_adds_boolor() {
        let ms = Miniscript::OrB(
            Box::new(Miniscript::Pk(KEY1)),
            Box::new(Miniscript::Pk(KEY2)),
        );
        let script = ms.encode();
        assert_eq!(*script.last().unwrap(), op::OP_BOOLOR);
    }

    #[test]
    fn test_or_i_uses_if_else_endif() {
        let ms = Miniscript::OrI(
            Box::new(Miniscript::Pk(KEY1)),
            Box::new(Miniscript::Pk(KEY2)),
        );
        let script = ms.encode();
        assert_eq!(script[0], op::OP_IF);
        assert!(script.contains(&op::OP_ELSE));
        assert_eq!(*script.last().unwrap(), op::OP_ENDIF);
    }

    #[test]
    fn test_true_encodes_op_1() {
        let script = Miniscript::True.encode();
        assert_eq!(script, vec![0x51]);
    }

    #[test]
    fn test_false_encodes_op_0() {
        let script = Miniscript::False.encode();
        assert_eq!(script, vec![op::OP_0]);
    }

    // ─── Script Size ────────────────────────────────────────────

    #[test]
    fn test_pk_script_size() {
        assert_eq!(Miniscript::Pk(KEY1).script_size(), 35);
    }

    #[test]
    fn test_thresh_m_script_size() {
        let ms = Miniscript::ThreshM(2, vec![KEY1, KEY2, KEY3]);
        // OP_2 + 3×(push+key) + OP_3 + OP_CHECKMULTISIG = 1 + 102 + 1 + 1 = 105
        assert_eq!(ms.script_size(), 105);
    }

    // ─── Witness Size ───────────────────────────────────────────

    #[test]
    fn test_pk_witness_elements() {
        assert_eq!(Miniscript::Pk(KEY1).max_satisfaction_witness_elements(), 1);
    }

    #[test]
    fn test_pkh_witness_elements() {
        assert_eq!(Miniscript::PkH(HASH20).max_satisfaction_witness_elements(), 2);
    }

    #[test]
    fn test_thresh_m_witness_elements() {
        let ms = Miniscript::ThreshM(2, vec![KEY1, KEY2, KEY3]);
        assert_eq!(ms.max_satisfaction_witness_elements(), 3); // 2 sigs + dummy OP_0
    }

    #[test]
    fn test_pk_witness_size() {
        assert_eq!(Miniscript::Pk(KEY1).max_satisfaction_size(), 73);
    }

    #[test]
    fn test_thresh_m_witness_size() {
        let ms = Miniscript::ThreshM(2, vec![KEY1, KEY2, KEY3]);
        assert_eq!(ms.max_satisfaction_size(), 1 + 2 * 73); // OP_0 + 2 sigs
    }

    #[test]
    fn test_sha256_witness_size() {
        assert_eq!(Miniscript::Sha256(HASH32).max_satisfaction_size(), 33);
    }

    // ─── End-to-End ─────────────────────────────────────────────

    #[test]
    fn test_e2e_2_of_3_policy_to_script() {
        let policy = Policy::Threshold(2, vec![
            Policy::Key(KEY1),
            Policy::Key(KEY2),
            Policy::Key(KEY3),
        ]);
        let ms = policy.compile().unwrap();
        let script = ms.encode();
        // Should be a valid OP_CHECKMULTISIG script
        assert_eq!(*script.last().unwrap(), op::OP_CHECKMULTISIG);
        assert!(script.len() > 100);
    }

    #[test]
    fn test_e2e_key_and_timelock() {
        let policy = Policy::And(vec![
            Policy::Key(KEY1),
            Policy::After(800_000),
        ]);
        let ms = policy.compile().unwrap();
        let script = ms.encode();
        assert!(script.contains(&op::OP_CHECKSIG));
        assert!(script.contains(&op::OP_CLTV));
    }

    #[test]
    fn test_e2e_htlc_like_policy() {
        // hashlock OR (key + timelock) — typical HTLC
        let policy = Policy::Or(vec![
            Policy::And(vec![
                Policy::Sha256(HASH32),
                Policy::Key(KEY1),
            ]),
            Policy::And(vec![
                Policy::Key(KEY2),
                Policy::After(700_000),
            ]),
        ]);
        let ms = policy.compile().unwrap();
        let script = ms.encode();
        assert!(script.len() > 50);
        assert!(script.contains(&op::OP_SHA256));
        assert!(script.contains(&op::OP_CLTV));
    }

    // ─── push_script_number ─────────────────────────────────────

    #[test]
    fn test_push_script_number_zero() {
        let mut s = Vec::new();
        push_script_number(&mut s, 0);
        assert_eq!(s, vec![0x00]);
    }

    #[test]
    fn test_push_script_number_small() {
        for n in 1..=16 {
            let mut s = Vec::new();
            push_script_number(&mut s, n);
            assert_eq!(s, vec![0x50 + n as u8]);
        }
    }

    #[test]
    fn test_push_script_number_17() {
        let mut s = Vec::new();
        push_script_number(&mut s, 17);
        assert_eq!(s, vec![1, 17]); // 1-byte push + value
    }

    #[test]
    fn test_push_script_number_256() {
        let mut s = Vec::new();
        push_script_number(&mut s, 256);
        assert_eq!(s, vec![2, 0x00, 0x01]); // 2-byte push LE
    }
}
