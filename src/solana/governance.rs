//! SPL Governance instruction builders.
//!
//! Provides instruction encoding for the Solana SPL Governance program,
//! which powers on-chain DAOs, proposals, and voting on Solana.
//!
//! Supports:
//! - Realm creation and configuration
//! - Proposal lifecycle (create, sign-off, vote, execute)
//! - Token owner record management
//!
//! # Example
//! ```no_run
//! use chains_sdk::solana::governance::*;
//!
//! let ix = create_proposal(
//!     &GOVERNANCE_PROGRAM_ID,
//!     &[1; 32], // governance
//!     &[2; 32], // proposal owner
//!     &[3; 32], // token owner record
//!     &[4; 32], // payer
//!     &[5; 32], // authority
//!     "My Proposal",
//!     "Proposal description link",
//! );
//! ```

use crate::solana::transaction::{AccountMeta, Instruction};

/// SPL Governance program ID.
pub const GOVERNANCE_PROGRAM_ID: [u8; 32] = [
    0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// System program ID.
const SYSTEM_PROGRAM: [u8; 32] = [0u8; 32];
/// Rent sysvar.
const RENT_SYSVAR: [u8; 32] = {
    let mut v = [0u8; 32];
    v[0] = 0x06; v[1] = 0xa7; v[2] = 0xd5; v[3] = 0x17;
    v[4] = 0x18; v[5] = 0x7b; v[6] = 0xd1; v[7] = 0x63;
    v
};
/// Clock sysvar.
const CLOCK_SYSVAR: [u8; 32] = {
    let mut v = [0u8; 32];
    v[0] = 0x06; v[1] = 0xa7; v[2] = 0xd5; v[3] = 0x17;
    v[4] = 0x18; v[5] = 0x7b; v[6] = 0xd1; v[7] = 0x62;
    v
};
/// Token program ID.
const TOKEN_PROGRAM: [u8; 32] = {
    let mut v = [0u8; 32];
    v[0] = 0x06; v[1] = 0xdd; v[2] = 0xf6; v[3] = 0xe1;
    v
};

// ═══════════════════════════════════════════════════════════════════
// Instruction Indices (SPL Governance)
// ═══════════════════════════════════════════════════════════════════

const IX_CREATE_REALM: u8 = 0;
const IX_DEPOSIT_GOVERNING_TOKENS: u8 = 1;
/// Withdraw governing tokens (SPL Governance instruction index).
///
/// Included for spec completeness — not currently used in the encoding API.
#[allow(dead_code)]
const IX_WITHDRAW_GOVERNING_TOKENS: u8 = 2;
/// Create governance (SPL Governance instruction index).
///
/// Included for spec completeness — not currently used in the encoding API.
#[allow(dead_code)]
const IX_CREATE_GOVERNANCE: u8 = 3;
const IX_CREATE_PROPOSAL: u8 = 4;
const IX_SIGN_OFF_PROPOSAL: u8 = 6;
const IX_CAST_VOTE: u8 = 7;
const IX_CANCEL_PROPOSAL: u8 = 9;
const IX_EXECUTE_TRANSACTION: u8 = 11;
const IX_SET_GOVERNANCE_DELEGATE: u8 = 12;

// ═══════════════════════════════════════════════════════════════════
// Vote Weight
// ═══════════════════════════════════════════════════════════════════

/// A vote choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    /// Approve the proposal.
    Approve,
    /// Deny the proposal.
    Deny,
    /// Abstain from voting.
    Abstain,
    /// Veto the proposal.
    Veto,
}

impl Vote {
    /// Serialize the vote type to governance instruction bytes.
    fn to_bytes(self) -> Vec<u8> {
        match self {
            Vote::Approve => {
                // Vote type 0 (Approve), 1 choice, rank 0, weight 100
                let mut v = vec![0u8; 1]; // vote type = Approve
                v.push(1); // choices count
                v.push(0); // choice rank
                v.push(100); // weight (%)
                v
            }
            Vote::Deny => vec![1],    // vote type = Deny
            Vote::Abstain => vec![2], // vote type = Abstain
            Vote::Veto => vec![3],    // vote type = Veto
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Instructions
// ═══════════════════════════════════════════════════════════════════

/// Create a governance realm.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn create_realm(
    program_id: &[u8; 32],
    realm_authority: &[u8; 32],
    community_token_mint: &[u8; 32],
    payer: &[u8; 32],
    realm_account: &[u8; 32],
    name: &str,
    min_community_weight: u64,
) -> Instruction {
    let mut data = vec![IX_CREATE_REALM];
    // Name (borsh string: u32 len + bytes)
    data.extend_from_slice(&(name.len() as u32).to_le_bytes());
    data.extend_from_slice(name.as_bytes());
    // Min weight to create governance
    data.extend_from_slice(&min_community_weight.to_le_bytes());
    // Community mint max voter weight source: Absolute
    data.push(0); // MintMaxVoterWeightSource::Absolute
    data.extend_from_slice(&u64::MAX.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*realm_account, false),
            AccountMeta::new_readonly(*realm_authority, false),
            AccountMeta::new_readonly(*community_token_mint, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
            AccountMeta::new_readonly(RENT_SYSVAR, false),
        ],
        data,
    }
}

/// Deposit governing tokens (join a realm).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn deposit_governing_tokens(
    program_id: &[u8; 32],
    realm: &[u8; 32],
    governing_token_source: &[u8; 32],
    governing_token_owner: &[u8; 32],
    governing_token_mint: &[u8; 32],
    payer: &[u8; 32],
    token_owner_record: &[u8; 32],
    amount: u64,
) -> Instruction {
    let mut data = vec![IX_DEPOSIT_GOVERNING_TOKENS];
    data.extend_from_slice(&amount.to_le_bytes());



    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*realm, false),
            AccountMeta::new(*token_owner_record, false),
            AccountMeta::new(*governing_token_source, false),
            AccountMeta::new_readonly(*governing_token_owner, true),
            AccountMeta::new_readonly(*governing_token_owner, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(TOKEN_PROGRAM, false),
            AccountMeta::new_readonly(*governing_token_mint, false),
        ],
        data,
    }
}

/// Create a proposal.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn create_proposal(
    program_id: &[u8; 32],
    governance: &[u8; 32],
    proposal_owner: &[u8; 32],
    token_owner_record: &[u8; 32],
    payer: &[u8; 32],
    authority: &[u8; 32],
    name: &str,
    description_link: &str,
) -> Instruction {
    let mut data = vec![IX_CREATE_PROPOSAL];
    // Name
    data.extend_from_slice(&(name.len() as u32).to_le_bytes());
    data.extend_from_slice(name.as_bytes());
    // Description link
    data.extend_from_slice(&(description_link.len() as u32).to_le_bytes());
    data.extend_from_slice(description_link.as_bytes());
    // Vote type: single choice
    data.push(0);
    // Options: ["Approve"]
    data.extend_from_slice(&1u32.to_le_bytes());
    let label = "Approve";
    data.extend_from_slice(&(label.len() as u32).to_le_bytes());
    data.extend_from_slice(label.as_bytes());
    // use_deny_option
    data.push(1u8); // true

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*governance, false),
            AccountMeta::new(*proposal_owner, false),
            AccountMeta::new_readonly(*token_owner_record, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(RENT_SYSVAR, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
        ],
        data,
    }
}

/// Sign off a proposal (ready for voting).
#[must_use]
pub fn sign_off_proposal(
    program_id: &[u8; 32],
    realm: &[u8; 32],
    governance: &[u8; 32],
    proposal: &[u8; 32],
    signatory: &[u8; 32],
) -> Instruction {
    let data = vec![IX_SIGN_OFF_PROPOSAL];

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*realm, false),
            AccountMeta::new_readonly(*governance, false),
            AccountMeta::new(*proposal, false),
            AccountMeta::new_readonly(*signatory, true),
        ],
        data,
    }
}

/// Cast a vote on a proposal.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn cast_vote(
    program_id: &[u8; 32],
    realm: &[u8; 32],
    governance: &[u8; 32],
    proposal: &[u8; 32],
    token_owner_record: &[u8; 32],
    voter_authority: &[u8; 32],
    payer: &[u8; 32],
    vote_record: &[u8; 32],
    vote: Vote,
) -> Instruction {
    let mut data = vec![IX_CAST_VOTE];
    data.extend_from_slice(&vote.to_bytes());



    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*realm, false),
            AccountMeta::new(*governance, false),
            AccountMeta::new(*proposal, false),
            AccountMeta::new(*token_owner_record, false),
            AccountMeta::new(*vote_record, false),
            AccountMeta::new_readonly(*voter_authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(RENT_SYSVAR, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
        ],
        data,
    }
}

/// Cancel a proposal.
#[must_use]
pub fn cancel_proposal(
    program_id: &[u8; 32],
    realm: &[u8; 32],
    governance: &[u8; 32],
    proposal: &[u8; 32],
    token_owner_record: &[u8; 32],
    authority: &[u8; 32],
) -> Instruction {
    let data = vec![IX_CANCEL_PROPOSAL];

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*realm, false),
            AccountMeta::new(*governance, false),
            AccountMeta::new(*proposal, false),
            AccountMeta::new_readonly(*token_owner_record, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
        ],
        data,
    }
}

/// Execute a proposal transaction.
#[must_use]
pub fn execute_transaction(
    program_id: &[u8; 32],
    governance: &[u8; 32],
    proposal: &[u8; 32],
    proposal_transaction: &[u8; 32],
) -> Instruction {
    let data = vec![IX_EXECUTE_TRANSACTION];

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*governance, false),
            AccountMeta::new(*proposal, false),
            AccountMeta::new(*proposal_transaction, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
        ],
        data,
    }
}

/// Set a governance delegate.
#[must_use]
pub fn set_governance_delegate(
    program_id: &[u8; 32],
    token_owner_record: &[u8; 32],
    authority: &[u8; 32],
    new_delegate: Option<&[u8; 32]>,
) -> Instruction {
    let mut data = vec![IX_SET_GOVERNANCE_DELEGATE];
    match new_delegate {
        Some(d) => {
            data.push(1); // Option::Some
            data.extend_from_slice(d);
        }
        None => {
            data.push(0); // Option::None
        }
    }

    Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(*token_owner_record, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const REALM: [u8; 32] = [1; 32];
    const GOVERNANCE: [u8; 32] = [2; 32];
    const PROPOSAL: [u8; 32] = [3; 32];
    const TOKEN_RECORD: [u8; 32] = [4; 32];
    const PAYER: [u8; 32] = [5; 32];
    const AUTHORITY: [u8; 32] = [6; 32];
    const MINT: [u8; 32] = [7; 32];
    const SOURCE: [u8; 32] = [8; 32];
    const SIGNATORY: [u8; 32] = [9; 32];

    // ─── create_realm ───────────────────────────────────────────

    #[test]
    fn test_create_realm_instruction_index() {
        let ix = create_realm(
            &GOVERNANCE_PROGRAM_ID, &AUTHORITY, &MINT, &PAYER,
            &REALM, "Test Realm", 1_000_000,
        );
        assert_eq!(ix.data[0], IX_CREATE_REALM);
    }

    #[test]
    fn test_create_realm_name_encoded() {
        let ix = create_realm(
            &GOVERNANCE_PROGRAM_ID, &AUTHORITY, &MINT, &PAYER,
            &REALM, "MyDAO", 1_000,
        );
        let name_len = u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]);
        assert_eq!(name_len, 5);
        assert_eq!(&ix.data[5..10], b"MyDAO");
    }

    #[test]
    fn test_create_realm_accounts() {
        let ix = create_realm(
            &GOVERNANCE_PROGRAM_ID, &AUTHORITY, &MINT, &PAYER,
            &REALM, "Test", 1_000,
        );
        assert_eq!(ix.accounts.len(), 7);
        assert!(ix.accounts[0].is_writable); // realm account
    }

    // ─── deposit_governing_tokens ───────────────────────────────

    #[test]
    fn test_deposit_instruction_index() {
        let ix = deposit_governing_tokens(
            &GOVERNANCE_PROGRAM_ID, &REALM, &SOURCE,
            &AUTHORITY, &MINT, &PAYER, &TOKEN_RECORD, 1_000_000,
        );
        assert_eq!(ix.data[0], IX_DEPOSIT_GOVERNING_TOKENS);
    }

    #[test]
    fn test_deposit_amount_encoded() {
        let ix = deposit_governing_tokens(
            &GOVERNANCE_PROGRAM_ID, &REALM, &SOURCE,
            &AUTHORITY, &MINT, &PAYER, &TOKEN_RECORD, 42,
        );
        let amount = u64::from_le_bytes([
            ix.data[1], ix.data[2], ix.data[3], ix.data[4],
            ix.data[5], ix.data[6], ix.data[7], ix.data[8],
        ]);
        assert_eq!(amount, 42);
    }

    // ─── create_proposal ────────────────────────────────────────

    #[test]
    fn test_create_proposal_instruction_index() {
        let ix = create_proposal(
            &GOVERNANCE_PROGRAM_ID, &GOVERNANCE, &PROPOSAL,
            &TOKEN_RECORD, &PAYER, &AUTHORITY,
            "Upgrade Program", "https://link",
        );
        assert_eq!(ix.data[0], IX_CREATE_PROPOSAL);
    }

    #[test]
    fn test_create_proposal_name_encoded() {
        let name = "My Proposal";
        let ix = create_proposal(
            &GOVERNANCE_PROGRAM_ID, &GOVERNANCE, &PROPOSAL,
            &TOKEN_RECORD, &PAYER, &AUTHORITY,
            name, "desc",
        );
        let len = u32::from_le_bytes([ix.data[1], ix.data[2], ix.data[3], ix.data[4]]);
        assert_eq!(len, name.len() as u32);
    }

    #[test]
    fn test_create_proposal_accounts() {
        let ix = create_proposal(
            &GOVERNANCE_PROGRAM_ID, &GOVERNANCE, &PROPOSAL,
            &TOKEN_RECORD, &PAYER, &AUTHORITY,
            "Test", "desc",
        );
        assert_eq!(ix.accounts.len(), 8);
    }

    // ─── sign_off_proposal ──────────────────────────────────────

    #[test]
    fn test_sign_off_instruction_index() {
        let ix = sign_off_proposal(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &SIGNATORY,
        );
        assert_eq!(ix.data[0], IX_SIGN_OFF_PROPOSAL);
    }

    #[test]
    fn test_sign_off_accounts() {
        let ix = sign_off_proposal(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &SIGNATORY,
        );
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[2].is_writable); // proposal
    }

    // ─── cast_vote ──────────────────────────────────────────────

    #[test]
    fn test_cast_vote_approve() {
        let ix = cast_vote(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY, &PAYER,
            &[10; 32], Vote::Approve,
        );
        assert_eq!(ix.data[0], IX_CAST_VOTE);
        assert_eq!(ix.data[1], 0); // Approve
    }

    #[test]
    fn test_cast_vote_deny() {
        let ix = cast_vote(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY, &PAYER,
            &[10; 32], Vote::Deny,
        );
        assert_eq!(ix.data[1], 1);
    }

    #[test]
    fn test_cast_vote_abstain() {
        let ix = cast_vote(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY, &PAYER,
            &[10; 32], Vote::Abstain,
        );
        assert_eq!(ix.data[1], 2);
    }

    #[test]
    fn test_cast_vote_veto() {
        let ix = cast_vote(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY, &PAYER,
            &[10; 32], Vote::Veto,
        );
        assert_eq!(ix.data[1], 3);
    }

    #[test]
    fn test_cast_vote_accounts() {
        let ix = cast_vote(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY, &PAYER,
            &[10; 32], Vote::Approve,
        );
        assert_eq!(ix.accounts.len(), 10);
    }

    // ─── cancel_proposal ────────────────────────────────────────

    #[test]
    fn test_cancel_proposal_instruction_index() {
        let ix = cancel_proposal(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY,
        );
        assert_eq!(ix.data[0], IX_CANCEL_PROPOSAL);
    }

    #[test]
    fn test_cancel_proposal_accounts() {
        let ix = cancel_proposal(
            &GOVERNANCE_PROGRAM_ID, &REALM, &GOVERNANCE,
            &PROPOSAL, &TOKEN_RECORD, &AUTHORITY,
        );
        assert_eq!(ix.accounts.len(), 6);
    }

    // ─── execute_transaction ────────────────────────────────────

    #[test]
    fn test_execute_transaction_instruction_index() {
        let ix = execute_transaction(
            &GOVERNANCE_PROGRAM_ID, &GOVERNANCE,
            &PROPOSAL, &[10; 32],
        );
        assert_eq!(ix.data[0], IX_EXECUTE_TRANSACTION);
    }

    // ─── set_governance_delegate ────────────────────────────────

    #[test]
    fn test_set_delegate_with_delegate() {
        let delegate = [0xDD; 32];
        let ix = set_governance_delegate(
            &GOVERNANCE_PROGRAM_ID, &TOKEN_RECORD, &AUTHORITY,
            Some(&delegate),
        );
        assert_eq!(ix.data[0], IX_SET_GOVERNANCE_DELEGATE);
        assert_eq!(ix.data[1], 1); // Some
        assert_eq!(&ix.data[2..34], &delegate);
    }

    #[test]
    fn test_set_delegate_none() {
        let ix = set_governance_delegate(
            &GOVERNANCE_PROGRAM_ID, &TOKEN_RECORD, &AUTHORITY,
            None,
        );
        assert_eq!(ix.data[1], 0); // None
        assert_eq!(ix.data.len(), 2);
    }

    // ─── Vote enum ──────────────────────────────────────────────

    #[test]
    fn test_vote_approve_bytes() {
        let b = Vote::Approve.to_bytes();
        assert_eq!(b[0], 0); // type
        assert_eq!(b.len(), 4); // type + count + rank + weight
    }

    #[test]
    fn test_vote_deny_bytes() {
        let b = Vote::Deny.to_bytes();
        assert_eq!(b, vec![1]);
    }
}
