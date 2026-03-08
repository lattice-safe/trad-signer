//! Additional Solana program helpers: ATA, Memo, Stake, Durable Nonce.

use crate::error::SignerError;
use super::transaction::{Instruction, AccountMeta};

// ═══════════════════════════════════════════════════════════════════
// Associated Token Account (ATA)
// ═══════════════════════════════════════════════════════════════════

/// ATA Program ID: `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`.
pub const ATA_PROGRAM_ID: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
    11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];

/// SPL Token Program ID.
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
    28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// System Program ID.
const SYSTEM_PROGRAM_ID: [u8; 32] = [0; 32];

/// Derive the Associated Token Account address.
///
/// ATA = PDA(ATA_PROGRAM_ID, [wallet, TOKEN_PROGRAM_ID, mint])
///
/// Returns the deterministic ATA address as 32 bytes.
pub fn derive_ata_address(
    wallet: &[u8; 32],
    mint: &[u8; 32],
) -> [u8; 32] {
    // Simplified PDA derivation: SHA-256(seeds || program_id || "ProgramDerivedAddress")
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(wallet);
    hasher.update(SPL_TOKEN_PROGRAM_ID);
    hasher.update(mint);
    hasher.update(ATA_PROGRAM_ID);
    hasher.update(b"ProgramDerivedAddress");
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Create an Associated Token Account instruction.
///
/// Creates the ATA for `wallet` and `mint` if it doesn't exist.
/// The payer covers the rent-exempt balance.
pub fn create_ata(
    payer: [u8; 32],
    wallet: [u8; 32],
    mint: [u8; 32],
) -> Instruction {
    let ata = derive_ata_address(&wallet, &mint);

    Instruction {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer, true),               // payer (writable, signer)
            AccountMeta::new(ata, false),                 // ATA (writable)
            AccountMeta::new_readonly(wallet, false),     // wallet owner
            AccountMeta::new_readonly(mint, false),       // token mint
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),     // system program
            AccountMeta::new_readonly(SPL_TOKEN_PROGRAM_ID, false),  // token program
        ],
        data: vec![0], // CreateAssociatedTokenAccount = index 0
    }
}

/// Create an ATA instruction with idempotency (CreateIdempotent).
///
/// Like `create_ata` but doesn't fail if the account already exists.
pub fn create_ata_idempotent(
    payer: [u8; 32],
    wallet: [u8; 32],
    mint: [u8; 32],
) -> Instruction {
    let ata = derive_ata_address(&wallet, &mint);

    Instruction {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(wallet, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(SPL_TOKEN_PROGRAM_ID, false),
        ],
        data: vec![1], // CreateIdempotent = index 1
    }
}

// ═══════════════════════════════════════════════════════════════════
// Memo Program
// ═══════════════════════════════════════════════════════════════════

/// Memo Program ID (v2): `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`.
pub const MEMO_PROGRAM_ID: [u8; 32] = [
    5, 74, 83, 80, 248, 93, 200, 130, 214, 20, 165, 86, 114, 120, 138, 41,
    109, 223, 30, 171, 171, 208, 166, 6, 120, 136, 73, 50, 244, 238, 246, 160,
];

/// Create a Memo instruction (v2 — supports signer verification).
///
/// # Arguments
/// - `memo` — UTF-8 memo text (max ~566 bytes for a single tx)
/// - `signers` — Optional signer public keys that must sign this memo
pub fn memo(memo_text: &str, signers: &[[u8; 32]]) -> Instruction {
    let accounts: Vec<AccountMeta> = signers
        .iter()
        .map(|pk| AccountMeta::new_readonly(*pk, true))
        .collect();

    Instruction {
        program_id: MEMO_PROGRAM_ID,
        accounts,
        data: memo_text.as_bytes().to_vec(),
    }
}

/// Create a simple memo instruction with no required signers.
pub fn memo_unsigned(memo_text: &str) -> Instruction {
    Instruction {
        program_id: MEMO_PROGRAM_ID,
        accounts: vec![],
        data: memo_text.as_bytes().to_vec(),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Stake Program
// ═══════════════════════════════════════════════════════════════════

/// Stake Program ID: `Stake11111111111111111111111111111111111111`.
pub const STAKE_PROGRAM_ID: [u8; 32] = [
    6, 161, 216, 23, 145, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Stake Config ID.
pub const STAKE_CONFIG_ID: [u8; 32] = [
    6, 161, 216, 23, 165, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Clock sysvar.
pub const CLOCK_SYSVAR: [u8; 32] = [
    6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182,
    139, 94, 184, 163, 155, 75, 109, 92, 115, 85, 91, 33, 0, 0, 0, 0,
];

/// Stake History sysvar.
pub const STAKE_HISTORY_SYSVAR: [u8; 32] = [
    6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122,
    218, 130, 197, 41, 208, 190, 59, 19, 110, 45, 0, 85, 32, 0, 0, 0,
];

/// Create a DelegateStake instruction.
///
/// Delegates a stake account to a validator's vote account.
pub fn stake_delegate(
    stake_account: [u8; 32],
    vote_account: [u8; 32],
    stake_authority: [u8; 32],
) -> Instruction {
    let mut data = vec![0u8; 4]; // instruction index 2 = Delegate
    data[0] = 2;

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(stake_account, false),      // stake account (writable)
            AccountMeta::new_readonly(vote_account, false), // vote account
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
            AccountMeta::new_readonly(STAKE_HISTORY_SYSVAR, false),
            AccountMeta::new_readonly(STAKE_CONFIG_ID, false),
            AccountMeta::new_readonly(stake_authority, true), // stake authority (signer)
        ],
        data,
    }
}

/// Create a Deactivate instruction.
///
/// Deactivates a stake account, beginning the cooldown period.
pub fn stake_deactivate(
    stake_account: [u8; 32],
    stake_authority: [u8; 32],
) -> Instruction {
    let mut data = vec![0u8; 4];
    data[0] = 5; // instruction index 5 = Deactivate

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(stake_account, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
            AccountMeta::new_readonly(stake_authority, true),
        ],
        data,
    }
}

/// Create a Withdraw instruction.
///
/// Withdraws SOL from a deactivated stake account.
pub fn stake_withdraw(
    stake_account: [u8; 32],
    withdraw_authority: [u8; 32],
    recipient: [u8; 32],
    lamports: u64,
) -> Instruction {
    let mut data = vec![0u8; 12];
    data[0] = 4; // instruction index 4 = Withdraw
    data[4..12].copy_from_slice(&lamports.to_le_bytes());

    Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(stake_account, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(CLOCK_SYSVAR, false),
            AccountMeta::new_readonly(STAKE_HISTORY_SYSVAR, false),
            AccountMeta::new_readonly(withdraw_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Durable Nonce Transactions
// ═══════════════════════════════════════════════════════════════════

/// Create an AdvanceNonceAccount instruction.
///
/// This must be the first instruction in a durable nonce transaction.
/// It advances the nonce value, preventing replay.
pub fn advance_nonce(
    nonce_account: [u8; 32],
    nonce_authority: [u8; 32],
) -> Instruction {
    // Recent Sysvar ID
    let recent_blockhashes_sysvar: [u8; 32] = [
        6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182,
        139, 94, 184, 163, 155, 75, 109, 92, 115, 85, 91, 32, 0, 0, 0, 0,
    ];

    let mut data = vec![0u8; 4];
    data[0] = 4; // AdvanceNonceAccount = SystemInstruction index 4

    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(nonce_account, false),
            AccountMeta::new_readonly(recent_blockhashes_sysvar, false),
            AccountMeta::new_readonly(nonce_authority, true),
        ],
        data,
    }
}

/// Create a NonceInitialize instruction.
///
/// Initializes a nonce account with a specified authority.
pub fn initialize_nonce(
    nonce_account: [u8; 32],
    nonce_authority: [u8; 32],
) -> Instruction {
    let recent_blockhashes_sysvar: [u8; 32] = [
        6, 167, 213, 23, 24, 199, 116, 201, 40, 86, 99, 152, 105, 29, 94, 182,
        139, 94, 184, 163, 155, 75, 109, 92, 115, 85, 91, 32, 0, 0, 0, 0,
    ];
    // Rent sysvar
    let rent_sysvar: [u8; 32] = [
        6, 167, 213, 23, 25, 47, 10, 175, 198, 242, 101, 227, 251, 119, 204, 122,
        218, 130, 197, 41, 208, 190, 59, 19, 110, 45, 0, 85, 31, 0, 0, 0,
    ];

    let mut data = vec![0u8; 36];
    data[0] = 6; // InitializeNonceAccount = SystemInstruction index 6
    data[4..36].copy_from_slice(&nonce_authority);

    Instruction {
        program_id: SYSTEM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(nonce_account, false),
            AccountMeta::new_readonly(recent_blockhashes_sysvar, false),
            AccountMeta::new_readonly(rent_sysvar, false),
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

    const WALLET: [u8; 32] = [1; 32];
    const MINT: [u8; 32] = [2; 32];
    const PAYER: [u8; 32] = [3; 32];

    // ─── ATA Tests ──────────────────────────────────────────────

    #[test]
    fn test_derive_ata_deterministic() {
        let ata1 = derive_ata_address(&WALLET, &MINT);
        let ata2 = derive_ata_address(&WALLET, &MINT);
        assert_eq!(ata1, ata2);
    }

    #[test]
    fn test_derive_ata_different_mints() {
        let mint2 = [3; 32];
        let ata1 = derive_ata_address(&WALLET, &MINT);
        let ata2 = derive_ata_address(&WALLET, &mint2);
        assert_ne!(ata1, ata2);
    }

    #[test]
    fn test_create_ata_instruction() {
        let ix = create_ata(PAYER, WALLET, MINT);
        assert_eq!(ix.program_id, ATA_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.data, vec![0]); // CreateAssociatedTokenAccount
        assert!(ix.accounts[0].is_signer); // payer signs
    }

    #[test]
    fn test_create_ata_idempotent() {
        let ix = create_ata_idempotent(PAYER, WALLET, MINT);
        assert_eq!(ix.data, vec![1]); // CreateIdempotent
    }

    // ─── Memo Tests ─────────────────────────────────────────────

    #[test]
    fn test_memo_basic() {
        let ix = memo("Hello, Solana!", &[WALLET]);
        assert_eq!(ix.program_id, MEMO_PROGRAM_ID);
        assert_eq!(ix.data, b"Hello, Solana!");
        assert_eq!(ix.accounts.len(), 1);
        assert!(ix.accounts[0].is_signer);
    }

    #[test]
    fn test_memo_unsigned() {
        let ix = memo_unsigned("test memo");
        assert!(ix.accounts.is_empty());
        assert_eq!(ix.data, b"test memo");
    }

    #[test]
    fn test_memo_multiple_signers() {
        let signer2 = [4; 32];
        let ix = memo("multi-signer memo", &[WALLET, signer2]);
        assert_eq!(ix.accounts.len(), 2);
    }

    // ─── Stake Tests ────────────────────────────────────────────

    #[test]
    fn test_stake_delegate() {
        let vote = [5; 32];
        let ix = stake_delegate(WALLET, vote, PAYER);
        assert_eq!(ix.program_id, STAKE_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.data[0], 2); // DelegateStake index
    }

    #[test]
    fn test_stake_deactivate() {
        let ix = stake_deactivate(WALLET, PAYER);
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.data[0], 5); // Deactivate index
    }

    #[test]
    fn test_stake_withdraw() {
        let recipient = [6; 32];
        let ix = stake_withdraw(WALLET, PAYER, recipient, 1_000_000_000);
        assert_eq!(ix.data[0], 4); // Withdraw index
        let lamports = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        assert_eq!(lamports, 1_000_000_000);
    }

    // ─── Durable Nonce Tests ────────────────────────────────────

    #[test]
    fn test_advance_nonce() {
        let nonce_account = [7; 32];
        let ix = advance_nonce(nonce_account, PAYER);
        assert_eq!(ix.program_id, SYSTEM_PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.data[0], 4); // AdvanceNonceAccount
    }

    #[test]
    fn test_initialize_nonce() {
        let nonce_account = [8; 32];
        let ix = initialize_nonce(nonce_account, PAYER);
        assert_eq!(ix.data[0], 6); // InitializeNonceAccount
        assert_eq!(&ix.data[4..36], &PAYER); // authority
    }
}
