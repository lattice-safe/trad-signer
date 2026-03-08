//! SPL Token-2022 extension instructions.
//!
//! Provides instruction builders for Token-2022 extensions:
//! - Transfer Hook
//! - Confidential Transfer
//! - Transfer Fee
//! - Default Account State
//! - CPI Guard
//! - Memo Required
//! - Permanent Delegate
//! - Interest-Bearing Config
//! - Metadata (Token Metadata Interface)

use super::transaction::{AccountMeta, Instruction};

// ═══════════════════════════════════════════════════════════════════
// Program IDs
// ═══════════════════════════════════════════════════════════════════

/// Token-2022 Program ID: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
pub const TOKEN_2022_ID: [u8; 32] = [
    0x06, 0xDD, 0xF6, 0xE1, 0xD7, 0x65, 0xA1, 0x93, 0xD9, 0xCB, 0xE1, 0x46, 0xCE, 0xEB, 0x79,
    0xAC, 0x1C, 0xB4, 0x85, 0xED, 0x5F, 0x5B, 0x37, 0x91, 0x3A, 0x8C, 0xF5, 0x85, 0x7E, 0xFF,
    0x00, 0xAA,
];

/// System Program ID.
const SYSTEM_PROGRAM_ID: [u8; 32] = [0; 32];

// ═══════════════════════════════════════════════════════════════════
// Default Account State Extension
// ═══════════════════════════════════════════════════════════════════

/// Account states for Default Account State extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    /// Uninitialized / default.
    Uninitialized = 0,
    /// Initialized (active).
    Initialized = 1,
    /// Frozen (cannot transfer).
    Frozen = 2,
}

/// Initialize DefaultAccountState extension on a mint.
///
/// Sets the default state for new token accounts created for this mint.
#[must_use]
pub fn initialize_default_account_state(
    mint: &[u8; 32],
    state: AccountState,
) -> Instruction {
    // Extension instruction: discriminator = 29 (DefaultAccountState)
    // Sub-instruction: 0 = Initialize
    let data = vec![29, 0, state as u8];
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Update DefaultAccountState on a mint.
#[must_use]
pub fn update_default_account_state(
    mint: &[u8; 32],
    freeze_authority: &[u8; 32],
    state: AccountState,
) -> Instruction {
    let data = vec![29, 1, state as u8];
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*freeze_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transfer Fee Extension
// ═══════════════════════════════════════════════════════════════════

/// Initialize TransferFeeConfig extension on a mint.
///
/// # Arguments
/// - `mint` — The mint to configure
/// - `transfer_fee_config_authority` — Authority to update fee config
/// - `withdraw_withheld_authority` — Authority to withdraw withheld fees
/// - `transfer_fee_basis_points` — Fee in basis points (100 = 1%)
/// - `maximum_fee` — Maximum fee per transfer (in token smallest units)
#[must_use]
pub fn initialize_transfer_fee_config(
    mint: &[u8; 32],
    transfer_fee_config_authority: Option<&[u8; 32]>,
    withdraw_withheld_authority: Option<&[u8; 32]>,
    transfer_fee_basis_points: u16,
    maximum_fee: u64,
) -> Instruction {
    // Extension instruction: discriminator = 26 (TransferFeeExtension)
    // Sub-instruction: 0 = Initialize
    let mut data = vec![26, 0];

    // COption<Pubkey> for config authority
    match transfer_fee_config_authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth);
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }

    // COption<Pubkey> for withdraw authority
    match withdraw_withheld_authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth);
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }

    data.extend_from_slice(&transfer_fee_basis_points.to_le_bytes());
    data.extend_from_slice(&maximum_fee.to_le_bytes());

    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Create a `HarvestWithheldTokensToMint` instruction.
///
/// Harvests withheld tokens from token accounts back to the mint.
#[must_use]
pub fn harvest_withheld_tokens_to_mint(
    mint: &[u8; 32],
    token_accounts: &[[u8; 32]],
) -> Instruction {
    let data = vec![26, 4]; // TransferFee + HarvestWithheld
    let mut accounts = vec![AccountMeta::new(*mint, false)];
    for acct in token_accounts {
        accounts.push(AccountMeta::new(*acct, false));
    }
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts,
        data,
    }
}

/// Create a `WithdrawWithheldTokensFromMint` instruction.
#[must_use]
pub fn withdraw_withheld_tokens_from_mint(
    mint: &[u8; 32],
    destination: &[u8; 32],
    withdraw_authority: &[u8; 32],
) -> Instruction {
    let data = vec![26, 3]; // TransferFee + WithdrawFromMint
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*withdraw_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transfer Hook Extension
// ═══════════════════════════════════════════════════════════════════

/// Initialize TransferHook extension on a mint.
///
/// Sets the program that will be CPI-called on every token transfer.
#[must_use]
pub fn initialize_transfer_hook(
    mint: &[u8; 32],
    authority: Option<&[u8; 32]>,
    transfer_hook_program_id: &[u8; 32],
) -> Instruction {
    // Extension instruction: discriminator = 36 (TransferHook)
    // Sub-instruction: 0 = Initialize
    let mut data = vec![36, 0];
    match authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth);
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }
    data.extend_from_slice(transfer_hook_program_id);

    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Update the TransferHook program ID on a mint.
#[must_use]
pub fn update_transfer_hook(
    mint: &[u8; 32],
    authority: &[u8; 32],
    new_program_id: &[u8; 32],
) -> Instruction {
    let mut data = vec![36, 1]; // TransferHook + Update
    data.extend_from_slice(new_program_id);
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// CPI Guard Extension
// ═══════════════════════════════════════════════════════════════════

/// Enable CPI Guard on a token account.
///
/// Prevents certain actions from being performed via CPI (cross-program invocation).
#[must_use]
pub fn enable_cpi_guard(
    account: &[u8; 32],
    owner: &[u8; 32],
) -> Instruction {
    let data = vec![37, 0]; // CpiGuard + Enable
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// Disable CPI Guard on a token account.
#[must_use]
pub fn disable_cpi_guard(
    account: &[u8; 32],
    owner: &[u8; 32],
) -> Instruction {
    let data = vec![37, 1]; // CpiGuard + Disable
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Permanent Delegate Extension
// ═══════════════════════════════════════════════════════════════════

/// Initialize PermanentDelegate extension on a mint.
///
/// Sets a delegate that can transfer/burn from any account of this mint.
#[must_use]
pub fn initialize_permanent_delegate(
    mint: &[u8; 32],
    delegate: &[u8; 32],
) -> Instruction {
    let mut data = vec![35, 0]; // PermanentDelegate + Initialize
    data.extend_from_slice(delegate);
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Memo Required Extension (MemoTransfer)
// ═══════════════════════════════════════════════════════════════════

/// Enable required memo on incoming transfers for a token account.
#[must_use]
pub fn enable_required_memo_transfers(
    account: &[u8; 32],
    owner: &[u8; 32],
) -> Instruction {
    let data = vec![30, 0]; // MemoTransfer + Enable
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// Disable required memo on incoming transfers for a token account.
#[must_use]
pub fn disable_required_memo_transfers(
    account: &[u8; 32],
    owner: &[u8; 32],
) -> Instruction {
    let data = vec![30, 1]; // MemoTransfer + Disable
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Interest-Bearing Config Extension
// ═══════════════════════════════════════════════════════════════════

/// Initialize InterestBearingConfig extension on a mint.
///
/// # Arguments
/// - `rate_authority` — Authority that can update the interest rate
/// - `rate` — Interest rate in basis points (per year)
#[must_use]
pub fn initialize_interest_bearing_config(
    mint: &[u8; 32],
    rate_authority: Option<&[u8; 32]>,
    rate: i16,
) -> Instruction {
    let mut data = vec![33, 0]; // InterestBearingConfig + Initialize
    match rate_authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth);
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }
    data.extend_from_slice(&rate.to_le_bytes());

    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Update the interest rate.
#[must_use]
pub fn update_interest_rate(
    mint: &[u8; 32],
    rate_authority: &[u8; 32],
    new_rate: i16,
) -> Instruction {
    let mut data = vec![33, 1]; // InterestBearingConfig + Update
    data.extend_from_slice(&new_rate.to_le_bytes());
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*rate_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Token Metadata Interface (SPL Token Metadata)
// ═══════════════════════════════════════════════════════════════════

/// Initialize token metadata on a Token-2022 mint.
///
/// Sets the name, symbol, and URI for the token.
#[must_use]
pub fn initialize_token_metadata(
    mint: &[u8; 32],
    update_authority: &[u8; 32],
    mint_authority: &[u8; 32],
    name: &str,
    symbol: &str,
    uri: &str,
) -> Instruction {
    let mut data = Vec::new();
    // Anchor-compatible discriminator for spl_token_metadata_interface::Initialize
    // SHA256("spl_token_metadata_interface:initialize")[..8]
    data.extend_from_slice(&[210, 225, 30, 162, 88, 184, 226, 143]);

    // Borsh: string = u32_len + bytes
    let name_bytes = name.as_bytes();
    data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(name_bytes);

    let symbol_bytes = symbol.as_bytes();
    data.extend_from_slice(&(symbol_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(symbol_bytes);

    let uri_bytes = uri.as_bytes();
    data.extend_from_slice(&(uri_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(uri_bytes);

    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*update_authority, false),
            AccountMeta::new_readonly(*mint_authority, true),
        ],
        data,
    }
}

/// Update a metadata field on a Token-2022 mint.
///
/// # Arguments
/// - `field` — Field name (e.g., "name", "symbol", "uri", or custom key)
/// - `value` — New value for the field
#[must_use]
pub fn update_token_metadata_field(
    mint: &[u8; 32],
    update_authority: &[u8; 32],
    field: &str,
    value: &str,
) -> Instruction {
    let mut data = Vec::new();
    // SHA256("spl_token_metadata_interface:updating_field")[..8]
    data.extend_from_slice(&[221, 233, 49, 45, 181, 202, 220, 200]);

    let field_bytes = field.as_bytes();
    data.extend_from_slice(&(field_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(field_bytes);

    let value_bytes = value.as_bytes();
    data.extend_from_slice(&(value_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(value_bytes);

    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*update_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Group / Member Token Extensions
// ═══════════════════════════════════════════════════════════════════

/// Initialize GroupPointer extension on a mint.
#[must_use]
pub fn initialize_group_pointer(
    mint: &[u8; 32],
    authority: Option<&[u8; 32]>,
    group_address: &[u8; 32],
) -> Instruction {
    let mut data = vec![40, 0]; // GroupPointer + Initialize
    match authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth);
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }
    data.extend_from_slice(group_address);
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
        data,
    }
}

/// Initialize GroupMemberPointer extension on a mint.
#[must_use]
pub fn initialize_group_member_pointer(
    mint: &[u8; 32],
    authority: Option<&[u8; 32]>,
    member_address: &[u8; 32],
) -> Instruction {
    let mut data = vec![41, 0]; // GroupMemberPointer + Initialize
    match authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth);
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }
    data.extend_from_slice(member_address);
    Instruction {
        program_id: TOKEN_2022_ID,
        accounts: vec![AccountMeta::new(*mint, false)],
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

    const MINT: [u8; 32] = [0xAA; 32];
    const AUTH: [u8; 32] = [0xBB; 32];
    const DEST: [u8; 32] = [0xCC; 32];

    // ─── Default Account State ───────────────────────────────────

    #[test]
    fn test_initialize_default_account_state() {
        let ix = initialize_default_account_state(&MINT, AccountState::Frozen);
        assert_eq!(ix.program_id, TOKEN_2022_ID);
        assert_eq!(ix.data[0], 29); // extension discriminator
        assert_eq!(ix.data[1], 0); // sub-instruction
        assert_eq!(ix.data[2], 2); // Frozen
    }

    #[test]
    fn test_update_default_account_state() {
        let ix = update_default_account_state(&MINT, &AUTH, AccountState::Initialized);
        assert_eq!(ix.data[0], 29);
        assert_eq!(ix.data[1], 1);
        assert_eq!(ix.data[2], 1); // Initialized
        assert_eq!(ix.accounts.len(), 2);
    }

    // ─── Transfer Fee ────────────────────────────────────────────

    #[test]
    fn test_initialize_transfer_fee_config() {
        let ix = initialize_transfer_fee_config(
            &MINT,
            Some(&AUTH),
            Some(&DEST),
            100, // 1%
            1_000_000,
        );
        assert_eq!(ix.data[0], 26);
        assert_eq!(ix.data[1], 0);
        // Has option bytes + pubkeys
        assert!(ix.data.len() > 70);
    }

    #[test]
    fn test_initialize_transfer_fee_config_no_authorities() {
        let ix = initialize_transfer_fee_config(&MINT, None, None, 50, 500);
        assert_eq!(ix.data[0], 26);
        assert_eq!(ix.data[2], 0); // None for first authority
    }

    #[test]
    fn test_harvest_withheld_tokens() {
        let accounts = vec![[0x11; 32], [0x22; 32]];
        let ix = harvest_withheld_tokens_to_mint(&MINT, &accounts);
        assert_eq!(ix.data, vec![26, 4]);
        assert_eq!(ix.accounts.len(), 3); // mint + 2 token accounts
    }

    #[test]
    fn test_withdraw_withheld_tokens() {
        let ix = withdraw_withheld_tokens_from_mint(&MINT, &DEST, &AUTH);
        assert_eq!(ix.data, vec![26, 3]);
        assert_eq!(ix.accounts.len(), 3);
    }

    // ─── Transfer Hook ───────────────────────────────────────────

    #[test]
    fn test_initialize_transfer_hook() {
        let hook_program = [0xDD; 32];
        let ix = initialize_transfer_hook(&MINT, Some(&AUTH), &hook_program);
        assert_eq!(ix.data[0], 36);
        assert_eq!(ix.data[1], 0);
        assert_eq!(ix.data[2], 1); // Some
    }

    #[test]
    fn test_initialize_transfer_hook_no_authority() {
        let hook_program = [0xDD; 32];
        let ix = initialize_transfer_hook(&MINT, None, &hook_program);
        assert_eq!(ix.data[2], 0); // None
    }

    #[test]
    fn test_update_transfer_hook() {
        let new_program = [0xEE; 32];
        let ix = update_transfer_hook(&MINT, &AUTH, &new_program);
        assert_eq!(ix.data[0], 36);
        assert_eq!(ix.data[1], 1);
        assert_eq!(&ix.data[2..34], &new_program);
    }

    // ─── CPI Guard ───────────────────────────────────────────────

    #[test]
    fn test_enable_cpi_guard() {
        let ix = enable_cpi_guard(&MINT, &AUTH);
        assert_eq!(ix.data, vec![37, 0]);
        assert_eq!(ix.accounts.len(), 2);
    }

    #[test]
    fn test_disable_cpi_guard() {
        let ix = disable_cpi_guard(&MINT, &AUTH);
        assert_eq!(ix.data, vec![37, 1]);
    }

    // ─── Permanent Delegate ──────────────────────────────────────

    #[test]
    fn test_initialize_permanent_delegate() {
        let ix = initialize_permanent_delegate(&MINT, &AUTH);
        assert_eq!(ix.data[0], 35);
        assert_eq!(ix.data[1], 0);
        assert_eq!(&ix.data[2..34], &AUTH);
    }

    // ─── Memo Transfer ───────────────────────────────────────────

    #[test]
    fn test_enable_required_memo() {
        let ix = enable_required_memo_transfers(&MINT, &AUTH);
        assert_eq!(ix.data, vec![30, 0]);
    }

    #[test]
    fn test_disable_required_memo() {
        let ix = disable_required_memo_transfers(&MINT, &AUTH);
        assert_eq!(ix.data, vec![30, 1]);
    }

    // ─── Interest-Bearing Config ─────────────────────────────────

    #[test]
    fn test_initialize_interest_bearing() {
        let ix = initialize_interest_bearing_config(&MINT, Some(&AUTH), 500);
        assert_eq!(ix.data[0], 33);
        assert_eq!(ix.data[1], 0);
        assert_eq!(ix.data[2], 1); // Some
        // Check rate is at the end
        let rate_offset = ix.data.len() - 2;
        let rate = i16::from_le_bytes([ix.data[rate_offset], ix.data[rate_offset + 1]]);
        assert_eq!(rate, 500);
    }

    #[test]
    fn test_update_interest_rate() {
        let ix = update_interest_rate(&MINT, &AUTH, -100);
        assert_eq!(ix.data[0], 33);
        assert_eq!(ix.data[1], 1);
        let rate = i16::from_le_bytes([ix.data[2], ix.data[3]]);
        assert_eq!(rate, -100);
    }

    // ─── Token Metadata ──────────────────────────────────────────

    #[test]
    fn test_initialize_token_metadata() {
        let ix = initialize_token_metadata(
            &MINT, &AUTH, &AUTH,
            "Test Token", "TEST", "https://example.com/meta.json",
        );
        assert_eq!(ix.program_id, TOKEN_2022_ID);
        assert_eq!(ix.accounts.len(), 3);
        // Should start with the 8-byte discriminator
        assert_eq!(ix.data.len(), 8 + 4 + 10 + 4 + 4 + 4 + 29); // disc + 3 strings with length prefix
    }

    #[test]
    fn test_update_token_metadata_field() {
        let ix = update_token_metadata_field(&MINT, &AUTH, "name", "New Name");
        assert_eq!(ix.program_id, TOKEN_2022_ID);
        assert_eq!(ix.accounts.len(), 2);
        // Discriminator (8) + "name" (4+4) + "New Name" (4+8)
        assert_eq!(ix.data.len(), 8 + 4 + 4 + 4 + 8);
    }

    // ─── Group / Member ──────────────────────────────────────────

    #[test]
    fn test_initialize_group_pointer() {
        let group_addr = [0xFF; 32];
        let ix = initialize_group_pointer(&MINT, Some(&AUTH), &group_addr);
        assert_eq!(ix.data[0], 40);
        assert_eq!(ix.data[1], 0);
    }

    #[test]
    fn test_initialize_group_member_pointer() {
        let member_addr = [0xEE; 32];
        let ix = initialize_group_member_pointer(&MINT, None, &member_addr);
        assert_eq!(ix.data[0], 41);
        assert_eq!(ix.data[1], 0);
        assert_eq!(ix.data[2], 0); // None
    }

    // ─── Account State Enum ──────────────────────────────────────

    #[test]
    fn test_account_state_values() {
        assert_eq!(AccountState::Uninitialized as u8, 0);
        assert_eq!(AccountState::Initialized as u8, 1);
        assert_eq!(AccountState::Frozen as u8, 2);
    }
}
