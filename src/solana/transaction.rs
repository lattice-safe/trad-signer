//! Solana transaction building, signing, and program interaction helpers.
//!
//! Implements the Solana transaction wire format including:
//! - Compact-u16 encoding
//! - Instructions and message serialization (legacy + v0 versioned)
//! - System Program helpers (transfer, create_account, allocate)
//! - SPL Token helpers (transfer, approve, mint_to)
//! - Compute Budget (priority fees)
//! - Address Lookup Table references (versioned transactions)
//!
//! # Example
//! ```no_run
//! use chains_sdk::solana::transaction::*;
//! use chains_sdk::solana::SolanaSigner;
//! use chains_sdk::traits::KeyPair;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let signer = SolanaSigner::generate()?;
//!     let to = [0xBB; 32];
//!     let ix = system_program::transfer(&signer.public_key_bytes_32(), &to, 1_000_000);
//!     let msg = Message::new(&[ix], signer.public_key_bytes_32());
//!     let tx = Transaction::sign(&msg, &[&signer], [0u8; 32])?;
//!     let raw = tx.serialize();
//!     Ok(())
//! }
//! ```

use super::SolanaSigner;
use crate::error::SignerError;
use ed25519_dalek::Signer as DalekSigner;

// ─── Compact-u16 Encoding ──────────────────────────────────────────

/// Encode a `u16` as a Solana compact-u16 (variable-length encoding).
///
/// Used throughout Solana wire format for lengths.
#[must_use]
pub fn encode_compact_u16(val: u16) -> Vec<u8> {
    if val < 0x80 {
        vec![val as u8]
    } else if val < 0x4000 {
        vec![(val & 0x7F | 0x80) as u8, (val >> 7) as u8]
    } else {
        vec![
            (val & 0x7F | 0x80) as u8,
            ((val >> 7) & 0x7F | 0x80) as u8,
            (val >> 14) as u8,
        ]
    }
}

/// Decode a compact-u16 from bytes. Returns (value, bytes_consumed).
pub fn decode_compact_u16(data: &[u8]) -> Result<(u16, usize), SignerError> {
    if data.is_empty() {
        return Err(SignerError::ParseError("compact-u16: empty".into()));
    }
    let b0 = data[0] as u16;
    if b0 < 0x80 {
        return Ok((b0, 1));
    }
    if data.len() < 2 {
        return Err(SignerError::ParseError("compact-u16: truncated".into()));
    }
    let b1 = data[1] as u16;
    if b1 < 0x80 {
        return Ok(((b0 & 0x7F) | (b1 << 7), 2));
    }
    if data.len() < 3 {
        return Err(SignerError::ParseError("compact-u16: truncated".into()));
    }
    let b2 = data[2] as u16;
    Ok(((b0 & 0x7F) | ((b1 & 0x7F) << 7) | (b2 << 14), 3))
}

// ─── Account Meta ──────────────────────────────────────────────────

/// An account reference in a Solana instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    /// 32-byte public key.
    pub pubkey: [u8; 32],
    /// Whether this account is a signer.
    pub is_signer: bool,
    /// Whether this account is writable.
    pub is_writable: bool,
}

impl AccountMeta {
    /// Create a writable signer account.
    #[must_use]
    pub fn new(pubkey: [u8; 32], is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }

    /// Create a read-only account.
    #[must_use]
    pub fn new_readonly(pubkey: [u8; 32], is_signer: bool) -> Self {
        Self {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

// ─── Instruction ───────────────────────────────────────────────────

/// A Solana instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Program ID (32 bytes).
    pub program_id: [u8; 32],
    /// Account references.
    pub accounts: Vec<AccountMeta>,
    /// Instruction data.
    pub data: Vec<u8>,
}

// ─── Message ───────────────────────────────────────────────────────

/// A Solana transaction message (legacy format).
#[derive(Debug, Clone)]
pub struct Message {
    /// Number of required signatures.
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts.
    pub num_readonly_signed_accounts: u8,
    /// Number of read-only unsigned accounts.
    pub num_readonly_unsigned_accounts: u8,
    /// All account keys referenced by the message.
    pub account_keys: Vec<[u8; 32]>,
    /// Recent blockhash (32 bytes).
    pub recent_blockhash: [u8; 32],
    /// Compiled instructions.
    pub instructions: Vec<CompiledInstruction>,
}

/// A compiled instruction (indices into account_keys array).
#[derive(Debug, Clone)]
pub struct CompiledInstruction {
    /// Index of the program ID in account_keys.
    pub program_id_index: u8,
    /// Indices of accounts in account_keys.
    pub accounts: Vec<u8>,
    /// Instruction data.
    pub data: Vec<u8>,
}

impl Message {
    /// Build a message from instructions and a fee payer.
    ///
    /// # Panics
    /// Panics if any instruction references an account key not present in the
    /// deduplicated key list, or if the key list exceeds 256 entries.
    /// Use [`try_new`](Self::try_new) for the fallible version.
    #[must_use]
    pub fn new(instructions: &[Instruction], fee_payer: [u8; 32]) -> Self {
        match Self::try_new(instructions, fee_payer) {
            Ok(msg) => msg,
            Err(_) => {
                // All instructions were built by our own constructors, so key
                // lookups should never fail.  If they do, the caller assembled
                // an invalid instruction set — surface this loudly.
                #[allow(clippy::panic)]
                {
                    panic!(
                        "Message::new: instruction references unknown account key \
                         or key list exceeds u8::MAX"
                    );
                }
            }
        }
    }

    /// Fallible version of [`new`](Self::new).
    ///
    /// Returns an error if any instruction references an account key not
    /// present in the deduplicated key list, or if the key list exceeds 256.
    pub fn try_new(instructions: &[Instruction], fee_payer: [u8; 32]) -> Result<Self, SignerError> {
        let mut writable_signers: Vec<[u8; 32]> = vec![fee_payer];
        let mut readonly_signers: Vec<[u8; 32]> = Vec::new();
        let mut writable_nonsigners: Vec<[u8; 32]> = Vec::new();
        let mut readonly_nonsigners: Vec<[u8; 32]> = Vec::new();

        for ix in instructions {
            for acc in &ix.accounts {
                // Skip if already fee payer
                if acc.pubkey == fee_payer {
                    continue;
                }
                match (acc.is_signer, acc.is_writable) {
                    (true, true) => {
                        if !writable_signers.contains(&acc.pubkey) {
                            writable_signers.push(acc.pubkey);
                        }
                    }
                    (true, false) => {
                        if !readonly_signers.contains(&acc.pubkey) {
                            readonly_signers.push(acc.pubkey);
                        }
                    }
                    (false, true) => {
                        if !writable_nonsigners.contains(&acc.pubkey) {
                            writable_nonsigners.push(acc.pubkey);
                        }
                    }
                    (false, false) => {
                        if !readonly_nonsigners.contains(&acc.pubkey) {
                            readonly_nonsigners.push(acc.pubkey);
                        }
                    }
                }
            }
            // Add program IDs as read-only non-signers
            if !writable_signers.contains(&ix.program_id)
                && !readonly_signers.contains(&ix.program_id)
                && !writable_nonsigners.contains(&ix.program_id)
                && !readonly_nonsigners.contains(&ix.program_id)
            {
                readonly_nonsigners.push(ix.program_id);
            }
        }

        let total_keys = writable_signers.len()
            + readonly_signers.len()
            + writable_nonsigners.len()
            + readonly_nonsigners.len();
        if total_keys > 256 {
            return Err(SignerError::ParseError(format!(
                "too many account keys: {total_keys}, max 256"
            )));
        }

        let num_required_signatures = (writable_signers.len() + readonly_signers.len()) as u8;
        let num_readonly_signed = readonly_signers.len() as u8;
        let num_readonly_unsigned = readonly_nonsigners.len() as u8;

        let mut account_keys = Vec::new();
        account_keys.extend_from_slice(&writable_signers);
        account_keys.extend_from_slice(&readonly_signers);
        account_keys.extend_from_slice(&writable_nonsigners);
        account_keys.extend_from_slice(&readonly_nonsigners);

        // Compile instructions
        let mut compiled = Vec::with_capacity(instructions.len());
        for ix in instructions {
            let program_id_index = account_keys
                .iter()
                .position(|k| *k == ix.program_id)
                .ok_or_else(|| {
                    SignerError::ParseError("program id not found in account keys".into())
                })? as u8;
            let mut accounts = Vec::with_capacity(ix.accounts.len());
            for a in &ix.accounts {
                let idx = account_keys
                    .iter()
                    .position(|k| *k == a.pubkey)
                    .ok_or_else(|| {
                        SignerError::ParseError("account key not found in key list".into())
                    })? as u8;
                accounts.push(idx);
            }
            compiled.push(CompiledInstruction {
                program_id_index,
                accounts,
                data: ix.data.clone(),
            });
        }

        Ok(Self {
            num_required_signatures,
            num_readonly_signed_accounts: num_readonly_signed,
            num_readonly_unsigned_accounts: num_readonly_unsigned,
            account_keys,
            recent_blockhash: [0u8; 32], // set later
            instructions: compiled,
        })
    }

    /// Serialize the message to bytes for signing.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.num_required_signatures);
        buf.push(self.num_readonly_signed_accounts);
        buf.push(self.num_readonly_unsigned_accounts);

        buf.extend_from_slice(&encode_compact_u16(self.account_keys.len() as u16));
        for key in &self.account_keys {
            buf.extend_from_slice(key);
        }

        buf.extend_from_slice(&self.recent_blockhash);

        buf.extend_from_slice(&encode_compact_u16(self.instructions.len() as u16));
        for ix in &self.instructions {
            buf.push(ix.program_id_index);
            buf.extend_from_slice(&encode_compact_u16(ix.accounts.len() as u16));
            buf.extend_from_slice(&ix.accounts);
            buf.extend_from_slice(&encode_compact_u16(ix.data.len() as u16));
            buf.extend_from_slice(&ix.data);
        }
        buf
    }
}

// ─── Transaction ───────────────────────────────────────────────────

/// A signed Solana transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Ed25519 signatures (64 bytes each).
    pub signatures: Vec<[u8; 64]>,
    /// The message that was signed.
    pub message: Message,
}

impl Transaction {
    /// Sign a message with one or more signers.
    pub fn sign(
        message: &Message,
        signers: &[&SolanaSigner],
        recent_blockhash: [u8; 32],
    ) -> Result<Self, SignerError> {
        let mut msg = message.clone();
        msg.recent_blockhash = recent_blockhash;
        let serialized = msg.serialize();

        let mut signatures = Vec::new();
        for signer in signers {
            let sig = signer.signing_key.sign(&serialized);
            signatures.push(sig.to_bytes());
        }

        Ok(Self {
            signatures,
            message: msg,
        })
    }

    /// Serialize the transaction for sending via `sendTransaction` RPC.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_compact_u16(self.signatures.len() as u16));
        for sig in &self.signatures {
            buf.extend_from_slice(sig);
        }
        buf.extend_from_slice(&self.message.serialize());
        buf
    }
}

// ═══════════════════════════════════════════════════════════════════
// System Program
// ═══════════════════════════════════════════════════════════════════

/// Solana System Program helpers.
pub mod system_program {
    use super::*;

    /// System Program ID: `11111111111111111111111111111111`
    pub const ID: [u8; 32] = [0; 32];

    /// Create a SOL transfer instruction.
    ///
    /// # Arguments
    /// - `from` — Sender pubkey (must be signer)
    /// - `to` — Recipient pubkey
    /// - `lamports` — Amount in lamports (1 SOL = 1_000_000_000 lamports)
    #[must_use]
    pub fn transfer(from: &[u8; 32], to: &[u8; 32], lamports: u64) -> Instruction {
        let mut data = vec![2, 0, 0, 0]; // Transfer instruction index
        data.extend_from_slice(&lamports.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
            data,
        }
    }

    /// Create a `CreateAccount` instruction.
    #[must_use]
    pub fn create_account(
        from: &[u8; 32],
        new_account: &[u8; 32],
        lamports: u64,
        space: u64,
        owner: &[u8; 32],
    ) -> Instruction {
        let mut data = vec![0, 0, 0, 0]; // CreateAccount instruction index
        data.extend_from_slice(&lamports.to_le_bytes());
        data.extend_from_slice(&space.to_le_bytes());
        data.extend_from_slice(owner);
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*from, true),
                AccountMeta::new(*new_account, true),
            ],
            data,
        }
    }

    /// Create an `Allocate` instruction.
    #[must_use]
    pub fn allocate(account: &[u8; 32], space: u64) -> Instruction {
        let mut data = vec![8, 0, 0, 0]; // Allocate instruction index
        data.extend_from_slice(&space.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![AccountMeta::new(*account, true)],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SPL Token Program
// ═══════════════════════════════════════════════════════════════════

/// SPL Token Program helpers.
pub mod spl_token {
    use super::*;

    /// SPL Token Program ID: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`
    pub const ID: [u8; 32] = [
        0x06, 0xDD, 0xF6, 0xE1, 0xD7, 0x65, 0xA1, 0x93, 0xD9, 0xCB, 0xE1, 0x46, 0xCE, 0xEB, 0x79,
        0xAC, 0x1C, 0xB4, 0x85, 0xED, 0x5F, 0x5B, 0x37, 0x91, 0x3A, 0x8C, 0xF5, 0x85, 0x7E, 0xFF,
        0x00, 0xA9,
    ];

    /// Create an SPL Token `Transfer` instruction.
    ///
    /// # Arguments
    /// - `source` — Source token account
    /// - `destination` — Destination token account
    /// - `authority` — Owner of the source account (signer)
    /// - `amount` — Token amount (in smallest unit)
    #[must_use]
    pub fn transfer(
        source: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![3]; // Transfer instruction discriminator
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `Approve` instruction.
    #[must_use]
    pub fn approve(
        source: &[u8; 32],
        delegate: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![4]; // Approve instruction discriminator
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*delegate, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `MintTo` instruction.
    #[must_use]
    pub fn mint_to(
        mint: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![7]; // MintTo instruction discriminator
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `Burn` instruction.
    #[must_use]
    pub fn burn(
        token_account: &[u8; 32],
        mint: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
    ) -> Instruction {
        let mut data = vec![8]; // Burn
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*token_account, false),
                AccountMeta::new(*mint, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `CloseAccount` instruction.
    #[must_use]
    pub fn close_account(
        account: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
    ) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data: vec![9], // CloseAccount
        }
    }

    /// Create an SPL Token `FreezeAccount` instruction.
    #[must_use]
    pub fn freeze_account(
        account: &[u8; 32],
        mint: &[u8; 32],
        freeze_authority: &[u8; 32],
    ) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(*freeze_authority, true),
            ],
            data: vec![10], // FreezeAccount
        }
    }

    /// Create an SPL Token `ThawAccount` instruction.
    #[must_use]
    pub fn thaw_account(
        account: &[u8; 32],
        mint: &[u8; 32],
        freeze_authority: &[u8; 32],
    ) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(*freeze_authority, true),
            ],
            data: vec![11], // ThawAccount
        }
    }

    /// Create an SPL Token `InitializeMint` instruction.
    ///
    /// # Arguments
    /// - `mint` — The mint account to initialize
    /// - `decimals` — Number of decimals for the token
    /// - `mint_authority` — Authority that can mint new tokens
    /// - `freeze_authority` — Optional authority that can freeze accounts
    #[must_use]
    pub fn initialize_mint(
        mint: &[u8; 32],
        decimals: u8,
        mint_authority: &[u8; 32],
        freeze_authority: Option<&[u8; 32]>,
    ) -> Instruction {
        let rent_sysvar: [u8; 32] = {
            let mut id = [0u8; 32];
            // SysvarRent111111111111111111111111111111111
            id[0] = 0x06;
            id[1] = 0xa7;
            id[2] = 0xd5;
            id[3] = 0x17;
            id[4] = 0x19;
            id[5] = 0x2c;
            id
        };
        let mut data = vec![0]; // InitializeMint
        data.push(decimals);
        data.extend_from_slice(mint_authority);
        match freeze_authority {
            Some(auth) => {
                data.push(1); // COption::Some
                data.extend_from_slice(auth);
            }
            None => {
                data.push(0); // COption::None
                data.extend_from_slice(&[0u8; 32]);
            }
        }
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*mint, false),
                AccountMeta::new_readonly(rent_sysvar, false),
            ],
            data,
        }
    }

    /// Create an SPL Token `InitializeAccount` instruction.
    #[must_use]
    pub fn initialize_account(
        account: &[u8; 32],
        mint: &[u8; 32],
        owner: &[u8; 32],
    ) -> Instruction {
        let rent_sysvar: [u8; 32] = {
            let mut id = [0u8; 32];
            id[0] = 0x06;
            id[1] = 0xa7;
            id[2] = 0xd5;
            id[3] = 0x17;
            id[4] = 0x19;
            id[5] = 0x2c;
            id
        };
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*account, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new_readonly(*owner, false),
                AccountMeta::new_readonly(rent_sysvar, false),
            ],
            data: vec![1], // InitializeAccount
        }
    }

    /// SPL Token authority types for `SetAuthority`.
    #[derive(Debug, Clone, Copy)]
    pub enum AuthorityType {
        /// Authority to mint new tokens.
        MintTokens = 0,
        /// Authority to freeze accounts.
        FreezeAccount = 1,
        /// Owner of a token account.
        AccountOwner = 2,
        /// Authority to close a token account.
        CloseAccount = 3,
    }

    /// Create an SPL Token `SetAuthority` instruction.
    #[must_use]
    pub fn set_authority(
        account_or_mint: &[u8; 32],
        current_authority: &[u8; 32],
        authority_type: AuthorityType,
        new_authority: Option<&[u8; 32]>,
    ) -> Instruction {
        let mut data = vec![6]; // SetAuthority
        data.push(authority_type as u8);
        match new_authority {
            Some(auth) => {
                data.push(1); // COption::Some
                data.extend_from_slice(auth);
            }
            None => {
                data.push(0); // COption::None
                data.extend_from_slice(&[0u8; 32]);
            }
        }
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*account_or_mint, false),
                AccountMeta::new_readonly(*current_authority, true),
            ],
            data,
        }
    }

    /// Create an SPL Token `Revoke` instruction (revoke delegate).
    #[must_use]
    pub fn revoke(source: &[u8; 32], authority: &[u8; 32]) -> Instruction {
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data: vec![5], // Revoke
        }
    }

    /// Create an SPL Token `TransferChecked` instruction.
    ///
    /// Like `transfer` but also verifies the token's decimals and mint.
    #[must_use]
    pub fn transfer_checked(
        source: &[u8; 32],
        mint: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
        decimals: u8,
    ) -> Instruction {
        let mut data = vec![12]; // TransferChecked
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SPL Token-2022 Program
// ═══════════════════════════════════════════════════════════════════

/// SPL Token-2022 (Token Extensions) program helpers.
pub mod spl_token_2022 {
    use super::*;

    /// Token-2022 Program ID: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`
    pub const ID: [u8; 32] = [
        0x06, 0xDD, 0xF6, 0xE1, 0xEE, 0x75, 0x8F, 0xDE, 0x18, 0x42, 0x5D, 0xBC, 0xE4, 0x6C, 0xCD,
        0xDA, 0xB6, 0x1A, 0xFC, 0x4D, 0x83, 0xB9, 0x0D, 0x27, 0xFE, 0xBD, 0xF9, 0x28, 0xD8, 0xA1,
        0x8B, 0xFC,
    ];

    /// Create a Token-2022 `TransferChecked` instruction.
    #[must_use]
    pub fn transfer_checked(
        source: &[u8; 32],
        mint: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
        decimals: u8,
    ) -> Instruction {
        let mut data = vec![12]; // TransferChecked
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }

    /// Create a Token-2022 `TransferCheckedWithFee` instruction.
    ///
    /// Used when the mint has a TransferFeeConfig extension.
    #[must_use]
    pub fn transfer_checked_with_fee(
        source: &[u8; 32],
        mint: &[u8; 32],
        destination: &[u8; 32],
        authority: &[u8; 32],
        amount: u64,
        decimals: u8,
        fee: u64,
    ) -> Instruction {
        let mut data = vec![26]; // TransferCheckedWithFee
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);
        data.extend_from_slice(&fee.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(*source, false),
                AccountMeta::new_readonly(*mint, false),
                AccountMeta::new(*destination, false),
                AccountMeta::new_readonly(*authority, true),
            ],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Compute Budget (Priority Fees)
// ═══════════════════════════════════════════════════════════════════

/// Compute Budget program helpers for priority fees.
pub mod compute_budget {
    use super::*;

    /// Compute Budget Program ID.
    pub const ID: [u8; 32] = [
        0x03, 0x06, 0x46, 0x6F, 0xE5, 0x21, 0x17, 0x32, 0xFF, 0xEC, 0xAD, 0xBA, 0x72, 0xC3, 0x9B,
        0xE7, 0xBC, 0x8C, 0xE5, 0xBB, 0xC5, 0xF7, 0x12, 0x6B, 0x2C, 0x43, 0x9B, 0x3A, 0x40, 0x00,
        0x00, 0x00,
    ];

    /// Set the compute unit limit.
    #[must_use]
    pub fn set_compute_unit_limit(units: u32) -> Instruction {
        let mut data = vec![2]; // SetComputeUnitLimit
        data.extend_from_slice(&units.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![],
            data,
        }
    }

    /// Set the compute unit price (priority fee in micro-lamports).
    #[must_use]
    pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
        let mut data = vec![3]; // SetComputeUnitPrice
        data.extend_from_slice(&micro_lamports.to_le_bytes());
        Instruction {
            program_id: ID,
            accounts: vec![],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Versioned Transactions (v0)
// ═══════════════════════════════════════════════════════════════════

/// Address lookup table reference for versioned transactions.
#[derive(Debug, Clone)]
pub struct AddressLookupTable {
    /// Account key of the lookup table.
    pub account_key: [u8; 32],
    /// Indices of writable accounts in the table.
    pub writable_indexes: Vec<u8>,
    /// Indices of read-only accounts in the table.
    pub readonly_indexes: Vec<u8>,
}

/// A versioned transaction message (v0).
#[derive(Debug, Clone)]
pub struct MessageV0 {
    /// The legacy message portion.
    pub message: Message,
    /// Address lookup table references.
    pub address_table_lookups: Vec<AddressLookupTable>,
}

impl MessageV0 {
    /// Serialize a v0 message.
    ///
    /// Format: `0x80 || legacy_message_bytes || address_table_lookups`
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x80); // Version prefix (v0 = 0x80)
        buf.extend_from_slice(&self.message.serialize());

        // Serialize address table lookups
        buf.extend_from_slice(&encode_compact_u16(self.address_table_lookups.len() as u16));
        for table in &self.address_table_lookups {
            buf.extend_from_slice(&table.account_key);
            buf.extend_from_slice(&encode_compact_u16(table.writable_indexes.len() as u16));
            buf.extend_from_slice(&table.writable_indexes);
            buf.extend_from_slice(&encode_compact_u16(table.readonly_indexes.len() as u16));
            buf.extend_from_slice(&table.readonly_indexes);
        }
        buf
    }
}

/// A signed versioned transaction (v0).
#[derive(Debug, Clone)]
pub struct VersionedTransaction {
    /// Ed25519 signatures.
    pub signatures: Vec<[u8; 64]>,
    /// The v0 message.
    pub message: MessageV0,
}

impl VersionedTransaction {
    /// Sign a v0 message with one or more signers.
    pub fn sign(
        message: &MessageV0,
        signers: &[&SolanaSigner],
        recent_blockhash: [u8; 32],
    ) -> Result<Self, SignerError> {
        let mut msg = message.clone();
        msg.message.recent_blockhash = recent_blockhash;
        let serialized = msg.serialize();

        let mut signatures = Vec::new();
        for signer in signers {
            let sig = signer.signing_key.sign(&serialized);
            signatures.push(sig.to_bytes());
        }

        Ok(Self {
            signatures,
            message: msg,
        })
    }

    /// Serialize the versioned transaction for sending.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_compact_u16(self.signatures.len() as u16));
        for sig in &self.signatures {
            buf.extend_from_slice(sig);
        }
        buf.extend_from_slice(&self.message.serialize());
        buf
    }
}

// ═══════════════════════════════════════════════════════════════════
// Program Derived Addresses (PDA)
// ═══════════════════════════════════════════════════════════════════

/// Find a Program Derived Address (PDA) for the given seeds and program ID.
///
/// Iterates bump seeds from 255 down to 0, returning the first valid
/// off-curve address along with its bump seed.
///
/// # Returns
/// `(address, bump)` — the 32-byte PDA and the bump seed used.
///
/// # Example
/// ```
/// use chains_sdk::solana::transaction::find_program_address;
///
/// let program_id = [0xAA; 32];
/// let (pda, bump) = find_program_address(&[b"vault", &[1u8; 32]], &program_id).unwrap();
/// assert_eq!(pda.len(), 32);
/// assert!(bump <= 255);
/// ```
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &[u8; 32],
) -> Result<([u8; 32], u8), SignerError> {
    for bump in (0..=255u8).rev() {
        if let Ok(addr) = create_program_address(seeds, &[bump], program_id) {
            return Ok((addr, bump));
        }
    }
    Err(SignerError::SigningFailed(
        "PDA: no valid bump found".into(),
    ))
}

/// Create a Program Derived Address from seeds, a bump, and a program ID.
///
/// Returns `Err` if the resulting point is on the Ed25519 curve (not a valid PDA).
pub fn create_program_address(
    seeds: &[&[u8]],
    bump: &[u8],
    program_id: &[u8; 32],
) -> Result<[u8; 32], SignerError> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for seed in seeds {
        if seed.len() > 32 {
            return Err(SignerError::SigningFailed("PDA seed > 32 bytes".into()));
        }
        hasher.update(seed);
    }
    hasher.update(bump);
    hasher.update(program_id);
    hasher.update(b"ProgramDerivedAddress");
    let hash = hasher.finalize();

    let mut candidate = [0u8; 32];
    candidate.copy_from_slice(&hash);

    // Check that the resulting point is NOT on the Ed25519 curve.
    // A valid PDA must not be a valid public key.
    // ed25519_dalek::VerifyingKey::from_bytes checks if the point decompresses
    // on the curve — if it succeeds, the hash is on-curve and NOT a valid PDA.
    if ed25519_dalek::VerifyingKey::from_bytes(&candidate).is_ok() {
        return Err(SignerError::SigningFailed("PDA: on curve".into()));
    }

    Ok(candidate)
}

// ═══════════════════════════════════════════════════════════════════
// Transaction & Message Deserialization
// ═══════════════════════════════════════════════════════════════════

impl Message {
    /// Deserialize a legacy message from wire-format bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, SignerError> {
        if data.len() < 3 {
            return Err(SignerError::ParseError("message too short".into()));
        }
        let num_required_signatures = data[0];
        let num_readonly_signed_accounts = data[1];
        let num_readonly_unsigned_accounts = data[2];
        let mut pos = 3;

        // Account keys
        let (num_keys, consumed) = decode_compact_u16(&data[pos..])?;
        pos += consumed;
        let mut account_keys = Vec::with_capacity(num_keys as usize);
        for _ in 0..num_keys {
            if pos + 32 > data.len() {
                return Err(SignerError::ParseError(
                    "message: truncated account key".into(),
                ));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            account_keys.push(key);
            pos += 32;
        }

        // Recent blockhash
        if pos + 32 > data.len() {
            return Err(SignerError::ParseError(
                "message: truncated blockhash".into(),
            ));
        }
        let mut recent_blockhash = [0u8; 32];
        recent_blockhash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Instructions
        let (num_ix, consumed) = decode_compact_u16(&data[pos..])?;
        pos += consumed;
        let mut instructions = Vec::with_capacity(num_ix as usize);
        for _ in 0..num_ix {
            if pos >= data.len() {
                return Err(SignerError::ParseError(
                    "message: truncated instruction".into(),
                ));
            }
            let program_id_index = data[pos];
            pos += 1;

            let (num_accounts, consumed) = decode_compact_u16(&data[pos..])?;
            pos += consumed;
            if pos + num_accounts as usize > data.len() {
                return Err(SignerError::ParseError(
                    "message: truncated instruction accounts".into(),
                ));
            }
            let accounts = data[pos..pos + num_accounts as usize].to_vec();
            pos += num_accounts as usize;

            let (data_len, consumed) = decode_compact_u16(&data[pos..])?;
            pos += consumed;
            if pos + data_len as usize > data.len() {
                return Err(SignerError::ParseError(
                    "message: truncated instruction data".into(),
                ));
            }
            let ix_data = data[pos..pos + data_len as usize].to_vec();
            pos += data_len as usize;

            instructions.push(CompiledInstruction {
                program_id_index,
                accounts,
                data: ix_data,
            });
        }

        Ok(Self {
            num_required_signatures,
            num_readonly_signed_accounts,
            num_readonly_unsigned_accounts,
            account_keys,
            recent_blockhash,
            instructions,
        })
    }
}

impl Transaction {
    /// Deserialize a signed legacy transaction from wire-format bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, SignerError> {
        let mut pos = 0;

        // Signatures
        let (num_sigs, consumed) = decode_compact_u16(&data[pos..])?;
        pos += consumed;
        let mut signatures = Vec::with_capacity(num_sigs as usize);
        for _ in 0..num_sigs {
            if pos + 64 > data.len() {
                return Err(SignerError::ParseError(
                    "transaction: truncated signature".into(),
                ));
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&data[pos..pos + 64]);
            signatures.push(sig);
            pos += 64;
        }

        // Message
        let message = Message::deserialize(&data[pos..])?;

        Ok(Self {
            signatures,
            message,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
// Instruction Data Encoding (Borsh-compatible)
// ═══════════════════════════════════════════════════════════════════

/// Borsh-compatible instruction data encoder.
///
/// Builds instruction data by appending fields in order, matching
/// the Borsh serialization format used by most Solana programs.
///
/// # Example
/// ```
/// use chains_sdk::solana::transaction::InstructionDataBuilder;
///
/// let data = InstructionDataBuilder::new()
///     .write_u8(1)                    // discriminator
///     .write_u64(1_000_000)           // amount
///     .write_bytes(&[0xAA; 32])       // pubkey
///     .write_string("hello")          // string (Borsh: u32 len + UTF-8)
///     .build();
/// ```
pub struct InstructionDataBuilder {
    buf: Vec<u8>,
}

impl InstructionDataBuilder {
    /// Create a new empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Write a `u8`.
    #[must_use]
    pub fn write_u8(mut self, val: u8) -> Self {
        self.buf.push(val);
        self
    }

    /// Write a `u16` (little-endian).
    #[must_use]
    pub fn write_u16(mut self, val: u16) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Write a `u32` (little-endian).
    #[must_use]
    pub fn write_u32(mut self, val: u32) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Write a `u64` (little-endian).
    #[must_use]
    pub fn write_u64(mut self, val: u64) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Write a `i64` (little-endian).
    #[must_use]
    pub fn write_i64(mut self, val: i64) -> Self {
        self.buf.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Write a `bool` (1 byte: 0 or 1).
    #[must_use]
    pub fn write_bool(mut self, val: bool) -> Self {
        self.buf.push(u8::from(val));
        self
    }

    /// Write raw bytes (no length prefix).
    #[must_use]
    pub fn write_bytes(mut self, data: &[u8]) -> Self {
        self.buf.extend_from_slice(data);
        self
    }

    /// Write a 32-byte public key.
    #[must_use]
    pub fn write_pubkey(self, key: &[u8; 32]) -> Self {
        self.write_bytes(key)
    }

    /// Write a Borsh-encoded string (u32 length prefix + UTF-8 bytes).
    #[must_use]
    pub fn write_string(mut self, s: &str) -> Self {
        let bytes = s.as_bytes();
        self.buf
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(bytes);
        self
    }

    /// Write a Borsh-encoded `Option<T>` (0 = None, 1 + data = Some).
    #[must_use]
    pub fn write_option(mut self, val: Option<&[u8]>) -> Self {
        match val {
            None => {
                self.buf.push(0);
            }
            Some(data) => {
                self.buf.push(1);
                self.buf.extend_from_slice(data);
            }
        }
        self
    }

    /// Write a Borsh-encoded `Vec<u8>` (u32 length prefix + bytes).
    #[must_use]
    pub fn write_vec(mut self, data: &[u8]) -> Self {
        self.buf
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(data);
        self
    }

    /// Finalize and return the instruction data.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for InstructionDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Borsh-compatible instruction data decoder.
///
/// Reads fields from instruction data in order.
pub struct InstructionDataReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> InstructionDataReader<'a> {
    /// Create a new reader over `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a `u8`.
    pub fn read_u8(&mut self) -> Result<u8, SignerError> {
        if self.pos >= self.data.len() {
            return Err(SignerError::ParseError("read_u8: EOF".into()));
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    /// Read a `u16` (little-endian).
    pub fn read_u16(&mut self) -> Result<u16, SignerError> {
        if self.pos + 2 > self.data.len() {
            return Err(SignerError::ParseError("read_u16: EOF".into()));
        }
        let val = u16::from_le_bytes(
            self.data[self.pos..self.pos + 2]
                .try_into()
                .map_err(|_| SignerError::ParseError("read_u16: bad bytes".into()))?,
        );
        self.pos += 2;
        Ok(val)
    }

    /// Read a `u32` (little-endian).
    pub fn read_u32(&mut self) -> Result<u32, SignerError> {
        if self.pos + 4 > self.data.len() {
            return Err(SignerError::ParseError("read_u32: EOF".into()));
        }
        let val = u32::from_le_bytes(
            self.data[self.pos..self.pos + 4]
                .try_into()
                .map_err(|_| SignerError::ParseError("read_u32: bad bytes".into()))?,
        );
        self.pos += 4;
        Ok(val)
    }

    /// Read a `u64` (little-endian).
    pub fn read_u64(&mut self) -> Result<u64, SignerError> {
        if self.pos + 8 > self.data.len() {
            return Err(SignerError::ParseError("read_u64: EOF".into()));
        }
        let val = u64::from_le_bytes(
            self.data[self.pos..self.pos + 8]
                .try_into()
                .map_err(|_| SignerError::ParseError("read_u64: bad bytes".into()))?,
        );
        self.pos += 8;
        Ok(val)
    }

    /// Read a `bool`.
    pub fn read_bool(&mut self) -> Result<bool, SignerError> {
        Ok(self.read_u8()? != 0)
    }

    /// Read exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], SignerError> {
        if self.pos + n > self.data.len() {
            return Err(SignerError::ParseError(format!("read_bytes({n}): EOF")));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a 32-byte public key.
    pub fn read_pubkey(&mut self) -> Result<[u8; 32], SignerError> {
        let bytes = self.read_bytes(32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(key)
    }

    /// Read a Borsh-encoded string (u32 len + UTF-8).
    pub fn read_string(&mut self) -> Result<String, SignerError> {
        let len = self.read_u32()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| SignerError::ParseError(format!("read_string: {e}")))
    }

    /// Remaining unread bytes.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Whether all data has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    // ─── Compact-u16 Tests (Solana specification vectors) ──────────

    #[test]
    fn test_compact_u16_zero() {
        assert_eq!(encode_compact_u16(0), vec![0]);
        assert_eq!(decode_compact_u16(&[0]).unwrap(), (0, 1));
    }

    #[test]
    fn test_compact_u16_small() {
        assert_eq!(encode_compact_u16(5), vec![5]);
        assert_eq!(decode_compact_u16(&[5]).unwrap(), (5, 1));
    }

    #[test]
    fn test_compact_u16_127_boundary() {
        assert_eq!(encode_compact_u16(0x7F), vec![0x7F]);
        assert_eq!(decode_compact_u16(&[0x7F]).unwrap(), (0x7F, 1));
    }

    #[test]
    fn test_compact_u16_128() {
        let encoded = encode_compact_u16(0x80);
        assert_eq!(encoded.len(), 2);
        assert_eq!(decode_compact_u16(&encoded).unwrap(), (0x80, 2));
    }

    #[test]
    fn test_compact_u16_16383() {
        // Maximum 2-byte value
        let encoded = encode_compact_u16(0x3FFF);
        assert_eq!(encoded.len(), 2);
        assert_eq!(decode_compact_u16(&encoded).unwrap(), (0x3FFF, 2));
    }

    #[test]
    fn test_compact_u16_16384() {
        // First 3-byte value
        let encoded = encode_compact_u16(0x4000);
        assert_eq!(encoded.len(), 3);
        assert_eq!(decode_compact_u16(&encoded).unwrap(), (0x4000, 3));
    }

    #[test]
    fn test_compact_u16_roundtrip_all_boundaries() {
        for val in [0u16, 1, 127, 128, 255, 256, 16383, 16384, 32767, 65535] {
            let encoded = encode_compact_u16(val);
            let (decoded, _) = decode_compact_u16(&encoded).unwrap();
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    // ─── System Program Tests ──────────────────────────────────────

    #[test]
    fn test_system_transfer_instruction() {
        let from = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&from, &to, 1_000_000_000);
        assert_eq!(ix.program_id, system_program::ID);
        assert_eq!(ix.accounts.len(), 2);
        assert_eq!(ix.accounts[0].pubkey, from);
        assert!(ix.accounts[0].is_signer);
        assert!(!ix.accounts[1].is_signer);
        // Data: 4 bytes instruction index + 8 bytes lamports
        assert_eq!(ix.data.len(), 12);
        assert_eq!(&ix.data[..4], &[2, 0, 0, 0]);
        let lamports = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        assert_eq!(lamports, 1_000_000_000);
    }

    #[test]
    fn test_system_create_account() {
        let from = [0xAA; 32];
        let new = [0xBB; 32];
        let owner = [0xCC; 32];
        let ix = system_program::create_account(&from, &new, 1_000_000, 165, &owner);
        assert_eq!(ix.program_id, system_program::ID);
        assert_eq!(ix.accounts.len(), 2);
        // Data: 4 index + 8 lamports + 8 space + 32 owner = 52
        assert_eq!(ix.data.len(), 52);
    }

    #[test]
    fn test_system_allocate() {
        let account = [0xAA; 32];
        let ix = system_program::allocate(&account, 1024);
        assert_eq!(ix.data.len(), 12);
    }

    // ─── SPL Token Tests ───────────────────────────────────────────

    #[test]
    fn test_spl_token_transfer() {
        let src = [0x11; 32];
        let dst = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::transfer(&src, &dst, &auth, 1_000_000);
        assert_eq!(ix.program_id, spl_token::ID);
        assert_eq!(ix.accounts.len(), 3);
        assert!(!ix.accounts[0].is_signer); // source
        assert!(!ix.accounts[1].is_signer); // destination
        assert!(ix.accounts[2].is_signer); // authority
        assert_eq!(ix.data[0], 3); // Transfer discriminator
        assert_eq!(ix.data.len(), 9);
    }

    #[test]
    fn test_spl_token_approve() {
        let src = [0x11; 32];
        let delegate = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::approve(&src, &delegate, &auth, 500_000);
        assert_eq!(ix.data[0], 4); // Approve discriminator
    }

    #[test]
    fn test_spl_token_mint_to() {
        let mint = [0x11; 32];
        let dst = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::mint_to(&mint, &dst, &auth, 1_000);
        assert_eq!(ix.data[0], 7); // MintTo discriminator
    }

    // ─── Compute Budget Tests ──────────────────────────────────────

    #[test]
    fn test_compute_unit_limit() {
        let ix = compute_budget::set_compute_unit_limit(200_000);
        assert_eq!(ix.data[0], 2);
        let units = u32::from_le_bytes(ix.data[1..5].try_into().unwrap());
        assert_eq!(units, 200_000);
        assert!(ix.accounts.is_empty());
    }

    #[test]
    fn test_compute_unit_price() {
        let ix = compute_budget::set_compute_unit_price(50_000);
        assert_eq!(ix.data[0], 3);
        let price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        assert_eq!(price, 50_000);
    }

    // ─── Message Building Tests ────────────────────────────────────

    #[test]
    fn test_message_building() {
        let payer = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 100);
        let msg = Message::new(&[ix], payer);

        assert_eq!(msg.num_required_signatures, 1);
        assert_eq!(msg.num_readonly_signed_accounts, 0);
        // system program = readonly unsigned
        assert_eq!(msg.num_readonly_unsigned_accounts, 1);
        // payer, to, system_program
        assert_eq!(msg.account_keys.len(), 3);
        assert_eq!(msg.account_keys[0], payer); // fee payer first
    }

    #[test]
    fn test_message_serialization() {
        let payer = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 100);
        let msg = Message::new(&[ix], payer);
        let bytes = msg.serialize();
        assert!(!bytes.is_empty());
        // Header: 3 bytes
        assert_eq!(bytes[0], 1); // num_required_signatures
        assert_eq!(bytes[1], 0); // num_readonly_signed
        assert_eq!(bytes[2], 1); // num_readonly_unsigned (system program)
    }

    // ─── Transaction Tests ─────────────────────────────────────────

    #[test]
    fn test_transaction_sign_and_serialize() {
        let signer = SolanaSigner::generate().unwrap();
        let payer = signer.public_key_bytes_32();
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 1_000_000);
        let msg = Message::new(&[ix], payer);
        let blockhash = [0xCC; 32];

        let tx = Transaction::sign(&msg, &[&signer], blockhash).unwrap();
        assert_eq!(tx.signatures.len(), 1);
        assert_eq!(tx.signatures[0].len(), 64);

        let raw = tx.serialize();
        assert!(!raw.is_empty());
        // First byte should be compact-u16(1) = 0x01
        assert_eq!(raw[0], 1);
    }

    #[test]
    fn test_transaction_deterministic() {
        let signer = SolanaSigner::from_bytes(&[0x42; 32]).unwrap();
        let payer = signer.public_key_bytes_32();
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);

        let tx1 = Transaction::sign(&msg, &[&signer], [0; 32]).unwrap();
        let tx2 = Transaction::sign(&msg, &[&signer], [0; 32]).unwrap();
        assert_eq!(tx1.serialize(), tx2.serialize());
    }

    // ─── Versioned Transaction Tests ───────────────────────────────

    #[test]
    fn test_v0_message_has_version_prefix() {
        let payer = [0xAA; 32];
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let v0 = MessageV0 {
            message: msg,
            address_table_lookups: vec![],
        };
        let bytes = v0.serialize();
        assert_eq!(bytes[0], 0x80, "v0 messages start with 0x80");
    }

    #[test]
    fn test_v0_with_lookup_table() {
        let payer = [0xAA; 32];
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let v0 = MessageV0 {
            message: msg,
            address_table_lookups: vec![AddressLookupTable {
                account_key: [0xDD; 32],
                writable_indexes: vec![0, 1],
                readonly_indexes: vec![2],
            }],
        };
        let bytes = v0.serialize();
        assert_eq!(bytes[0], 0x80);
        assert!(bytes.len() > 100); // includes lookup table data
    }

    // ─── PDA Tests ────────────────────────────────────────────────

    #[test]
    fn test_find_program_address() {
        let program_id = [0xAA; 32];
        let (pda, bump) = find_program_address(&[b"test_seed"], &program_id).unwrap();
        assert_eq!(pda.len(), 32);
        assert_ne!(bump, 0, "bump should be valid");
        // Same inputs → same output
        let (pda2, bump2) = find_program_address(&[b"test_seed"], &program_id).unwrap();
        assert_eq!(pda, pda2);
        assert_eq!(bump, bump2);
    }

    #[test]
    fn test_pda_different_seeds() {
        let program_id = [0xBB; 32];
        let (pda1, _) = find_program_address(&[b"seed_a"], &program_id).unwrap();
        let (pda2, _) = find_program_address(&[b"seed_b"], &program_id).unwrap();
        assert_ne!(pda1, pda2);
    }

    #[test]
    fn test_pda_seed_too_long() {
        let program_id = [0xCC; 32];
        let long_seed = [0u8; 33]; // > 32 bytes
        let result = create_program_address(&[&long_seed[..]], &[0], &program_id);
        assert!(result.is_err());
    }

    // ─── Transaction Deserialization Tests ─────────────────────────

    #[test]
    fn test_message_serialize_deserialize_roundtrip() {
        let payer = [0xAA; 32];
        let to = [0xBB; 32];
        let ix = system_program::transfer(&payer, &to, 1_000_000);
        let msg = Message::new(&[ix], payer);
        let serialized = msg.serialize();

        let restored = Message::deserialize(&serialized).unwrap();
        assert_eq!(
            restored.num_required_signatures,
            msg.num_required_signatures
        );
        assert_eq!(restored.account_keys.len(), msg.account_keys.len());
        assert_eq!(restored.instructions.len(), msg.instructions.len());
        assert_eq!(restored.instructions[0].data, msg.instructions[0].data);
    }

    #[test]
    fn test_transaction_serialize_deserialize_roundtrip() {
        let signer = SolanaSigner::from_bytes(&[0x42; 32]).unwrap();
        let payer = signer.public_key_bytes_32();
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let tx = Transaction::sign(&msg, &[&signer], [0xDD; 32]).unwrap();

        let raw = tx.serialize();
        let restored = Transaction::deserialize(&raw).unwrap();

        assert_eq!(restored.signatures.len(), tx.signatures.len());
        assert_eq!(restored.signatures[0], tx.signatures[0]);
        assert_eq!(
            restored.message.account_keys.len(),
            tx.message.account_keys.len()
        );
    }

    #[test]
    fn test_deserialize_empty_fails() {
        assert!(Transaction::deserialize(&[]).is_err());
        assert!(Message::deserialize(&[]).is_err());
        assert!(Message::deserialize(&[0, 0]).is_err()); // too short
    }

    // ─── Instruction Data Builder/Reader Tests ────────────────────

    #[test]
    fn test_instruction_data_builder_reader_roundtrip() {
        let data = InstructionDataBuilder::new()
            .write_u8(42)
            .write_u16(1000)
            .write_u32(100_000)
            .write_u64(1_000_000_000)
            .write_bool(true)
            .write_pubkey(&[0xAA; 32])
            .write_string("hello solana")
            .build();

        let mut reader = InstructionDataReader::new(&data);
        assert_eq!(reader.read_u8().unwrap(), 42);
        assert_eq!(reader.read_u16().unwrap(), 1000);
        assert_eq!(reader.read_u32().unwrap(), 100_000);
        assert_eq!(reader.read_u64().unwrap(), 1_000_000_000);
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.read_pubkey().unwrap(), [0xAA; 32]);
        assert_eq!(reader.read_string().unwrap(), "hello solana");
        assert!(reader.is_empty());
    }

    #[test]
    fn test_instruction_data_builder_option() {
        let none_data = InstructionDataBuilder::new().write_option(None).build();
        assert_eq!(none_data, vec![0]);

        let some_data = InstructionDataBuilder::new()
            .write_option(Some(&[1, 2, 3]))
            .build();
        assert_eq!(some_data, vec![1, 1, 2, 3]);
    }

    #[test]
    fn test_reader_eof_errors() {
        let mut reader = InstructionDataReader::new(&[]);
        assert!(reader.read_u8().is_err());
        assert!(reader.read_u64().is_err());
        assert!(reader.read_pubkey().is_err());
    }

    // ─── SPL Token Extended Tests ─────────────────────────────────

    #[test]
    fn test_spl_token_burn() {
        let account = [0x11; 32];
        let mint = [0x22; 32];
        let auth = [0x33; 32];
        let ix = spl_token::burn(&account, &mint, &auth, 500);
        assert_eq!(ix.data[0], 8);
        assert_eq!(ix.accounts.len(), 3);
    }

    #[test]
    fn test_spl_token_close_account() {
        let ix = spl_token::close_account(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        assert_eq!(ix.data, vec![9]);
    }

    #[test]
    fn test_spl_token_freeze_thaw() {
        let ix_freeze = spl_token::freeze_account(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        assert_eq!(ix_freeze.data, vec![10]);
        let ix_thaw = spl_token::thaw_account(&[0x11; 32], &[0x22; 32], &[0x33; 32]);
        assert_eq!(ix_thaw.data, vec![11]);
    }

    #[test]
    fn test_spl_token_initialize_mint() {
        let mint = [0x11; 32];
        let auth = [0x22; 32];
        let ix = spl_token::initialize_mint(&mint, 6, &auth, Some(&[0x33; 32]));
        assert_eq!(ix.data[0], 0); // InitializeMint
        assert_eq!(ix.data[1], 6); // decimals
    }

    #[test]
    fn test_spl_token_set_authority() {
        let ix = spl_token::set_authority(
            &[0x11; 32],
            &[0x22; 32],
            spl_token::AuthorityType::MintTokens,
            Some(&[0x33; 32]),
        );
        assert_eq!(ix.data[0], 6); // SetAuthority
        assert_eq!(ix.data[1], 0); // MintTokens
        assert_eq!(ix.data[2], 1); // Some
    }

    #[test]
    fn test_spl_token_revoke() {
        let ix = spl_token::revoke(&[0x11; 32], &[0x22; 32]);
        assert_eq!(ix.data, vec![5]);
    }

    #[test]
    fn test_spl_token_transfer_checked() {
        let ix = spl_token::transfer_checked(
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            &[0x44; 32],
            1000,
            6,
        );
        assert_eq!(ix.data[0], 12); // TransferChecked
        assert_eq!(ix.accounts.len(), 4); // source, mint, dest, authority
    }

    // ─── Token-2022 Tests ─────────────────────────────────────────

    #[test]
    fn test_token_2022_transfer_checked() {
        let ix = spl_token_2022::transfer_checked(
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            &[0x44; 32],
            1000,
            9,
        );
        assert_eq!(ix.program_id, spl_token_2022::ID);
        assert_eq!(ix.data[0], 12);
    }

    #[test]
    fn test_token_2022_transfer_checked_with_fee() {
        let ix = spl_token_2022::transfer_checked_with_fee(
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            &[0x44; 32],
            1000,
            9,
            50,
        );
        assert_eq!(ix.data[0], 26); // TransferCheckedWithFee
        let fee = u64::from_le_bytes(ix.data[10..18].try_into().unwrap());
        assert_eq!(fee, 50);
    }

    // ─── VersionedTransaction Tests ───────────────────────────────

    #[test]
    fn test_versioned_transaction_sign() {
        let signer = SolanaSigner::from_bytes(&[0x42; 32]).unwrap();
        let payer = signer.public_key_bytes_32();
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let v0 = MessageV0 {
            message: msg,
            address_table_lookups: vec![],
        };

        let vtx = VersionedTransaction::sign(&v0, &[&signer], [0xCC; 32]).unwrap();
        assert_eq!(vtx.signatures.len(), 1);
        let raw = vtx.serialize();
        assert!(!raw.is_empty());
    }

    #[test]
    fn test_versioned_transaction_deterministic() {
        let signer = SolanaSigner::from_bytes(&[0x42; 32]).unwrap();
        let payer = signer.public_key_bytes_32();
        let ix = system_program::transfer(&payer, &[0xBB; 32], 100);
        let msg = Message::new(&[ix], payer);
        let v0 = MessageV0 {
            message: msg,
            address_table_lookups: vec![],
        };

        let vtx1 = VersionedTransaction::sign(&v0, &[&signer], [0; 32]).unwrap();
        let vtx2 = VersionedTransaction::sign(&v0, &[&signer], [0; 32]).unwrap();
        assert_eq!(vtx1.serialize(), vtx2.serialize());
    }
}
