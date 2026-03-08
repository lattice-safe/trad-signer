//! Additional Solana program helpers: ATA, Memo, Stake, Durable Nonce.

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
// Address Lookup Table Program
// ═══════════════════════════════════════════════════════════════════

/// Address Lookup Table program helpers.
pub mod address_lookup_table {
    use super::*;

    /// Address Lookup Table Program ID: `AddressLookupTab1e1111111111111111111111111`
    pub const ID: [u8; 32] = [
        0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x68, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Create an Address Lookup Table.
    ///
    /// # Arguments
    /// - `authority` — Authority that can extend/deactivate/close the table
    /// - `payer` — Account that pays for storage
    /// - `lookup_table` — The derived lookup table address
    /// - `recent_slot` — A recent slot for derivation
    #[must_use]
    pub fn create(
        authority: [u8; 32],
        payer: [u8; 32],
        lookup_table: [u8; 32],
        recent_slot: u64,
    ) -> Instruction {
        let mut data = vec![0u8; 4]; // CreateLookupTable = 0
        data.extend_from_slice(&recent_slot.to_le_bytes());

        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(lookup_table, false),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        }
    }

    /// Extend an Address Lookup Table with new addresses.
    #[must_use]
    pub fn extend(
        lookup_table: [u8; 32],
        authority: [u8; 32],
        payer: [u8; 32],
        new_addresses: &[[u8; 32]],
    ) -> Instruction {
        let mut data = vec![0u8; 4];
        data[0] = 2; // ExtendLookupTable = 2
        // u32 count of addresses
        data.extend_from_slice(&(new_addresses.len() as u32).to_le_bytes());
        for addr in new_addresses {
            data.extend_from_slice(addr);
        }

        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(lookup_table, false),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data,
        }
    }

    /// Deactivate an Address Lookup Table.
    ///
    /// After deactivation, the table enters a cooldown and can then be closed.
    #[must_use]
    pub fn deactivate(
        lookup_table: [u8; 32],
        authority: [u8; 32],
    ) -> Instruction {
        let mut data = vec![0u8; 4];
        data[0] = 3; // DeactivateLookupTable = 3

        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(lookup_table, false),
                AccountMeta::new_readonly(authority, true),
            ],
            data,
        }
    }

    /// Close a deactivated Address Lookup Table and reclaim rent.
    #[must_use]
    pub fn close(
        lookup_table: [u8; 32],
        authority: [u8; 32],
        recipient: [u8; 32],
    ) -> Instruction {
        let mut data = vec![0u8; 4];
        data[0] = 4; // CloseLookupTable = 4

        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(lookup_table, false),
                AccountMeta::new_readonly(authority, true),
                AccountMeta::new(recipient, false),
            ],
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Metaplex Token Metadata Program
// ═══════════════════════════════════════════════════════════════════

/// Metaplex Token Metadata program helpers.
pub mod token_metadata {
    use super::*;

    /// Metaplex Token Metadata Program ID: `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`
    pub const ID: [u8; 32] = [
        0x0b, 0x74, 0x65, 0x78, 0x74, 0x50, 0x55, 0x73,
        0x40, 0x6a, 0xc2, 0x14, 0x12, 0xf3, 0x26, 0xf7,
        0x1b, 0x1e, 0xce, 0xf0, 0x77, 0x87, 0x28, 0x76,
        0xf8, 0xba, 0x16, 0x1b, 0x70, 0x4c, 0x9f, 0x04,
    ];

    /// Token Metadata data for CreateMetadataAccountV3.
    #[derive(Debug, Clone)]
    pub struct DataV2 {
        /// The name of the asset.
        pub name: String,
        /// The symbol for the asset.
        pub symbol: String,
        /// URI pointing to metadata JSON (Arweave, IPFS, etc).
        pub uri: String,
        /// Royalty basis points (e.g., 500 = 5%).
        pub seller_fee_basis_points: u16,
        /// Optional creators list.
        pub creators: Option<Vec<Creator>>,
    }

    /// A creator with an address and share.
    #[derive(Debug, Clone)]
    pub struct Creator {
        /// Creator's public key.
        pub address: [u8; 32],
        /// Whether this creator has verified the metadata.
        pub verified: bool,
        /// Share of royalties (0-100, all shares must sum to 100).
        pub share: u8,
    }

    /// Derive the metadata account address for a given mint.
    ///
    /// PDA: `["metadata", metadata_program_id, mint]`
    pub fn derive_metadata_address(mint: &[u8; 32]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        // Simplified PDA — in production use find_program_address
        let mut hasher = Sha256::new();
        hasher.update(b"metadata");
        hasher.update(ID);
        hasher.update(mint);
        hasher.update(ID);
        hasher.update(b"ProgramDerivedAddress");
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Serialize a Borsh-encoded string (u32 len + UTF-8 bytes).
    fn borsh_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// Serialize DataV2 to Borsh bytes.
    fn serialize_data_v2(data: &DataV2) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(borsh_string(&data.name));
        buf.extend(borsh_string(&data.symbol));
        buf.extend(borsh_string(&data.uri));
        buf.extend_from_slice(&data.seller_fee_basis_points.to_le_bytes());

        // Creators: Option<Vec<Creator>>
        match &data.creators {
            None => buf.push(0),
            Some(creators) => {
                buf.push(1);
                buf.extend_from_slice(&(creators.len() as u32).to_le_bytes());
                for c in creators {
                    buf.extend_from_slice(&c.address);
                    buf.push(u8::from(c.verified));
                    buf.push(c.share);
                }
            }
        }
        buf
    }

    /// Create a `CreateMetadataAccountV3` instruction.
    ///
    /// # Arguments
    /// - `metadata` — The derived metadata account PDA
    /// - `mint` — The token mint
    /// - `mint_authority` — Current authority of the mint
    /// - `payer` — Who pays for the account
    /// - `update_authority` — Who can update the metadata
    /// - `data` — The token metadata
    /// - `is_mutable` — Whether the metadata can be updated later
    pub fn create_metadata_v3(
        metadata: [u8; 32],
        mint: [u8; 32],
        mint_authority: [u8; 32],
        payer: [u8; 32],
        update_authority: [u8; 32],
        data: &DataV2,
        is_mutable: bool,
    ) -> Instruction {
        // Instruction discriminator for CreateMetadataAccountV3 = 33
        let mut ix_data = vec![33];
        ix_data.extend(serialize_data_v2(data));
        ix_data.push(u8::from(is_mutable));
        // collection_details: Option = None
        ix_data.push(0);

        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(metadata, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(mint_authority, true),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(update_authority, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ],
            data: ix_data,
        }
    }

    /// Create an `UpdateMetadataAccountV2` instruction.
    ///
    /// # Arguments
    /// - `metadata` — The metadata account to update
    /// - `update_authority` — Current update authority (signer)
    /// - `new_data` — Optional new data (pass None to keep existing)
    /// - `new_update_authority` — Optional new update authority
    /// - `primary_sale_happened` — Optional flag
    /// - `is_mutable` — Optional mutability flag
    pub fn update_metadata_v2(
        metadata: [u8; 32],
        update_authority: [u8; 32],
        new_data: Option<&DataV2>,
        new_update_authority: Option<&[u8; 32]>,
        primary_sale_happened: Option<bool>,
        is_mutable: Option<bool>,
    ) -> Instruction {
        // Instruction discriminator for UpdateMetadataAccountV2 = 15
        let mut ix_data = vec![15];

        // Optional<DataV2>
        match new_data {
            None => ix_data.push(0),
            Some(d) => {
                ix_data.push(1);
                ix_data.extend(serialize_data_v2(d));
            }
        }

        // Optional<Pubkey>
        match new_update_authority {
            None => ix_data.push(0),
            Some(auth) => {
                ix_data.push(1);
                ix_data.extend_from_slice(auth);
            }
        }

        // Optional<bool> primary_sale_happened
        match primary_sale_happened {
            None => ix_data.push(0),
            Some(val) => {
                ix_data.push(1);
                ix_data.push(u8::from(val));
            }
        }

        // Optional<bool> is_mutable
        match is_mutable {
            None => ix_data.push(0),
            Some(val) => {
                ix_data.push(1);
                ix_data.push(u8::from(val));
            }
        }

        Instruction {
            program_id: ID,
            accounts: vec![
                AccountMeta::new(metadata, false),
                AccountMeta::new_readonly(update_authority, true),
            ],
            data: ix_data,
        }
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

    // ─── Address Lookup Table Tests ─────────────────────────────

    #[test]
    fn test_alt_create() {
        let table = [9; 32];
        let ix = address_lookup_table::create(PAYER, PAYER, table, 12345);
        assert_eq!(ix.program_id, address_lookup_table::ID);
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.data[0], 0); // CreateLookupTable
        let slot = u64::from_le_bytes(ix.data[4..12].try_into().unwrap());
        assert_eq!(slot, 12345);
    }

    #[test]
    fn test_alt_extend() {
        let table = [9; 32];
        let addrs = [[10u8; 32], [11u8; 32]];
        let ix = address_lookup_table::extend(table, PAYER, PAYER, &addrs);
        assert_eq!(ix.data[0], 2); // ExtendLookupTable
        let count = u32::from_le_bytes(ix.data[4..8].try_into().unwrap());
        assert_eq!(count, 2);
        assert_eq!(&ix.data[8..40], &addrs[0]);
        assert_eq!(&ix.data[40..72], &addrs[1]);
    }

    #[test]
    fn test_alt_deactivate() {
        let table = [9; 32];
        let ix = address_lookup_table::deactivate(table, PAYER);
        assert_eq!(ix.data[0], 3);
        assert_eq!(ix.accounts.len(), 2);
    }

    #[test]
    fn test_alt_close() {
        let table = [9; 32];
        let recipient = [10; 32];
        let ix = address_lookup_table::close(table, PAYER, recipient);
        assert_eq!(ix.data[0], 4);
        assert_eq!(ix.accounts.len(), 3);
    }

    // ─── Metaplex Token Metadata Tests ──────────────────────────

    #[test]
    fn test_derive_metadata_deterministic() {
        let addr1 = token_metadata::derive_metadata_address(&MINT);
        let addr2 = token_metadata::derive_metadata_address(&MINT);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_create_metadata_v3() {
        let metadata = [12; 32];
        let update_auth = [13; 32];
        let data = token_metadata::DataV2 {
            name: "My NFT".to_string(),
            symbol: "MNFT".to_string(),
            uri: "https://example.com/meta.json".to_string(),
            seller_fee_basis_points: 500,
            creators: Some(vec![token_metadata::Creator {
                address: PAYER,
                verified: true,
                share: 100,
            }]),
        };
        let ix = token_metadata::create_metadata_v3(
            metadata, MINT, PAYER, PAYER, update_auth, &data, true,
        );
        assert_eq!(ix.program_id, token_metadata::ID);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.data[0], 33); // CreateMetadataAccountV3
    }

    #[test]
    fn test_update_metadata_v2() {
        let metadata = [12; 32];
        let ix = token_metadata::update_metadata_v2(
            metadata, PAYER, None, None, Some(true), None,
        );
        assert_eq!(ix.data[0], 15); // UpdateMetadataAccountV2
        assert_eq!(ix.accounts.len(), 2);
    }

    #[test]
    fn test_metadata_without_creators() {
        let metadata = [12; 32];
        let update_auth = [13; 32];
        let data = token_metadata::DataV2 {
            name: "Token".to_string(),
            symbol: "TKN".to_string(),
            uri: "https://example.com".to_string(),
            seller_fee_basis_points: 0,
            creators: None,
        };
        let ix = token_metadata::create_metadata_v3(
            metadata, MINT, PAYER, PAYER, update_auth, &data, false,
        );
        assert_eq!(ix.data[0], 33);
        // is_mutable should be false (0) near the end
        let last_data = ix.data.last().unwrap();
        // collection_details = None (0)
        assert_eq!(*last_data, 0);
    }
}

