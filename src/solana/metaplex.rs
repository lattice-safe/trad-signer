//! Metaplex NFT instruction builders for Solana.
//!
//! Supports Token Metadata v3 (create, update, verify collection)
//! and Bubblegum compressed NFTs (mint, transfer).
//!
//! # Example
//! ```no_run
//! use chains_sdk::solana::metaplex::*;
//! use chains_sdk::solana::transaction::AccountMeta;
//!
//! let mint = [0xAA; 32];
//! let authority = [0xBB; 32];
//! let payer = [0xCC; 32];
//! let metadata_acct = [0xDD; 32];
//!
//! let data = MetadataData {
//!     name: "Cool NFT".into(),
//!     symbol: "COOL".into(),
//!     uri: "https://example.com/nft.json".into(),
//!     seller_fee_basis_points: 500,
//!     creators: vec![Creator { address: authority, verified: true, share: 100 }],
//! };
//!
//! let ix = create_metadata_account_v3(&metadata_acct, &mint, &authority, &payer, &authority, &data, true, None);
//! ```

use crate::solana::transaction::{AccountMeta, Instruction};

// ═══════════════════════════════════════════════════════════════════
// Program IDs
// ═══════════════════════════════════════════════════════════════════

/// Metaplex Token Metadata program ID.
/// `metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s`
pub const METADATA_PROGRAM_ID: [u8; 32] = [
    11, 112, 101, 177, 227, 209, 124, 69, 56, 157, 82, 127, 107, 4, 195, 205,
    88, 184, 108, 115, 26, 160, 253, 181, 73, 182, 209, 188, 3, 248, 41, 70,
];

/// Bubblegum program ID (compressed NFTs).
/// `BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY`
pub const BUBBLEGUM_PROGRAM_ID: [u8; 32] = [
    2, 64, 226, 173, 168, 97, 14, 240, 103, 34, 248, 172, 238, 69, 103, 48,
    133, 116, 160, 173, 138, 136, 96, 195, 13, 141, 161, 25, 60, 236, 156, 87,
];

/// System program ID (for rent/payer operations).
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// Sysvar Rent ID.
const SYSVAR_RENT_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    // SysvarRent111111111111111111111111111111111
    id[0] = 0x06;
    id[1] = 0xa7;
    id[2] = 0xd5;
    id[3] = 0x17;
    id
};

// ═══════════════════════════════════════════════════════════════════
// Data Types
// ═══════════════════════════════════════════════════════════════════

/// Creator info for NFT metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Creator {
    /// Creator's wallet address.
    pub address: [u8; 32],
    /// Whether this creator has verified the metadata.
    pub verified: bool,
    /// Percentage share (0-100, all must sum to 100).
    pub share: u8,
}

/// Metadata for an NFT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataData {
    /// Name of the NFT (max 32 characters).
    pub name: String,
    /// Symbol (max 10 characters).
    pub symbol: String,
    /// URI to off-chain metadata JSON (max 200 characters).
    pub uri: String,
    /// Royalty basis points (e.g., 500 = 5%).
    pub seller_fee_basis_points: u16,
    /// List of creators.
    pub creators: Vec<Creator>,
}

/// Collection info (optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collection {
    /// Whether this NFT is verified as part of the collection.
    pub verified: bool,
    /// The collection NFT mint address.
    pub key: [u8; 32],
}

/// Uses configuration (optional).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uses {
    /// Use method.
    pub use_method: UseMethod,
    /// Remaining uses.
    pub remaining: u64,
    /// Total uses.
    pub total: u64,
}

/// How the NFT can be "used".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UseMethod {
    /// Can be burned.
    Burn = 0,
    /// Usable multiple times.
    Multiple = 1,
    /// Single-use.
    Single = 2,
}

// ═══════════════════════════════════════════════════════════════════
// Serialization Helpers
// ═══════════════════════════════════════════════════════════════════

fn borsh_string(data: &mut Vec<u8>, s: &str) {
    data.extend_from_slice(&(s.len() as u32).to_le_bytes());
    data.extend_from_slice(s.as_bytes());
}

fn borsh_option_pubkey(data: &mut Vec<u8>, key: Option<&[u8; 32]>) {
    match key {
        Some(k) => {
            data.push(1); // Some
            data.extend_from_slice(k);
        }
        None => data.push(0), // None
    }
}

fn borsh_creators(data: &mut Vec<u8>, creators: &[Creator]) {
    data.push(1); // Some(creators)
    data.extend_from_slice(&(creators.len() as u32).to_le_bytes());
    for c in creators {
        data.extend_from_slice(&c.address);
        data.push(u8::from(c.verified));
        data.push(c.share);
    }
}

fn borsh_metadata_data(data: &mut Vec<u8>, md: &MetadataData) {
    borsh_string(data, &md.name);
    borsh_string(data, &md.symbol);
    borsh_string(data, &md.uri);
    data.extend_from_slice(&md.seller_fee_basis_points.to_le_bytes());
    borsh_creators(data, &md.creators);
}

fn borsh_collection(data: &mut Vec<u8>, collection: Option<&Collection>) {
    match collection {
        Some(c) => {
            data.push(1);
            data.push(u8::from(c.verified));
            data.extend_from_slice(&c.key);
        }
        None => data.push(0),
    }
}

fn borsh_uses(data: &mut Vec<u8>, uses: Option<&Uses>) {
    match uses {
        Some(u) => {
            data.push(1);
            data.push(u.use_method as u8);
            data.extend_from_slice(&u.remaining.to_le_bytes());
            data.extend_from_slice(&u.total.to_le_bytes());
        }
        None => data.push(0),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Token Metadata v3 Instructions
// ═══════════════════════════════════════════════════════════════════

/// Create a metadata account for an NFT (CreateMetadataAccountV3, discriminator 33).
///
/// # Accounts
/// 0. `[writable]` Metadata account (PDA)
/// 1. `[]` Mint
/// 2. `[signer]` Mint authority
/// 3. `[signer, writable]` Payer
/// 4. `[]` Update authority
/// 5. `[]` System program
/// 6. `[]` Rent sysvar
#[allow(clippy::too_many_arguments)]
pub fn create_metadata_account_v3(
    metadata_account: &[u8; 32],
    mint: &[u8; 32],
    mint_authority: &[u8; 32],
    payer: &[u8; 32],
    update_authority: &[u8; 32],
    metadata: &MetadataData,
    is_mutable: bool,
    collection: Option<&Collection>,
) -> Instruction {
    let mut data = Vec::with_capacity(256);
    data.push(33); // CreateMetadataAccountV3 discriminator

    borsh_metadata_data(&mut data, metadata);
    data.push(u8::from(is_mutable));
    borsh_collection(&mut data, collection);
    borsh_uses(&mut data, None); // uses: None

    Instruction {
        program_id: METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*metadata_account, false),   // metadata (writable)
            AccountMeta::new_readonly(*mint, false),       // mint
            AccountMeta::new_readonly(*mint_authority, true), // mint authority (signer)
            AccountMeta::new(*payer, true),                // payer (signer, writable)
            AccountMeta::new_readonly(*update_authority, false), // update authority
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(SYSVAR_RENT_ID, false),
        ],
        data,
    }
}

/// Create a master edition (CreateMasterEditionV3, discriminator 17).
///
/// # Accounts
/// 0. `[writable]` Edition account (PDA)
/// 1. `[writable]` Mint
/// 2. `[signer]` Update authority
/// 3. `[signer]` Mint authority
/// 4. `[signer, writable]` Payer
/// 5. `[]` Metadata account
/// 6. `[]` Token program
/// 7. `[]` System program
/// 8. `[]` Rent sysvar
pub fn create_master_edition_v3(
    edition_account: &[u8; 32],
    mint: &[u8; 32],
    update_authority: &[u8; 32],
    mint_authority: &[u8; 32],
    payer: &[u8; 32],
    metadata_account: &[u8; 32],
    max_supply: Option<u64>,
) -> Instruction {
    let mut data = Vec::with_capacity(16);
    data.push(17); // CreateMasterEditionV3 discriminator

    match max_supply {
        Some(supply) => {
            data.push(1); // Some
            data.extend_from_slice(&supply.to_le_bytes());
        }
        None => data.push(0), // None (unlimited)
    }

    // SPL Token program ID
    let token_program = {
        let mut id = [0u8; 32];
        // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
        id[0] = 0x06;
        id[1] = 0xDD;
        id[2] = 0xF6;
        id[3] = 0xE1;
        id
    };

    Instruction {
        program_id: METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*edition_account, false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*update_authority, true),
            AccountMeta::new_readonly(*mint_authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*metadata_account, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            AccountMeta::new_readonly(SYSVAR_RENT_ID, false),
        ],
        data,
    }
}

/// Verify an NFT as part of a collection (VerifyCollection, discriminator 18).
///
/// # Accounts
/// 0. `[writable]` Metadata account
/// 1. `[signer]` Collection authority
/// 2. `[signer, writable]` Payer
/// 3. `[]` Collection mint
/// 4. `[]` Collection metadata account
/// 5. `[]` Collection master edition account
pub fn verify_collection(
    metadata_account: &[u8; 32],
    collection_authority: &[u8; 32],
    payer: &[u8; 32],
    collection_mint: &[u8; 32],
    collection_metadata: &[u8; 32],
    collection_edition: &[u8; 32],
) -> Instruction {
    let data = vec![18]; // VerifyCollection discriminator

    Instruction {
        program_id: METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*metadata_account, false),
            AccountMeta::new_readonly(*collection_authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*collection_mint, false),
            AccountMeta::new_readonly(*collection_metadata, false),
            AccountMeta::new_readonly(*collection_edition, false),
        ],
        data,
    }
}

/// Update metadata (UpdateMetadataAccountV2, discriminator 15).
///
/// # Accounts
/// 0. `[writable]` Metadata account
/// 1. `[signer]` Update authority
pub fn update_metadata_account_v2(
    metadata_account: &[u8; 32],
    update_authority: &[u8; 32],
    new_data: Option<&MetadataData>,
    new_update_authority: Option<&[u8; 32]>,
    primary_sale_happened: Option<bool>,
    is_mutable: Option<bool>,
) -> Instruction {
    let mut data = Vec::with_capacity(256);
    data.push(15); // UpdateMetadataAccountV2 discriminator

    // Option<Data>
    match new_data {
        Some(md) => {
            data.push(1);
            borsh_metadata_data(&mut data, md);
        }
        None => data.push(0),
    }

    // Option<Pubkey> new update authority
    borsh_option_pubkey(&mut data, new_update_authority);

    // Option<bool> primary_sale_happened
    match primary_sale_happened {
        Some(v) => {
            data.push(1);
            data.push(u8::from(v));
        }
        None => data.push(0),
    }

    // Option<bool> is_mutable
    match is_mutable {
        Some(v) => {
            data.push(1);
            data.push(u8::from(v));
        }
        None => data.push(0),
    }

    Instruction {
        program_id: METADATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*metadata_account, false),
            AccountMeta::new_readonly(*update_authority, true),
        ],
        data,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Bubblegum (Compressed NFT) Instructions
// ═══════════════════════════════════════════════════════════════════

/// Mint a compressed NFT (Bubblegum MintV1).
///
/// Uses the Anchor discriminator for `mint_v1`: SHA-256("global:mint_v1")[..8]
///
/// # Accounts
/// 0. `[writable]` Tree authority PDA
/// 1. `[]` Leaf owner
/// 2. `[]` Leaf delegate
/// 3. `[writable]` Merkle tree account
/// 4. `[signer, writable]` Payer
/// 5. `[signer]` Tree delegate
/// 6. `[]` Log wrapper (SPL Noop)
/// 7. `[]` Compression program
/// 8. `[]` System program
#[allow(clippy::too_many_arguments)]
pub fn mint_v1(
    tree_authority: &[u8; 32],
    leaf_owner: &[u8; 32],
    leaf_delegate: &[u8; 32],
    merkle_tree: &[u8; 32],
    payer: &[u8; 32],
    tree_delegate: &[u8; 32],
    log_wrapper: &[u8; 32],
    compression_program: &[u8; 32],
    metadata: &MetadataData,
) -> Instruction {
    // Anchor discriminator for "mint_v1"
    let discriminator: [u8; 8] = [145, 98, 192, 118, 184, 147, 118, 104];

    let mut data = Vec::with_capacity(256);
    data.extend_from_slice(&discriminator);
    borsh_metadata_data(&mut data, metadata);

    Instruction {
        program_id: BUBBLEGUM_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*tree_authority, false),
            AccountMeta::new_readonly(*leaf_owner, false),
            AccountMeta::new_readonly(*leaf_delegate, false),
            AccountMeta::new(*merkle_tree, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*tree_delegate, true),
            AccountMeta::new_readonly(*log_wrapper, false),
            AccountMeta::new_readonly(*compression_program, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
        data,
    }
}

/// Transfer a compressed NFT.
///
/// Anchor discriminator for "transfer": `SHA-256("global:transfer")[..8]`
///
/// # Accounts
///
/// - 0. `[writable]` Tree authority PDA
/// - 1. `[]` Leaf owner
/// - 2. `[]` Leaf delegate
/// - 3. `[]` New leaf owner
/// - 4. `[writable]` Merkle tree
/// - 5. `[]` Log wrapper
/// - 6. `[]` Compression program
/// - 7. `[]` System program
/// - 8..N. `[]` Proof accounts
#[allow(clippy::too_many_arguments)]
pub fn transfer(
    tree_authority: &[u8; 32],
    leaf_owner: &[u8; 32],
    leaf_delegate: &[u8; 32],
    new_leaf_owner: &[u8; 32],
    merkle_tree: &[u8; 32],
    log_wrapper: &[u8; 32],
    compression_program: &[u8; 32],
    root: &[u8; 32],
    data_hash: &[u8; 32],
    creator_hash: &[u8; 32],
    nonce: u64,
    index: u32,
    proof: &[[u8; 32]],
) -> Instruction {
    // Anchor discriminator for "transfer"
    let discriminator: [u8; 8] = [163, 52, 200, 231, 140, 3, 69, 186];

    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(&discriminator);
    data.extend_from_slice(root);
    data.extend_from_slice(data_hash);
    data.extend_from_slice(creator_hash);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&index.to_le_bytes());

    let mut accounts = vec![
        AccountMeta::new(*tree_authority, false),
        AccountMeta::new_readonly(*leaf_owner, true), // signer
        AccountMeta::new_readonly(*leaf_delegate, false),
        AccountMeta::new_readonly(*new_leaf_owner, false),
        AccountMeta::new(*merkle_tree, false),
        AccountMeta::new_readonly(*log_wrapper, false),
        AccountMeta::new_readonly(*compression_program, false),
        AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
    ];

    // Append proof accounts
    for node in proof {
        accounts.push(AccountMeta::new_readonly(*node, false));
    }

    Instruction {
        program_id: BUBBLEGUM_PROGRAM_ID,
        accounts,
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
    const PAYER: [u8; 32] = [0xCC; 32];
    const META_ACCT: [u8; 32] = [0xDD; 32];
    const EDITION: [u8; 32] = [0xEE; 32];

    fn sample_metadata() -> MetadataData {
        MetadataData {
            name: "Test NFT".into(),
            symbol: "TNFT".into(),
            uri: "https://example.com/nft.json".into(),
            seller_fee_basis_points: 500,
            creators: vec![Creator {
                address: AUTH,
                verified: true,
                share: 100,
            }],
        }
    }

    // ─── Program IDs ────────────────────────────────────────────

    #[test]
    fn test_metadata_program_id_length() {
        assert_eq!(METADATA_PROGRAM_ID.len(), 32);
    }

    #[test]
    fn test_bubblegum_program_id_length() {
        assert_eq!(BUBBLEGUM_PROGRAM_ID.len(), 32);
    }

    #[test]
    fn test_program_ids_differ() {
        assert_ne!(METADATA_PROGRAM_ID, BUBBLEGUM_PROGRAM_ID);
    }

    // ─── CreateMetadataAccountV3 ────────────────────────────────

    #[test]
    fn test_create_metadata_v3_discriminator() {
        let ix = create_metadata_account_v3(
            &META_ACCT, &MINT, &AUTH, &PAYER, &AUTH,
            &sample_metadata(), true, None,
        );
        assert_eq!(ix.data[0], 33);
    }

    #[test]
    fn test_create_metadata_v3_program_id() {
        let ix = create_metadata_account_v3(
            &META_ACCT, &MINT, &AUTH, &PAYER, &AUTH,
            &sample_metadata(), true, None,
        );
        assert_eq!(ix.program_id, METADATA_PROGRAM_ID);
    }

    #[test]
    fn test_create_metadata_v3_accounts() {
        let ix = create_metadata_account_v3(
            &META_ACCT, &MINT, &AUTH, &PAYER, &AUTH,
            &sample_metadata(), true, None,
        );
        assert_eq!(ix.accounts.len(), 7);
        assert_eq!(ix.accounts[0].pubkey, META_ACCT);
        assert!(ix.accounts[0].is_writable);
        assert_eq!(ix.accounts[2].pubkey, AUTH);
        assert!(ix.accounts[2].is_signer); // mint authority
        assert_eq!(ix.accounts[3].pubkey, PAYER);
        assert!(ix.accounts[3].is_signer); // payer
    }

    #[test]
    fn test_create_metadata_v3_data_encoding() {
        let md = MetadataData {
            name: "A".into(),
            symbol: "B".into(),
            uri: "C".into(),
            seller_fee_basis_points: 100,
            creators: vec![],
        };
        let ix = create_metadata_account_v3(
            &META_ACCT, &MINT, &AUTH, &PAYER, &AUTH, &md, false, None,
        );
        // [0]: discriminator 33
        assert_eq!(ix.data[0], 33);
        // [1..5]: name length (1)
        let name_len = u32::from_le_bytes(ix.data[1..5].try_into().unwrap());
        assert_eq!(name_len, 1);
        assert_eq!(ix.data[5], b'A');
    }

    #[test]
    fn test_create_metadata_v3_with_collection() {
        let col = Collection { verified: false, key: [0xFF; 32] };
        let ix = create_metadata_account_v3(
            &META_ACCT, &MINT, &AUTH, &PAYER, &AUTH,
            &sample_metadata(), true, Some(&col),
        );
        // Data should be longer with collection
        assert!(ix.data.len() > 50);
    }

    // ─── CreateMasterEditionV3 ──────────────────────────────────

    #[test]
    fn test_create_master_edition_v3_discriminator() {
        let ix = create_master_edition_v3(
            &EDITION, &MINT, &AUTH, &AUTH, &PAYER, &META_ACCT, Some(1),
        );
        assert_eq!(ix.data[0], 17);
    }

    #[test]
    fn test_create_master_edition_v3_max_supply() {
        let ix = create_master_edition_v3(
            &EDITION, &MINT, &AUTH, &AUTH, &PAYER, &META_ACCT, Some(100),
        );
        assert_eq!(ix.data[1], 1); // Some
        let supply = u64::from_le_bytes(ix.data[2..10].try_into().unwrap());
        assert_eq!(supply, 100);
    }

    #[test]
    fn test_create_master_edition_v3_unlimited() {
        let ix = create_master_edition_v3(
            &EDITION, &MINT, &AUTH, &AUTH, &PAYER, &META_ACCT, None,
        );
        assert_eq!(ix.data[1], 0); // None
        assert_eq!(ix.data.len(), 2);
    }

    #[test]
    fn test_create_master_edition_v3_accounts() {
        let ix = create_master_edition_v3(
            &EDITION, &MINT, &AUTH, &AUTH, &PAYER, &META_ACCT, None,
        );
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[2].is_signer); // update authority
        assert!(ix.accounts[3].is_signer); // mint authority
        assert!(ix.accounts[4].is_signer); // payer
    }

    // ─── VerifyCollection ───────────────────────────────────────

    #[test]
    fn test_verify_collection_discriminator() {
        let ix = verify_collection(
            &META_ACCT, &AUTH, &PAYER, &MINT, &[0x11; 32], &[0x22; 32],
        );
        assert_eq!(ix.data, vec![18]);
    }

    #[test]
    fn test_verify_collection_accounts() {
        let ix = verify_collection(
            &META_ACCT, &AUTH, &PAYER, &MINT, &[0x11; 32], &[0x22; 32],
        );
        assert_eq!(ix.accounts.len(), 6);
        assert!(ix.accounts[1].is_signer); // collection authority
        assert!(ix.accounts[2].is_signer); // payer
    }

    // ─── UpdateMetadataAccountV2 ────────────────────────────────

    #[test]
    fn test_update_metadata_v2_discriminator() {
        let ix = update_metadata_account_v2(
            &META_ACCT, &AUTH, None, None, None, None,
        );
        assert_eq!(ix.data[0], 15);
    }

    #[test]
    fn test_update_metadata_v2_no_changes() {
        let ix = update_metadata_account_v2(
            &META_ACCT, &AUTH, None, None, None, None,
        );
        // [15, 0, 0, 0, 0] = discriminator + 4 × None
        assert_eq!(ix.data, vec![15, 0, 0, 0, 0]);
    }

    #[test]
    fn test_update_metadata_v2_with_new_authority() {
        let new_auth = [0xFF; 32];
        let ix = update_metadata_account_v2(
            &META_ACCT, &AUTH, None, Some(&new_auth), None, None,
        );
        assert_eq!(ix.data[0], 15);
        assert_eq!(ix.data[1], 0); // no data
        assert_eq!(ix.data[2], 1); // Some(new_authority)
        assert_eq!(&ix.data[3..35], &new_auth);
    }

    #[test]
    fn test_update_metadata_v2_accounts() {
        let ix = update_metadata_account_v2(
            &META_ACCT, &AUTH, None, None, None, None,
        );
        assert_eq!(ix.accounts.len(), 2);
        assert!(ix.accounts[1].is_signer);
    }

    // ─── Bubblegum MintV1 ───────────────────────────────────────

    #[test]
    fn test_bubblegum_mint_v1_discriminator() {
        let ix = mint_v1(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &PAYER, &AUTH, &[0x05; 32], &[0x06; 32],
            &sample_metadata(),
        );
        assert_eq!(&ix.data[0..8], &[145, 98, 192, 118, 184, 147, 118, 104]);
    }

    #[test]
    fn test_bubblegum_mint_v1_program_id() {
        let ix = mint_v1(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &PAYER, &AUTH, &[0x05; 32], &[0x06; 32],
            &sample_metadata(),
        );
        assert_eq!(ix.program_id, BUBBLEGUM_PROGRAM_ID);
    }

    #[test]
    fn test_bubblegum_mint_v1_accounts() {
        let ix = mint_v1(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &PAYER, &AUTH, &[0x05; 32], &[0x06; 32],
            &sample_metadata(),
        );
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[4].is_signer); // payer
        assert!(ix.accounts[5].is_signer); // tree delegate
    }

    // ─── Bubblegum Transfer ─────────────────────────────────────

    #[test]
    fn test_bubblegum_transfer_discriminator() {
        let ix = transfer(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &[0x05; 32], &[0x06; 32], &[0x07; 32],
            &[0xAA; 32], &[0xBB; 32], &[0xCC; 32],
            0, 0, &[],
        );
        assert_eq!(&ix.data[0..8], &[163, 52, 200, 231, 140, 3, 69, 186]);
    }

    #[test]
    fn test_bubblegum_transfer_data_encoding() {
        let root = [0xAA; 32];
        let data_hash = [0xBB; 32];
        let creator_hash = [0xCC; 32];
        let ix = transfer(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &[0x05; 32], &[0x06; 32], &[0x07; 32],
            &root, &data_hash, &creator_hash,
            42, 7, &[],
        );
        assert_eq!(&ix.data[8..40], &root);
        assert_eq!(&ix.data[40..72], &data_hash);
        assert_eq!(&ix.data[72..104], &creator_hash);
        let nonce = u64::from_le_bytes(ix.data[104..112].try_into().unwrap());
        assert_eq!(nonce, 42);
        let idx = u32::from_le_bytes(ix.data[112..116].try_into().unwrap());
        assert_eq!(idx, 7);
    }

    #[test]
    fn test_bubblegum_transfer_with_proof() {
        let proof = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
        let ix = transfer(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &[0x05; 32], &[0x06; 32], &[0x07; 32],
            &[0xAA; 32], &[0xBB; 32], &[0xCC; 32],
            0, 0, &proof,
        );
        assert_eq!(ix.accounts.len(), 8 + 3); // base + proof
    }

    #[test]
    fn test_bubblegum_transfer_leaf_owner_is_signer() {
        let ix = transfer(
            &[0x01; 32], &[0x02; 32], &[0x03; 32], &[0x04; 32],
            &[0x05; 32], &[0x06; 32], &[0x07; 32],
            &[0xAA; 32], &[0xBB; 32], &[0xCC; 32],
            0, 0, &[],
        );
        assert_eq!(ix.accounts[1].pubkey, [0x02; 32]);
        assert!(ix.accounts[1].is_signer); // leaf owner must sign
    }

    // ─── Borsh Encoding ─────────────────────────────────────────

    #[test]
    fn test_borsh_string() {
        let mut buf = Vec::new();
        borsh_string(&mut buf, "Hello");
        assert_eq!(buf.len(), 4 + 5);
        let len = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(len, 5);
        assert_eq!(&buf[4..], b"Hello");
    }

    #[test]
    fn test_borsh_string_empty() {
        let mut buf = Vec::new();
        borsh_string(&mut buf, "");
        assert_eq!(buf.len(), 4);
        assert_eq!(u32::from_le_bytes(buf[..4].try_into().unwrap()), 0);
    }

    #[test]
    fn test_borsh_creators() {
        let mut buf = Vec::new();
        borsh_creators(&mut buf, &[Creator {
            address: [0xFF; 32],
            verified: true,
            share: 50,
        }]);
        assert_eq!(buf[0], 1); // Some
        let count = u32::from_le_bytes(buf[1..5].try_into().unwrap());
        assert_eq!(count, 1);
        assert_eq!(&buf[5..37], &[0xFF; 32]);
        assert_eq!(buf[37], 1); // verified
        assert_eq!(buf[38], 50); // share
    }

    #[test]
    fn test_borsh_collection_some() {
        let mut buf = Vec::new();
        let col = Collection { verified: true, key: [0xAA; 32] };
        borsh_collection(&mut buf, Some(&col));
        assert_eq!(buf[0], 1); // Some
        assert_eq!(buf[1], 1); // verified
        assert_eq!(&buf[2..34], &[0xAA; 32]);
    }

    #[test]
    fn test_borsh_collection_none() {
        let mut buf = Vec::new();
        borsh_collection(&mut buf, None);
        assert_eq!(buf, vec![0]); // None
    }

    #[test]
    fn test_use_method_values() {
        assert_eq!(UseMethod::Burn as u8, 0);
        assert_eq!(UseMethod::Multiple as u8, 1);
        assert_eq!(UseMethod::Single as u8, 2);
    }
}
