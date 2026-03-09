//! Solana DEX swap instruction builders.
//!
//! Provides helpers for constructing swap instructions for major
//! Solana DEX protocols: Jupiter Aggregator and Raydium AMM.
//!
//! # Example
//! ```no_run
//! use chains_sdk::solana::dex::*;
//! use chains_sdk::solana::transaction::InstructionDataBuilder;
//!
//! let params = SwapParams {
//!     in_amount: 1_000_000_000,  // 1 SOL
//!     minimum_out_amount: 50_000_000, // minimum USDC
//!     slippage_bps: 50,  // 0.5%
//! };
//! ```

use super::transaction::{AccountMeta, Instruction};

// ═══════════════════════════════════════════════════════════════════
// Common Types
// ═══════════════════════════════════════════════════════════════════

/// Parameters for a token swap.
#[derive(Debug, Clone)]
pub struct SwapParams {
    /// Amount of input tokens (in smallest unit).
    pub in_amount: u64,
    /// Minimum output tokens (slippage protection).
    pub minimum_out_amount: u64,
    /// Slippage tolerance in basis points (100 = 1%).
    pub slippage_bps: u16,
}

impl SwapParams {
    /// Create swap params with explicit slippage.
    #[must_use]
    pub fn new(in_amount: u64, minimum_out_amount: u64, slippage_bps: u16) -> Self {
        Self {
            in_amount,
            minimum_out_amount,
            slippage_bps,
        }
    }

    /// Calculate minimum output from input amount and slippage.
    ///
    /// `min_out = expected_out * (10000 - slippage_bps) / 10000`
    #[must_use]
    pub fn with_slippage(in_amount: u64, expected_out: u64, slippage_bps: u16) -> Self {
        let min_out = expected_out * (10_000 - slippage_bps as u64) / 10_000;
        Self {
            in_amount,
            minimum_out_amount: min_out,
            slippage_bps,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Jupiter Aggregator (v6)
// ═══════════════════════════════════════════════════════════════════

/// Jupiter v6 aggregator helpers.
pub mod jupiter {
    use super::*;

    /// Jupiter v6 Program ID: `JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4`
    pub const PROGRAM_ID: [u8; 32] = [
        0x04, 0x79, 0xD5, 0x5B, 0xF2, 0x31, 0xC0, 0x6E, 0xEE, 0x74, 0xC5, 0x6E, 0xCE, 0x68,
        0x15, 0x07, 0xFD, 0xB1, 0xB2, 0xDE, 0xA3, 0xF4, 0x8E, 0x51, 0x02, 0xB1, 0xCD, 0xA2,
        0x56, 0xBC, 0x13, 0x8F,
    ];

    /// Token Program ID (SPL Token).
    const TOKEN_PROGRAM_ID: [u8; 32] = [
        0x06, 0xDD, 0xF6, 0xE1, 0xD7, 0x65, 0xA1, 0x93, 0xD9, 0xCB, 0xE1, 0x46, 0xCE, 0xEB,
        0x79, 0xAC, 0x1C, 0xB4, 0x85, 0xED, 0x5F, 0x5B, 0x37, 0x91, 0x3A, 0x8C, 0xF5, 0x85,
        0x7E, 0xFF, 0x00, 0xA9,
    ];

    /// Build a Jupiter `sharedAccountsRoute` instruction.
    ///
    /// This is the most common Jupiter swap instruction. The route
    /// accounts are passed as remaining accounts after the fixed ones.
    ///
    /// # Arguments
    /// - `payer` — Transaction fee payer (signer)
    /// - `user_source_token` — User's source token account
    /// - `user_destination_token` — User's destination token account
    /// - `source_mint` — Source token mint
    /// - `destination_mint` — Destination token mint
    /// - `params` — Swap parameters
    /// - `route_accounts` — Intermediate route accounts from Jupiter API
    ///
    /// # Note
    /// In production, the route accounts come from Jupiter's `/quote` API.
    /// This builder lets you encode the instruction once you have them.
    #[must_use]
    pub fn shared_accounts_route(
        payer: &[u8; 32],
        user_source_token: &[u8; 32],
        user_destination_token: &[u8; 32],
        source_mint: &[u8; 32],
        destination_mint: &[u8; 32],
        params: &SwapParams,
        route_accounts: &[AccountMeta],
    ) -> Instruction {
        // Anchor discriminator for `shared_accounts_route`
        // SHA256("global:shared_accounts_route")[..8]
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(&[193, 32, 155, 51, 65, 214, 156, 129]); // discriminator

        // Encode: id (u8), in_amount (u64), quoted_out_amount (u64),
        //         slippage_bps (u16), platform_fee_bps (u8)
        data.push(0); // route plan id (single route)
        data.extend_from_slice(&params.in_amount.to_le_bytes());
        data.extend_from_slice(&params.minimum_out_amount.to_le_bytes());
        data.extend_from_slice(&params.slippage_bps.to_le_bytes());
        data.push(0); // platform_fee_bps

        let mut accounts = vec![
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new(*user_source_token, false),
            AccountMeta::new(*user_destination_token, false),
            AccountMeta::new_readonly(*source_mint, false),
            AccountMeta::new_readonly(*destination_mint, false),
        ];
        accounts.extend_from_slice(route_accounts);

        Instruction {
            program_id: PROGRAM_ID,
            accounts,
            data,
        }
    }

    /// Build a Jupiter `route` instruction (direct routing).
    ///
    /// Simpler than `sharedAccountsRoute` — all intermediate accounts
    /// are managed by the program.
    #[must_use]
    pub fn route(
        payer: &[u8; 32],
        user_source_token: &[u8; 32],
        user_destination_token: &[u8; 32],
        params: &SwapParams,
        route_accounts: &[AccountMeta],
    ) -> Instruction {
        // Anchor discriminator for `route`
        // SHA256("global:route")[..8]
        let mut data = Vec::with_capacity(24);
        data.extend_from_slice(&[229, 23, 203, 151, 122, 227, 173, 42]); // discriminator

        data.extend_from_slice(&params.in_amount.to_le_bytes());
        data.extend_from_slice(&params.minimum_out_amount.to_le_bytes());
        data.extend_from_slice(&params.slippage_bps.to_le_bytes());

        let mut accounts = vec![
            AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new(*user_source_token, false),
            AccountMeta::new(*user_destination_token, false),
        ];
        accounts.extend_from_slice(route_accounts);

        Instruction {
            program_id: PROGRAM_ID,
            accounts,
            data,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Raydium AMM
// ═══════════════════════════════════════════════════════════════════

/// Raydium AMM v4 helpers.
pub mod raydium {
    use super::*;

    /// Raydium AMM v4 Program ID: `675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8`
    pub const PROGRAM_ID: [u8; 32] = [
        0x4B, 0xD9, 0x49, 0xC4, 0x36, 0x02, 0xC3, 0x3F, 0x20, 0x77, 0x90, 0xED, 0x16, 0xA3,
        0x52, 0x4C, 0xA1, 0xB9, 0x97, 0x5C, 0xF1, 0x21, 0xA2, 0xA9, 0x0C, 0xFF, 0xEC, 0x7D,
        0xF8, 0xB6, 0x8A, 0xCD,
    ];

    /// Token Program ID (SPL Token).
    const TOKEN_PROGRAM_ID: [u8; 32] = [
        0x06, 0xDD, 0xF6, 0xE1, 0xD7, 0x65, 0xA1, 0x93, 0xD9, 0xCB, 0xE1, 0x46, 0xCE, 0xEB,
        0x79, 0xAC, 0x1C, 0xB4, 0x85, 0xED, 0x5F, 0x5B, 0x37, 0x91, 0x3A, 0x8C, 0xF5, 0x85,
        0x7E, 0xFF, 0x00, 0xA9,
    ];

    /// Build a Raydium AMM `swap` instruction.
    ///
    /// # Arguments
    /// - `amm_id` — AMM pool account
    /// - `amm_authority` — AMM authority (PDA)
    /// - `amm_open_orders` — AMM open orders account
    /// - `amm_target_orders` — AMM target orders account
    /// - `pool_coin_token` — Pool's coin (base) token account
    /// - `pool_pc_token` — Pool's PC (quote) token account
    /// - `serum_program_id` — Serum/OpenBook DEX program
    /// - `serum_market` — Serum market account
    /// - `serum_bids` — Serum bids account
    /// - `serum_asks` — Serum asks account
    /// - `serum_event_queue` — Serum event queue
    /// - `serum_coin_vault` — Serum coin vault
    /// - `serum_pc_vault` — Serum PC vault
    /// - `serum_vault_signer` — Serum vault signer (PDA)
    /// - `user_source_token` — User's source token account
    /// - `user_destination_token` — User's destination token account
    /// - `user_owner` — User wallet (signer)
    /// - `params` — Swap parameters
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn swap(
        amm_id: &[u8; 32],
        amm_authority: &[u8; 32],
        amm_open_orders: &[u8; 32],
        amm_target_orders: &[u8; 32],
        pool_coin_token: &[u8; 32],
        pool_pc_token: &[u8; 32],
        serum_program_id: &[u8; 32],
        serum_market: &[u8; 32],
        serum_bids: &[u8; 32],
        serum_asks: &[u8; 32],
        serum_event_queue: &[u8; 32],
        serum_coin_vault: &[u8; 32],
        serum_pc_vault: &[u8; 32],
        serum_vault_signer: &[u8; 32],
        user_source_token: &[u8; 32],
        user_destination_token: &[u8; 32],
        user_owner: &[u8; 32],
        params: &SwapParams,
    ) -> Instruction {
        // Instruction discriminator: 9 = SwapBaseIn
        let mut data = vec![9];
        data.extend_from_slice(&params.in_amount.to_le_bytes());
        data.extend_from_slice(&params.minimum_out_amount.to_le_bytes());

        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
                AccountMeta::new(*amm_id, false),
                AccountMeta::new_readonly(*amm_authority, false),
                AccountMeta::new(*amm_open_orders, false),
                AccountMeta::new(*amm_target_orders, false),
                AccountMeta::new(*pool_coin_token, false),
                AccountMeta::new(*pool_pc_token, false),
                AccountMeta::new_readonly(*serum_program_id, false),
                AccountMeta::new(*serum_market, false),
                AccountMeta::new(*serum_bids, false),
                AccountMeta::new(*serum_asks, false),
                AccountMeta::new(*serum_event_queue, false),
                AccountMeta::new(*serum_coin_vault, false),
                AccountMeta::new(*serum_pc_vault, false),
                AccountMeta::new_readonly(*serum_vault_signer, false),
                AccountMeta::new(*user_source_token, false),
                AccountMeta::new(*user_destination_token, false),
                AccountMeta::new_readonly(*user_owner, true),
            ],
            data,
        }
    }

    /// Build a Raydium `swapBaseOut` instruction.
    ///
    /// Like `swap` but specifies the exact output amount instead of input.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn swap_base_out(
        amm_id: &[u8; 32],
        amm_authority: &[u8; 32],
        amm_open_orders: &[u8; 32],
        amm_target_orders: &[u8; 32],
        pool_coin_token: &[u8; 32],
        pool_pc_token: &[u8; 32],
        serum_program_id: &[u8; 32],
        serum_market: &[u8; 32],
        serum_bids: &[u8; 32],
        serum_asks: &[u8; 32],
        serum_event_queue: &[u8; 32],
        serum_coin_vault: &[u8; 32],
        serum_pc_vault: &[u8; 32],
        serum_vault_signer: &[u8; 32],
        user_source_token: &[u8; 32],
        user_destination_token: &[u8; 32],
        user_owner: &[u8; 32],
        max_in_amount: u64,
        exact_out_amount: u64,
    ) -> Instruction {
        // Instruction discriminator: 11 = SwapBaseOut
        let mut data = vec![11];
        data.extend_from_slice(&max_in_amount.to_le_bytes());
        data.extend_from_slice(&exact_out_amount.to_le_bytes());

        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(TOKEN_PROGRAM_ID, false),
                AccountMeta::new(*amm_id, false),
                AccountMeta::new_readonly(*amm_authority, false),
                AccountMeta::new(*amm_open_orders, false),
                AccountMeta::new(*amm_target_orders, false),
                AccountMeta::new(*pool_coin_token, false),
                AccountMeta::new(*pool_pc_token, false),
                AccountMeta::new_readonly(*serum_program_id, false),
                AccountMeta::new(*serum_market, false),
                AccountMeta::new(*serum_bids, false),
                AccountMeta::new(*serum_asks, false),
                AccountMeta::new(*serum_event_queue, false),
                AccountMeta::new(*serum_coin_vault, false),
                AccountMeta::new(*serum_pc_vault, false),
                AccountMeta::new_readonly(*serum_vault_signer, false),
                AccountMeta::new(*user_source_token, false),
                AccountMeta::new(*user_destination_token, false),
                AccountMeta::new_readonly(*user_owner, true),
            ],
            data,
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

    const PAYER: [u8; 32] = [0x01; 32];
    const SRC_TOKEN: [u8; 32] = [0x02; 32];
    const DST_TOKEN: [u8; 32] = [0x03; 32];
    const SRC_MINT: [u8; 32] = [0x04; 32];
    const DST_MINT: [u8; 32] = [0x05; 32];

    fn dummy_raydium_accounts() -> Vec<[u8; 32]> {
        (0..14).map(|i| [i + 10u8; 32]).collect()
    }

    // ─── SwapParams ──────────────────────────────────────────────

    #[test]
    fn test_swap_params_new() {
        let params = SwapParams::new(1_000_000, 500_000, 50);
        assert_eq!(params.in_amount, 1_000_000);
        assert_eq!(params.minimum_out_amount, 500_000);
        assert_eq!(params.slippage_bps, 50);
    }

    #[test]
    fn test_swap_params_with_slippage() {
        let params = SwapParams::with_slippage(1_000_000, 1_000_000, 100); // 1%
        assert_eq!(params.minimum_out_amount, 990_000);
    }

    #[test]
    fn test_swap_params_with_slippage_50bps() {
        let params = SwapParams::with_slippage(1_000_000, 2_000_000, 50); // 0.5%
        assert_eq!(params.minimum_out_amount, 1_990_000);
    }

    #[test]
    fn test_swap_params_zero_slippage() {
        let params = SwapParams::with_slippage(100, 200, 0);
        assert_eq!(params.minimum_out_amount, 200);
    }

    #[test]
    fn test_swap_params_max_slippage() {
        let params = SwapParams::with_slippage(1_000_000, 1_000_000, 10_000); // 100%
        assert_eq!(params.minimum_out_amount, 0);
    }

    #[test]
    fn test_swap_params_large_amounts() {
        // 1000 SOL → expected 100000 USDC (6 decimals)
        let params = SwapParams::with_slippage(
            1_000_000_000_000,
            100_000_000_000,
            50,
        );
        // 100_000_000_000 * 9950 / 10000 = 99_500_000_000
        assert_eq!(params.minimum_out_amount, 99_500_000_000);
    }

    #[test]
    fn test_swap_params_1_lamport() {
        let params = SwapParams::with_slippage(1, 1, 50);
        // 1 * 9950 / 10000 = 0 (integer math)
        assert_eq!(params.minimum_out_amount, 0);
    }

    // ─── Jupiter ─────────────────────────────────────────────────

    #[test]
    fn test_jupiter_shared_accounts_route() {
        let params = SwapParams::new(1_000_000_000, 50_000_000, 50);
        let ix = jupiter::shared_accounts_route(
            &PAYER, &SRC_TOKEN, &DST_TOKEN, &SRC_MINT, &DST_MINT,
            &params, &[],
        );
        assert_eq!(ix.program_id, jupiter::PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.data.len(), 8 + 1 + 8 + 8 + 2 + 1);
    }

    #[test]
    fn test_jupiter_shared_accounts_route_discriminator() {
        let params = SwapParams::new(100, 50, 10);
        let ix = jupiter::shared_accounts_route(
            &PAYER, &SRC_TOKEN, &DST_TOKEN, &SRC_MINT, &DST_MINT,
            &params, &[],
        );
        assert_eq!(&ix.data[0..8], &[193, 32, 155, 51, 65, 214, 156, 129]);
    }

    #[test]
    fn test_jupiter_shared_accounts_route_data_encoding() {
        let params = SwapParams::new(1_000_000_000, 50_000_000, 50);
        let ix = jupiter::shared_accounts_route(
            &PAYER, &SRC_TOKEN, &DST_TOKEN, &SRC_MINT, &DST_MINT,
            &params, &[],
        );
        // [8]: route plan id
        assert_eq!(ix.data[8], 0);
        // [9..17]: in_amount
        let in_amt = u64::from_le_bytes(ix.data[9..17].try_into().unwrap());
        assert_eq!(in_amt, 1_000_000_000);
        // [17..25]: minimum_out_amount
        let min_out = u64::from_le_bytes(ix.data[17..25].try_into().unwrap());
        assert_eq!(min_out, 50_000_000);
        // [25..27]: slippage_bps
        let slippage = u16::from_le_bytes(ix.data[25..27].try_into().unwrap());
        assert_eq!(slippage, 50);
        // [27]: platform_fee_bps
        assert_eq!(ix.data[27], 0);
    }

    #[test]
    fn test_jupiter_shared_accounts_route_with_extra_accounts() {
        let params = SwapParams::new(1_000_000, 500_000, 100);
        let extra = vec![AccountMeta::new([0xAA; 32], false)];
        let ix = jupiter::shared_accounts_route(
            &PAYER, &SRC_TOKEN, &DST_TOKEN, &SRC_MINT, &DST_MINT,
            &params, &extra,
        );
        assert_eq!(ix.accounts.len(), 7);
    }

    #[test]
    fn test_jupiter_shared_accounts_route_payer_is_signer() {
        let params = SwapParams::new(100, 50, 10);
        let ix = jupiter::shared_accounts_route(
            &PAYER, &SRC_TOKEN, &DST_TOKEN, &SRC_MINT, &DST_MINT,
            &params, &[],
        );
        // accounts[1] is the payer
        assert!(ix.accounts[1].is_signer);
        assert_eq!(ix.accounts[1].pubkey, PAYER);
    }

    #[test]
    fn test_jupiter_route() {
        let params = SwapParams::new(1_000, 500, 10);
        let ix = jupiter::route(&PAYER, &SRC_TOKEN, &DST_TOKEN, &params, &[]);
        assert_eq!(ix.program_id, jupiter::PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 4);
    }

    #[test]
    fn test_jupiter_route_discriminator() {
        let params = SwapParams::new(100, 50, 10);
        let ix = jupiter::route(&PAYER, &SRC_TOKEN, &DST_TOKEN, &params, &[]);
        assert_eq!(&ix.data[0..8], &[229, 23, 203, 151, 122, 227, 173, 42]);
    }

    #[test]
    fn test_jupiter_route_data_encoding() {
        let params = SwapParams::new(1_000_000, 500_000, 50);
        let ix = jupiter::route(&PAYER, &SRC_TOKEN, &DST_TOKEN, &params, &[]);
        let in_amount = u64::from_le_bytes(ix.data[8..16].try_into().unwrap());
        let min_out = u64::from_le_bytes(ix.data[16..24].try_into().unwrap());
        let slippage = u16::from_le_bytes(ix.data[24..26].try_into().unwrap());
        assert_eq!(in_amount, 1_000_000);
        assert_eq!(min_out, 500_000);
        assert_eq!(slippage, 50);
    }

    #[test]
    fn test_jupiter_route_payer_is_signer() {
        let params = SwapParams::new(100, 50, 10);
        let ix = jupiter::route(&PAYER, &SRC_TOKEN, &DST_TOKEN, &params, &[]);
        assert!(ix.accounts[1].is_signer);
    }

    #[test]
    fn test_jupiter_route_with_extra_accounts() {
        let params = SwapParams::new(100, 50, 10);
        let extras = vec![
            AccountMeta::new([0xAA; 32], false),
            AccountMeta::new([0xBB; 32], false),
        ];
        let ix = jupiter::route(&PAYER, &SRC_TOKEN, &DST_TOKEN, &params, &extras);
        assert_eq!(ix.accounts.len(), 6); // 4 fixed + 2 extras
    }

    // ─── Raydium ─────────────────────────────────────────────────

    #[test]
    fn test_raydium_swap() {
        let params = SwapParams::new(1_000_000, 500_000, 50);
        let accounts = dummy_raydium_accounts();
        let ix = raydium::swap(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, &params,
        );
        assert_eq!(ix.program_id, raydium::PROGRAM_ID);
        assert_eq!(ix.accounts.len(), 18);
        assert_eq!(ix.data[0], 9); // SwapBaseIn discriminator
    }

    #[test]
    fn test_raydium_swap_data_encoding() {
        let params = SwapParams::new(5_000_000, 2_500_000, 100);
        let accounts = dummy_raydium_accounts();
        let ix = raydium::swap(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, &params,
        );
        let in_amt = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        let min_out = u64::from_le_bytes(ix.data[9..17].try_into().unwrap());
        assert_eq!(in_amt, 5_000_000);
        assert_eq!(min_out, 2_500_000);
        assert_eq!(ix.data.len(), 1 + 8 + 8); // discriminator + 2 x u64
    }

    #[test]
    fn test_raydium_swap_base_out() {
        let accounts = dummy_raydium_accounts();
        let ix = raydium::swap_base_out(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, 2_000_000, 1_000_000,
        );
        assert_eq!(ix.data[0], 11); // SwapBaseOut
        let max_in = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        let exact_out = u64::from_le_bytes(ix.data[9..17].try_into().unwrap());
        assert_eq!(max_in, 2_000_000);
        assert_eq!(exact_out, 1_000_000);
    }

    #[test]
    fn test_raydium_swap_base_out_accounts() {
        let accounts = dummy_raydium_accounts();
        let ix = raydium::swap_base_out(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, 100, 50,
        );
        assert_eq!(ix.accounts.len(), 18);
        // Last account is user_owner (signer)
        assert!(ix.accounts[17].is_signer);
        assert_eq!(ix.accounts[17].pubkey, PAYER);
    }

    #[test]
    fn test_raydium_swap_payer_is_signer() {
        let params = SwapParams::new(100, 50, 10);
        let accounts = dummy_raydium_accounts();
        let ix = raydium::swap(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, &params,
        );
        let last = &ix.accounts[ix.accounts.len() - 1];
        assert!(last.is_signer);
    }

    #[test]
    fn test_raydium_swap_discriminators_differ() {
        // SwapBaseIn = 9, SwapBaseOut = 11
        let params = SwapParams::new(100, 50, 10);
        let accounts = dummy_raydium_accounts();
        let ix_in = raydium::swap(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, &params,
        );
        let ix_out = raydium::swap_base_out(
            &accounts[0], &accounts[1], &accounts[2], &accounts[3],
            &accounts[4], &accounts[5], &accounts[6], &accounts[7],
            &accounts[8], &accounts[9], &accounts[10], &accounts[11],
            &accounts[12], &accounts[13], &SRC_TOKEN, &DST_TOKEN,
            &PAYER, 100, 50,
        );
        assert_ne!(ix_in.data[0], ix_out.data[0]);
        assert_eq!(ix_in.data[0], 9);
        assert_eq!(ix_out.data[0], 11);
    }

    // ─── Program IDs ─────────────────────────────────────────────

    #[test]
    fn test_jupiter_program_id_length() {
        assert_eq!(jupiter::PROGRAM_ID.len(), 32);
    }

    #[test]
    fn test_raydium_program_id_length() {
        assert_eq!(raydium::PROGRAM_ID.len(), 32);
    }

    #[test]
    fn test_program_ids_differ() {
        assert_ne!(jupiter::PROGRAM_ID, raydium::PROGRAM_ID);
    }
}
