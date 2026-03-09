//! Uniswap V4 swap router instruction encoding.
//!
//! Provides ABI encoding for Uniswap V4's Universal Router and
//! PoolManager operations, including exact-input/output swaps,
//! pool key construction, and multi-hop path encoding.
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::uniswap_v4::*;
//!
//! let pool = PoolKey {
//!     currency0: [0xAA; 20],
//!     currency1: [0xBB; 20],
//!     fee: 3000,
//!     tick_spacing: 60,
//!     hooks: [0u8; 20],
//! };
//! let params = SwapParams::exact_input(1_000_000, 990_000);
//! let calldata = encode_swap(&pool, &params);
//! ```

use crate::ethereum::abi::{AbiValue, Function};

// ═══════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════

/// Uniswap V4 PoolManager address (Ethereum mainnet).
///
/// **WARNING**: This is a placeholder value — V4 is not yet deployed on mainnet.
/// Do **not** use in production until updated with the canonical address.
#[deprecated(note = "placeholder address — Uniswap V4 not yet deployed on mainnet")]
pub const POOL_MANAGER: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, // placeholder — V4 not yet deployed
];

/// Common fee tiers (in hundredths of a basis point).
pub const FEE_LOWEST: u32 = 100;    // 0.01%
/// Low fee tier.
pub const FEE_LOW: u32 = 500;       // 0.05%
/// Medium fee tier.
pub const FEE_MEDIUM: u32 = 3000;   // 0.30%
/// High fee tier.
pub const FEE_HIGH: u32 = 10_000;   // 1.00%

/// Standard tick spacings per fee tier.
pub const TICK_SPACING_LOWEST: i32 = 1;
/// Low tick spacing.
pub const TICK_SPACING_LOW: i32 = 10;
/// Medium tick spacing.
pub const TICK_SPACING_MEDIUM: i32 = 60;
/// High tick spacing.
pub const TICK_SPACING_HIGH: i32 = 200;

/// Universal Router command IDs.
pub const CMD_V4_SWAP: u8 = 0x10;
/// Exact-input single swap.
pub const CMD_EXACT_IN_SINGLE: u8 = 0x00;
/// Exact-output single swap.
pub const CMD_EXACT_OUT_SINGLE: u8 = 0x01;
/// Exact-input multi-hop.
pub const CMD_EXACT_IN: u8 = 0x02;
/// Exact-output multi-hop.
pub const CMD_EXACT_OUT: u8 = 0x03;

// ═══════════════════════════════════════════════════════════════════
// Pool Key
// ═══════════════════════════════════════════════════════════════════

/// A Uniswap V4 pool key identifying a unique pool.
///
/// `currency0 < currency1` must always hold (sorted order).
/// Use `address(0)` for native ETH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolKey {
    /// Lower-sorted token address (address(0) = ETH).
    pub currency0: [u8; 20],
    /// Higher-sorted token address.
    pub currency1: [u8; 20],
    /// Fee in hundredths of a basis point (e.g., 3000 = 0.30%).
    pub fee: u32,
    /// Tick spacing.
    pub tick_spacing: i32,
    /// Hooks contract address (address(0) if no hooks).
    pub hooks: [u8; 20],
}

impl PoolKey {
    /// Create a pool key with standard fee tier.
    ///
    /// Automatically sorts currencies and selects tick spacing.
    #[must_use]
    pub fn new(token_a: [u8; 20], token_b: [u8; 20], fee: u32) -> Self {
        let (currency0, currency1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        let tick_spacing = match fee {
            FEE_LOWEST => TICK_SPACING_LOWEST,
            FEE_LOW => TICK_SPACING_LOW,
            FEE_MEDIUM => TICK_SPACING_MEDIUM,
            FEE_HIGH => TICK_SPACING_HIGH,
            _ => TICK_SPACING_MEDIUM,
        };

        Self {
            currency0,
            currency1,
            fee,
            tick_spacing,
            hooks: [0u8; 20],
        }
    }

    /// Create a pool key with a hooks contract.
    #[must_use]
    pub fn with_hooks(mut self, hooks: [u8; 20]) -> Self {
        self.hooks = hooks;
        self
    }

    /// ABI-encode this pool key as a tuple.
    #[must_use]
    pub fn encode(&self) -> Vec<AbiValue> {
        vec![
            AbiValue::Address(self.currency0),
            AbiValue::Address(self.currency1),
            AbiValue::from_u64(self.fee as u64),
            AbiValue::from_u64(self.tick_spacing as u64),
            AbiValue::Address(self.hooks),
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════
// Swap Parameters
// ═══════════════════════════════════════════════════════════════════

/// Parameters for a V4 swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapParams {
    /// True for exact-input swap (zeroForOne direction).
    pub zero_for_one: bool,
    /// The swap amount (positive = exact input, negative = exact output).
    pub amount_specified: i128,
    /// Slippage bound (min output for exact-in, max input for exact-out).
    pub slippage_bound: u64,
    /// Price limit (sqrt price × 2^96).
    /// Use `MIN_SQRT_RATIO + 1` for sells, `MAX_SQRT_RATIO - 1` for buys.
    pub sqrt_price_limit_x96: [u8; 32],
}

/// Minimum sqrt ratio (for zeroForOne = true swaps).
pub const MIN_SQRT_RATIO: [u8; 32] = {
    let mut v = [0u8; 32];
    v[31] = 1; // MIN_SQRT_RATIO + 1
    v
};

/// Maximum sqrt ratio (for zeroForOne = false swaps).
pub const MAX_SQRT_RATIO: [u8; 32] = {
    let mut v = [0u8; 32];
    // 0xFFFD8963EFD1FC6A506488495D951D5263988D26 (approx MAX_SQRT_RATIO - 1)
    v[12] = 0xff;
    v[13] = 0xfd;
    v[14] = 0x89;
    v[15] = 0x63;
    v[16] = 0xef;
    v[17] = 0xd1;
    v[18] = 0xfc;
    v[19] = 0x6a;
    v[20] = 0x50;
    v[21] = 0x64;
    v[22] = 0x88;
    v[23] = 0x49;
    v[24] = 0x5d;
    v[25] = 0x95;
    v[26] = 0x1d;
    v[27] = 0x52;
    v[28] = 0x63;
    v[29] = 0x98;
    v[30] = 0x8d;
    v[31] = 0x26;
    v
};

impl SwapParams {
    /// Create exact-input swap parameters.
    ///
    /// Swaps exactly `amount_in` of token0 for at least `min_out` of token1.
    #[must_use]
    pub fn exact_input(amount_in: u64, min_out: u64) -> Self {
        Self {
            zero_for_one: true,
            amount_specified: amount_in as i128,
            slippage_bound: min_out,
            sqrt_price_limit_x96: MIN_SQRT_RATIO,
        }
    }

    /// Create exact-output swap parameters.
    ///
    /// Gets exactly `amount_out` of token1 for at most `max_in` of token0.
    #[must_use]
    pub fn exact_output(amount_out: u64, max_in: u64) -> Self {
        Self {
            zero_for_one: true,
            // Negative for exact output
            amount_specified: -(amount_out as i128),
            slippage_bound: max_in,
            sqrt_price_limit_x96: MIN_SQRT_RATIO,
        }
    }

    /// Set the swap direction.
    #[must_use]
    pub fn with_direction(mut self, zero_for_one: bool) -> Self {
        self.zero_for_one = zero_for_one;
        if !zero_for_one {
            self.sqrt_price_limit_x96 = MAX_SQRT_RATIO;
        }
        self
    }
}

// ═══════════════════════════════════════════════════════════════════
// Swap Encoding
// ═══════════════════════════════════════════════════════════════════

/// ABI-encode a `swap(PoolKey, SwapParams, bytes hookData)` call.
#[must_use]
pub fn encode_swap(pool: &PoolKey, params: &SwapParams) -> Vec<u8> {
    let func = Function::new(
        "swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)",
    );

    // Encode amount_specified as int256
    let amount_bytes = i128_to_int256(params.amount_specified);

    func.encode(&[
        AbiValue::Tuple(pool.encode()),
        AbiValue::Tuple(vec![
            AbiValue::Bool(params.zero_for_one),
            AbiValue::Int256(amount_bytes),
            AbiValue::Uint256(params.sqrt_price_limit_x96),
        ]),
        AbiValue::Bytes(vec![]), // empty hook data
    ])
}

/// Encode a multi-hop exact-input swap path.
///
/// Path format: `token0, fee, tickSpacing, hooks, token1, fee, tickSpacing, hooks, token2, ...`
#[must_use]
pub fn encode_multihop_path(hops: &[(PoolKey, bool)]) -> Vec<u8> {
    let mut path = Vec::new();
    for (i, (pool, zero_for_one)) in hops.iter().enumerate() {
        if i == 0 {
            let first_token = if *zero_for_one { pool.currency0 } else { pool.currency1 };
            path.extend_from_slice(&first_token);
        }
        path.extend_from_slice(&pool.fee.to_be_bytes()[1..]); // 3 bytes
        path.extend_from_slice(&(pool.tick_spacing as u32).to_be_bytes()[2..]); // 2 bytes
        path.extend_from_slice(&pool.hooks);
        let next_token = if *zero_for_one { pool.currency1 } else { pool.currency0 };
        path.extend_from_slice(&next_token);
    }
    path
}

/// ABI-encode `exactInputSingle` for the Universal Router.
#[must_use]
pub fn encode_exact_input_single(
    pool: &PoolKey,
    amount_in: u64,
    amount_out_min: u64,
    recipient: &[u8; 20],
    deadline: u64,
) -> Vec<u8> {
    let func = Function::new(
        "exactInputSingle((address,address,uint24,int24,address,uint256,uint256,uint256,address,bytes))",
    );

    func.encode(&[AbiValue::Tuple(vec![
        AbiValue::Address(pool.currency0),
        AbiValue::Address(pool.currency1),
        AbiValue::from_u64(pool.fee as u64),
        AbiValue::from_u64(pool.tick_spacing as u64),
        AbiValue::Address(pool.hooks),
        AbiValue::from_u64(amount_in),
        AbiValue::from_u64(amount_out_min),
        AbiValue::from_u64(deadline),
        AbiValue::Address(*recipient),
        AbiValue::Bytes(vec![]), // hook data
    ])])
}

/// ABI-encode `exactOutputSingle` for the Universal Router.
#[must_use]
pub fn encode_exact_output_single(
    pool: &PoolKey,
    amount_out: u64,
    amount_in_max: u64,
    recipient: &[u8; 20],
    deadline: u64,
) -> Vec<u8> {
    let func = Function::new(
        "exactOutputSingle((address,address,uint24,int24,address,uint256,uint256,uint256,address,bytes))",
    );

    func.encode(&[AbiValue::Tuple(vec![
        AbiValue::Address(pool.currency0),
        AbiValue::Address(pool.currency1),
        AbiValue::from_u64(pool.fee as u64),
        AbiValue::from_u64(pool.tick_spacing as u64),
        AbiValue::Address(pool.hooks),
        AbiValue::from_u64(amount_out),
        AbiValue::from_u64(amount_in_max),
        AbiValue::from_u64(deadline),
        AbiValue::Address(*recipient),
        AbiValue::Bytes(vec![]),
    ])])
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Convert i128 to 32-byte two's complement (int256).
fn i128_to_int256(val: i128) -> [u8; 32] {
    let mut buf = if val < 0 { [0xff; 32] } else { [0u8; 32] };
    buf[16..32].copy_from_slice(&val.to_be_bytes());
    buf
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TOKEN_A: [u8; 20] = [0x11; 20];
    const TOKEN_B: [u8; 20] = [0x22; 20];
    const RECIPIENT: [u8; 20] = [0xCC; 20];
    const HOOKS: [u8; 20] = [0xFF; 20];

    fn sample_pool() -> PoolKey {
        PoolKey::new(TOKEN_A, TOKEN_B, FEE_MEDIUM)
    }

    // ─── PoolKey ────────────────────────────────────────────────

    #[test]
    fn test_pool_key_sorts_currencies() {
        let pool = PoolKey::new(TOKEN_B, TOKEN_A, FEE_MEDIUM);
        assert!(pool.currency0 < pool.currency1);
        assert_eq!(pool.currency0, TOKEN_A);
        assert_eq!(pool.currency1, TOKEN_B);
    }

    #[test]
    fn test_pool_key_already_sorted() {
        let pool = PoolKey::new(TOKEN_A, TOKEN_B, FEE_MEDIUM);
        assert_eq!(pool.currency0, TOKEN_A);
    }

    #[test]
    fn test_pool_key_tick_spacing_medium() {
        let pool = PoolKey::new(TOKEN_A, TOKEN_B, FEE_MEDIUM);
        assert_eq!(pool.tick_spacing, TICK_SPACING_MEDIUM);
    }

    #[test]
    fn test_pool_key_tick_spacing_low() {
        let pool = PoolKey::new(TOKEN_A, TOKEN_B, FEE_LOW);
        assert_eq!(pool.tick_spacing, TICK_SPACING_LOW);
    }

    #[test]
    fn test_pool_key_tick_spacing_high() {
        let pool = PoolKey::new(TOKEN_A, TOKEN_B, FEE_HIGH);
        assert_eq!(pool.tick_spacing, TICK_SPACING_HIGH);
    }

    #[test]
    fn test_pool_key_with_hooks() {
        let pool = sample_pool().with_hooks(HOOKS);
        assert_eq!(pool.hooks, HOOKS);
    }

    #[test]
    fn test_pool_key_no_hooks_default() {
        let pool = sample_pool();
        assert_eq!(pool.hooks, [0u8; 20]);
    }

    #[test]
    fn test_pool_key_encode_length() {
        let pool = sample_pool();
        let encoded = pool.encode();
        assert_eq!(encoded.len(), 5); // 5 ABI values
    }

    // ─── SwapParams ─────────────────────────────────────────────

    #[test]
    fn test_exact_input_params() {
        let params = SwapParams::exact_input(1_000_000, 990_000);
        assert!(params.zero_for_one);
        assert_eq!(params.amount_specified, 1_000_000);
    }

    #[test]
    fn test_exact_output_params() {
        let params = SwapParams::exact_output(500_000, 510_000);
        assert!(params.zero_for_one);
        assert!(params.amount_specified < 0);
        assert_eq!(params.amount_specified, -500_000);
    }

    #[test]
    fn test_swap_direction_change() {
        let params = SwapParams::exact_input(100, 90).with_direction(false);
        assert!(!params.zero_for_one);
        assert_eq!(params.sqrt_price_limit_x96, MAX_SQRT_RATIO);
    }

    #[test]
    fn test_swap_default_direction_uses_min_ratio() {
        let params = SwapParams::exact_input(100, 90);
        assert_eq!(params.sqrt_price_limit_x96, MIN_SQRT_RATIO);
    }

    // ─── Swap Encoding ──────────────────────────────────────────

    #[test]
    fn test_encode_swap_not_empty() {
        let pool = sample_pool();
        let params = SwapParams::exact_input(1_000_000, 990_000);
        let data = encode_swap(&pool, &params);
        assert!(data.len() > 4);
    }

    #[test]
    fn test_encode_swap_deterministic() {
        let pool = sample_pool();
        let params = SwapParams::exact_input(100, 90);
        assert_eq!(encode_swap(&pool, &params), encode_swap(&pool, &params));
    }

    #[test]
    fn test_encode_swap_has_selector() {
        let pool = sample_pool();
        let params = SwapParams::exact_input(100, 90);
        let data = encode_swap(&pool, &params);
        // First 4 bytes are the function selector
        assert_eq!(data.len() % 32, 4, "should be 4 + N*32 bytes");
    }

    // ─── Multi-hop Path ─────────────────────────────────────────

    #[test]
    fn test_multihop_single_hop() {
        let pool = sample_pool();
        let path = encode_multihop_path(&[(pool, true)]);
        // 20 (token0) + 3 (fee) + 2 (tickSpacing) + 20 (hooks) + 20 (token1)
        assert_eq!(path.len(), 65);
    }

    #[test]
    fn test_multihop_two_hops() {
        let pool1 = PoolKey::new(TOKEN_A, TOKEN_B, FEE_MEDIUM);
        let pool2 = PoolKey::new(TOKEN_B, [0x33; 20], FEE_LOW);
        let path = encode_multihop_path(&[(pool1, true), (pool2, true)]);
        // 20 + (3+2+20+20) + (3+2+20+20) = 20 + 45 + 45 = 110
        assert_eq!(path.len(), 110);
    }

    #[test]
    fn test_multihop_starts_with_token() {
        let pool = sample_pool();
        let path = encode_multihop_path(&[(pool, true)]);
        assert_eq!(&path[..20], &TOKEN_A);
    }

    // ─── ExactInputSingle ───────────────────────────────────────

    #[test]
    fn test_exact_input_single_not_empty() {
        let pool = sample_pool();
        let data = encode_exact_input_single(&pool, 1000, 900, &RECIPIENT, 1_700_000_000);
        assert!(data.len() > 4);
    }

    #[test]
    fn test_exact_input_single_deterministic() {
        let pool = sample_pool();
        let d1 = encode_exact_input_single(&pool, 1000, 900, &RECIPIENT, 1_700_000_000);
        let d2 = encode_exact_input_single(&pool, 1000, 900, &RECIPIENT, 1_700_000_000);
        assert_eq!(d1, d2);
    }

    // ─── ExactOutputSingle ──────────────────────────────────────

    #[test]
    fn test_exact_output_single_not_empty() {
        let pool = sample_pool();
        let data = encode_exact_output_single(&pool, 500, 600, &RECIPIENT, 1_700_000_000);
        assert!(data.len() > 4);
    }

    // ─── int256 Helper ──────────────────────────────────────────

    #[test]
    fn test_i128_to_int256_positive() {
        let bytes = i128_to_int256(42);
        assert_eq!(bytes[31], 42);
        assert!(bytes[..16].iter().all(|b| *b == 0));
    }

    #[test]
    fn test_i128_to_int256_negative() {
        let bytes = i128_to_int256(-1);
        assert!(bytes.iter().all(|b| *b == 0xff));
    }

    #[test]
    fn test_i128_to_int256_zero() {
        let bytes = i128_to_int256(0);
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn test_i128_to_int256_large_negative() {
        let bytes = i128_to_int256(-500_000);
        // First 16 bytes should be 0xff (sign-extended)
        assert!(bytes[..16].iter().all(|b| *b == 0xff));
    }

    // ─── Fee Constants ──────────────────────────────────────────

    #[test]
    fn test_fee_tiers_ordered() {
        assert!(FEE_LOWEST < FEE_LOW);
        assert!(FEE_LOW < FEE_MEDIUM);
        assert!(FEE_MEDIUM < FEE_HIGH);
    }

    #[test]
    fn test_tick_spacings() {
        assert_eq!(TICK_SPACING_LOWEST, 1);
        assert_eq!(TICK_SPACING_LOW, 10);
        assert_eq!(TICK_SPACING_MEDIUM, 60);
        assert_eq!(TICK_SPACING_HIGH, 200);
    }
}
