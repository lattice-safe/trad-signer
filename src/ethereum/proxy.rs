//! **Proxy contract** interaction helpers for UUPS, Transparent, and Beacon proxies.
//!
//! Provides calldata encoding for proxy upgrades, admin management,
//! EIP-1967 storage slot constants, and Multicall3 batch encoding.
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::proxy;
//!
//! // UUPS upgrade
//! let calldata = proxy::encode_upgrade_to([0xBB; 20]);
//!
//! // Multicall3 batch
//! let calls = vec![
//!     proxy::Multicall3Call { target: [0xAA; 20], allow_failure: false, call_data: vec![0x01] },
//!     proxy::Multicall3Call { target: [0xBB; 20], allow_failure: true, call_data: vec![0x02] },
//! ];
//! let batch = proxy::encode_multicall(&calls);
//! ```

use crate::ethereum::abi::{self, AbiValue};
use sha3::{Digest, Keccak256};

// ─── EIP-1967 Storage Slots ────────────────────────────────────────

/// EIP-1967 implementation storage slot.
///
/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`
pub const IMPLEMENTATION_SLOT: [u8; 32] = {
    // keccak256("eip1967.proxy.implementation") - 1
    // = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
    let mut s = [0u8; 32];
    s[0] = 0x36; s[1] = 0x08; s[2] = 0x94; s[3] = 0xa1;
    s[4] = 0x3b; s[5] = 0xa1; s[6] = 0xa3; s[7] = 0x21;
    s[8] = 0x06; s[9] = 0x67; s[10] = 0xc8; s[11] = 0x28;
    s[12] = 0x49; s[13] = 0x2d; s[14] = 0xb9; s[15] = 0x8d;
    s[16] = 0xca; s[17] = 0x3e; s[18] = 0x20; s[19] = 0x76;
    s[20] = 0xcc; s[21] = 0x37; s[22] = 0x35; s[23] = 0xa9;
    s[24] = 0x20; s[25] = 0xa3; s[26] = 0xca; s[27] = 0x50;
    s[28] = 0x5d; s[29] = 0x38; s[30] = 0x2b; s[31] = 0xbc;
    s
};

/// EIP-1967 admin storage slot.
///
/// `bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)`
pub const ADMIN_SLOT: [u8; 32] = {
    // 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
    let mut s = [0u8; 32];
    s[0] = 0xb5; s[1] = 0x31; s[2] = 0x27; s[3] = 0x68;
    s[4] = 0x4a; s[5] = 0x56; s[6] = 0x8b; s[7] = 0x31;
    s[8] = 0x73; s[9] = 0xae; s[10] = 0x13; s[11] = 0xb9;
    s[12] = 0xf8; s[13] = 0xa6; s[14] = 0x01; s[15] = 0x6e;
    s[16] = 0x24; s[17] = 0x3e; s[18] = 0x63; s[19] = 0xb6;
    s[20] = 0xe8; s[21] = 0xee; s[22] = 0x11; s[23] = 0x78;
    s[24] = 0xd6; s[25] = 0xa7; s[26] = 0x17; s[27] = 0x85;
    s[28] = 0x0b; s[29] = 0x5d; s[30] = 0x61; s[31] = 0x03;
    s
};

/// EIP-1967 beacon storage slot.
///
/// `bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)`
pub const BEACON_SLOT: [u8; 32] = {
    // 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
    let mut s = [0u8; 32];
    s[0] = 0xa3; s[1] = 0xf0; s[2] = 0xad; s[3] = 0x74;
    s[4] = 0xe5; s[5] = 0x42; s[6] = 0x3a; s[7] = 0xeb;
    s[8] = 0xfd; s[9] = 0x80; s[10] = 0xd3; s[11] = 0xef;
    s[12] = 0x43; s[13] = 0x46; s[14] = 0x57; s[15] = 0x83;
    s[16] = 0x35; s[17] = 0xa9; s[18] = 0xa7; s[19] = 0x2a;
    s[20] = 0xea; s[21] = 0xee; s[22] = 0x59; s[23] = 0xff;
    s[24] = 0x6c; s[25] = 0xb3; s[26] = 0x58; s[27] = 0x2b;
    s[28] = 0x35; s[29] = 0x13; s[30] = 0x3d; s[31] = 0x50;
    s
};

// ─── EIP-1967 Slot Computation ─────────────────────────────────────

/// Compute an EIP-1967 storage slot from its label.
///
/// `bytes32(uint256(keccak256(label)) - 1)`
#[must_use]
pub fn eip1967_slot(label: &str) -> [u8; 32] {
    let hash = keccak256(label.as_bytes());
    // Subtract 1 from the 256-bit hash
    let mut slot = hash;
    let mut borrow = true;
    for byte in slot.iter_mut().rev() {
        if borrow {
            if *byte == 0 {
                *byte = 0xFF;
            } else {
                *byte -= 1;
                borrow = false;
            }
        }
    }
    slot
}

// ─── UUPS Proxy ────────────────────────────────────────────────────

/// ABI-encode `upgradeTo(address newImplementation)`.
///
/// Standard UUPS upgrade function (OpenZeppelin `UUPSUpgradeable`).
#[must_use]
pub fn encode_upgrade_to(new_implementation: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("upgradeTo(address)");
    func.encode(&[AbiValue::Address(new_implementation)])
}

/// ABI-encode `upgradeToAndCall(address newImplementation, bytes data)`.
///
/// UUPS upgrade with initialization call in the new implementation context.
#[must_use]
pub fn encode_upgrade_to_and_call(new_implementation: [u8; 20], data: &[u8]) -> Vec<u8> {
    let func = abi::Function::new("upgradeToAndCall(address,bytes)");
    func.encode(&[
        AbiValue::Address(new_implementation),
        AbiValue::Bytes(data.to_vec()),
    ])
}

/// ABI-encode `proxiableUUID()` for UUPS compliance check.
///
/// Returns the implementation slot — compliant contracts return `IMPLEMENTATION_SLOT`.
#[must_use]
pub fn encode_proxiable_uuid() -> Vec<u8> {
    let func = abi::Function::new("proxiableUUID()");
    func.encode(&[])
}

/// ABI-encode `implementation()` to query the current implementation address.
#[must_use]
pub fn encode_implementation() -> Vec<u8> {
    let func = abi::Function::new("implementation()");
    func.encode(&[])
}

// ─── Transparent Proxy ─────────────────────────────────────────────

/// ABI-encode `changeAdmin(address newAdmin)`.
#[must_use]
pub fn encode_change_admin(new_admin: [u8; 20]) -> Vec<u8> {
    let func = abi::Function::new("changeAdmin(address)");
    func.encode(&[AbiValue::Address(new_admin)])
}

/// ABI-encode `admin()` to query the proxy admin address.
#[must_use]
pub fn encode_admin() -> Vec<u8> {
    let func = abi::Function::new("admin()");
    func.encode(&[])
}

// ─── Beacon Proxy ──────────────────────────────────────────────────

/// ABI-encode `upgradeTo(address newBeacon)` for beacon upgrades.
///
/// Note: Same function signature as UUPS, but called on the beacon contract.
#[must_use]
pub fn encode_upgrade_beacon(new_beacon: [u8; 20]) -> Vec<u8> {
    encode_upgrade_to(new_beacon)
}

// ─── Initializable ─────────────────────────────────────────────────

/// ABI-encode `initialize(...)` with arbitrary arguments.
///
/// Generic initializer encoder for proxy-behind initialization.
#[must_use]
pub fn encode_initialize(args: &[AbiValue]) -> Vec<u8> {
    // The Initialize function signature varies per contract, but
    // for simple cases, the user provides the full signature
    let func = abi::Function::new("initialize()");
    func.encode(args)
}

/// ABI-encode a custom initializer with a specific function signature.
#[must_use]
pub fn encode_initializer(signature: &str, args: &[AbiValue]) -> Vec<u8> {
    let func = abi::Function::new(signature);
    func.encode(args)
}

// ─── Multicall3 ────────────────────────────────────────────────────

/// A single call in a Multicall3 batch.
#[derive(Debug, Clone)]
pub struct Multicall3Call {
    /// Target contract address.
    pub target: [u8; 20],
    /// Whether this call is allowed to fail without reverting the batch.
    pub allow_failure: bool,
    /// Encoded calldata for this call.
    pub call_data: Vec<u8>,
}

/// ABI-encode `aggregate3(Call3[])` for Multicall3.
///
/// Multicall3 is deployed at `0xcA11bde05977b3631167028862bE2a173976CA11`
/// on 70+ chains.
#[must_use]
pub fn encode_multicall(calls: &[Multicall3Call]) -> Vec<u8> {
    let func = abi::Function::new("aggregate3((address,bool,bytes)[])");
    let call_tuples: Vec<AbiValue> = calls
        .iter()
        .map(|c| {
            AbiValue::Tuple(vec![
                AbiValue::Address(c.target),
                AbiValue::Bool(c.allow_failure),
                AbiValue::Bytes(c.call_data.clone()),
            ])
        })
        .collect();
    func.encode(&[AbiValue::Array(call_tuples)])
}

/// Multicall3 canonical deployment address (same on 70+ chains).
pub const MULTICALL3_ADDRESS: [u8; 20] = [
    0xca, 0x11, 0xbd, 0xe0, 0x59, 0x77, 0xb3, 0x63, 0x11, 0x67,
    0x02, 0x88, 0x62, 0xbe, 0x2a, 0x17, 0x39, 0x76, 0xca, 0x11,
];

/// ABI-encode `aggregate(Call[])` for Multicall2 (legacy).
#[must_use]
pub fn encode_multicall_legacy(calls: &[([u8; 20], Vec<u8>)]) -> Vec<u8> {
    let func = abi::Function::new("aggregate((address,bytes)[])");
    let call_tuples: Vec<AbiValue> = calls
        .iter()
        .map(|(target, data)| {
            AbiValue::Tuple(vec![
                AbiValue::Address(*target),
                AbiValue::Bytes(data.clone()),
            ])
        })
        .collect();
    func.encode(&[AbiValue::Array(call_tuples)])
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── EIP-1967 Slot Constants ──────────────────────────────

    #[test]
    fn test_implementation_slot_matches_eip1967() {
        let computed = eip1967_slot("eip1967.proxy.implementation");
        assert_eq!(computed, IMPLEMENTATION_SLOT);
    }

    #[test]
    fn test_admin_slot_matches_eip1967() {
        let computed = eip1967_slot("eip1967.proxy.admin");
        assert_eq!(computed, ADMIN_SLOT);
    }

    #[test]
    fn test_beacon_slot_matches_eip1967() {
        let computed = eip1967_slot("eip1967.proxy.beacon");
        assert_eq!(computed, BEACON_SLOT);
    }

    #[test]
    fn test_implementation_slot_hex() {
        assert_eq!(
            hex::encode(IMPLEMENTATION_SLOT),
            "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        );
    }

    #[test]
    fn test_admin_slot_hex() {
        assert_eq!(
            hex::encode(ADMIN_SLOT),
            "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
        );
    }

    #[test]
    fn test_beacon_slot_hex() {
        assert_eq!(
            hex::encode(BEACON_SLOT),
            "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
        );
    }

    // ─── Slot Computation ─────────────────────────────────────

    #[test]
    fn test_eip1967_slot_deterministic() {
        let s1 = eip1967_slot("eip1967.proxy.implementation");
        let s2 = eip1967_slot("eip1967.proxy.implementation");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_eip1967_slot_different_labels() {
        let s1 = eip1967_slot("eip1967.proxy.implementation");
        let s2 = eip1967_slot("eip1967.proxy.admin");
        assert_ne!(s1, s2);
    }

    // ─── UUPS Encoding ───────────────────────────────────────

    #[test]
    fn test_encode_upgrade_to_selector() {
        let calldata = encode_upgrade_to([0xBB; 20]);
        let expected = abi::function_selector("upgradeTo(address)");
        assert_eq!(&calldata[..4], &expected);
        assert_eq!(calldata.len(), 4 + 32);
    }

    #[test]
    fn test_encode_upgrade_to_contains_address() {
        let addr = [0xBB; 20];
        let calldata = encode_upgrade_to(addr);
        // Address should be at bytes 4+12..4+32 (left-padded)
        assert_eq!(&calldata[4 + 12..4 + 32], &addr);
    }

    #[test]
    fn test_encode_upgrade_to_and_call_selector() {
        let calldata = encode_upgrade_to_and_call([0xBB; 20], &[0xDE, 0xAD]);
        let expected = abi::function_selector("upgradeToAndCall(address,bytes)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_upgrade_to_and_call_with_empty_data() {
        let calldata = encode_upgrade_to_and_call([0xBB; 20], &[]);
        let expected = abi::function_selector("upgradeToAndCall(address,bytes)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_proxiable_uuid_selector() {
        let calldata = encode_proxiable_uuid();
        let expected = abi::function_selector("proxiableUUID()");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_implementation_selector() {
        let calldata = encode_implementation();
        let expected = abi::function_selector("implementation()");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Transparent Proxy ────────────────────────────────────

    #[test]
    fn test_encode_change_admin_selector() {
        let calldata = encode_change_admin([0xCC; 20]);
        let expected = abi::function_selector("changeAdmin(address)");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_admin_selector() {
        let calldata = encode_admin();
        let expected = abi::function_selector("admin()");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Beacon Proxy ─────────────────────────────────────────

    #[test]
    fn test_encode_upgrade_beacon_selector() {
        let calldata = encode_upgrade_beacon([0xDD; 20]);
        let expected = abi::function_selector("upgradeTo(address)");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Initializable ────────────────────────────────────────

    #[test]
    fn test_encode_initialize_selector() {
        let calldata = encode_initialize(&[]);
        let expected = abi::function_selector("initialize()");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_initializer_custom() {
        let calldata = encode_initializer(
            "initialize(address,uint256)",
            &[AbiValue::Address([0xAA; 20]), AbiValue::from_u64(42)],
        );
        let expected = abi::function_selector("initialize(address,uint256)");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Multicall3 ───────────────────────────────────────────

    #[test]
    fn test_encode_multicall_selector() {
        let calls = vec![Multicall3Call {
            target: [0xAA; 20],
            allow_failure: false,
            call_data: vec![0x01],
        }];
        let calldata = encode_multicall(&calls);
        let expected = abi::function_selector("aggregate3((address,bool,bytes)[])");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_multicall_empty() {
        let calldata = encode_multicall(&[]);
        let expected = abi::function_selector("aggregate3((address,bool,bytes)[])");
        assert_eq!(&calldata[..4], &expected);
    }

    #[test]
    fn test_encode_multicall_multiple_calls() {
        let calls = vec![
            Multicall3Call {
                target: [0xAA; 20],
                allow_failure: false,
                call_data: vec![0x01, 0x02],
            },
            Multicall3Call {
                target: [0xBB; 20],
                allow_failure: true,
                call_data: vec![0x03],
            },
        ];
        let calldata = encode_multicall(&calls);
        assert!(calldata.len() > 4); // At minimum has selector
    }

    #[test]
    fn test_encode_multicall_deterministic() {
        let calls = vec![Multicall3Call {
            target: [0xAA; 20],
            allow_failure: false,
            call_data: vec![0x01],
        }];
        let c1 = encode_multicall(&calls);
        let c2 = encode_multicall(&calls);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_encode_multicall_legacy_selector() {
        let calls = vec![([0xAA; 20], vec![0x01u8])];
        let calldata = encode_multicall_legacy(&calls);
        let expected = abi::function_selector("aggregate((address,bytes)[])");
        assert_eq!(&calldata[..4], &expected);
    }

    // ─── Multicall3 Address ───────────────────────────────────

    #[test]
    fn test_multicall3_address() {
        assert_eq!(
            hex::encode(MULTICALL3_ADDRESS).to_lowercase(),
            "ca11bde05977b3631167028862be2a173976ca11"
        );
    }
}
