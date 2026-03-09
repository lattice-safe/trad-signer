#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::ethereum::abi;

fuzz_target!(|data: &[u8]| {
    // Fuzz uint256 decoding — must not panic
    let _ = abi::decode_uint256(data);
    let _ = abi::decode_uint256_as_u64(data);
    let _ = abi::decode_address(data);
    let _ = abi::decode_bool(data);

    if data.len() >= 64 {
        let _ = abi::decode_bytes(data, 0);
        let _ = abi::decode_string(data, 0);
    }
});
