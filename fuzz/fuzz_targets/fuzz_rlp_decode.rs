#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::ethereum::rlp;

fuzz_target!(|data: &[u8]| {
    // Fuzz RLP decoding — must not panic
    let _ = rlp::decode(data);
    let _ = rlp::decode_list(data);
});
