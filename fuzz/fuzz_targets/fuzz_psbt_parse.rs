#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz PSBTv2 deserialization — must not panic
    let _ = chains_sdk::bitcoin::psbt::v2::Psbt::deserialize(data);
});
