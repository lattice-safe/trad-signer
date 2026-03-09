#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz mnemonic parsing from arbitrary strings — must not panic
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = chains_sdk::mnemonic::Mnemonic::from_phrase(s);
    }
});
