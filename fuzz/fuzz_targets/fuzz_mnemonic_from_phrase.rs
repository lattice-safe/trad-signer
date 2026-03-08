#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::mnemonic::Mnemonic;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // from_phrase must never panic on arbitrary word strings
        let _ = Mnemonic::from_phrase(s);
    }
});
