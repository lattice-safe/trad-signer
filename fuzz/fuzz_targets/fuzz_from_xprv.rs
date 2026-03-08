#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::hd_key::ExtendedPrivateKey;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // from_xprv must never panic on arbitrary base58-ish input
        let _ = ExtendedPrivateKey::from_xprv(s);
    }
});
