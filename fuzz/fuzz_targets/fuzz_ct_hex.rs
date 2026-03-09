#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::security;

fuzz_target!(|data: &[u8]| {
    // Roundtrip: encode -> decode must recover original bytes
    let hex = security::ct_hex_encode(data);
    if let Some(decoded) = security::ct_hex_decode(&hex) {
        assert_eq!(data, decoded.as_slice(), "roundtrip failed");
    }

    // Fuzz decode of arbitrary strings — must not panic
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = security::ct_hex_decode(s);
    }
});
