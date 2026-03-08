#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::bitcoin::psbt::Psbt;

fuzz_target!(|data: &[u8]| {
    // PSBT deserializer must never panic on arbitrary bytes
    let _ = Psbt::deserialize(data);
});
