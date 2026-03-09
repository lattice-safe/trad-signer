#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::ethereum::permit2::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < 60 { return; }

    // Construct a PermitSingle from fuzzed bytes
    let mut token = [0u8; 20];
    token.copy_from_slice(&data[0..20]);
    let mut spender = [0u8; 20];
    spender.copy_from_slice(&data[20..40]);

    let amount = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0; 8]));
    let exp = u64::from_le_bytes(data[48..56].try_into().unwrap_or([0; 8]));
    let nonce = u64::from_le_bytes(data[52..60].try_into().unwrap_or([0; 8]));

    let permit = PermitSingle {
        token, amount, expiration: exp, nonce, spender,
        sig_deadline: exp,
    };

    // Must not panic
    let _ = permit.struct_hash();
    let ds = permit2_domain_separator(1);
    let _ = permit.signing_hash(&ds);
});
