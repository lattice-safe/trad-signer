#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::solana::{SolanaSigner, SolanaVerifier};
use chains_sdk::traits::{KeyPair, Signer, Verifier};

fuzz_target!(|data: &[u8]| {
    // Fuzz signing: any message should sign without panic
    let signer = SolanaSigner::generate().unwrap();
    if let Ok(sig) = signer.sign(data) {
        let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let _ = verifier.verify(data, &sig);
    }

    // Fuzz key loading: should not panic (accepts any 32 bytes)
    let _ = SolanaSigner::from_bytes(data);

    // Fuzz verifier construction
    let _ = SolanaVerifier::from_public_key_bytes(data);
});
