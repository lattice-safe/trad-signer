#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::bitcoin::{BitcoinSigner, BitcoinVerifier};
use chains_sdk::traits::{KeyPair, Signer, Verifier};

fuzz_target!(|data: &[u8]| {
    // Fuzz signing: any message should sign without panic
    let signer = BitcoinSigner::generate().unwrap();
    if let Ok(sig) = signer.sign(data) {
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let _ = verifier.verify(data, &sig);
    }

    // Fuzz prehashed
    let _ = signer.sign_prehashed(data);

    // Fuzz key loading: should not panic
    let _ = BitcoinSigner::from_bytes(data);

    // Fuzz verifier construction
    let _ = BitcoinVerifier::from_public_key_bytes(data);
});
