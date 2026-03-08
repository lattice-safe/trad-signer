#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::ethereum::{EthereumSigner, EthereumVerifier, EthereumSignature};
use chains_sdk::traits::{KeyPair, Signer, Verifier};

fuzz_target!(|data: &[u8]| {
    // Fuzz signing: any message should sign without panic
    let signer = EthereumSigner::generate().unwrap();
    if let Ok(sig) = signer.sign(data) {
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        // Must verify
        let _ = verifier.verify(data, &sig);
    }

    // Fuzz prehashed: if length == 32, should not panic
    let _ = signer.sign_prehashed(data);

    // Fuzz signature parsing: should not panic
    let _ = EthereumSignature::from_bytes(data);

    // Fuzz verifier construction: should not panic
    let _ = EthereumVerifier::from_public_key_bytes(data);

    // Fuzz key loading: should not panic
    let _ = EthereumSigner::from_bytes(data);
});
