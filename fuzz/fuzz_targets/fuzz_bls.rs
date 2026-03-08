#![no_main]
use libfuzzer_sys::fuzz_target;
use chains_sdk::bls::{BlsSigner, BlsVerifier, BlsSignature, aggregate_signatures};
use chains_sdk::traits::{KeyPair, Signer, Verifier};

fuzz_target!(|data: &[u8]| {
    // Fuzz signing
    let signer = BlsSigner::generate().unwrap();
    if let Ok(sig) = signer.sign(data) {
        let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let _ = verifier.verify(data, &sig);
    }

    // Fuzz key loading: should not panic
    let _ = BlsSigner::from_bytes(data);

    // Fuzz verifier construction
    let _ = BlsVerifier::from_public_key_bytes(data);

    // Fuzz signature parsing via aggregation with invalid bytes
    if data.len() >= 96 {
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&data[..96]);
        let _ = aggregate_signatures(&[BlsSignature { bytes }]);
    }
});
