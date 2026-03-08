//! Property-based tests for core cryptographic operations.
//!
//! Uses `proptest` to verify invariants across random inputs.

use proptest::prelude::*;

#[cfg(feature = "ethereum")]
mod ethereum_props {
    use super::*;
    use chains_sdk::ethereum::EthereumSigner;
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    proptest! {
        #[test]
        fn sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
            let signer = EthereumSigner::generate().unwrap();
            let sig = signer.sign(&msg).unwrap();
            let verifier = chains_sdk::ethereum::EthereumVerifier::from_public_key_bytes(
                &Signer::public_key_bytes(&signer),
            ).unwrap();
            prop_assert!(verifier.verify(&msg, &sig).unwrap());
        }

        #[test]
        fn keygen_roundtrip(seed in prop::collection::vec(any::<u8>(), 32..33)) {
            let signer = EthereumSigner::from_bytes(&seed).unwrap();
            let pk1 = Signer::public_key_bytes(&signer);
            let restored = EthereumSigner::from_bytes(&*signer.private_key_bytes()).unwrap();
            let pk2 = Signer::public_key_bytes(&restored);
            prop_assert_eq!(pk1, pk2);
        }

        #[test]
        fn different_messages_different_sigs(
            msg1 in prop::collection::vec(any::<u8>(), 1..64),
            msg2 in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(msg1 != msg2);
            let signer = EthereumSigner::generate().unwrap();
            let sig1 = signer.sign(&msg1).unwrap();
            let sig2 = signer.sign(&msg2).unwrap();
            prop_assert_ne!(sig1.r, sig2.r);
        }

        #[test]
        fn address_always_20_bytes(_seed in prop::collection::vec(any::<u8>(), 32..33)) {
            let signer = EthereumSigner::generate().unwrap();
            prop_assert_eq!(signer.address().len(), 20);
        }
    }
}

#[cfg(feature = "bitcoin")]
mod bitcoin_props {
    use super::*;
    use chains_sdk::bitcoin::BitcoinSigner;
    use chains_sdk::traits::{KeyPair, Signer};

    proptest! {
        #[test]
        fn wif_roundtrip(seed in prop::collection::vec(any::<u8>(), 32..33)) {
            let signer = BitcoinSigner::from_bytes(&seed).unwrap();
            let wif = signer.to_wif();
            let restored = BitcoinSigner::from_wif(&wif).unwrap();
            prop_assert_eq!(
                Signer::public_key_bytes(&signer),
                Signer::public_key_bytes(&restored)
            );
        }

        #[test]
        fn sign_produces_valid_der(msg in prop::collection::vec(any::<u8>(), 1..512)) {
            let signer = BitcoinSigner::generate().unwrap();
            let sig = signer.sign(&msg).unwrap();
            // DER-encoded ECDSA sig starts with 0x30 (SEQUENCE tag)
            prop_assert_eq!(sig.der_bytes()[0], 0x30);
        }
    }
}

#[cfg(feature = "bls")]
mod bls_props {
    use super::*;
    use chains_sdk::bls::BlsSigner;
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    proptest! {
        #[test]
        fn bls_sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 1..256)) {
            let signer = BlsSigner::generate().unwrap();
            let sig = signer.sign(&msg).unwrap();
            let verifier = chains_sdk::bls::BlsVerifier::from_public_key_bytes(
                &Signer::public_key_bytes(&signer),
            ).unwrap();
            prop_assert!(verifier.verify(&msg, &sig).unwrap());
        }

        #[test]
        fn bls_keygen_deterministic(seed in prop::collection::vec(any::<u8>(), 32..33)) {
            // Not all 32-byte values are valid BLS12-381 scalars
            if let (Ok(s1), Ok(s2)) = (BlsSigner::from_bytes(&seed), BlsSigner::from_bytes(&seed)) {
                prop_assert_eq!(
                    Signer::public_key_bytes(&s1),
                    Signer::public_key_bytes(&s2)
                );
            }
        }
    }
}

#[cfg(feature = "solana")]
mod solana_props {
    use super::*;
    use chains_sdk::solana::SolanaSigner;
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    proptest! {
        #[test]
        fn solana_sign_verify_roundtrip(msg in prop::collection::vec(any::<u8>(), 1..256)) {
            let signer = SolanaSigner::generate().unwrap();
            let sig = signer.sign(&msg).unwrap();
            let verifier = chains_sdk::solana::SolanaVerifier::from_public_key_bytes(
                &Signer::public_key_bytes(&signer),
            ).unwrap();
            prop_assert!(verifier.verify(&msg, &sig).unwrap());
        }
    }
}
