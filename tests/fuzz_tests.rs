//! Fuzz-style tests for security-critical parsing paths.
//!
//! Feeds random/malformed inputs to parsers that accept untrusted data,
//! ensuring they return errors rather than panicking.

/// Feed deterministic pseudo-random bytes to a function, ensuring it never panics.
fn fuzz_no_panic<F>(name: &str, iterations: usize, max_len: usize, f: F)
where
    F: Fn(&[u8]),
{
    let mut buf = vec![0u8; max_len];
    for i in 0..iterations {
        let len = (i * 7 + 3) % max_len.max(1);
        for (j, b) in buf[..len].iter_mut().enumerate() {
            *b = ((i.wrapping_mul(257).wrapping_add(j.wrapping_mul(31))) & 0xFF) as u8;
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f(&buf[..len]);
        }))
        .unwrap_or_else(|_| panic!("{name}: panicked on input length {len}, iteration {i}"));
    }
}

#[cfg(feature = "ethereum")]
mod ethereum_fuzz {
    use super::*;

    #[test]
    fn fuzz_eth_signature_from_bytes() {
        fuzz_no_panic("ETH sig from_bytes", 1000, 128, |data| {
            let _ = chains_sdk::ethereum::EthereumSignature::from_bytes(data);
        });
    }

    #[test]
    fn fuzz_eth_keystore_decrypt_no_panic() {
        use chains_sdk::ethereum::keystore::{Keystore, ScryptParams};

        let pk = [0x42u8; 32];
        let ks = Keystore::encrypt(&pk, b"correct", &ScryptParams::light()).unwrap();

        fuzz_no_panic("keystore decrypt", 50, 64, |data| {
            let _ = ks.decrypt(data);
        });
    }

    #[test]
    fn fuzz_eth_validate_address() {
        fuzz_no_panic("ETH validate_address", 1000, 64, |data| {
            let s = String::from_utf8_lossy(data);
            let _ = chains_sdk::ethereum::validate_address(&s);
        });
    }

    #[test]
    fn fuzz_eth_from_bytes() {
        use chains_sdk::ethereum::EthereumSigner;
        use chains_sdk::traits::KeyPair;

        fuzz_no_panic("ETH from_bytes", 500, 64, |data| {
            let _ = EthereumSigner::from_bytes(data);
        });
    }
}

#[cfg(feature = "bitcoin")]
mod bitcoin_fuzz {
    use super::*;

    #[test]
    fn fuzz_psbt_deserialize_no_panic() {
        fuzz_no_panic("PSBT deserialize", 500, 1024, |data| {
            let _ = chains_sdk::bitcoin::psbt::v0::Psbt::deserialize(data);
        });
    }

    #[test]
    fn fuzz_wif_import_no_panic() {
        fuzz_no_panic("WIF import", 500, 64, |data| {
            let s = String::from_utf8_lossy(data);
            let _ = chains_sdk::bitcoin::BitcoinSigner::from_wif(&s);
        });
    }

    #[test]
    fn fuzz_btc_from_bytes() {
        use chains_sdk::bitcoin::BitcoinSigner;
        use chains_sdk::traits::KeyPair;

        fuzz_no_panic("BTC from_bytes", 500, 64, |data| {
            let _ = BitcoinSigner::from_bytes(data);
        });
    }

    #[test]
    fn fuzz_schnorr_from_bytes() {
        use chains_sdk::bitcoin::schnorr::SchnorrSigner;
        use chains_sdk::traits::KeyPair;

        fuzz_no_panic("Schnorr from_bytes", 500, 64, |data| {
            let _ = SchnorrSigner::from_bytes(data);
        });
    }

    #[test]
    fn fuzz_btc_validate_address() {
        fuzz_no_panic("BTC validate_address", 1000, 128, |data| {
            let s = String::from_utf8_lossy(data);
            let _ = chains_sdk::bitcoin::validate_address(&s);
        });
    }
}

#[cfg(feature = "bls")]
mod bls_fuzz {
    use super::*;

    #[test]
    fn fuzz_bls_keystore_decrypt_no_panic() {
        use chains_sdk::bls::keystore::{BlsKeystore, BlsScryptParams};
        use chains_sdk::bls::BlsSigner;
        use chains_sdk::traits::{KeyPair, Signer};

        let signer = BlsSigner::generate().unwrap();
        let pk_bytes = Signer::public_key_bytes(&signer);
        let sk_bytes = signer.private_key_bytes();
        let ks = BlsKeystore::encrypt(
            &sk_bytes,
            &pk_bytes,
            b"correct",
            "m/12381/3600/0/0/0",
            &BlsScryptParams::light(),
        )
        .unwrap();

        fuzz_no_panic("BLS keystore decrypt", 50, 64, |data| {
            let _ = ks.decrypt(data);
        });
    }
}

#[cfg(feature = "hd_key")]
mod hd_key_fuzz {
    use super::*;

    #[test]
    fn fuzz_xprv_deserialize_no_panic() {
        fuzz_no_panic("xprv deserialize", 500, 128, |data| {
            let s = String::from_utf8_lossy(data);
            let _ = chains_sdk::hd_key::ExtendedPrivateKey::from_xprv(&s);
        });
    }

    #[test]
    fn fuzz_from_seed_no_panic() {
        fuzz_no_panic("from_seed", 500, 128, |data| {
            let _ = chains_sdk::hd_key::ExtendedPrivateKey::from_seed(data);
        });
    }
}

#[cfg(feature = "neo")]
mod neo_fuzz {
    use super::*;

    #[test]
    fn fuzz_neo_from_bytes() {
        use chains_sdk::neo::NeoSigner;
        use chains_sdk::traits::KeyPair;

        fuzz_no_panic("NEO from_bytes", 500, 64, |data| {
            let _ = NeoSigner::from_bytes(data);
        });
    }
}

/// Security module fuzz tests
mod security_fuzz {
    use super::*;

    #[test]
    fn fuzz_ct_hex_decode() {
        fuzz_no_panic("ct_hex_decode", 1000, 128, |data| {
            let s = String::from_utf8_lossy(data);
            let _ = chains_sdk::security::ct_hex_decode(&s);
        });
    }

    #[test]
    fn fuzz_ct_hex_roundtrip() {
        fuzz_no_panic("ct_hex_roundtrip", 500, 64, |data| {
            let encoded = chains_sdk::security::ct_hex_encode(data);
            let decoded = chains_sdk::security::ct_hex_decode(&encoded);
            assert_eq!(decoded.as_deref(), Some(data));
        });
    }
}
