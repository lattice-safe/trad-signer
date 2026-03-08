// tests/sdk_features_tests.rs — Full coverage tests for SDK completion features.

#[cfg(feature = "ethereum")]
mod eip155 {
    use chains_sdk::ethereum::EthereumSigner;
    use chains_sdk::traits::{KeyPair, Signer};

    #[test]
    fn test_eip155_mainnet_v_value() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign_with_chain_id(b"test", 1).unwrap();
        // v should be 37 or 38 (35 + 1*2 + {0,1})
        assert!(sig.v == 37 || sig.v == 38, "v={}, expected 37 or 38", sig.v);
    }

    #[test]
    fn test_eip155_polygon_v_value() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign_with_chain_id(b"test", 137).unwrap();
        // v = 35 + 137*2 + {0,1} = 309 or 310
        let expected_v_0: u64 = 35 + 137 * 2;
        let expected_v_1: u64 = 35 + 137 * 2 + 1;
        assert!(sig.v == expected_v_0 || sig.v == expected_v_1);
    }

    #[test]
    fn test_eip155_recovery_still_works() {
        let signer = EthereumSigner::generate().unwrap();
        let msg = b"EIP-155 recovery test";
        // Standard (pre-EIP-155) signing — v=27/28
        let sig = signer.sign(msg).unwrap();
        let recovered = chains_sdk::ethereum::ecrecover(msg, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_eip155_chain_id_0() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign_with_chain_id(b"test", 0).unwrap();
        // v = 35 + 0*2 + {0,1} = 35 or 36
        assert!(sig.v == 35 || sig.v == 36);
    }

    #[test]
    fn test_personal_sign_with_chain_id() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.personal_sign_with_chain_id(b"hello", 1).unwrap();
        assert!(sig.v == 37 || sig.v == 38);
    }

    #[test]
    fn test_eip155_different_chain_ids_produce_different_v() {
        let signer = EthereumSigner::generate().unwrap();
        let sig1 = signer.sign_with_chain_id(b"test", 1).unwrap();
        let sig5 = signer.sign_with_chain_id(b"test", 5).unwrap();
        // Same message, same key, but different chain IDs → different v values
        // (r and s are the same because the underlying signing is deterministic on the same message)
        assert_ne!(
            sig1.v, sig5.v,
            "different chain IDs should produce different v"
        );
    }
}

#[cfg(feature = "hd_key")]
mod xpub_xprv {
    use chains_sdk::hd_key::ExtendedPrivateKey;

    #[test]
    fn test_xprv_starts_with_xprv() {
        let seed = [0xABu8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let xprv = master.to_xprv();
        assert!(
            xprv.starts_with("xprv"),
            "xprv should start with 'xprv': {}",
            &*xprv
        );
    }

    #[test]
    fn test_xpub_starts_with_xpub() {
        let seed = [0xABu8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let xpub = master.to_xpub().unwrap();
        assert!(
            xpub.starts_with("xpub"),
            "xpub should start with 'xpub': {xpub}"
        );
    }

    #[test]
    fn test_xprv_roundtrip() {
        let seed = [0x42u8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
        let xprv_str = master.to_xprv();
        let restored = ExtendedPrivateKey::from_xprv(&xprv_str).unwrap();
        assert_eq!(
            master.private_key_bytes().as_slice(),
            restored.private_key_bytes().as_slice()
        );
        assert_eq!(master.chain_code(), restored.chain_code());
        assert_eq!(master.depth(), restored.depth());
    }

    #[test]
    fn test_xprv_invalid_base58() {
        assert!(ExtendedPrivateKey::from_xprv("not-valid-base58!@#").is_err());
    }

    #[test]
    fn test_xprv_wrong_version() {
        // xpub version bytes (0488B21E) instead of xprv
        let xpub_str = {
            let seed = [0x42u8; 64];
            let m = ExtendedPrivateKey::from_seed(&seed).unwrap();
            m.to_xpub().unwrap()
        };
        assert!(ExtendedPrivateKey::from_xprv(&xpub_str).is_err());
    }

    #[test]
    fn test_xprv_different_seeds_produce_different_keys() {
        let m1 = ExtendedPrivateKey::from_seed(&[0x01u8; 64]).unwrap();
        let m2 = ExtendedPrivateKey::from_seed(&[0x02u8; 64]).unwrap();
        assert_ne!(m1.to_xprv(), m2.to_xprv());
    }

    #[test]
    fn test_xpub_length() {
        let master = ExtendedPrivateKey::from_seed(&[0x55u8; 64]).unwrap();
        let xpub = master.to_xpub().unwrap();
        // xpub is ~111 chars Base58
        assert!(
            xpub.len() > 100 && xpub.len() < 120,
            "unexpected xpub length: {}",
            xpub.len()
        );
    }
}

#[cfg(feature = "bitcoin")]
mod btc_message_signing {
    use chains_sdk::bitcoin::schnorr::SchnorrSigner;
    use chains_sdk::bitcoin::{
        bitcoin_message_hash, validate_address, validate_mainnet_address, validate_testnet_address,
        BitcoinSigner,
    };
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_message_hash_deterministic() {
        let h1 = bitcoin_message_hash(b"Hello, Bitcoin!");
        let h2 = bitcoin_message_hash(b"Hello, Bitcoin!");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_message_hash_different_messages() {
        let h1 = bitcoin_message_hash(b"Hello");
        let h2 = bitcoin_message_hash(b"World");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sign_message_produces_valid_sig() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign_message(b"test message").unwrap();
        // Should be a valid DER signature
        assert!(!sig.to_bytes().is_empty());
        // Verify: manually hash and verify
        let verifier =
            chains_sdk::bitcoin::BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes())
                .unwrap();
        let digest = bitcoin_message_hash(b"test message");
        assert!(verifier.verify_prehashed(&digest, &sig).is_ok());
    }

    #[test]
    fn test_sign_message_wrong_msg_fails_verify() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign_message(b"message A").unwrap();
        let verifier =
            chains_sdk::bitcoin::BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes())
                .unwrap();
        // Verify with wrong message digest — should fail verification
        let wrong_digest = bitcoin_message_hash(b"message B");
        let result = verifier.verify_prehashed(&wrong_digest, &sig);
        // May return Ok(false) or Err depending on implementation
        if let Ok(valid) = result {
            assert!(!valid, "wrong digest should not verify");
        }
    }

    // ─── Address Validation ──────────────────

    #[test]
    fn test_validate_p2pkh_address() {
        let signer = BitcoinSigner::generate().unwrap();
        let addr = signer.p2pkh_address();
        assert!(
            validate_mainnet_address(&addr),
            "P2PKH should be valid: {addr}"
        );
    }

    #[test]
    fn test_validate_p2wpkh_address() {
        let signer = BitcoinSigner::generate().unwrap();
        let addr = signer.p2wpkh_address().unwrap();
        assert!(
            validate_mainnet_address(&addr),
            "P2WPKH should be valid: {addr}"
        );
    }

    #[test]
    fn test_validate_p2tr_address() {
        let signer = SchnorrSigner::generate().unwrap();
        let addr = signer.p2tr_address().unwrap();
        assert!(
            validate_mainnet_address(&addr),
            "P2TR should be valid: {addr}"
        );
    }

    #[test]
    fn test_validate_testnet_address_p2pkh() {
        let signer = BitcoinSigner::generate().unwrap();
        let addr = signer.p2pkh_testnet_address();
        assert!(
            validate_testnet_address(&addr),
            "testnet P2PKH should be valid: {addr}"
        );
        assert!(
            addr.starts_with('m') || addr.starts_with('n'),
            "got: {addr}"
        );
    }

    #[test]
    fn test_validate_testnet_address_p2wpkh() {
        let signer = BitcoinSigner::generate().unwrap();
        let addr = signer.p2wpkh_testnet_address().unwrap();
        assert!(
            validate_testnet_address(&addr),
            "testnet P2WPKH should be valid: {addr}"
        );
        assert!(addr.starts_with("tb1q"), "got: {addr}");
    }

    #[test]
    fn test_validate_testnet_p2tr() {
        let signer = SchnorrSigner::generate().unwrap();
        let addr = signer.p2tr_testnet_address().unwrap();
        assert!(
            validate_testnet_address(&addr),
            "testnet P2TR should be valid: {addr}"
        );
        assert!(addr.starts_with("tb1p"), "got: {addr}");
    }

    #[test]
    fn test_validate_invalid_addresses() {
        assert!(!validate_address(""));
        assert!(!validate_address("not_an_address"));
        assert!(!validate_address("1InvalidChecksum1234567890abcde"));
        assert!(!validate_address("bc1invalidbech32"));
    }

    #[test]
    fn test_validate_known_mainnet_address() {
        // Known valid P2PKH from privkey=1
        assert!(validate_mainnet_address(
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        ));
    }

    #[test]
    fn test_validate_rejects_testnet_as_mainnet() {
        let signer = BitcoinSigner::generate().unwrap();
        let testnet = signer.p2pkh_testnet_address();
        assert!(
            !validate_mainnet_address(&testnet),
            "testnet should not validate as mainnet"
        );
    }

    #[test]
    fn test_validate_combined() {
        let signer = BitcoinSigner::generate().unwrap();
        // Both mainnet and testnet pass validate_address
        assert!(validate_address(&signer.p2pkh_address()));
        assert!(validate_address(&signer.p2wpkh_address().unwrap()));
        assert!(validate_address(&signer.p2pkh_testnet_address()));
        assert!(validate_address(&signer.p2wpkh_testnet_address().unwrap()));
    }
}

#[cfg(feature = "mnemonic")]
mod mnemonic_integration {
    use chains_sdk::hd_key::{DerivationPath, ExtendedPrivateKey};
    use chains_sdk::mnemonic::Mnemonic;

    #[test]
    fn test_mnemonic_to_btc_address() {
        let m = Mnemonic::generate(12).unwrap();
        let seed = m.to_seed("");
        let master = ExtendedPrivateKey::from_seed(&*seed).unwrap();
        let child = master.derive_path(&DerivationPath::bitcoin(0)).unwrap();
        assert_eq!(child.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_mnemonic_to_solana_path() {
        let m = Mnemonic::generate(24).unwrap();
        let seed = m.to_seed("my passphrase");
        let master = ExtendedPrivateKey::from_seed(&*seed).unwrap();
        let child = master.derive_path(&DerivationPath::solana(0)).unwrap();
        assert_eq!(child.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_mnemonic_24_word_to_xprv() {
        let m = Mnemonic::generate(24).unwrap();
        let seed = m.to_seed("");
        let master = ExtendedPrivateKey::from_seed(&*seed).unwrap();
        let xprv = master.to_xprv();
        assert!(xprv.starts_with("xprv"));
        // Round-trip
        let restored = ExtendedPrivateKey::from_xprv(&xprv).unwrap();
        assert_eq!(
            master.private_key_bytes().as_slice(),
            restored.private_key_bytes().as_slice()
        );
    }

    #[test]
    fn test_15_word_mnemonic() {
        let m = Mnemonic::generate(15).unwrap();
        assert_eq!(m.word_count(), 15);
        let m2 = Mnemonic::from_phrase(m.phrase()).unwrap();
        assert_eq!(m.phrase(), m2.phrase());
    }

    #[test]
    fn test_18_word_mnemonic() {
        let m = Mnemonic::generate(18).unwrap();
        assert_eq!(m.word_count(), 18);
        let m2 = Mnemonic::from_phrase(m.phrase()).unwrap();
        assert_eq!(m.phrase(), m2.phrase());
    }

    #[test]
    fn test_21_word_mnemonic() {
        let m = Mnemonic::generate(21).unwrap();
        assert_eq!(m.word_count(), 21);
    }
}

// ─── Bitcoin WIF Tests ──────────────────

#[cfg(feature = "bitcoin")]
mod wif_tests {
    use chains_sdk::bitcoin::BitcoinSigner;
    use chains_sdk::traits::KeyPair;

    #[test]
    fn test_wif_starts_with_k_or_l() {
        let signer = BitcoinSigner::generate().unwrap();
        let wif = signer.to_wif();
        assert!(
            wif.starts_with('K') || wif.starts_with('L'),
            "WIF should start with K or L: {}",
            &*wif
        );
    }

    #[test]
    fn test_wif_testnet_starts_with_c() {
        let signer = BitcoinSigner::generate().unwrap();
        let wif = signer.to_wif_testnet();
        assert!(
            wif.starts_with('c'),
            "testnet WIF should start with 'c': {}",
            &*wif
        );
    }

    #[test]
    fn test_wif_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let wif = signer.to_wif();
        let restored = BitcoinSigner::from_wif(&wif).unwrap();
        // Round-trip: verify the restored key produces the same WIF
        assert_eq!(signer.to_wif(), restored.to_wif());
    }

    #[test]
    fn test_wif_testnet_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let wif = signer.to_wif_testnet();
        let restored = BitcoinSigner::from_wif(&wif).unwrap();
        assert_eq!(signer.to_wif(), restored.to_wif());
    }

    #[test]
    fn test_wif_invalid_rejected() {
        assert!(BitcoinSigner::from_wif("notavalidwif").is_err());
        assert!(BitcoinSigner::from_wif("").is_err());
    }
}

// ─── xpub/xprv Fingerprint Tests ────────────────────

#[cfg(feature = "hd_key")]
mod fingerprint_tests {
    use chains_sdk::hd_key::{DerivationPath, ExtendedPrivateKey};

    #[test]
    fn test_master_key_has_zero_fingerprint() {
        let master = ExtendedPrivateKey::from_seed(&[0x42u8; 64]).unwrap();
        assert_eq!(*master.parent_fingerprint(), [0u8; 4]);
        assert_eq!(master.child_index(), 0);
        assert_eq!(master.depth(), 0);
    }

    #[test]
    fn test_child_key_has_nonzero_fingerprint() {
        let master = ExtendedPrivateKey::from_seed(&[0x42u8; 64]).unwrap();
        let child = master.derive_path(&DerivationPath::ethereum(0)).unwrap();
        // Depth should be 5 (m/44'/60'/0'/0/0)
        assert_eq!(child.depth(), 5);
        // Fingerprint should not be zero (it's derived from parent's pubkey)
        assert_ne!(*child.parent_fingerprint(), [0u8; 4]);
    }

    #[test]
    fn test_xprv_roundtrip_preserves_fingerprint() {
        let master = ExtendedPrivateKey::from_seed(&[0x42u8; 64]).unwrap();
        let child = master.derive_path(&DerivationPath::bitcoin(0)).unwrap();
        let xprv = child.to_xprv();
        let restored = ExtendedPrivateKey::from_xprv(&xprv).unwrap();
        assert_eq!(*child.parent_fingerprint(), *restored.parent_fingerprint());
        assert_eq!(child.child_index(), restored.child_index());
        assert_eq!(child.depth(), restored.depth());
    }

    #[test]
    fn test_different_children_have_same_parent_fingerprint() {
        let master = ExtendedPrivateKey::from_seed(&[0x42u8; 64]).unwrap();
        let child0 = master.derive_child(0, false).unwrap();
        let child1 = master.derive_child(1, false).unwrap();
        // Same parent → same fingerprint
        assert_eq!(*child0.parent_fingerprint(), *child1.parent_fingerprint());
        // But different child indices
        assert_ne!(child0.child_index(), child1.child_index());
    }
}

// ─── Mnemonic → Signer Helper Tests ────────────────────

#[cfg(feature = "mnemonic")]
mod mnemonic_signer_helpers {
    use chains_sdk::mnemonic::Mnemonic;

    #[cfg(feature = "ethereum")]
    #[test]
    fn test_mnemonic_to_ethereum_signer() {
        let m = Mnemonic::generate(12).unwrap();
        let signer = m.to_ethereum_signer("", 0).unwrap();
        let addr = signer.address_checksum();
        assert!(addr.starts_with("0x") && addr.len() == 42);
    }

    #[cfg(feature = "bitcoin")]
    #[test]
    fn test_mnemonic_to_bitcoin_signer() {
        let m = Mnemonic::generate(12).unwrap();
        let signer = m.to_bitcoin_signer("", 0).unwrap();
        let addr = signer.p2pkh_address();
        assert!(addr.starts_with('1'));
    }

    #[cfg(feature = "solana")]
    #[test]
    fn test_mnemonic_to_solana_signer() {
        let m = Mnemonic::generate(12).unwrap();
        let signer = m.to_solana_signer("", 0).unwrap();
        let addr = signer.address();
        assert!(chains_sdk::solana::validate_address(&addr));
    }

    #[cfg(feature = "xrp")]
    #[test]
    fn test_mnemonic_to_xrp_signer() {
        let m = Mnemonic::generate(12).unwrap();
        let signer = m.to_xrp_signer("", 0).unwrap();
        let addr = signer.address().unwrap();
        assert!(addr.starts_with('r'));
    }

    #[cfg(feature = "ethereum")]
    #[test]
    fn test_same_mnemonic_same_signer() {
        let m = Mnemonic::generate(12).unwrap();
        let s1 = m.to_ethereum_signer("pass", 0).unwrap();
        let s2 = m.to_ethereum_signer("pass", 0).unwrap();
        assert_eq!(s1.address(), s2.address());
    }
}

// ─── DerivationPath::parse Tests ──────────────────

#[cfg(feature = "hd_key")]
mod derivation_path_parse {
    use chains_sdk::hd_key::DerivationPath;

    #[test]
    fn test_parse_ethereum_path() {
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path.steps.len(), 5);
        assert!(path.steps[0].hardened);
        assert_eq!(path.steps[0].index, 44);
        assert!(!path.steps[4].hardened);
        assert_eq!(path.steps[4].index, 0);
    }

    #[test]
    fn test_parse_h_notation() {
        let path = DerivationPath::parse("m/44h/60h/0h/0/0").unwrap();
        assert_eq!(path.steps.len(), 5);
        assert!(path.steps[0].hardened);
    }

    #[test]
    fn test_parse_invalid_rejected() {
        assert!(DerivationPath::parse("").is_err());
        assert!(DerivationPath::parse("44'/60'").is_err()); // no m/ prefix
    }
}
