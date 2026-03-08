// tests/address_tests.rs — Tests for address generation across all chains.

#[cfg(feature = "ethereum")]
mod ethereum {
    use chains_sdk::ethereum::{ecrecover, eip55_checksum, EthereumSigner};
    use chains_sdk::traits::{KeyPair, Signer};

    #[test]
    fn test_eip55_checksum_known_vector() {
        // Known address from EIP-55 spec
        let addr_bytes: [u8; 20] = hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
            .unwrap()
            .try_into()
            .unwrap();
        let checksum = eip55_checksum(&addr_bytes);
        assert_eq!(checksum, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_eip55_checksum_all_lowercase() {
        let addr_bytes: [u8; 20] = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359")
            .unwrap()
            .try_into()
            .unwrap();
        let checksum = eip55_checksum(&addr_bytes);
        assert_eq!(checksum, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
    }

    #[test]
    fn test_address_checksum_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let addr = signer.address_checksum();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_ecrecover_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let msg = b"ecrecover test message";
        let sig = signer.sign(msg).unwrap();
        let recovered = ecrecover(msg, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_ecrecover_personal_sign() {
        use chains_sdk::ethereum::{ecrecover_digest, eip191_hash};
        let signer = EthereumSigner::generate().unwrap();
        let msg = b"personal sign recovery test";
        let sig = signer.personal_sign(msg).unwrap();
        let digest = eip191_hash(msg);
        let recovered = ecrecover_digest(&digest, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_ecrecover_wrong_message_fails() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"message A").unwrap();
        let recovered = ecrecover(b"message B", &sig).unwrap();
        assert_ne!(recovered, signer.address());
    }
}

#[cfg(feature = "bitcoin")]
mod bitcoin {
    use chains_sdk::bitcoin::schnorr::SchnorrSigner;
    use chains_sdk::bitcoin::BitcoinSigner;
    use chains_sdk::traits::KeyPair;

    #[test]
    fn test_p2pkh_address_starts_with_1() {
        let signer = BitcoinSigner::generate().unwrap();
        let addr = signer.p2pkh_address();
        assert!(
            addr.starts_with('1'),
            "P2PKH should start with '1', got: {addr}"
        );
    }

    #[test]
    fn test_p2wpkh_address_starts_with_bc1q() {
        let signer = BitcoinSigner::generate().unwrap();
        let addr = signer.p2wpkh_address().unwrap();
        assert!(
            addr.starts_with("bc1q"),
            "P2WPKH should start with 'bc1q', got: {addr}"
        );
    }

    #[test]
    fn test_p2tr_address_starts_with_bc1p() {
        let signer = SchnorrSigner::generate().unwrap();
        let addr = signer.p2tr_address().unwrap();
        assert!(
            addr.starts_with("bc1p"),
            "P2TR should start with 'bc1p', got: {addr}"
        );
    }

    #[test]
    fn test_p2pkh_known_vector() {
        // Private key = 1 -> known Bitcoin address
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let signer = BitcoinSigner::from_bytes(&privkey).unwrap();
        let addr = signer.p2pkh_address();
        // Private key 1 -> compressed pubkey 02..98 -> P2PKH = 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
        assert_eq!(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_p2wpkh_known_vector() {
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let signer = BitcoinSigner::from_bytes(&privkey).unwrap();
        let addr = signer.p2wpkh_address().unwrap();
        assert!(addr.starts_with("bc1q"), "expected bc1q, got: {addr}");
        // Known: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 is for privkey=1
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_addresses_deterministic() {
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let s1 = BitcoinSigner::from_bytes(&privkey).unwrap();
        let s2 = BitcoinSigner::from_bytes(&privkey).unwrap();
        assert_eq!(s1.p2pkh_address(), s2.p2pkh_address());
        assert_eq!(s1.p2wpkh_address().unwrap(), s2.p2wpkh_address().unwrap());
    }
}

#[cfg(feature = "solana")]
mod solana {
    use chains_sdk::solana::SolanaSigner;
    use chains_sdk::traits::KeyPair;

    #[test]
    fn test_solana_address_is_base58() {
        let signer = SolanaSigner::generate().unwrap();
        let addr = signer.address();
        // Solana addresses are 32-44 chars Base58
        assert!(
            addr.len() >= 32 && addr.len() <= 44,
            "unexpected length: {}",
            addr.len()
        );
        // Must decode back to 32 bytes
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_solana_address_matches_pubkey() {
        use chains_sdk::traits::Signer;
        let signer = SolanaSigner::generate().unwrap();
        let addr = signer.address();
        let pubkey = signer.public_key_bytes();
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded, pubkey);
    }
}

#[cfg(feature = "xrp")]
mod xrp {
    use chains_sdk::traits::KeyPair;
    use chains_sdk::xrp::{XrpEcdsaSigner, XrpEddsaSigner};

    #[test]
    fn test_xrp_ecdsa_address_starts_with_r() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let addr = signer.address().unwrap();
        assert!(
            addr.starts_with('r'),
            "XRP address should start with 'r', got: {addr}"
        );
    }

    #[test]
    fn test_xrp_eddsa_address_starts_with_r() {
        let signer = XrpEddsaSigner::generate().unwrap();
        let addr = signer.address().unwrap();
        assert!(
            addr.starts_with('r'),
            "XRP address should start with 'r', got: {addr}"
        );
    }

    #[test]
    fn test_xrp_ecdsa_vs_eddsa_different_addresses() {
        let ecdsa = XrpEcdsaSigner::generate().unwrap();
        let eddsa = XrpEddsaSigner::generate().unwrap();
        assert_ne!(ecdsa.address().unwrap(), eddsa.address().unwrap());
    }

    #[test]
    fn test_xrp_address_deterministic() {
        let privkey =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let s1 = XrpEcdsaSigner::from_bytes(&privkey).unwrap();
        let s2 = XrpEcdsaSigner::from_bytes(&privkey).unwrap();
        assert_eq!(s1.address().unwrap(), s2.address().unwrap());
    }
}

#[cfg(feature = "neo")]
mod neo {
    use chains_sdk::neo::NeoSigner;
    use chains_sdk::traits::KeyPair;

    #[test]
    fn test_neo_address_starts_with_a() {
        let signer = NeoSigner::generate().unwrap();
        let addr = signer.address();
        assert!(
            addr.starts_with('A'),
            "NEO address should start with 'A', got: {addr}"
        );
    }

    #[test]
    fn test_neo_script_hash_length() {
        let signer = NeoSigner::generate().unwrap();
        let hash = signer.script_hash();
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_neo_address_deterministic() {
        let privkey =
            hex::decode("708309a7449e156b0db70e5b52e606c7e094ed676ce8953bf6c14757c826f590")
                .unwrap();
        let s1 = NeoSigner::from_bytes(&privkey).unwrap();
        let s2 = NeoSigner::from_bytes(&privkey).unwrap();
        assert_eq!(s1.address(), s2.address());
    }

    #[test]
    fn test_neo_address_length() {
        let signer = NeoSigner::generate().unwrap();
        let addr = signer.address();
        // NEO addresses are 34 characters (Base58Check)
        assert_eq!(
            addr.len(),
            34,
            "NEO address should be 34 chars, got: {}",
            addr.len()
        );
    }

    #[test]
    fn test_neo_validate_generated_address() {
        let signer = NeoSigner::generate().unwrap();
        assert!(chains_sdk::neo::validate_address(&signer.address()));
    }

    #[test]
    fn test_neo_validate_rejects_invalid() {
        assert!(!chains_sdk::neo::validate_address(""));
        assert!(!chains_sdk::neo::validate_address("not_a_neo_address"));
        assert!(!chains_sdk::neo::validate_address("A"));
    }
}

// ─── Address Validation Tests ────────────────────────────────────────

#[cfg(feature = "ethereum")]
mod eth_validation {
    use chains_sdk::ethereum::{validate_address, EthereumSigner};
    use chains_sdk::traits::KeyPair;

    #[test]
    fn test_validate_eip55_checksummed() {
        let signer = EthereumSigner::generate().unwrap();
        let addr = signer.address_checksum();
        assert!(
            validate_address(&addr),
            "checksummed address should be valid: {addr}"
        );
    }

    #[test]
    fn test_validate_all_lowercase() {
        assert!(validate_address(
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        ));
    }

    #[test]
    fn test_validate_correct_eip55() {
        assert!(validate_address(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
    }

    #[test]
    fn test_validate_wrong_eip55_checksum() {
        assert!(!validate_address(
            "0x5AAEB6053f3e94c9b9A09f33669435E7Ef1BeAed"
        ));
    }

    #[test]
    fn test_validate_too_short() {
        assert!(!validate_address("0x1234"));
    }

    #[test]
    fn test_validate_no_prefix() {
        assert!(!validate_address(
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
    }

    #[test]
    fn test_validate_invalid_hex() {
        assert!(!validate_address(
            "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
        ));
    }
}

#[cfg(feature = "solana")]
mod sol_validation {
    use chains_sdk::solana::{validate_address, SolanaSigner};
    use chains_sdk::traits::KeyPair;

    #[test]
    fn test_validate_generated_address() {
        let signer = SolanaSigner::generate().unwrap();
        assert!(validate_address(&signer.address()));
    }

    #[test]
    fn test_validate_system_program() {
        assert!(validate_address("11111111111111111111111111111112"));
    }

    #[test]
    fn test_validate_rejects_short() {
        assert!(!validate_address("abc"));
    }
}

#[cfg(feature = "xrp")]
mod xrp_validation {
    use chains_sdk::traits::KeyPair;
    use chains_sdk::xrp::{validate_address, XrpEcdsaSigner, XrpEddsaSigner};

    #[test]
    fn test_validate_ecdsa_address() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        assert!(validate_address(&signer.address().unwrap()));
    }

    #[test]
    fn test_validate_eddsa_address() {
        let signer = XrpEddsaSigner::generate().unwrap();
        assert!(validate_address(&signer.address().unwrap()));
    }

    #[test]
    fn test_validate_rejects_invalid() {
        assert!(!validate_address(""));
        assert!(!validate_address("not_xrp"));
        assert!(!validate_address("r"));
    }

    #[test]
    fn test_validate_rejects_wrong_prefix() {
        assert!(!validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
    }
}
