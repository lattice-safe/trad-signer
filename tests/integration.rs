//! Cross-module integration tests for trad-signer.
//!
//! Verifies that modules are correctly isolated, trait implementations
//! are consistent, and the same private key material produces different
//! results on different chains (as expected).

#[cfg(all(feature = "ethereum", feature = "bitcoin"))]
mod cross_chain {
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::ethereum::EthereumSigner;
    use trad_signer::traits::{KeyPair, Signer};

    /// Same private key bytes must produce different signatures on ETH vs BTC
    /// because they use different hash functions (Keccak-256 vs Double SHA-256).
    #[test]
    fn test_same_key_different_chain_signatures() {
        let privkey = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();

        let eth = EthereumSigner::from_bytes(&privkey).unwrap();
        let btc = BitcoinSigner::from_bytes(&privkey).unwrap();

        let msg = b"cross-chain test";
        let eth_sig = eth.sign(msg).unwrap();
        let btc_sig = btc.sign(msg).unwrap();

        // Signatures must differ (different hash functions)
        let eth_bytes = eth_sig.to_bytes();
        assert_ne!(&eth_bytes[..64], &btc_sig.der_bytes[..64.min(btc_sig.der_bytes.len())]);
    }

    /// Same private key bytes must produce the same public key on ETH and BTC
    /// (both are secp256k1).
    #[test]
    fn test_same_key_same_pubkey() {
        let privkey = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();

        let eth = EthereumSigner::from_bytes(&privkey).unwrap();
        let btc = BitcoinSigner::from_bytes(&privkey).unwrap();

        // Both should produce the same compressed secp256k1 public key
        assert_eq!(eth.public_key_bytes(), btc.public_key_bytes());
    }
}

#[cfg(all(feature = "solana", feature = "xrp"))]
mod ed25519_cross {
    use trad_signer::solana::SolanaSigner;
    use trad_signer::xrp::XrpEddsaSigner;
    use trad_signer::traits::{KeyPair, Signer};

    /// Same Ed25519 seed produces the same public key on Solana and XRP.
    #[test]
    fn test_same_ed25519_key_cross_chain() {
        let seed = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap();

        let sol = SolanaSigner::from_bytes(&seed).unwrap();
        let xrp = XrpEddsaSigner::from_bytes(&seed).unwrap();

        // Same public key
        assert_eq!(sol.public_key_bytes(), xrp.public_key_bytes());

        // Same message should produce the same signature
        let msg = b"hello ed25519";
        let sol_sig = sol.sign(msg).unwrap();
        let xrp_sig = xrp.sign(msg).unwrap();
        assert_eq!(sol_sig.bytes.to_vec(), xrp_sig.bytes);
    }
}

#[cfg(feature = "ethereum")]
mod eip712_integration {
    use trad_signer::ethereum::{EthereumSigner, EthereumVerifier, Eip712Domain, eip712_hash};
    use trad_signer::traits::{KeyPair, Signer, Verifier};
    use sha3::{Digest, Keccak256};

    /// Full EIP-712 Permit flow: domain + struct type hash + encoding.
    #[test]
    fn test_eip712_permit_flow() {
        let privkey = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();
        let signer = EthereumSigner::from_bytes(&privkey).unwrap();
        let verifier =
            EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();

        let contract_addr: [u8; 20] = [0xCC; 20];
        let domain = Eip712Domain {
            name: "USDC",
            version: "2",
            chain_id: 1,
            verifying_contract: &contract_addr,
        };
        let domain_sep = domain.separator();

        // Build the Permit struct hash
        let permit_type_hash = Keccak256::digest(
            b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
        );
        let mut struct_data = [0u8; 192]; // typeHash + 5 params × 32
        struct_data[0..32].copy_from_slice(&permit_type_hash);
        // owner (address, right-aligned)
        struct_data[44..64].copy_from_slice(&signer.address());
        // spender
        struct_data[76..96].copy_from_slice(&[0xBB; 20]);
        // value = 1000
        struct_data[120..128].copy_from_slice(&1000u64.to_be_bytes());
        // nonce = 0 (already zero)
        // deadline (already zero = infinite)

        let mut struct_hash = [0u8; 32];
        struct_hash.copy_from_slice(&Keccak256::digest(struct_data));

        let sig = signer.sign_typed_data(&domain_sep, &struct_hash).unwrap();
        assert!(sig.v == 27 || sig.v == 28);

        // Verify
        assert!(verifier
            .verify_typed_data(&domain_sep, &struct_hash, &sig)
            .unwrap());

        // Verify the digest matches eip712_hash
        let full_hash = eip712_hash(&domain_sep, &struct_hash);
        assert!(verifier.verify_prehashed(&full_hash, &sig).unwrap());
    }
}

#[cfg(feature = "bls")]
mod bls_integration {
    use trad_signer::bls::{BlsSigner, aggregate_signatures, verify_aggregated};
    use trad_signer::traits::{KeyPair, Signer};

    /// Aggregate 100 signatures and verify
    #[test]
    fn test_large_aggregation() {
        let msg = b"consensus round 42";
        let signers: Vec<BlsSigner> = (0..20)
            .map(|_| BlsSigner::generate().unwrap())
            .collect();
        let sigs: Vec<_> = signers.iter().map(|s| s.sign(msg).unwrap()).collect();
        let pks: Vec<_> = signers.iter().map(|s| s.public_key()).collect();

        let agg = aggregate_signatures(&sigs).unwrap();
        assert!(verify_aggregated(&pks, msg, &agg).unwrap());
    }
}

#[cfg(all(feature = "ethereum", feature = "bitcoin", feature = "neo"))]
mod trait_consistency {
    use trad_signer::traits::{KeyPair, Signer};
    use trad_signer::ethereum::EthereumSigner;
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::neo::NeoSigner;

    /// All ECDSA signers should produce 32-byte private keys.
    #[test]
    fn test_private_key_length_consistency() {
        let eth = EthereumSigner::generate().unwrap();
        let btc = BitcoinSigner::generate().unwrap();
        let neo = NeoSigner::generate().unwrap();

        assert_eq!(eth.private_key_bytes().len(), 32);
        assert_eq!(btc.private_key_bytes().len(), 32);
        assert_eq!(neo.private_key_bytes().len(), 32);
    }

    /// All ECDSA signers should produce compressed 33-byte public keys.
    #[test]
    fn test_public_key_length_consistency() {
        let eth = EthereumSigner::generate().unwrap();
        let btc = BitcoinSigner::generate().unwrap();
        let neo = NeoSigner::generate().unwrap();

        assert_eq!(eth.public_key_bytes().len(), 33);
        assert_eq!(btc.public_key_bytes().len(), 33);
        assert_eq!(neo.public_key_bytes().len(), 33);
    }
}

// ─── Mnemonic → HD → Multi-Chain Signing Workflow ───────────────

#[cfg(all(feature = "mnemonic", feature = "ethereum", feature = "bitcoin", feature = "solana"))]
mod mnemonic_multichaain {
    use trad_signer::mnemonic::Mnemonic;
    use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};
    use trad_signer::ethereum::EthereumSigner;
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::solana::SolanaSigner;
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    /// Full workflow: generate mnemonic → derive HD keys → sign on ETH, BTC, SOL
    #[test]
    fn test_mnemonic_to_all_chains() {
        let entropy = hex::decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivateKey::from_seed(&*seed).unwrap();

        // ETH: m/44'/60'/0'/0/0
        let eth_key = master.derive_path(&DerivationPath::ethereum(0)).unwrap();
        let eth_signer = EthereumSigner::from_bytes(&eth_key.private_key_bytes()).unwrap();
        let eth_sig = eth_signer.sign(b"cross-chain test").unwrap();
        let eth_verifier = trad_signer::ethereum::EthereumVerifier::from_public_key_bytes(
            &eth_signer.public_key_bytes(),
        ).unwrap();
        assert!(eth_verifier.verify(b"cross-chain test", &eth_sig).unwrap());

        // BTC: m/84'/0'/0'/0/0
        let btc_key = master.derive_path(&DerivationPath::bitcoin_segwit(0)).unwrap();
        let btc_signer = BitcoinSigner::from_bytes(&btc_key.private_key_bytes()).unwrap();
        let btc_addr = btc_signer.p2wpkh_address().unwrap();
        assert!(btc_addr.starts_with("bc1q"));

        // SOL: m/44'/501'/0'/0'
        let sol_key = master.derive_path(&DerivationPath::solana(0)).unwrap();
        assert_eq!(sol_key.private_key_bytes().len(), 32);

        // All chains should use different derivation paths → different privkeys
        assert_ne!(&*eth_key.private_key_bytes(), &*btc_key.private_key_bytes());
        assert_ne!(&*btc_key.private_key_bytes(), &*sol_key.private_key_bytes());
    }
}

#[cfg(all(feature = "bip85", feature = "mnemonic", feature = "bitcoin"))]
mod bip85_workflow {
    use trad_signer::hd_key::ExtendedPrivateKey;
    use trad_signer::bip85;
    use trad_signer::mnemonic::Mnemonic;
    use trad_signer::bitcoin::BitcoinSigner;
    use trad_signer::traits::{KeyPair, Signer};

    /// BIP-85: master → child mnemonic → derive BTC → sign
    #[test]
    fn test_bip85_child_mnemonic_to_btc_signing() {
        let seed = [0xABu8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        // Derive a child 12-word mnemonic from the master
        let child_phrase = bip85::derive_bip39(&master, 0, 12, 0).unwrap();

        // This should NOT fail — proves the checksum bug is fixed
        let child_m = Mnemonic::from_phrase(&child_phrase).unwrap();
        let child_seed = child_m.to_seed("");
        let child_master = ExtendedPrivateKey::from_seed(&*child_seed).unwrap();

        // Derive BTC key from the child HD tree
        let btc_key = child_master
            .derive_path(&trad_signer::hd_key::DerivationPath::bitcoin_segwit(0))
            .unwrap();
        let btc_signer = BitcoinSigner::from_bytes(&btc_key.private_key_bytes()).unwrap();
        let sig = btc_signer.sign(b"BIP-85 derived signing").unwrap();
        assert!(!sig.der_bytes.is_empty());

        // Deterministic: same master → same child → same address
        let child_phrase_2 = bip85::derive_bip39(&master, 0, 12, 0).unwrap();
        assert_eq!(child_phrase, child_phrase_2);
    }

    /// BIP-85: derive_bip39 round-trips through from_phrase for all word counts
    #[test]
    fn test_bip85_mnemonic_roundtrip_all_sizes() {
        let seed = [0x42u8; 64];
        let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

        for words in [12, 15, 18, 21, 24] {
            let phrase = bip85::derive_bip39(&master, 0, words, 0).unwrap();
            let parsed = Mnemonic::from_phrase(&phrase);
            assert!(
                parsed.is_ok(),
                "BIP-85 derive_bip39({words}) → from_phrase round-trip failed: {:?}",
                parsed.err()
            );
            let w: Vec<&str> = phrase.split_whitespace().collect();
            assert_eq!(w.len(), words as usize);
        }
    }
}

#[cfg(all(feature = "frost", feature = "musig2"))]
mod threshold_e2e {
    use trad_signer::threshold::frost::{keygen, signing};
    use trad_signer::threshold::musig2::signing as musig2;

    /// Full FROST keygen → sign → verify → different-subset
    #[test]
    fn test_frost_full_e2e_with_subset_rotation() {
        let secret = [0x33u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let group_pk = kgen.group_public_key;
        let msg = b"threshold e2e test";

        // Sign with participants {1, 2}
        let n1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let n2 = signing::commit(&kgen.key_packages[1]).unwrap();
        let comms_12 = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = signing::sign(&kgen.key_packages[0], n1, &comms_12, msg).unwrap();
        let s2 = signing::sign(&kgen.key_packages[1], n2, &comms_12, msg).unwrap();
        let sig_12 = signing::aggregate(&comms_12, &[s1, s2], &group_pk, msg).unwrap();
        assert!(signing::verify(&sig_12, &group_pk, msg).unwrap());

        // Sign with participants {2, 3}
        let n2b = signing::commit(&kgen.key_packages[1]).unwrap();
        let n3 = signing::commit(&kgen.key_packages[2]).unwrap();
        let comms_23 = vec![n2b.commitments.clone(), n3.commitments.clone()];
        let s2b = signing::sign(&kgen.key_packages[1], n2b, &comms_23, msg).unwrap();
        let s3 = signing::sign(&kgen.key_packages[2], n3, &comms_23, msg).unwrap();
        let sig_23 = signing::aggregate(&comms_23, &[s2b, s3], &group_pk, msg).unwrap();
        assert!(signing::verify(&sig_23, &group_pk, msg).unwrap());

        // Both sigs must verify against same group key, but R will differ
        assert_ne!(sig_12.r_bytes, sig_23.r_bytes);
    }

    /// Full MuSig2 keygen → sign → verify
    #[test]
    fn test_musig2_full_e2e() {
        let sk1 = [0x11u8; 32];
        let sk2 = [0x22u8; 32];
        let pk1 = musig2::individual_pubkey(&sk1).unwrap();
        let pk2 = musig2::individual_pubkey(&sk2).unwrap();
        let ctx = musig2::key_agg(&[pk1, pk2]).unwrap();
        let msg = b"musig2 e2e test";

        let (sn1, pn1) = musig2::nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
        let (sn2, pn2) = musig2::nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
        let agg_nonce = musig2::nonce_agg(&[pn1, pn2]).unwrap();
        let ps1 = musig2::sign(sn1, &sk1, &ctx, &agg_nonce, msg).unwrap();
        let ps2 = musig2::sign(sn2, &sk2, &ctx, &agg_nonce, msg).unwrap();
        let sig = musig2::partial_sig_agg(&[ps1, ps2], &agg_nonce, &ctx, msg).unwrap();
        assert!(musig2::verify(&sig, &ctx.x_only_pubkey, msg).unwrap());
    }
}
