// tests/threshold_tests.rs — FROST and MuSig2 threshold signature tests.
//
// Test vectors from:
//   - RFC 9591 Section E.5: FROST(secp256k1, SHA-256)
//   - BIP-327: MuSig2 key aggregation

// ─── FROST Tests ─────────────────────────────────────────────────────

#[cfg(feature = "frost")]
mod frost_tests {
    use chains_sdk::threshold::frost::{keygen, signing};

    #[test]
    fn test_frost_2_of_3_full_roundtrip() {
        // Generate 2-of-3 key shares
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        assert_eq!(kgen.key_packages.len(), 3);

        // Verify all shares against VSS commitments
        for pkg in &kgen.key_packages {
            assert!(kgen
                .vss_commitments
                .verify_share(pkg.identifier, pkg.secret_share()));
        }

        // Participants 1 and 3 sign a message
        let msg = b"Hello FROST";
        let nonce1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let nonce3 = signing::commit(&kgen.key_packages[2]).unwrap();

        let commitments = vec![nonce1.commitments.clone(), nonce3.commitments.clone()];

        let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg).unwrap();
        let share3 = signing::sign(&kgen.key_packages[2], nonce3, &commitments, msg).unwrap();

        // Aggregate
        let sig = signing::aggregate(&commitments, &[share1, share3], &kgen.group_public_key, msg)
            .unwrap();

        // Verify
        assert!(signing::verify(&sig, &kgen.group_public_key, msg).unwrap());
    }

    #[test]
    fn test_frost_2_of_3_different_participants() {
        let secret = [0x55u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();

        let msg = b"Different pair";

        // Participants 1 and 2 this time (instead of 1 and 3)
        let nonce1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let nonce2 = signing::commit(&kgen.key_packages[1]).unwrap();

        let commitments = vec![nonce1.commitments.clone(), nonce2.commitments.clone()];

        let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg).unwrap();
        let share2 = signing::sign(&kgen.key_packages[1], nonce2, &commitments, msg).unwrap();

        let sig = signing::aggregate(&commitments, &[share1, share2], &kgen.group_public_key, msg)
            .unwrap();

        assert!(signing::verify(&sig, &kgen.group_public_key, msg).unwrap());
    }

    #[test]
    fn test_frost_3_of_5() {
        let secret = [0xAAu8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 3, 5).unwrap();
        assert_eq!(kgen.key_packages.len(), 5);
        assert_eq!(kgen.vss_commitments.commitments.len(), 3); // threshold = 3 coefficients

        let msg = b"3-of-5 test";

        // Use participants 1, 3, 5
        let nonce1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let nonce3 = signing::commit(&kgen.key_packages[2]).unwrap();
        let nonce5 = signing::commit(&kgen.key_packages[4]).unwrap();

        let commitments = vec![
            nonce1.commitments.clone(),
            nonce3.commitments.clone(),
            nonce5.commitments.clone(),
        ];

        let s1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg).unwrap();
        let s3 = signing::sign(&kgen.key_packages[2], nonce3, &commitments, msg).unwrap();
        let s5 = signing::sign(&kgen.key_packages[4], nonce5, &commitments, msg).unwrap();

        let sig =
            signing::aggregate(&commitments, &[s1, s3, s5], &kgen.group_public_key, msg).unwrap();

        assert!(signing::verify(&sig, &kgen.group_public_key, msg).unwrap());
    }

    #[test]
    fn test_frost_wrong_message_fails_verification() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();

        let nonce1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let nonce3 = signing::commit(&kgen.key_packages[2]).unwrap();
        let commitments = vec![nonce1.commitments.clone(), nonce3.commitments.clone()];

        let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, b"msg A").unwrap();
        let share3 = signing::sign(&kgen.key_packages[2], nonce3, &commitments, b"msg A").unwrap();

        let sig = signing::aggregate(
            &commitments,
            &[share1, share3],
            &kgen.group_public_key,
            b"msg A",
        )
        .unwrap();

        // Verify with different message
        assert!(!signing::verify(&sig, &kgen.group_public_key, b"msg B").unwrap());
    }

    #[test]
    fn test_frost_share_verification_identifiable_abort() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();

        let msg = b"identifiable abort test";
        let nonce1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let nonce3 = signing::commit(&kgen.key_packages[2]).unwrap();
        let commitments = vec![nonce1.commitments.clone(), nonce3.commitments.clone()];

        let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg).unwrap();
        let share3 = signing::sign(&kgen.key_packages[2], nonce3, &commitments, msg).unwrap();

        // Verify individual shares
        let pk1 = kgen.key_packages[0].public_key();
        let pk3 = kgen.key_packages[2].public_key();

        assert!(signing::verify_share(
            &share1,
            &commitments[0],
            &pk1,
            &kgen.group_public_key,
            &commitments,
            msg,
        )
        .unwrap());

        assert!(signing::verify_share(
            &share3,
            &commitments[1],
            &pk3,
            &kgen.group_public_key,
            &commitments,
            msg,
        )
        .unwrap());
    }

    #[test]
    fn test_frost_vss_rejects_wrong_share() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();

        // Tamper with share: verify against wrong identifier
        let share = kgen.key_packages[0].secret_share();
        // Identifier 2's share should not match identifier 1's share against VSS
        assert!(!kgen.vss_commitments.verify_share(2, share));
    }

    #[test]
    fn test_frost_lagrange_reconstruct_secret() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();

        // Any 2 shares should reconstruct the secret
        let ids = [k256::Scalar::from(1u64), k256::Scalar::from(2u64)];
        let shares = [
            *kgen.key_packages[0].secret_share(),
            *kgen.key_packages[1].secret_share(),
        ];

        let mut reconstructed = k256::Scalar::ZERO;
        for (i, share) in shares.iter().enumerate() {
            let lambda = keygen::derive_interpolating_value(&ids[i], &ids).unwrap();
            reconstructed += lambda * share;
        }

        let original = keygen::scalar_from_bytes(&secret).unwrap();
        assert_eq!(reconstructed, original);
    }

    #[test]
    fn test_frost_invalid_params_rejected() {
        let secret = [0x42u8; 32];
        assert!(keygen::trusted_dealer_keygen(&secret, 1, 3).is_err()); // min < 2
        assert!(keygen::trusted_dealer_keygen(&secret, 3, 2).is_err()); // max < min
    }

    // RFC 9591 Section E.5 — FROST(secp256k1, SHA-256) test vector
    //
    // Configuration: MAX_PARTICIPANTS=3, MIN_PARTICIPANTS=2, NUM_PARTICIPANTS=2
    // participant_list: 1, 3
    #[test]
    fn test_rfc9591_group_public_key() {
        let group_secret =
            hex_to_32("0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114");
        let expected_pk = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f";

        let s = keygen::scalar_from_bytes(&group_secret).unwrap();
        let pk = (k256::ProjectivePoint::GENERATOR * s).to_affine();
        let pk_enc = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&pk, true);
        let pk_hex = hex::encode(pk_enc.as_bytes());

        assert_eq!(pk_hex, expected_pk);
    }

    #[test]
    fn test_rfc9591_participant_shares() {
        let group_secret =
            hex_to_32("0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114");
        let coeff1 = hex_to_32("fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579");

        // Build polynomial coefficients manually
        let s = keygen::scalar_from_bytes(&group_secret).unwrap();
        let a1 = keygen::scalar_from_bytes(&coeff1).unwrap();
        let coefficients = [s, a1];

        // P1: f(1) = s + a1*1
        let p1_share = keygen::polynomial_evaluate(&k256::Scalar::from(1u64), &coefficients);
        let expected_p1 = "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c";
        assert_eq!(hex::encode(p1_share.to_bytes()), expected_p1);

        // P3: f(3) = s + a1*3
        let p3_share = keygen::polynomial_evaluate(&k256::Scalar::from(3u64), &coefficients);
        let expected_p3 = "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc";
        assert_eq!(hex::encode(p3_share.to_bytes()), expected_p3);
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    // ─── Additional FROST Coverage Tests ──────────────────

    #[test]
    fn test_frost_empty_message() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let msg = b"";
        let n1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let n2 = signing::commit(&kgen.key_packages[1]).unwrap();
        let commits = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = signing::sign(&kgen.key_packages[0], n1, &commits, msg).unwrap();
        let s2 = signing::sign(&kgen.key_packages[1], n2, &commits, msg).unwrap();
        let sig = signing::aggregate(&commits, &[s1, s2], &kgen.group_public_key, msg).unwrap();
        assert!(signing::verify(&sig, &kgen.group_public_key, msg).unwrap());
    }

    #[test]
    fn test_frost_5_of_7() {
        let secret = [0xBBu8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 5, 7).unwrap();
        assert_eq!(kgen.key_packages.len(), 7);
        assert_eq!(kgen.vss_commitments.commitments.len(), 5);

        let msg = b"5-of-7 threshold";
        let indices = [0, 1, 3, 5, 6]; // participants 1,2,4,6,7
        let nonces: Vec<_> = indices
            .iter()
            .map(|&i| signing::commit(&kgen.key_packages[i]).unwrap())
            .collect();
        let commits: Vec<_> = nonces.iter().map(|n| n.commitments.clone()).collect();
        let mut shares = Vec::new();
        for (idx, nonce) in indices.iter().zip(nonces.into_iter()) {
            shares.push(signing::sign(&kgen.key_packages[*idx], nonce, &commits, msg).unwrap());
        }
        let sig = signing::aggregate(&commits, &shares, &kgen.group_public_key, msg).unwrap();
        assert!(signing::verify(&sig, &kgen.group_public_key, msg).unwrap());
    }

    #[test]
    fn test_frost_all_participants_sign() {
        let secret = [0x77u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let msg = b"all 3 sign";
        let n1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let n2 = signing::commit(&kgen.key_packages[1]).unwrap();
        let n3 = signing::commit(&kgen.key_packages[2]).unwrap();
        let commits = vec![
            n1.commitments.clone(),
            n2.commitments.clone(),
            n3.commitments.clone(),
        ];
        let s1 = signing::sign(&kgen.key_packages[0], n1, &commits, msg).unwrap();
        let s2 = signing::sign(&kgen.key_packages[1], n2, &commits, msg).unwrap();
        let s3 = signing::sign(&kgen.key_packages[2], n3, &commits, msg).unwrap();
        let sig = signing::aggregate(&commits, &[s1, s2, s3], &kgen.group_public_key, msg).unwrap();
        assert!(signing::verify(&sig, &kgen.group_public_key, msg).unwrap());
    }

    #[test]
    fn test_frost_deterministic_keygen() {
        let secret = [0x42u8; 32];
        let kgen1 = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let kgen2 = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        // Same secret → same group public key
        assert_eq!(kgen1.group_public_key, kgen2.group_public_key);
        // But shares are different (random coefficients)
        assert_ne!(
            kgen1.key_packages[0].secret_share(),
            kgen2.key_packages[0].secret_share()
        );
    }

    #[test]
    fn test_frost_signature_bytes_format() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let msg = b"format test";
        let n1 = signing::commit(&kgen.key_packages[0]).unwrap();
        let n2 = signing::commit(&kgen.key_packages[1]).unwrap();
        let commits = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = signing::sign(&kgen.key_packages[0], n1, &commits, msg).unwrap();
        let s2 = signing::sign(&kgen.key_packages[1], n2, &commits, msg).unwrap();
        let sig = signing::aggregate(&commits, &[s1, s2], &kgen.group_public_key, msg).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 65); // 33 (R compressed) + 32 (s)
    }

    #[test]
    fn test_frost_vss_zero_identifier_rejected() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        assert!(!kgen
            .vss_commitments
            .verify_share(0, kgen.key_packages[0].secret_share()));
    }

    #[test]
    fn test_frost_key_package_public_key() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let pk = kgen.key_packages[0].public_key();
        // Public key should not be the identity point
        assert_ne!(pk, k256::AffinePoint::IDENTITY);
    }

    #[test]
    fn test_frost_secret_share_bytes_length() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let share_bytes = kgen.key_packages[0].secret_share_bytes();
        assert_eq!(share_bytes.len(), 32);
    }
}

// ─── MuSig2 Tests ────────────────────────────────────────────────────

#[cfg(feature = "musig2")]
mod musig2_tests {
    use chains_sdk::threshold::musig2;

    #[test]
    fn test_musig2_2_of_2_full_roundtrip() {
        // Generate two key pairs
        let sk1 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk2 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000002");

        let pk1 = musig2::individual_pubkey(&sk1).unwrap();
        let pk2 = musig2::individual_pubkey(&sk2).unwrap();

        // Key aggregation
        let key_agg = musig2::key_agg(&[pk1, pk2]).unwrap();
        assert_eq!(key_agg.x_only_pubkey.len(), 32);

        let msg = b"Hello MuSig2";

        // Nonce generation
        let (secnonce1, pubnonce1) = musig2::nonce_gen(&sk1, &pk1, &key_agg, msg, &[]).unwrap();
        let (secnonce2, pubnonce2) = musig2::nonce_gen(&sk2, &pk2, &key_agg, msg, &[]).unwrap();

        // Nonce aggregation
        let agg_nonce = musig2::nonce_agg(&[pubnonce1.clone(), pubnonce2.clone()]).unwrap();

        // Partial signing
        let psig1 = musig2::sign(secnonce1, &sk1, &key_agg, &agg_nonce, msg).unwrap();
        let psig2 = musig2::sign(secnonce2, &sk2, &key_agg, &agg_nonce, msg).unwrap();

        // Aggregate
        let sig = musig2::partial_sig_agg(&[psig1, psig2], &agg_nonce, &key_agg, msg).unwrap();

        // Verify
        assert!(musig2::verify(&sig, &key_agg.x_only_pubkey, msg).unwrap());
    }

    #[test]
    fn test_musig2_3_of_3() {
        let sk1 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000003");
        let sk2 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000004");
        let sk3 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000005");

        let pk1 = musig2::individual_pubkey(&sk1).unwrap();
        let pk2 = musig2::individual_pubkey(&sk2).unwrap();
        let pk3 = musig2::individual_pubkey(&sk3).unwrap();

        let key_agg = musig2::key_agg(&[pk1, pk2, pk3]).unwrap();
        let msg = b"3-of-3 MuSig2";

        let (sn1, pn1) = musig2::nonce_gen(&sk1, &pk1, &key_agg, msg, &[]).unwrap();
        let (sn2, pn2) = musig2::nonce_gen(&sk2, &pk2, &key_agg, msg, &[]).unwrap();
        let (sn3, pn3) = musig2::nonce_gen(&sk3, &pk3, &key_agg, msg, &[]).unwrap();

        let agg_nonce = musig2::nonce_agg(&[pn1, pn2, pn3]).unwrap();

        let ps1 = musig2::sign(sn1, &sk1, &key_agg, &agg_nonce, msg).unwrap();
        let ps2 = musig2::sign(sn2, &sk2, &key_agg, &agg_nonce, msg).unwrap();
        let ps3 = musig2::sign(sn3, &sk3, &key_agg, &agg_nonce, msg).unwrap();

        let sig = musig2::partial_sig_agg(&[ps1, ps2, ps3], &agg_nonce, &key_agg, msg).unwrap();
        assert!(musig2::verify(&sig, &key_agg.x_only_pubkey, msg).unwrap());
    }

    #[test]
    fn test_musig2_wrong_message_fails() {
        let sk1 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk2 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000002");
        let pk1 = musig2::individual_pubkey(&sk1).unwrap();
        let pk2 = musig2::individual_pubkey(&sk2).unwrap();
        let key_agg = musig2::key_agg(&[pk1, pk2]).unwrap();

        let (sn1, pn1) = musig2::nonce_gen(&sk1, &pk1, &key_agg, b"msg", &[]).unwrap();
        let (sn2, pn2) = musig2::nonce_gen(&sk2, &pk2, &key_agg, b"msg", &[]).unwrap();
        let agg_nonce = musig2::nonce_agg(&[pn1, pn2]).unwrap();

        let ps1 = musig2::sign(sn1, &sk1, &key_agg, &agg_nonce, b"msg").unwrap();
        let ps2 = musig2::sign(sn2, &sk2, &key_agg, &agg_nonce, b"msg").unwrap();

        let sig = musig2::partial_sig_agg(&[ps1, ps2], &agg_nonce, &key_agg, b"msg").unwrap();
        assert!(!musig2::verify(&sig, &key_agg.x_only_pubkey, b"wrong").unwrap());
    }

    #[test]
    fn test_musig2_key_sort() {
        let pk_a = [0x02u8; 33];
        let pk_b = [0x03u8; 33];
        let sorted = musig2::key_sort(&[pk_b, pk_a]);
        assert_eq!(sorted[0], pk_a); // 0x02 < 0x03
        assert_eq!(sorted[1], pk_b);
    }

    // BIP-327 key aggregation test vectors
    #[test]
    fn test_bip327_key_agg_vector_1() {
        let pubkeys_hex = [
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        ];
        let expected = "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C";

        let pubkeys: Vec<[u8; 33]> = pubkeys_hex.iter().map(|h| hex_to_33(h)).collect();
        let ctx = musig2::key_agg(&pubkeys).unwrap();
        let x_only_hex = hex::encode(ctx.x_only_pubkey).to_uppercase();
        assert_eq!(x_only_hex, expected);
    }

    #[test]
    fn test_bip327_key_agg_vector_2() {
        // Reversed order should give different result
        let pubkeys_hex = [
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        ];
        let expected = "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B";

        let pubkeys: Vec<[u8; 33]> = pubkeys_hex.iter().map(|h| hex_to_33(h)).collect();
        let ctx = musig2::key_agg(&pubkeys).unwrap();
        let x_only_hex = hex::encode(ctx.x_only_pubkey).to_uppercase();
        assert_eq!(x_only_hex, expected);
    }

    #[test]
    fn test_bip327_key_agg_vector_3_same_keys() {
        let pubkeys_hex = [
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        ];
        let expected = "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935";

        let pubkeys: Vec<[u8; 33]> = pubkeys_hex.iter().map(|h| hex_to_33(h)).collect();
        let ctx = musig2::key_agg(&pubkeys).unwrap();
        let x_only_hex = hex::encode(ctx.x_only_pubkey).to_uppercase();
        assert_eq!(x_only_hex, expected);
    }

    #[test]
    fn test_bip327_key_agg_vector_4_duplicate_pairs() {
        let pubkeys_hex = [
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        ];
        let expected = "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E";

        let pubkeys: Vec<[u8; 33]> = pubkeys_hex.iter().map(|h| hex_to_33(h)).collect();
        let ctx = musig2::key_agg(&pubkeys).unwrap();
        let x_only_hex = hex::encode(ctx.x_only_pubkey).to_uppercase();
        assert_eq!(x_only_hex, expected);
    }

    #[test]
    fn test_musig2_individual_pubkey_known_vector() {
        // privkey = 1 → pubkey is the generator point
        let sk = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let pk = musig2::individual_pubkey(&sk).unwrap();
        assert_eq!(
            hex::encode(pk).to_uppercase(),
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        );
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn hex_to_33(s: &str) -> [u8; 33] {
        let bytes = hex::decode(s).unwrap();
        let mut out = [0u8; 33];
        out.copy_from_slice(&bytes);
        out
    }

    // ─── Additional MuSig2 Coverage Tests ──────────────────

    #[test]
    fn test_musig2_single_signer() {
        let sk = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let pk = musig2::individual_pubkey(&sk).unwrap();
        let key_agg = musig2::key_agg(&[pk]).unwrap();

        let msg = b"single signer";
        let (sn, pn) = musig2::nonce_gen(&sk, &pk, &key_agg, msg, &[]).unwrap();
        let agg_nonce = musig2::nonce_agg(&[pn]).unwrap();
        let psig = musig2::sign(sn, &sk, &key_agg, &agg_nonce, msg).unwrap();
        let sig = musig2::partial_sig_agg(&[psig], &agg_nonce, &key_agg, msg).unwrap();
        assert!(musig2::verify(&sig, &key_agg.x_only_pubkey, msg).unwrap());
    }

    #[test]
    fn test_musig2_empty_pubkeys_rejected() {
        let result = musig2::key_agg(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_musig2_invalid_pubkey_rejected() {
        let bad_pk = [0x00u8; 33]; // All-zero is not a valid point
        let result = musig2::key_agg(&[bad_pk]);
        assert!(result.is_err());
    }

    #[test]
    fn test_musig2_different_messages_different_sigs() {
        let sk1 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let sk2 = hex_to_32("0000000000000000000000000000000000000000000000000000000000000002");
        let pk1 = musig2::individual_pubkey(&sk1).unwrap();
        let pk2 = musig2::individual_pubkey(&sk2).unwrap();
        let key_agg = musig2::key_agg(&[pk1, pk2]).unwrap();

        let make_sig = |msg: &[u8]| {
            let (sn1, pn1) = musig2::nonce_gen(&sk1, &pk1, &key_agg, msg, &[]).unwrap();
            let (sn2, pn2) = musig2::nonce_gen(&sk2, &pk2, &key_agg, msg, &[]).unwrap();
            let agg = musig2::nonce_agg(&[pn1, pn2]).unwrap();
            let ps1 = musig2::sign(sn1, &sk1, &key_agg, &agg, msg).unwrap();
            let ps2 = musig2::sign(sn2, &sk2, &key_agg, &agg, msg).unwrap();
            musig2::partial_sig_agg(&[ps1, ps2], &agg, &key_agg, msg).unwrap()
        };

        let sig_a = make_sig(b"message A");
        let sig_b = make_sig(b"message B");
        assert_ne!(sig_a.to_bytes(), sig_b.to_bytes());
    }

    #[test]
    fn test_musig2_signature_is_64_bytes() {
        let sk = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let pk = musig2::individual_pubkey(&sk).unwrap();
        let key_agg = musig2::key_agg(&[pk]).unwrap();
        let (sn, pn) = musig2::nonce_gen(&sk, &pk, &key_agg, b"test", &[]).unwrap();
        let agg = musig2::nonce_agg(&[pn]).unwrap();
        let psig = musig2::sign(sn, &sk, &key_agg, &agg, b"test").unwrap();
        let sig = musig2::partial_sig_agg(&[psig], &agg, &key_agg, b"test").unwrap();
        assert_eq!(sig.to_bytes().len(), 64);
    }

    #[test]
    fn test_musig2_nonce_agg_empty_rejected() {
        assert!(musig2::nonce_agg(&[]).is_err());
    }

    #[test]
    fn test_musig2_key_agg_deterministic() {
        let pk1 = hex_to_33("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let pk2 = hex_to_33("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
        let ctx1 = musig2::key_agg(&[pk1, pk2]).unwrap();
        let ctx2 = musig2::key_agg(&[pk1, pk2]).unwrap();
        assert_eq!(ctx1.x_only_pubkey, ctx2.x_only_pubkey);
    }

    #[test]
    fn test_musig2_key_sort_preserves_all() {
        let pk1 = hex_to_33("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
        let pk2 = hex_to_33("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
        let pk3 = hex_to_33("023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66");
        let sorted = musig2::key_sort(&[pk3, pk1, pk2]);
        assert_eq!(sorted.len(), 3);
        // pk1 (0x02F9...) should be last since 0x02F9 > 0x03
        // Actually 0x02 < 0x03, so pk1 and pk3 first
        assert!(sorted[0][0] <= sorted[1][0]);
        assert!(sorted[1][0] <= sorted[2][0]);
    }

    #[test]
    fn test_musig2_pubnonce_encoding() {
        let sk = hex_to_32("0000000000000000000000000000000000000000000000000000000000000001");
        let pk = musig2::individual_pubkey(&sk).unwrap();
        let key_agg = musig2::key_agg(&[pk]).unwrap();
        let (_, pn) = musig2::nonce_gen(&sk, &pk, &key_agg, b"test", &[]).unwrap();
        let bytes = pn.to_bytes();
        assert_eq!(bytes.len(), 66); // 33 + 33
    }

    #[test]
    fn test_musig2_zero_secret_key_rejected() {
        let zero = [0u8; 32];
        assert!(musig2::individual_pubkey(&zero).is_err());
    }
}
