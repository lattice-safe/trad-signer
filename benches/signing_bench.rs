//! Benchmarks for chains-sdk signing operations.
//!
//! Run with: `cargo bench --all-features`

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_ethereum(c: &mut Criterion) {
    use chains_sdk::ethereum::{EthereumSigner, EthereumVerifier};
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let signer = EthereumSigner::generate().unwrap();
    let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for ethereum ecdsa";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("eth_keygen", |b| {
        b.iter(|| EthereumSigner::generate().unwrap())
    });
    c.bench_function("eth_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("eth_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
    c.bench_function("eth_personal_sign", |b| {
        b.iter(|| signer.personal_sign(black_box(msg)).unwrap())
    });
}

fn bench_bitcoin(c: &mut Criterion) {
    use chains_sdk::bitcoin::{BitcoinSigner, BitcoinVerifier};
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let signer = BitcoinSigner::generate().unwrap();
    let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for bitcoin ecdsa";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("btc_keygen", |b| {
        b.iter(|| BitcoinSigner::generate().unwrap())
    });
    c.bench_function("btc_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("btc_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_schnorr(c: &mut Criterion) {
    use chains_sdk::bitcoin::schnorr::{SchnorrSigner, SchnorrVerifier};
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let signer = SchnorrSigner::generate().unwrap();
    let verifier = SchnorrVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for schnorr bip340";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("schnorr_keygen", |b| {
        b.iter(|| SchnorrSigner::generate().unwrap())
    });
    c.bench_function("schnorr_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("schnorr_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_solana(c: &mut Criterion) {
    use chains_sdk::solana::{SolanaSigner, SolanaVerifier};
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let signer = SolanaSigner::generate().unwrap();
    let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for solana ed25519";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("sol_keygen", |b| {
        b.iter(|| SolanaSigner::generate().unwrap())
    });
    c.bench_function("sol_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("sol_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_bls(c: &mut Criterion) {
    use chains_sdk::bls::{aggregate_signatures, verify_aggregated, BlsSigner, BlsVerifier};
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let signer = BlsSigner::generate().unwrap();
    let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for bls12-381";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("bls_keygen", |b| b.iter(|| BlsSigner::generate().unwrap()));
    c.bench_function("bls_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("bls_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });

    // Aggregation benchmark (10 signatures)
    let signers: Vec<BlsSigner> = (0..10).map(|_| BlsSigner::generate().unwrap()).collect();
    let sigs: Vec<_> = signers.iter().map(|s| s.sign(msg).unwrap()).collect();
    let pks: Vec<_> = signers.iter().map(|s| s.public_key()).collect();
    let agg = aggregate_signatures(&sigs).unwrap();

    c.bench_function("bls_aggregate_10", |b| {
        b.iter(|| aggregate_signatures(black_box(&sigs)).unwrap())
    });
    c.bench_function("bls_verify_agg_10", |b| {
        b.iter(|| verify_aggregated(black_box(&pks), black_box(msg), black_box(&agg)).unwrap())
    });
}

fn bench_bls_threshold(c: &mut Criterion) {
    use chains_sdk::bls::threshold;

    let kgen = threshold::threshold_keygen(2, 3).unwrap();
    let msg = b"bls threshold bench";

    c.bench_function("bls_threshold_2of3_keygen", |b| {
        b.iter(|| threshold::threshold_keygen(black_box(2), black_box(3)).unwrap())
    });
    c.bench_function("bls_threshold_partial_sign", |b| {
        b.iter(|| kgen.key_shares[0].sign(black_box(msg)).unwrap())
    });
    c.bench_function("bls_threshold_2of3_full", |b| {
        b.iter(|| {
            let p1 = kgen.key_shares[0].sign(msg).unwrap();
            let p2 = kgen.key_shares[1].sign(msg).unwrap();
            let agg = threshold::aggregate_partial_sigs(&[p1, p2], msg).unwrap();
            black_box(agg)
        })
    });
}

fn bench_bls_eip2333(c: &mut Criterion) {
    use chains_sdk::bls::eip2333;

    let seed = [0xABu8; 64];
    let master = eip2333::derive_master_sk(&seed).unwrap();

    c.bench_function("eip2333_derive_master", |b| {
        b.iter(|| eip2333::derive_master_sk(black_box(&seed)).unwrap())
    });
    c.bench_function("eip2333_derive_child", |b| {
        b.iter(|| eip2333::derive_child_sk(black_box(&master), black_box(0)).unwrap())
    });
    c.bench_function("eip2333_validator_path", |b| {
        b.iter(|| eip2333::derive_key_from_path(black_box(&seed), &[12381, 3600, 0, 0, 0]).unwrap())
    });
}

criterion_group!(
    benches,
    bench_ethereum,
    bench_bitcoin,
    bench_schnorr,
    bench_solana,
    bench_bls,
    bench_bls_threshold,
    bench_bls_eip2333,
    bench_xrp,
    bench_neo,
    bench_hd_key,
    bench_musig2,
    bench_frost,
    bench_mnemonic,
    bench_sighash,
    bench_transaction,
    bench_xpub,
);
criterion_main!(benches);

fn bench_xrp(c: &mut Criterion) {
    use chains_sdk::traits::{KeyPair, Signer, Verifier};
    use chains_sdk::xrp::{XrpEcdsaSigner, XrpEcdsaVerifier, XrpEddsaSigner, XrpEddsaVerifier};

    let msg = b"benchmark message for xrp";

    // ECDSA
    let ecdsa = XrpEcdsaSigner::generate().unwrap();
    let ecdsa_v = XrpEcdsaVerifier::from_public_key_bytes(&ecdsa.public_key_bytes()).unwrap();
    let ecdsa_sig = ecdsa.sign(msg).unwrap();

    c.bench_function("xrp_ecdsa_sign", |b| {
        b.iter(|| ecdsa.sign(black_box(msg)).unwrap())
    });
    c.bench_function("xrp_ecdsa_verify", |b| {
        b.iter(|| {
            ecdsa_v
                .verify(black_box(msg), black_box(&ecdsa_sig))
                .unwrap()
        })
    });

    // EdDSA
    let eddsa = XrpEddsaSigner::generate().unwrap();
    let eddsa_v = XrpEddsaVerifier::from_public_key_bytes(&eddsa.public_key_bytes()).unwrap();
    let eddsa_sig = eddsa.sign(msg).unwrap();

    c.bench_function("xrp_eddsa_sign", |b| {
        b.iter(|| eddsa.sign(black_box(msg)).unwrap())
    });
    c.bench_function("xrp_eddsa_verify", |b| {
        b.iter(|| {
            eddsa_v
                .verify(black_box(msg), black_box(&eddsa_sig))
                .unwrap()
        })
    });
}

fn bench_neo(c: &mut Criterion) {
    use chains_sdk::neo::{NeoSigner, NeoVerifier};
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let signer = NeoSigner::generate().unwrap();
    let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for neo p256";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("neo_keygen", |b| b.iter(|| NeoSigner::generate().unwrap()));
    c.bench_function("neo_sign", |b| {
        b.iter(|| signer.sign(black_box(msg)).unwrap())
    });
    c.bench_function("neo_verify", |b| {
        b.iter(|| verifier.verify(black_box(msg), black_box(&sig)).unwrap())
    });
}

fn bench_hd_key(c: &mut Criterion) {
    use chains_sdk::hd_key::{DerivationPath, ExtendedPrivateKey};

    let seed = [0x42u8; 64];
    let master = ExtendedPrivateKey::from_seed(&seed).unwrap();

    c.bench_function("hd_derive_eth_m44_60_0_0_0", |b| {
        b.iter(|| {
            master
                .derive_path(black_box(&DerivationPath::ethereum(0)))
                .unwrap()
        })
    });
    c.bench_function("hd_derive_btc_m84_0_0_0_0", |b| {
        b.iter(|| {
            master
                .derive_path(black_box(&DerivationPath::bitcoin_segwit(0)))
                .unwrap()
        })
    });
}

fn bench_musig2(c: &mut Criterion) {
    use chains_sdk::threshold::musig2::signing::*;

    let sk1 = [0x11u8; 32];
    let sk2 = [0x22u8; 32];
    let pk1 = individual_pubkey(&sk1).unwrap();
    let pk2 = individual_pubkey(&sk2).unwrap();
    let ctx = key_agg(&[pk1, pk2]).unwrap();
    let msg = b"musig2 bench";

    c.bench_function("musig2_2of2_full_sign", |b| {
        b.iter(|| {
            let (s1, p1) = nonce_gen(&sk1, &pk1, &ctx, msg, &[]).unwrap();
            let (s2, p2) = nonce_gen(&sk2, &pk2, &ctx, msg, &[]).unwrap();
            let an = nonce_agg(&[p1, p2]).unwrap();
            let ps1 = sign(s1, &sk1, &ctx, &an, msg).unwrap();
            let ps2 = sign(s2, &sk2, &ctx, &an, msg).unwrap();
            let sig = partial_sig_agg(&[ps1, ps2], &an, &ctx, msg).unwrap();
            black_box(sig)
        })
    });
}

fn bench_frost(c: &mut Criterion) {
    use chains_sdk::threshold::frost::{keygen, signing};

    let secret = [0x42u8; 32];
    let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
    let group_pk = kgen.group_public_key;
    let msg = b"frost bench";

    c.bench_function("frost_2of3_full_sign", |b| {
        b.iter(|| {
            let n1 = signing::commit(&kgen.key_packages[0]).unwrap();
            let n2 = signing::commit(&kgen.key_packages[1]).unwrap();
            let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
            let s1 = signing::sign(&kgen.key_packages[0], n1, &comms, msg).unwrap();
            let s2 = signing::sign(&kgen.key_packages[1], n2, &comms, msg).unwrap();
            let sig = signing::aggregate(&comms, &[s1, s2], &group_pk, msg).unwrap();
            black_box(sig)
        })
    });
}

fn bench_mnemonic(c: &mut Criterion) {
    use chains_sdk::mnemonic::Mnemonic;

    c.bench_function("mnemonic_generate_12", |b| {
        b.iter(|| Mnemonic::generate(12).unwrap())
    });
    c.bench_function("mnemonic_to_seed", |b| {
        let m = Mnemonic::generate(12).unwrap();
        b.iter(|| m.to_seed(black_box("")))
    });
}

// ─── NEW: Sighash benchmarks ───────────────────────────────────────

fn bench_sighash(c: &mut Criterion) {
    use chains_sdk::bitcoin::sighash;
    use chains_sdk::bitcoin::tapscript::SighashType;
    use chains_sdk::bitcoin::transaction::*;

    // Build a realistic 2-input, 2-output transaction
    let mut tx = Transaction::new(2);
    for i in 0u8..2 {
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: [i; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
    }
    for _ in 0..2 {
        tx.outputs.push(TxOut {
            value: 50_000,
            script_pubkey: vec![
                0x00, 0x14, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
                0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            ],
        });
    }

    let prev_out = sighash::PrevOut {
        script_code: sighash::p2wpkh_script_code(&[0xCC; 20]),
        value: 100_000,
    };

    c.bench_function("sighash_segwit_v0", |b| {
        b.iter(|| {
            sighash::segwit_v0_sighash(black_box(&tx), 0, black_box(&prev_out), SighashType::All)
                .unwrap()
        })
    });

    let prevouts: Vec<TxOut> = (0..2)
        .map(|_| TxOut {
            value: 100_000,
            script_pubkey: {
                let mut spk = vec![0x51, 0x20];
                spk.extend_from_slice(&[0xCC; 32]);
                spk
            },
        })
        .collect();

    c.bench_function("sighash_taproot_key_path", |b| {
        b.iter(|| {
            sighash::taproot_key_path_sighash(
                black_box(&tx),
                0,
                black_box(&prevouts),
                SighashType::Default,
            )
            .unwrap()
        })
    });

    let leaf_hash = [0xDD; 32];
    c.bench_function("sighash_taproot_script_path", |b| {
        b.iter(|| {
            sighash::taproot_script_path_sighash(
                black_box(&tx),
                0,
                black_box(&prevouts),
                SighashType::Default,
                black_box(&leaf_hash),
                0xFFFFFFFF,
            )
            .unwrap()
        })
    });
}

// ─── NEW: Transaction serialization benchmarks ─────────────────────

fn bench_transaction(c: &mut Criterion) {
    use chains_sdk::bitcoin::transaction::*;

    // 2-in, 2-out transaction with witness
    let mut tx = Transaction::new(2);
    for i in 0u8..2 {
        tx.inputs.push(TxIn {
            previous_output: OutPoint {
                txid: [i; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xFFFFFFFF,
        });
    }
    for _ in 0..2 {
        tx.outputs.push(TxOut {
            value: 50_000,
            script_pubkey: vec![
                0x00, 0x14, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            ],
        });
    }
    tx.witnesses.push(vec![vec![0x30; 72], vec![0x02; 33]]);
    tx.witnesses.push(vec![vec![0x30; 71], vec![0x02; 33]]);

    c.bench_function("tx_serialize_legacy", |b| {
        b.iter(|| black_box(tx.serialize_legacy()))
    });
    c.bench_function("tx_serialize_witness", |b| {
        b.iter(|| black_box(tx.serialize_witness()))
    });
    c.bench_function("tx_txid", |b| b.iter(|| black_box(tx.txid())));
    c.bench_function("tx_vsize", |b| b.iter(|| black_box(tx.vsize())));

    let raw = tx.serialize_legacy();
    c.bench_function("tx_parse_unsigned", |b| {
        b.iter(|| parse_unsigned_tx(black_box(&raw)).unwrap())
    });
}

// ─── NEW: ExtendedPublicKey + address benchmarks ───────────────────

fn bench_xpub(c: &mut Criterion) {
    use chains_sdk::hd_key::ExtendedPrivateKey;

    let seed = [0x42u8; 64];
    let master = ExtendedPrivateKey::from_seed(&seed).unwrap();
    let xpub = master.to_extended_public_key().unwrap();
    let xpub_str = xpub.to_xpub();

    c.bench_function("xpub_derive_child_normal", |b| {
        b.iter(|| xpub.derive_child_normal(black_box(0)).unwrap())
    });
    c.bench_function("xpub_to_xpub_string", |b| {
        b.iter(|| black_box(xpub.to_xpub()))
    });
    c.bench_function("xpub_from_xpub_string", |b| {
        b.iter(|| chains_sdk::hd_key::ExtendedPublicKey::from_xpub(black_box(&xpub_str)).unwrap())
    });
    c.bench_function("xpub_p2wpkh_address", |b| {
        b.iter(|| xpub.p2wpkh_address(black_box("bc")).unwrap())
    });
    c.bench_function("xpub_p2tr_address", |b| {
        b.iter(|| xpub.p2tr_address(black_box("bc")).unwrap())
    });
}
