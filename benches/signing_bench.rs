//! Benchmarks for trad-signer signing operations.
//!
//! Run with: `cargo bench --all-features`

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_ethereum(c: &mut Criterion) {
    use trad_signer::ethereum::{EthereumSigner, EthereumVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

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
    use trad_signer::bitcoin::{BitcoinSigner, BitcoinVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

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
    use trad_signer::bitcoin::schnorr::{SchnorrSigner, SchnorrVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

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
    use trad_signer::solana::{SolanaSigner, SolanaVerifier};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

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
    use trad_signer::bls::{BlsSigner, BlsVerifier, aggregate_signatures, verify_aggregated};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    let signer = BlsSigner::generate().unwrap();
    let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
    let msg = b"benchmark message for bls12-381";
    let sig = signer.sign(msg).unwrap();

    c.bench_function("bls_keygen", |b| {
        b.iter(|| BlsSigner::generate().unwrap())
    });
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

criterion_group!(benches, bench_ethereum, bench_bitcoin, bench_schnorr, bench_solana, bench_bls);
criterion_main!(benches);
