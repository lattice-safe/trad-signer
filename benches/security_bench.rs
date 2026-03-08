//! Benchmarks for chains-sdk security operations.
//!
//! Compares constant-time vs standard implementations and measures
//! enclave-critical operations like GuardedMemory and scrypt KDF.
//!
//! Run with: `cargo bench --all-features --bench security_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

// ─── Constant-Time Hex vs Standard Hex ─────────────────────────────

fn bench_ct_hex_encode(c: &mut Criterion) {
    use chains_sdk::security::{ct_hex_decode, ct_hex_encode};

    let sizes: &[usize] = &[32, 64, 256, 1024];

    let mut group = c.benchmark_group("hex_encode");
    for &size in sizes {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();

        group.bench_with_input(BenchmarkId::new("ct_hex", size), &data, |b, data| {
            b.iter(|| ct_hex_encode(black_box(data)));
        });

        group.bench_with_input(BenchmarkId::new("hex_crate", size), &data, |b, data| {
            b.iter(|| hex::encode(black_box(data)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("hex_decode");
    for &size in sizes {
        let data: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        let hex_str = hex::encode(&data);

        group.bench_with_input(BenchmarkId::new("ct_hex", size), &hex_str, |b, s| {
            b.iter(|| ct_hex_decode(black_box(s)));
        });

        group.bench_with_input(BenchmarkId::new("hex_crate", size), &hex_str, |b, s| {
            b.iter(|| hex::decode(black_box(s)));
        });
    }
    group.finish();
}

// ─── GuardedMemory Allocation ──────────────────────────────────────

fn bench_guarded_memory(c: &mut Criterion) {
    use chains_sdk::security::GuardedMemory;

    let mut group = c.benchmark_group("guarded_memory");

    // Allocation (zeroed)
    for &size in &[32usize, 256, 4096] {
        group.bench_with_input(BenchmarkId::new("new", size), &size, |b, &size| {
            b.iter(|| {
                let guard = GuardedMemory::new(black_box(size));
                // Ensure the compiler doesn't elide the allocation
                assert_eq!(guard.len(), size);
            });
        });
    }

    // From existing Vec (takes ownership)
    for &size in &[32usize, 256, 4096] {
        group.bench_with_input(BenchmarkId::new("from_vec", size), &size, |b, &size| {
            b.iter(|| {
                let data = vec![0xAA_u8; size];
                let guard = GuardedMemory::from_vec(black_box(data));
                assert_eq!(guard.len(), size);
            });
        });
    }

    // Drop (zeroization on drop)
    for &size in &[32usize, 256, 4096] {
        group.bench_with_input(BenchmarkId::new("alloc_drop", size), &size, |b, &size| {
            b.iter(|| {
                let mut guard = GuardedMemory::new(size);
                guard.as_mut()[0] = 0xFF; // Touch to prevent elision
                drop(black_box(guard));
            });
        });
    }

    group.finish();
}

// ─── Secure Zero ───────────────────────────────────────────────────

fn bench_secure_zero(c: &mut Criterion) {
    use chains_sdk::security::secure_zero;

    let mut group = c.benchmark_group("secure_zero");
    for &size in &[32usize, 256, 4096] {
        group.bench_with_input(
            BenchmarkId::new("volatile_zero", size),
            &size,
            |b, &size| {
                let mut buf = vec![0xFF_u8; size];
                b.iter(|| {
                    // Reset to non-zero before measuring
                    buf.fill(0xFF);
                    secure_zero(black_box(&mut buf));
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("slice_fill", size), &size, |b, &size| {
            let mut buf = vec![0xFF_u8; size];
            b.iter(|| {
                buf.fill(0xFF);
                black_box(&mut buf).fill(0);
            });
        });
    }
    group.finish();
}

// ─── Scrypt KDF (Keystore Encrypt/Decrypt) ─────────────────────────

fn bench_scrypt_kdf(c: &mut Criterion) {
    use chains_sdk::ethereum::keystore::Keystore;
    use chains_sdk::ethereum::keystore::ScryptParams;

    let private_key = [0x42_u8; 32];
    let password = b"benchmark-password-2024";

    let mut group = c.benchmark_group("scrypt_kdf");

    // Light params for benchmarking (standard params are too slow for CI)
    let light_params = ScryptParams {
        n: 1 << 12, // 4096 (light = fast)
        r: 8,
        p: 1,
        dklen: 32,
    };

    // Encrypt (KDF + AES-128-CTR + HMAC)
    group.bench_function("encrypt_light", |b| {
        b.iter(|| {
            Keystore::encrypt(black_box(&private_key), black_box(password), &light_params).unwrap();
        });
    });

    // Create a keystore for decrypt benchmarking
    let keystore = Keystore::encrypt(&private_key, password, &light_params).unwrap();

    // Decrypt (KDF + AES-128-CTR + MAC verify)
    group.bench_function("decrypt_light", |b| {
        b.iter(|| {
            keystore.decrypt(black_box(password)).unwrap();
        });
    });

    // Standard params (1<<18 = 262144 — the Ethereum default)
    // Only included for reference; takes ~1s per iteration
    let standard_params = ScryptParams {
        n: 1 << 18, // 262144 (standard)
        r: 8,
        p: 1,
        dklen: 32,
    };

    group.sample_size(10); // Reduce samples for slow ops
    group.bench_function("encrypt_standard", |b| {
        b.iter(|| {
            Keystore::encrypt(
                black_box(&private_key),
                black_box(password),
                &standard_params,
            )
            .unwrap();
        });
    });

    let std_keystore = Keystore::encrypt(&private_key, password, &standard_params).unwrap();
    group.bench_function("decrypt_standard", |b| {
        b.iter(|| {
            std_keystore.decrypt(black_box(password)).unwrap();
        });
    });

    group.finish();
}

// ─── Solana PDA Derivation ─────────────────────────────────────────

fn bench_pda(c: &mut Criterion) {
    use chains_sdk::solana::transaction::{create_program_address, find_program_address};

    let program_id = [0xAA_u8; 32];

    let mut group = c.benchmark_group("solana_pda");

    group.bench_function("find_program_address", |b| {
        b.iter(|| {
            find_program_address(black_box(&[b"vault", &[1u8; 32]]), black_box(&program_id))
                .unwrap();
        });
    });

    group.bench_function("create_program_address", |b| {
        b.iter(|| {
            let _ = create_program_address(
                black_box(&[b"vault", &[1u8; 32]]),
                black_box(&[255]),
                black_box(&program_id),
            );
        });
    });

    group.finish();
}

// ─── Ed25519 Key Generation vs Signing (Baseline) ──────────────────

fn bench_ed25519_ops(c: &mut Criterion) {
    use chains_sdk::solana::SolanaSigner;
    use chains_sdk::solana::SolanaVerifier;
    use chains_sdk::traits::{KeyPair, Signer, Verifier};

    let mut group = c.benchmark_group("ed25519");
    let signer = SolanaSigner::from_bytes(&[0x42; 32]).unwrap();
    let message = b"benchmark message for ed25519 operations";

    group.bench_function("keygen", |b| {
        b.iter(|| SolanaSigner::generate().unwrap());
    });

    group.bench_function("sign", |b| {
        b.iter(|| signer.sign(black_box(message)));
    });

    group.bench_function("verify", |b| {
        let sig = signer.sign(message).unwrap();
        let pk = signer.public_key_bytes();
        let verifier = SolanaVerifier::from_public_key_bytes(&pk).unwrap();
        b.iter(|| {
            verifier.verify(black_box(message), &sig).unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_ct_hex_encode,
    bench_guarded_memory,
    bench_secure_zero,
    bench_scrypt_kdf,
    bench_pda,
    bench_ed25519_ops,
);
criterion_main!(benches);
