# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-03-08

### Added
- **EIP-191** `personal_sign()` / `verify_personal_sign()` / `eip191_hash()` (Ethereum)
- **Multi-message BLS** `verify_aggregated_multi()` for different messages per signer
- SDK serialization: `public_key_bytes_uncompressed()`, `from_keypair_bytes()`, `keypair_bytes()`
- Solana `scalar_bytes()` for clamped Ed25519 scalar export
- Signature `to_bytes()` / `from_bytes()` on all signature types
- `BlsPublicKey::to_bytes()` / `from_bytes()`
- Criterion benchmarks (`benches/signing_bench.rs`)
- `CHANGELOG.md`, `LICENSE-MIT`, `LICENSE-APACHE`
- 2 runnable examples: `ethereum_signing`, `multi_chain`

### Fixed
- BLS IKM zeroization: replaced manual loop with `zeroize::Zeroize` (prevents compiler optimization)

### Security
- Full security audit documented in project artifacts
- `Zeroizing<Vec<u8>>` on all key exports, `ZeroizeOnDrop` on all signing keys

## [0.1.0] - 2026-03-07

### Added
- Ethereum ECDSA (secp256k1 + Keccak-256, EIP-2 Low-S, EIP-712 typed data)
- Bitcoin ECDSA (secp256k1 + double-SHA-256, DER encoding, RFC 6979)
- Bitcoin Schnorr (BIP-340, x-only public keys, tagged hashes)
- NEO ECDSA (P-256/secp256r1 + SHA-256)
- XRP ECDSA (secp256k1 + SHA-512 half) and Ed25519
- Solana Ed25519 (RFC 8032, bit-exact test vectors)
- BLS12-381 (Ethereum PoS, single signing + aggregation)
- Unified `Signer`, `Verifier`, `KeyPair` traits
- CI pipeline (`.github/workflows/ci.yml`)
- 4 fuzz targets
- `SECURITY.md`, `README.md`, `deny.toml`
