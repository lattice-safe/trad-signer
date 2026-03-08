# Contributing to chains-sdk

Thank you for your interest in contributing to chains-sdk!

## Getting Started

```bash
git clone https://github.com/lattice-safe/chains-sdk.git
cd chains-sdk
cargo test --all-features
```

## Development Requirements

- **Rust**: 1.75 or later (check `rust-version` in `Cargo.toml`)
- **C compiler**: required for the `bls` feature (builds `blst`)

## Running Tests

```bash
# Full test suite (all features)
cargo test --all-features

# Single feature isolation
cargo test --no-default-features --features ethereum

# Clippy (must pass with zero warnings)
cargo clippy --all-features -- -D warnings

# Format check
cargo fmt --check

# Dependency audit
cargo install cargo-deny --locked
cargo deny check advisories licenses bans
```

## Code Quality Standards

This is a **cryptographic signing library**. All contributions must meet:

1. **Zero unsafe code** — `#![deny(unsafe_code)]` (except `mlock` feature with audited `libc` calls)
2. **Zero panic surface** — `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`
3. **Zero clippy warnings** — `cargo clippy --all-features -- -D warnings`
4. **All public items documented** — `#![deny(missing_docs)]`
5. **All key material in `Zeroizing`** — no raw `Vec<u8>` for secrets

## Security Guidelines

- Use `subtle::ConstantTimeEq` for all secret comparisons
- Use `Zeroizing<T>` for all key material returns
- Use `secure_random()` instead of `getrandom` directly
- Never log or format secret key bytes in error messages
- Add test vectors from official standards (BIP, RFC, NIST, EIP)

## Pull Request Process

1. Fork and create a feature branch
2. Add tests for new functionality
3. Ensure `cargo test --all-features` passes
4. Ensure `cargo clippy --all-features -- -D warnings` is clean
5. Update CHANGELOG.md
6. Submit a PR with a clear description

## License

By contributing, you agree that your contributions will be licensed under MIT OR Apache-2.0.
