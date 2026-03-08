# Changelog

## [0.8.0] — 2026-03-09

### ⚠ Breaking Changes
- **`EthereumSignature.v`**: Changed from `u8` to `u64` to support EIP-155 chain IDs > 110 (Polygon, Arbitrum, Base, Optimism, Sepolia, etc.)
- Added `recovery_bit()` method and `to_bytes_eip155()` for large chain ID signatures

### Fixed
- **Private key leak in `keypair_bytes()`**: No longer copies private key into unprotected `Vec` before re-wrapping in `Zeroizing`
- **All 7 signers' `generate()` now use `secure_random()`**: Ethereum, Bitcoin, Schnorr, Solana, NEO, XRP ECDSA, XRP EdDSA — `set_custom_rng()` is now honored in TEE environments
- **`ct_hex_val` fully branchless**: Returns `(value, mask)` tuple — no data-dependent branches
- **`ct_hex_decode` timing leak**: No longer returns early on odd-length input
- **`validate_address` constant-time**: XRP and NEO checksum validation uses `subtle::ConstantTimeEq`
- **`GuardedMemory` mlock pointer stability**: Inner storage changed from `Vec<u8>` to `Box<[u8]>` — never reallocates, mlock'd pointer guaranteed stable
- **`to_seed` salt leak**: Salt `String` containing passphrase is now zeroized after PBKDF2

### Added
- **BLS re-exported from `ethereum::bls`**: BLS12-381 accessible via `ethereum::bls` (top-level `bls` kept for compat)
- **`Display`** for `XrpSignature`, `BlsSignature`, `NeoSignature`
- **`PartialEq`/`Eq`** derived for all 7 signature types
- **`#[must_use]`** on all 7 signature types

### Changed
- **Mnemonic word lookup**: `from_phrase()` uses binary search (was O(n) linear scan)
- **`bip85::entropy_to_mnemonic`**: Delegates to `Mnemonic::from_entropy` (eliminated duplicate implementation)

## [0.7.0] — 2026-03-09

### Added
- **SECURITY.md**: Vulnerability reporting policy and security model documentation
- **CONTRIBUTING.md**: Contributor guide with code quality and security standards
- **Display for signature types**: `BitcoinSignature`, `EthereumSignature`, `SolanaSignature` now implement `Display` (hex-formatted output)
- **Branchless constant-time hex**: `ct_hex_val` rewritten with arithmetic masks (no data-dependent branches)

### Fixed
- **CLI feature gates**: All chain references in `chains_sdk` binary are now `#[cfg(feature = "...")]` gated — `--no-default-features` compiles correctly
- **`missing_docs`**: Elevated from `warn` to `deny` — all public items must be documented
- **Ignored doc-tests**: Converted `set_custom_rng` and `EnclaveContext` examples from `ignore` to `no_run`
- **Unsafe safety docs**: Added `// SAFETY:` comments to all `#[allow(unsafe_code)]` blocks in `mlock`
- **Custom RNG**: Replaced `thread_local!` with `OnceLock`-based global — works correctly in multi-threaded enclave environments

### Changed
- **CI hardening**: Added MSRV (1.75) check, WASM compilation check, fuzz CI job, and expanded feature matrix to cover `frost`, `musig2`, `hd_key`, `mnemonic`, `bip85`, `serde`, `custom_rng`, `mlock`

## [0.6.0] — 2026-03-08

### Added
- **Enclave security module**: `security.rs` with `GuardedMemory`, `ct_hex_encode`, `ct_hex_decode`, `secure_random`, `rotate_key`, `EnclaveContext` trait
- **Pluggable RNG**: `set_custom_rng()` / `clear_custom_rng()` for TEE environments (requires `custom_rng` feature)
- **Memory locking**: `mlock` feature for preventing sensitive data from being swapped to disk
- **BLS threshold signatures**: `bls::threshold` module with t-of-n keygen and signing
- **EIP-2333/2334/2335**: BLS key derivation and keystore support
- **Serde support**: Optional `serde` feature for key and signature serialization

## [0.5.0] — 2026-03-08

### ⚠ Breaking Changes
- `to_wif()` now returns `Zeroizing<String>` instead of `String`
- `to_xprv()` now returns `Zeroizing<String>` instead of `String`

### Added — Round 3
- **BIP-322 Verification**: `verify_simple_p2wpkh()` and `verify_simple_p2tr()` counterparts to the signing functions
- **PSBT Signing**: `Psbt::sign_segwit_input()` for P2WPKH and `Psbt::sign_taproot_input()` for P2TR — auto-compute sighash and store signatures
- **Taproot Address from xpub**: `ExtendedPublicKey::p2tr_address()` and `p2wpkh_address()` for watch-only address derivation
- **Transaction Parser**: `parse_unsigned_tx()` — deserialize raw unsigned transactions

### Added — Round 2
- **BIP-342**: `taproot_script_path_sighash()` — script-path spending with tapleaf hash, key_version, codesep_pos
- **ExtendedPublicKey Tests**: 10 dedicated tests (derivation consistency, xpub round-trip, chain derivation)
- **Fuzz Targets**: 4 targets (`fuzz_from_wif`, `fuzz_from_xprv`, `fuzz_psbt_deserialize`, `fuzz_mnemonic_from_phrase`)

### Added — Round 1
- **Transaction Builder**: `transaction.rs` with legacy + SegWit serialization, txid, wtxid, vsize
- **BIP-143/341 Sighash**: `sighash.rs` with `segwit_v0_sighash()` and `taproot_key_path_sighash()`
- **BIP-322 Signing**: `sign_simple_p2wpkh()` and `sign_simple_p2tr()`
- **ExtendedPublicKey**: xpub serialization, normal child derivation, BIP-32 public key derivation
- **PSBT Parser**: `Psbt::deserialize()` with BIP-371 Taproot extensions
- **Doc-tests**: Converted 10 `ignore` examples to `no_run`

### Fixed
- All clippy warnings resolved (0 warnings across all targets)
- `#[must_use]` on 10+ functions
- Constant-time checksum comparisons via `subtle`
- `div_ceil` migration from manual to std

## [0.4.0]

Initial release with multi-chain signing support.
