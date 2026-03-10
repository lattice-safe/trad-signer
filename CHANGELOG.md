# Changelog

## [1.0.0] — 2026-03-11

### 🎉 Production-Ready Release

Marks the completion of a comprehensive three-phase security audit cycle across all modules, BIP/EIP/RFC compliance verification, and full test vector validation.

### Fixed — Deep Audit Security Findings
- **NEO `from_wif()`**: Constant-time checksum comparison via `subtle::ConstantTimeEq` (was timing-attackable `!=`)
- **XRP `decode_x_address()`**: Constant-time checksum comparison via `subtle::ConstantTimeEq`
- **Bitcoin `validate_base58check()`**: Constant-time checksum comparison via `subtle::ConstantTimeEq`

### Added — Test Vectors
- **BIP-32 Vector 3** (edge-case seed) — master + m/0' with xprv/xpub verification
- **BIP-32 xpub derivation consistency** — verifies public-only normal child derivation matches private path for indices 0-4
- **BIP-85 xprv import consistency** — verifies `from_xprv` and `from_seed` produce identical entropy derivations
- **BIP-85 entropy validation** — determinism, non-zero, mnemonic parseability checks

### Added — Integration Tests
- **BLS multi-message attestation** — 5 validators sign different slot attestations, aggregate verify via `verify_aggregated_multi`
- **All-chain address validation** — generates keys for all 5 chains (ETH, BTC, SOL, XRP, NEO) across 7 address formats and validates each
- **NEO WIF roundtrip** — export → import → sign → verify chain
- **XRP X-Address roundtrip** — encode with destination tag → decode → verify account_id and tag preservation

### Changed
- Test count: 1,614 → 1,805 (1,534 unit + 50 integration + 42 doc + 179 other)
- 0 clippy warnings across all features with `-D warnings`
- All constant-time checksums unified: every Base58Check decode path uses `subtle::ConstantTimeEq`

### Verified Standards Compliance
- **BIP**: 32, 39, 44, 84, 85, 86, 137, 143, 174, 322, 327, 340, 341, 342, 380-386
- **EIP**: 2, 55, 155, 191, 712, 1559, 2333, 2334, 2335, 2612, 2718, 2930, 3009, 3074, 4337, 4494, 4844, 6492, 7702
- **RFC**: 6979, 8032, 9591

## [0.9.0] — 2026-03-09

### ⚠ Breaking Changes
- **`SwapSecret::generate()`** now returns `Result<Self, SignerError>` instead of `Self` — callers must handle potential RNG failures
- **Permit2 amount fields** widened from `u64` to `u128` (`PermitSingle`, `PermitBatch`, `PermitTransferFrom`, `PermitBatchTransferFrom`, `TokenPermissions`)
- **`encode_transfer_from()` amount** widened from `u64` to `u128`
- **`deposit_governing_tokens()`** now requires a `token_owner_record: &[u8; 32]` parameter
- **`cast_vote()`** now requires a `vote_record: &[u8; 32]` parameter
- **`SwapParams`** gains a `slippage_bound: u64` field

### Added — Phase 5 (Bitcoin + Ethereum)
- **`atomic_swap`** — Cross-chain HTLC atomic swaps:
  - `SwapSecret` (generate, verify, from_preimage) with `Zeroize + ZeroizeOnDrop`
  - Bitcoin HTLC script builder (`build_htlc_script`)
  - EVM HTLC ABI encoding (`encode_new_contract`, `encode_claim`, `encode_refund`)
  - End-to-end swap flow helpers
- **`bitcoin::ordinals`** — Ordinals/Inscriptions (BIP-based):
  - `Inscription` builder with content type, body, metadata, rune, parent, delegate
  - `build_commit_output()` / `build_reveal_script()` for inscription workflow
  - `push_data` with full OP_PUSHDATA1/2/4 support
- **`ethereum::userop`** — ERC-4337 UserOperation v0.6:
  - `UserOperation` struct with `hash()`, `pack()`, `encode_handle_ops()`
  - Gas estimation helpers, paymaster encoding, initcode builder
- **`solana::staking`** — Native SOL staking:
  - `create_stake_account()`, `delegate_stake()`, `deactivate_stake()`, `withdraw_stake()`
  - Stake authority management, lockup support

### Added — Phase 6 (Ethereum + Solana)
- **`ethereum::permit2`** — Uniswap Permit2 (EIP-712):
  - `PermitSingle`, `PermitBatch` with struct hashing
  - `PermitTransferFrom`, `PermitBatchTransferFrom` (signature transfers)
  - ABI-encoded calldata: `encode_permit_single_call()`, `encode_transfer_from()`
  - `PERMIT2_ADDRESS` constant with hex verification test
- **`ethereum::uniswap_v4`** — Uniswap V4 Hooks/Pools:
  - `PoolKey`, `SwapParams` with `exact_input()` / `exact_output()` + slippage bounds
  - `encode_swap()`, `encode_modify_liquidity()`, `encode_initialize()`
  - `MIN/MAX_SQRT_RATIO`, `MIN/MAX_TICK` constants
- **`solana::governance`** — SPL Governance:
  - `create_realm()`, `deposit_governing_tokens()`, `create_proposal()`, `cast_vote()`
  - Vote types: Approve, Deny, Abstain, Veto
  - PDA accounts now explicit parameters (not hardcoded placeholders)
- **`solana::jupiter_dca`** — Jupiter DCA:
  - `DcaParams` with public `serialize()` method
  - `open_dca()`, `close_dca()` instruction builders

### Fixed — Code Review (13 findings)
- **C-1**: `SwapSecret::generate()` no longer silently drops RNG errors
- **C-2**: Token amounts use `u128` (was `u64`) — supports full `uint160` range
- **M-1**: Shared `keccak256()` in `ethereum/mod.rs` — removed 2 duplicate implementations
- **M-2**: Removed duplicate `OP_0`/`OP_FALSE` constant in ordinals
- **M-3**: `SwapSecret` derives `Zeroize + ZeroizeOnDrop` for secure memory cleanup
- **M-4**: `SwapParams` stores slippage bound (was silently discarding `min_out`/`max_in`)
- **M-5**: Governance PDA accounts are now explicit function parameters

### Changed
- Test count: 1,119 → 1,463 (344 new tests across 8 modules)
- Fuzzing harness: 6 fuzz targets (ABI, RLP, hex, BIP-39, PSBT, Permit2)
- `--no-default-features` build fixed: examples feature-gated in `Cargo.toml`
- README updated with Phase 5/6 module examples

## [0.8.1] — 2026-03-09

### Added
- **`ethereum::safe`** — Gnosis Safe multisig support:
  - `SafeTransaction` with EIP-712 typed signing (`safeTxHash`)
  - `encode_exec_transaction()` calldata encoding
  - `encode_signatures()` / `decode_signatures()` for multi-sig packing
  - Management: `addOwnerWithThreshold`, `removeOwner`, `changeThreshold`, `swapOwner`, `enableModule`, `disableModule`, `setGuard`
  - Query: `getOwners()`, `getThreshold()`, `nonce()`, `getTransactionHash()`
- **`ethereum::proxy`** — UUPS / Transparent / Beacon proxy support:
  - EIP-1967 storage slot constants (`IMPLEMENTATION_SLOT`, `ADMIN_SLOT`, `BEACON_SLOT`)
  - `eip1967_slot()` dynamic computation
  - UUPS: `upgradeTo`, `upgradeToAndCall`, `proxiableUUID`
  - Transparent: `changeAdmin`, `admin`
  - Multicall3: `aggregate3` encoding with `Multicall3Call`, legacy `aggregate` support
- **`ethereum::smart_wallet`** — EIP-4337 v0.7 Account Abstraction:
  - `PackedUserOperation` (v0.7 packed format) with `pack()`, `hash()`, `sign()`
  - Gas packing: `pack_account_gas_limits()`, `pack_gas_fees()` and unpacking
  - `encode_handle_ops()` for EntryPoint v0.7
  - Paymaster: `encode_paymaster_data()` / `decode_paymaster_data()`
  - Smart wallet: `encode_execute()`, `encode_execute_batch()`
  - ERC-1271: `encode_is_valid_signature()`, `is_valid_signature_magic()`
  - Account factory: `encode_create_account()`, `encode_get_address()`
  - Nonce: `encode_get_nonce()`

### Changed
- Test count: 1,006 → 1,119 (110 new tests across 3 modules)
- README updated with Safe, Proxy, and Smart Wallet examples

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
