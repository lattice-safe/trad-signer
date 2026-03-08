---
name: chains-sdk
description: Multi-chain cryptographic signing SDK for Rust. Use when working with this codebase — key generation, signing, address derivation, HD keys, BIP-39/85, FROST/MuSig2 threshold signatures, or any chain-specific operations (Ethereum, Bitcoin, Solana, XRP, NEO, BLS). Covers the full API surface, security invariants, feature system, and Ethereum ecosystem context (wallets, standards, L2s, security, audit).
---

# chains-sdk — Comprehensive Development Skill

## Project Overview

**chains-sdk** is a unified, secure multi-chain signing SDK for Rust (v0.8.0). It provides cryptographic signing across 5 blockchains and 8 algorithms from a single crate.

| Metric | Value |
|--------|-------|
| Source | ~28,000 lines across 56 `.rs` files |
| Tests | 1,006 (all passing, 0 ignored) |
| Clippy | 0 warnings |
| MSRV | Rust 1.75 |

## What You Probably Got Wrong

1. **The `v` field in `EthereumSignature` is `u64` (since v0.8.0).** It supports EIP-155 chain IDs of any size. Use `recovery_bit()` to extract the 0/1 recovery value. Use `to_bytes()` for legacy 65-byte encoding or `to_bytes_eip155()` for full-fidelity encoding.
2. **Ed25519 keys for Solana are NOT derived from BIP-32.** BIP-32 produces secp256k1 keys. The raw 32-byte seed from HD derivation is used directly as the Ed25519 seed.
3. **`to_wif()` and `to_xprv()` return `Zeroizing<String>`**, not `String`. You must dereference with `&*wif` or `.as_str()` equivalent.
4. **FROST nonces are single-use.** After calling `signing::sign()`, the nonce is consumed (moved). Creating a second signature requires new `commit()` calls.
5. **`custom_rng` is a separate feature.** Use `set_custom_rng()` only with the `custom_rng` feature enabled. It uses `OnceLock` — can only be set once per process.
6. **`missing_docs` is `deny`, not `warn`.** Every public item MUST have a doc comment or compilation fails.
7. **All `generate()` methods use `secure_random()`**, not `OsRng`. If you set a custom RNG via `set_custom_rng()`, all key generation respects it.
8. **All signature types derive `PartialEq`, `Eq` and are `#[must_use]`.** BLS is accessible via both `bls::` and `ethereum::bls::`.

---

## Architecture

```
src/
├── lib.rs              # Crate root: #![deny(unsafe_code, missing_docs)]
├── traits.rs           # Signer, Verifier, KeyPair traits
├── error.rs            # SignerError (10 variants)
├── crypto.rs           # tagged_hash, double_sha256, hash160, sha256
├── encoding.rs         # compact_size, bech32, base58check
├── security.rs         # GuardedMemory, ct_hex, mlock, OnceLock RNG
├── hd_key.rs           # BIP-32 HD derivation (1,252 lines)
├── mnemonic.rs         # BIP-39 (479 lines)
├── bip85.rs            # BIP-85 entropy derivation (421 lines)
├── bitcoin/            # ECDSA secp256k1, Schnorr, Taproot, PSBT, descriptors
├── ethereum/           # ECDSA secp256k1+Keccak, EIP-155/191/712, ABI, RLP, SIWE
├── solana/             # Ed25519, SPL Token, System, PDA derivation
├── xrp/                # ECDSA + Ed25519, binary codec, multisign
├── neo/                # P-256 ECDSA, NeoVM, NEP-17/11
├── bls/                # BLS12-381, threshold, EIP-2333 (also re-exported as ethereum::bls)
└── threshold/
    ├── frost/          # RFC 9591 (keygen, signing, DKG, refresh)
    └── musig2/         # BIP-327 (signing, adaptor, tweak, nested)
```

## Feature System (14 flags)

```toml
# Default: all chain + threshold features ON
# Minimal build:
chains-sdk = { version = "0.8", default-features = false, features = ["ethereum"] }
```

| Feature | What it enables |
|---------|----------------|
| `ethereum` | EthereumSigner + EIP-155/191/712 + ABI + RLP + SIWE + keystore |
| `bitcoin` | BitcoinSigner + Schnorr + Taproot + PSBT + descriptors + scripts |
| `solana` | SolanaSigner + SPL Token + System + PDA + transaction builder |
| `xrp` | XrpEcdsaSigner + XrpEd25519Signer + binary codec |
| `neo` | NeoSigner + NeoVM + NEP-17/11 |
| `bls` | BlsSigner + threshold + EIP-2333 + keystore |
| `hd_key` | ExtendedPrivateKey + ExtendedPublicKey + BIP-32/44 |
| `mnemonic` | Mnemonic + BIP-39 + chain-specific derivation helpers |
| `bip85` | BIP-85 child mnemonic/WIF/xprv/hex derivation |
| `frost` | FROST t-of-n threshold Schnorr (RFC 9591) |
| `musig2` | MuSig2 n-of-n multi-party Schnorr (BIP-327) |
| `serde` | Serialize/Deserialize for keys and signatures |
| `custom_rng` | `set_custom_rng()` for TEE environments |
| `mlock` | Memory locking via `libc::mlock` |

---

## Core API Patterns

### Key Generation + Signing + Verification

```rust
use chains_sdk::traits::{KeyPair, Signer, Verifier};
use chains_sdk::ethereum::{EthereumSigner, EthereumVerifier};

// Generate
let signer = EthereumSigner::generate()?;

// From raw bytes
let signer = EthereumSigner::from_bytes(&key_bytes)?;

// Sign (Keccak-256 hash internally)
let sig = signer.sign(b"hello")?;

// Verify
let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
assert!(verifier.verify(b"hello", &sig)?);
```

### HD Key Derivation (BIP-32/39/44)

```rust
use chains_sdk::mnemonic::Mnemonic;
use chains_sdk::hd_key::{ExtendedPrivateKey, DerivationPath};

let mnemonic = Mnemonic::generate(12)?; // 12-word phrase
let seed = mnemonic.to_seed("optional passphrase");
let master = ExtendedPrivateKey::from_seed(&*seed)?;

// Derive for Ethereum: m/44'/60'/0'/0/0
let child = master.derive_path(&DerivationPath::ethereum(0))?;
let eth_signer = EthereumSigner::from_bytes(&child.private_key_bytes())?;

// Or use the convenience method
let eth_signer = EthereumSigner::from_mnemonic("abandon ... about", "", 0)?;
```

### Chain-Specific Address Derivation

```rust
// Bitcoin
let btc = BitcoinSigner::from_bytes(&key)?;
let p2pkh = btc.p2pkh_address();           // "1..."
let p2wpkh = btc.p2wpkh_address()?;        // "bc1q..."
let wif = btc.to_wif();                     // Zeroizing<String>

// Ethereum
let eth = EthereumSigner::from_bytes(&key)?;
let addr = eth.address();                   // [u8; 20]
let checksum = eth.address_checksum();      // "0xAb5801..."

// Solana
let sol = SolanaSigner::from_bytes(&seed)?;
let addr = sol.address();                   // Base58 string

// XRP
let xrp = XrpEcdsaSigner::from_bytes(&key)?;
let addr = xrp.address()?;                 // "r..."
```

### FROST Threshold Signatures (2-of-3)

```rust
use chains_sdk::threshold::frost::{keygen, signing};

let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3)?;
let nonce1 = signing::commit(&kgen.key_packages[0])?;
let nonce2 = signing::commit(&kgen.key_packages[2])?;
let commitments = vec![nonce1.commitments.clone(), nonce2.commitments.clone()];

let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg)?;
let share2 = signing::sign(&kgen.key_packages[2], nonce2, &commitments, msg)?;

let sig = signing::aggregate(&commitments, &[share1, share2], &kgen.group_public_key, msg)?;
assert!(signing::verify(&sig, &kgen.group_public_key, msg)?);
```

### EIP-712 Typed Data Signing

```rust
use chains_sdk::ethereum::{EthereumSigner, Eip712Domain};

let domain = Eip712Domain {
    name: "MyDapp",
    version: "1",
    chain_id: 1,
    verifying_contract: &contract_addr,
};
let separator = domain.separator();
let sig = signer.sign_typed_data(&separator, &struct_hash)?;
```

---

## Security Invariants (MUST follow)

### Rust-Level

1. **`#![deny(unsafe_code)]`** — Zero unsafe in default builds. Only `mlock` feature has 3 audited `libc` calls.
2. **`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`** — Zero panic surface. Use `?` or `map_err`.
3. **`#![deny(missing_docs)]`** — All public items must have doc comments.
4. **All key material in `Zeroizing<T>`** — Never return raw `Vec<u8>` for private keys.
5. **RFC 6979 deterministic nonces** — All ECDSA (secp256k1 + P-256). Never roll your own.
6. **Constant-time comparisons** — Use `subtle::ConstantTimeEq` for signatures, checksums, public keys. All `validate_address()` functions use CT checksum comparison.
7. **Constant-time hex** — `ct_hex_decode` / `ct_hex_val` are fully branchless. No early returns, no data-dependent branches.
8. **Debug redaction** — `GuardedMemory` prints `[REDACTED]`. Never format key bytes in errors.
9. **`GuardedMemory` uses `Box<[u8]>`** — Not `Vec<u8>`. This guarantees the mlock'd pointer is never invalidated by reallocation.
10. **`generate()` uses `secure_random()`** — All 7 signers use the SDK's pluggable RNG, not `OsRng` directly.

### Testing Requirements

- Run `cargo test --all-features` before any PR
- Run `cargo clippy --all-features -- -D warnings` — must be 0 warnings
- Run `cargo test --no-default-features` — CLI binary must compile
- Add official test vectors from standards (BIP, RFC, EIP, NIST)
- Property tests with `proptest` for edge cases

---

## Ethereum Ecosystem Context

### 🚨 Key Safety for AI Agents (from ethskills.com/wallets)

1. **NEVER hardcode private keys in source code.** Not even for tests — use `generate()`.
2. **NEVER commit secrets to Git.** Bots scrape repos in real-time. A committed key is **permanently compromised**.
3. **Use `Zeroizing<T>`** — this SDK already does this. If adding new key material, always wrap in `Zeroizing`.
4. **Prefer encrypted keystores** over raw key files. Use `ethereum::keystore` or `bls::keystore`.
5. **For production wallets:** Use Safe (Gnosis Safe) multisig with 1-of-2 pattern (agent + human recovery).
6. **Always validate addresses** before sending: `ethereum::validate_address()`, `bitcoin::validate_address()`, `solana::validate_address()`.

### EIP-7702: Smart EOAs (Live Since May 2025)
EOAs can temporarily delegate to smart contracts within a single transaction. This enables batch operations, gas sponsorship, and session keys without migrating wallets. This SDK's `EthereumSigner` produces standard EOA signatures that work with EIP-7702 delegations.

### Ethereum Standards Quick Reference

| Standard | What | This SDK |
|----------|------|----------|
| EIP-155 | Replay protection (chain_id in v) | `sign_with_chain_id()` |
| EIP-191 | Personal message signing | `personal_sign()` |
| EIP-712 | Typed structured data signing | `sign_typed_data()` |
| EIP-2612 | Permit (gasless approvals) | `ethereum::eips` module |
| EIP-3009 | Transfer with authorization | `ethereum::eips` module |
| EIP-2718 | Typed transactions | `ethereum::transaction` |
| EIP-1559 | Type 2 (priority fee) transactions | `ethereum::transaction` |
| EIP-4844 | Blob transactions | `ethereum::transaction` |
| BIP-32/44 | HD key derivation | `hd_key` module |
| BIP-39 | Mnemonic phrases | `mnemonic` module |
| BIP-85 | Deterministic entropy | `bip85` module |
| BIP-174 | PSBT | `bitcoin::psbt` module |
| BIP-322 | Message signing | `bitcoin::message` module |
| BIP-340 | Schnorr signatures | `bitcoin::schnorr` module |
| BIP-341/342 | Taproot | `bitcoin::taproot/tapscript` |
| BIP-380-386 | Output descriptors | `bitcoin::descriptor` module |

### Smart Contract Security Awareness

When this SDK is used for signing transactions that interact with smart contracts, be aware:

1. **Token decimals vary.** USDC = 6 decimals, DAI = 18. Always check `decimals()`.
2. **Reentrancy is still the #1 vulnerability.** Sign withdrawal transactions with caution — verify the contract uses checks-effects-interactions.
3. **Infinite approvals are dangerous.** When signing ERC-20 `approve()` calls, prefer exact amounts over `type(uint256).max`.
4. **EIP-712 signatures are binding.** A `sign_typed_data()` result can authorize irreversible on-chain actions. Verify domain separator and struct hash carefully.
5. **MEV/sandwich attacks** affect swap transactions. Use private mempools or slippage protection when signing DEX transactions.

### L2 Deployment Notes

This SDK's Ethereum signing works on ALL EVM L2s — same ECDSA secp256k1 + Keccak-256:

| L2 | Chain ID | Notes |
|----|----------|-------|
| Ethereum | 1 | Use `sign_with_chain_id(msg, 1)` |
| Arbitrum One | 42161 | Same signing. Different tx fee structure |
| Base | 8453 | Same signing. OP Stack |
| Optimism | 10 | Same signing. OP Stack |
| zkSync Era | 324 | Same signing. Different account model |
| Polygon | 137 | Same signing. |

**Cross-chain same-address deployment:** HD derivation from one mnemonic produces the same Ethereum address on all chains (same key + same Keccak derivation = same address).

### Audit Methodology (for contracts this SDK signs for)

When reviewing contracts that this SDK will interact with, use the 20-domain EVM audit checklist:
- **Always load:** `evm-audit-general`, `evm-audit-precision-math`
- **For DeFi:** Add `evm-audit-defi-amm`, `evm-audit-erc20`, `evm-audit-flashloans`
- **For signatures:** Add `evm-audit-signatures` (covers EIP-712 permit abuse)
- **For cross-chain:** Add `evm-audit-bridges`, `evm-audit-chain-specific`
- Source: `https://raw.githubusercontent.com/austintgriffith/evm-audit-skills/main/evm-audit-master/SKILL.md`

---

## Common Tasks

### Adding a New Chain Module

1. Create `src/<chain>/mod.rs` with `<Chain>Signer` struct
2. Implement `traits::Signer`, `traits::Verifier`, `traits::KeyPair`
3. Add feature flag in `Cargo.toml`: `<chain> = ["dep-name"]`
4. Gate module in `lib.rs`: `#[cfg(feature = "<chain>")] pub mod <chain>;`
5. Add to CI feature matrix in `.github/workflows/ci.yml`
6. Add `Display` for the signature type
7. Update CLI binary with `#[cfg(feature = "<chain>")]` branches
8. Add address validation function
9. Add to `Mnemonic::to_<chain>_signer()` helpers if applicable
10. Add doc comments and doc-test example (must be `no_run` or compilable)

### Adding a New Signature Scheme

1. Define the signature struct with `#[derive(Debug, Clone, PartialEq, Eq)]` and `#[must_use]`
2. Implement `Display` (hex-formatted output)
3. If serde: add `#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]`
4. `to_bytes()` + `from_bytes()` methods
5. Implement `Signer` trait with `sign()`, `sign_prehashed()`, `public_key_bytes()`
6. Implement `KeyPair` trait with `generate()` using `secure_random()`, `from_bytes()`, `private_key_bytes()`
7. `private_key_bytes()` must return `Zeroizing<Vec<u8>>`
8. Add RFC/BIP test vectors
9. Add fuzz target in `fuzz/fuzz_targets/`

### Running the Test Suite

```bash
# Full suite
cargo test --all-features

# Single feature isolation
cargo test --no-default-features --features ethereum

# Clippy (must be 0 warnings)
cargo clippy --all-features -- -D warnings

# No-default-features must compile
cargo check --no-default-features

# Fuzzing (requires nightly)
cargo +nightly fuzz run fuzz_ethereum -- -max_total_time=30
```

---

## Error Handling

All errors use `SignerError` (10 variants):

```rust
pub enum SignerError {
    InvalidPrivateKey(String),
    InvalidPublicKey(String),
    InvalidSignature(String),
    SigningFailed(String),
    VerificationFailed(String),
    InvalidHashLength { expected: usize, got: usize },
    EncodingError(String),
    DecodingError(String),
    InvalidMnemonic(String),
    Other(String),
}
```

**Rules:**
- Never include key material in error messages
- Use `format!("expected 32 bytes, got {}", len)` — sizes are OK, bytes are NOT
- All errors are `Send + Sync`
