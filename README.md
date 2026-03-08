# trad-signer

**Unified, secure multi-chain signing SDK for Rust.** Supports ECDSA (secp256k1, P-256), EdDSA (Ed25519), BLS12-381, and Schnorr (BIP-340) — with BIP-32/39/44 HD key derivation, address generation, and full serde support.

[![Crates.io](https://img.shields.io/crates/v/trad-signer.svg)](https://crates.io/crates/trad-signer)
[![License](https://img.shields.io/crates/l/trad-signer.svg)](LICENSE)

## Supported Chains

| Chain | Curve | Addresses | Message Signing |
|-------|-------|-----------|-----------------|
| **Ethereum** | secp256k1 | EIP-55 checksum | EIP-191, EIP-712, EIP-155 |
| **Bitcoin** | secp256k1 | P2PKH, P2WPKH, P2TR | BIP-137 |
| **Bitcoin (Taproot)** | Schnorr (BIP-340) | P2TR (Bech32m) | — |
| **Solana** | Ed25519 | Base58 | — |
| **XRP** | secp256k1 + Ed25519 | r-address | — |
| **NEO** | P-256 (secp256r1) | A-address | — |
| **BLS** | BLS12-381 | — | Aggregated signatures |

## Quick Start

```toml
[dependencies]
trad-signer = "0.3"
```

### Generate Keys & Sign

```rust
use trad_signer::ethereum::EthereumSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = EthereumSigner::generate()?;
let signature = signer.sign(b"hello world")?;

// EIP-55 checksummed address
println!("Address: {}", signer.address_checksum());
```

### EIP-155 Chain-Aware Signing

```rust
use trad_signer::ethereum::EthereumSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = EthereumSigner::generate()?;

// Mainnet (chain_id = 1): v = 37 or 38
let sig = signer.sign_with_chain_id(b"tx data", 1)?;

// Polygon (chain_id = 137)
let sig = signer.sign_with_chain_id(b"tx data", 137)?;
```

### ecrecover

```rust
use trad_signer::ethereum::{EthereumSigner, ecrecover};
use trad_signer::traits::{KeyPair, Signer};

let signer = EthereumSigner::generate()?;
let sig = signer.sign(b"verify me")?;
let recovered_address = ecrecover(b"verify me", &sig)?;
assert_eq!(recovered_address, signer.address());
```

### BIP-39 Mnemonic → HD Keys

```rust
use trad_signer::mnemonic::Mnemonic;
use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};

// Generate 24-word mnemonic
let mnemonic = Mnemonic::generate(24)?;
println!("Seed phrase: {}", mnemonic.phrase());

// Derive seed (with optional passphrase)
let seed = mnemonic.to_seed("optional passphrase");

// BIP-32 master key → BIP-44 Ethereum path
let master = ExtendedPrivateKey::from_seed(&*seed)?;
let eth_key = master.derive_path(&DerivationPath::ethereum(0))?;
let btc_key = master.derive_path(&DerivationPath::bitcoin(0))?;
let sol_key = master.derive_path(&DerivationPath::solana(0))?;

// Export as xprv/xpub
println!("xprv: {}", master.to_xprv());
println!("xpub: {}", master.to_xpub()?);
```

### Bitcoin Addresses

```rust
use trad_signer::bitcoin::BitcoinSigner;
use trad_signer::bitcoin::schnorr::SchnorrSigner;
use trad_signer::traits::KeyPair;

let signer = BitcoinSigner::generate()?;
println!("P2PKH:  {}", signer.p2pkh_address());           // 1...
println!("P2WPKH: {}", signer.p2wpkh_address()?);          // bc1q...
println!("P2PKH (testnet): {}", signer.p2pkh_testnet_address()); // m.../n...
println!("P2WPKH (testnet): {}", signer.p2wpkh_testnet_address()?); // tb1q...

let schnorr = SchnorrSigner::generate()?;
println!("P2TR:   {}", schnorr.p2tr_address()?);            // bc1p...
println!("P2TR (testnet): {}", schnorr.p2tr_testnet_address()?); // tb1p...

// BIP-137 message signing
let sig = signer.sign_message(b"Hello Bitcoin")?;
```

### Address Validation

```rust
use trad_signer::bitcoin::validate_address;
use trad_signer::ethereum::validate_address as validate_eth;
use trad_signer::solana::validate_address as validate_sol;

assert!(validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));    // BTC P2PKH
assert!(validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")); // BTC P2WPKH
assert!(validate_eth("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")); // ETH EIP-55
assert!(validate_sol("11111111111111111111111111111112"));             // Solana
```

### Multi-Chain Signing

```rust
use trad_signer::solana::SolanaSigner;
use trad_signer::xrp::XrpEcdsaSigner;
use trad_signer::neo::NeoSigner;
use trad_signer::traits::{KeyPair, Signer};

// Solana
let sol = SolanaSigner::generate()?;
let sig = sol.sign(b"solana message")?;
println!("Solana address: {}", sol.address());

// XRP
let xrp = XrpEcdsaSigner::generate()?;
let sig = xrp.sign(b"xrp payload")?;
println!("XRP address: {}", xrp.address()?);

// NEO
let neo = NeoSigner::generate()?;
let sig = neo.sign(b"neo data")?;
println!("NEO address: {}", neo.address());
```

### BLS Aggregated Signatures

```rust
use trad_signer::bls::{BlsSigner, BlsVerifier};
use trad_signer::traits::{KeyPair, Signer, Verifier};

let signer1 = BlsSigner::generate()?;
let signer2 = BlsSigner::generate()?;
let sig1 = signer1.sign(b"consensus message")?;
let sig2 = signer2.sign(b"consensus message")?;

// Aggregate verify
let verifiers = vec![
    BlsVerifier::from_public_key_bytes(&signer1.public_key_bytes())?,
    BlsVerifier::from_public_key_bytes(&signer2.public_key_bytes())?,
];
let sigs = vec![sig1, sig2];
assert!(BlsVerifier::verify_aggregated(b"consensus message", &verifiers, &sigs)?);
```

## Features

All chain modules are enabled by default. Disable unused chains to reduce compile time:

```toml
[dependencies]
trad-signer = { version = "0.3", default-features = false, features = ["ethereum", "bitcoin"] }
```

| Feature | Description |
|---------|-------------|
| `ethereum` | Ethereum ECDSA + EIP-191/712/155 + ecrecover |
| `bitcoin` | Bitcoin ECDSA (DER) + P2PKH/P2WPKH + BIP-137 |
| `solana` | Solana Ed25519 |
| `xrp` | XRP ECDSA + Ed25519 |
| `neo` | NEO P-256 ECDSA |
| `bls` | BLS12-381 (requires C compiler for `blst`) |
| `hd_key` | BIP-32/44 HD key derivation + xpub/xprv |
| `mnemonic` | BIP-39 seed phrases (12/15/18/21/24 words) |
| `serde` | Serialization support for keys and signatures |

## Security

- `#![forbid(unsafe_code)]` — zero unsafe blocks
- `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` — zero panic surface
- All ECDSA uses **RFC 6979** deterministic nonces
- All key material wrapped in `Zeroizing` / `ZeroizeOnDrop`
- Constant-time comparisons via `subtle::ConstantTimeEq`
- `cargo audit`: **0 vulnerabilities** across 117+ dependencies
- **216+ tests** including official BIP-32, BIP-39, RFC 6979, BIP-340, RFC 8032, and FIPS 186-4 vectors

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
