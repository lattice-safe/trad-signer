# trad-signer

**Unified, secure multi-chain signing SDK for Rust.** Supports ECDSA (secp256k1, P-256), EdDSA (Ed25519), BLS12-381, Schnorr (BIP-340), FROST threshold signatures (RFC 9591), and MuSig2 multi-party signatures (BIP-327) — with BIP-32/39/44 HD key derivation, address generation, and full serde support.

[![Crates.io](https://img.shields.io/crates/v/trad-signer.svg)](https://crates.io/crates/trad-signer)
[![License](https://img.shields.io/crates/l/trad-signer.svg)](LICENSE)

## Supported Algorithms

| Algorithm | Curve / Scheme | Chains | Standard |
|-----------|---------------|--------|----------|
| **ECDSA** | secp256k1 | Ethereum, Bitcoin, XRP | RFC 6979 |
| **ECDSA** | P-256 (secp256r1) | NEO | FIPS 186-4 |
| **EdDSA** | Ed25519 | Solana, XRP | RFC 8032 |
| **Schnorr** | secp256k1 | Bitcoin (Taproot) | BIP-340 |
| **BLS** | BLS12-381 | Beacon chain | — |
| **FROST** | secp256k1 + SHA-256 | Any (threshold) | RFC 9591 |
| **MuSig2** | secp256k1 | Any (multi-party) | BIP-327 |

## Quick Start

```toml
[dependencies]
trad-signer = "0.4"
```

---

## Ethereum (secp256k1 ECDSA)

```rust
use trad_signer::ethereum::EthereumSigner;
use trad_signer::traits::{KeyPair, Signer};

// Generate a new key pair
let signer = EthereumSigner::generate()?;
println!("Address: {}", signer.address_checksum()); // 0x...

// Sign a message (EIP-191 personal_sign)
let sig = signer.sign(b"hello world")?;
println!("r: 0x{}", hex::encode(sig.r));
println!("s: 0x{}", hex::encode(sig.s));
println!("v: {}", sig.v); // 27 or 28

// EIP-155 chain-aware signing
let sig = signer.sign_with_chain_id(b"tx data", 1)?;   // Mainnet
let sig = signer.sign_with_chain_id(b"tx data", 137)?;  // Polygon

// ecrecover (recover address from signature)
use trad_signer::ethereum::ecrecover;
let recovered = ecrecover(b"hello world", &sig)?;
assert_eq!(recovered, signer.address());
```

---

## Bitcoin (secp256k1 ECDSA + BIP-340 Schnorr)

```rust
use trad_signer::bitcoin::BitcoinSigner;
use trad_signer::bitcoin::schnorr::SchnorrSigner;
use trad_signer::traits::{KeyPair, Signer};

// ECDSA signer — Legacy + SegWit addresses
let signer = BitcoinSigner::generate()?;
println!("P2PKH:  {}", signer.p2pkh_address());          // 1...
println!("P2WPKH: {}", signer.p2wpkh_address()?);        // bc1q...
println!("Testnet: {}", signer.p2wpkh_testnet_address()?); // tb1q...

// BIP-137 message signing
let sig = signer.sign_message(b"Hello Bitcoin")?;

// WIF import/export
let wif = signer.to_wif();
let restored = BitcoinSigner::from_wif(&wif)?;

// Schnorr / Taproot (BIP-340)
let schnorr = SchnorrSigner::generate()?;
println!("P2TR: {}", schnorr.p2tr_address()?);            // bc1p...
let sig = schnorr.sign(b"taproot message")?;
```

---

## Solana (Ed25519)

```rust
use trad_signer::solana::SolanaSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = SolanaSigner::generate()?;
println!("Address: {}", signer.address()); // Base58
let sig = signer.sign(b"solana message")?;
```

---

## XRP (secp256k1 ECDSA + Ed25519)

```rust
use trad_signer::xrp::{XrpEcdsaSigner, XrpEddsaSigner};
use trad_signer::traits::{KeyPair, Signer};

// ECDSA variant
let ecdsa = XrpEcdsaSigner::generate()?;
println!("XRP address: {}", ecdsa.address()?); // r...
let sig = ecdsa.sign(b"xrp payload")?;

// Ed25519 variant
let eddsa = XrpEddsaSigner::generate()?;
println!("XRP address: {}", eddsa.address()?);
```

---

## NEO (P-256 ECDSA)

```rust
use trad_signer::neo::NeoSigner;
use trad_signer::traits::{KeyPair, Signer};

let signer = NeoSigner::generate()?;
println!("NEO address: {}", signer.address()); // A...
let sig = signer.sign(b"neo data")?;
```

---

## BLS (BLS12-381 Aggregated Signatures)

```rust
use trad_signer::bls::{BlsSigner, BlsVerifier};
use trad_signer::traits::{KeyPair, Signer, Verifier};

let signer1 = BlsSigner::generate()?;
let signer2 = BlsSigner::generate()?;
let sig1 = signer1.sign(b"consensus")?;
let sig2 = signer2.sign(b"consensus")?;

// Aggregate verification (N signatures, 1 verify call)
let verifiers = vec![
    BlsVerifier::from_public_key_bytes(&signer1.public_key_bytes())?,
    BlsVerifier::from_public_key_bytes(&signer2.public_key_bytes())?,
];
assert!(BlsVerifier::verify_aggregated(b"consensus", &verifiers, &[sig1, sig2])?);
```

---

## BIP-39 Mnemonic → HD Keys (BIP-32/44)

```rust
use trad_signer::mnemonic::Mnemonic;
use trad_signer::hd_key::{ExtendedPrivateKey, DerivationPath};

// Generate 24-word mnemonic
let mnemonic = Mnemonic::generate(24)?;
println!("Seed phrase: {}", mnemonic.phrase());

// Derive seed → master key → chain-specific paths
let seed = mnemonic.to_seed("optional passphrase");
let master = ExtendedPrivateKey::from_seed(&*seed)?;

let eth_key = master.derive_path(&DerivationPath::ethereum(0))?;    // m/44'/60'/0'/0/0
let btc_key = master.derive_path(&DerivationPath::bitcoin(0))?;     // m/44'/0'/0'/0/0
let sol_key = master.derive_path(&DerivationPath::solana(0))?;      // m/44'/501'/0'/0'
let xrp_key = master.derive_path(&DerivationPath::xrp(0))?;        // m/44'/144'/0'/0/0

// Export as xprv/xpub (BIP-32 serialization)
println!("xprv: {}", master.to_xprv());
println!("xpub: {}", master.to_xpub()?);

// One-step: mnemonic → chain signer
let eth = Mnemonic::to_ethereum_signer("abandon abandon ... about", "")?;
let btc = Mnemonic::to_bitcoin_signer("abandon abandon ... about", "")?;
```

---

## BIP-85 — Deterministic Entropy Derivation

Derive unlimited child mnemonics, WIF keys, and xprv keys from a single master.

```rust
use trad_signer::hd_key::ExtendedPrivateKey;
use trad_signer::bip85;

let seed = [0xab_u8; 64];
let master = ExtendedPrivateKey::from_seed(&seed)?;

// Derive child BIP-39 mnemonics (deterministic & reproducible)
let mnemonic_12 = bip85::derive_bip39(&master, 0, 12, 0)?;  // 12 words
let mnemonic_24 = bip85::derive_bip39(&master, 0, 24, 0)?;  // 24 words

// Derive WIF private key
let wif = bip85::derive_wif(&master, 0)?;  // starts with K or L

// Derive child xprv
let child = bip85::derive_xprv(&master, 0)?;
println!("Child xprv: {}", child.to_xprv());

// Raw hex entropy (16-64 bytes)
let entropy = bip85::derive_hex(&master, 32, 0)?;
```

---

## FROST — T-of-N Threshold Schnorr (RFC 9591)

Any `t` of `n` participants can collaboratively sign. No single party holds the full key.

```rust
use trad_signer::threshold::frost::{keygen, signing};

// 1. Trusted dealer generates 2-of-3 key shares
let secret = [0x42u8; 32]; // group secret key
let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3)?;
// kgen.key_packages: 3 shares, any 2 can sign

// 2. Verify shares against VSS commitments
for pkg in &kgen.key_packages {
    assert!(kgen.vss_commitments.verify_share(pkg.identifier, pkg.secret_share()));
}

// 3. Round 1 — Participants 1 and 3 generate nonce commitments
let nonce1 = signing::commit(&kgen.key_packages[0])?;
let nonce3 = signing::commit(&kgen.key_packages[2])?;
let commitments = vec![nonce1.commitments.clone(), nonce3.commitments.clone()];

// 4. Round 2 — Each participant produces a partial signature share
let msg = b"threshold signed message";
let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg)?;
let share3 = signing::sign(&kgen.key_packages[2], nonce3, &commitments, msg)?;

// 5. Coordinator aggregates shares into a standard Schnorr signature
let sig = signing::aggregate(&commitments, &[share1, share3], &kgen.group_public_key, msg)?;

// 6. Anyone can verify — indistinguishable from single-signer Schnorr
assert!(signing::verify(&sig, &kgen.group_public_key, msg)?);
```

**Identifiable abort** — detect which participant sent a bad share:

```rust
let pk1 = kgen.key_packages[0].public_key();
let is_valid = signing::verify_share(
    &share1, &commitments[0], &pk1,
    &kgen.group_public_key, &commitments, msg,
)?;
assert!(is_valid);
```

---

## MuSig2 — N-of-N Multi-Party Schnorr (BIP-327)

All signers must participate. Produces a standard BIP-340 Schnorr signature.

```rust
use trad_signer::threshold::musig2;

// 1. Each signer has their own key pair
let sk1 = [0x01u8; 32];
let sk2 = [0x02u8; 32];
let pk1 = musig2::individual_pubkey(&sk1)?;
let pk2 = musig2::individual_pubkey(&sk2)?;

// 2. Key aggregation — combine into a single public key
let key_agg = musig2::key_agg(&[pk1, pk2])?;
println!("Aggregate x-only pubkey: {}", hex::encode(key_agg.x_only_pubkey));

// 3. Round 1 — Nonce generation
let msg = b"multi-party signed";
let (secnonce1, pubnonce1) = musig2::nonce_gen(&sk1, &pk1, &key_agg, msg, &[])?;
let (secnonce2, pubnonce2) = musig2::nonce_gen(&sk2, &pk2, &key_agg, msg, &[])?;

// 4. Nonce aggregation
let agg_nonce = musig2::nonce_agg(&[pubnonce1, pubnonce2])?;

// 5. Round 2 — Partial signing
let psig1 = musig2::sign(secnonce1, &sk1, &key_agg, &agg_nonce, msg)?;
let psig2 = musig2::sign(secnonce2, &sk2, &key_agg, &agg_nonce, msg)?;

// 6. Aggregate into a 64-byte BIP-340 Schnorr signature
let sig = musig2::partial_sig_agg(&[psig1, psig2], &agg_nonce, &key_agg, msg)?;
assert_eq!(sig.to_bytes().len(), 64);

// 7. Standard BIP-340 verification
assert!(musig2::verify(&sig, &key_agg.x_only_pubkey, msg)?);
```

---

## Address Validation

```rust
use trad_signer::bitcoin::validate_address;
use trad_signer::ethereum::validate_address as validate_eth;
use trad_signer::solana::validate_address as validate_sol;

assert!(validate_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));      // BTC P2PKH
assert!(validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")); // BTC P2WPKH
assert!(validate_eth("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));   // ETH EIP-55
assert!(validate_sol("11111111111111111111111111111112"));               // Solana
```

---

## BIP-322 Full Message Signing

```rust
use trad_signer::bitcoin::message;

// Sign a message using BIP-322 "full" format (virtual tx chain)
let witness = message::sign_full(
    &private_key_bytes, b"Hello World", &script_pubkey,
)?;

// Verify against the signer's script
let valid = message::verify_full(&witness, b"Hello World", &script_pubkey)?;
```

---

## PSBT (Partially Signed Bitcoin Transactions)

```rust
use trad_signer::bitcoin::psbt::v0::Psbt;

// Deserialize a PSBT
let psbt = Psbt::deserialize(&psbt_bytes)?;
println!("Inputs: {}", psbt.inputs.len());
println!("Outputs: {}", psbt.outputs.len());
println!("PSBT ID: {}", hex::encode(psbt.psbt_id()));

// Round-trip: serialize → deserialize
let reserialized = psbt.serialize();
assert_eq!(psbt_bytes, reserialized);
```

---

## Output Descriptors (BIP-380-386)

```rust
use trad_signer::bitcoin::descriptor;

// Parse and derive addresses from output descriptors
let desc = descriptor::parse("wpkh(02...pubkey...)");
let addr = descriptor::derive_address(&desc, 0)?;
```

---

## Features

All modules are enabled by default. Disable unused ones to reduce compile time:

```toml
[dependencies]
trad-signer = { version = "0.4", default-features = false, features = ["ethereum", "frost"] }
```

| Feature | Description |
|---------|-------------|
| `ethereum` | Ethereum ECDSA + EIP-191/712/155 + ecrecover |
| `bitcoin` | Bitcoin ECDSA + Schnorr + P2PKH/P2WPKH/P2TR + BIP-137 + WIF |
| `solana` | Solana Ed25519 |
| `xrp` | XRP ECDSA + Ed25519 + r-address |
| `neo` | NEO P-256 ECDSA + A-address |
| `bls` | BLS12-381 aggregated signatures (requires C compiler for `blst`) |
| `hd_key` | BIP-32/44 HD key derivation + xpub/xprv serialization |
| `mnemonic` | BIP-39 seed phrases (12/15/18/21/24 words) |
| `frost` | FROST T-of-N threshold Schnorr (RFC 9591, secp256k1-SHA256) |
| `musig2` | MuSig2 N-of-N multi-party Schnorr (BIP-327) |
| `bip85` | BIP-85 deterministic entropy (child mnemonics, WIF, xprv) |
| `serde` | Serialization support for keys and signatures |

## Security

- `#![forbid(unsafe_code)]` — zero unsafe blocks
- `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` — zero panic surface
- All ECDSA uses **RFC 6979** deterministic nonces (secp256k1 + P-256)
- All key material wrapped in `Zeroizing` / `ZeroizeOnDrop`
- Constant-time comparisons via `subtle::ConstantTimeEq`
- FROST nonces are single-use `Zeroizing<Scalar>` with drop guards
- `cargo audit`: **0 vulnerabilities** across 117+ dependencies
- **445+ tests** including NIST SHA-256, BIP-32, BIP-39, BIP-85, BIP-137, BIP-322, BIP-327, BIP-340, BIP-341, RFC 6979, RFC 8032, RFC 9591, and FIPS 186-4 vectors

## Architecture

```
src/
├── crypto.rs          # Shared: tagged_hash, double_sha256, hash160, sha256
├── encoding.rs        # Shared: compact_size, bech32, base58check
├── error.rs           # Unified SignerError enum
├── traits.rs          # KeyPair, Signer, Verifier traits
├── bitcoin/
│   ├── mod.rs         # ECDSA signer, WIF, P2PKH/P2WPKH, BIP-137
│   ├── schnorr.rs     # BIP-340 Schnorr, P2TR addresses
│   ├── taproot.rs     # BIP-341/342 Taproot scripts
│   ├── message.rs     # BIP-322 full message signing
│   ├── psbt/          # BIP-174 Partially Signed Bitcoin Transactions
│   └── descriptor.rs  # BIP-380-386 output descriptors
├── ethereum/          # EIP-191/712/155, ecrecover
├── solana/            # Ed25519 signing
├── xrp/               # ECDSA + Ed25519 dual-curve
├── neo/               # P-256 (secp256r1)
├── bls/               # BLS12-381 aggregated signatures
├── threshold/
│   ├── frost/         # RFC 9591 T-of-N threshold Schnorr
│   └── musig2/        # BIP-327 N-of-N multi-party Schnorr
├── hd_key.rs          # BIP-32/44 HD key derivation
├── mnemonic.rs        # BIP-39 seed phrases
└── bip85.rs           # BIP-85 deterministic entropy
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
