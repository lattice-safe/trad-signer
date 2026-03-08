# Changelog

## [0.3.0] — 2026-03-08

### Added

**Address Generation**
- Ethereum: `address_checksum()` (EIP-55), `eip55_checksum()`
- Bitcoin: `p2pkh_address()`, `p2wpkh_address()`, `p2tr_address()` (Schnorr)
- Solana: `address()` (Base58 Ed25519 pubkey)
- XRP: `address()` for both ECDSA and Ed25519 signers
- NEO: `address()`, `script_hash()`

**Address Validation**
- Ethereum: `validate_address()` (hex format + EIP-55 checksum)
- Bitcoin: `validate_address()`, `validate_mainnet_address()`, `validate_testnet_address()`
- Solana: `validate_address()` (Base58 32-byte check)
- XRP: `validate_address()` (r-address checksum)
- NEO: `validate_address()` (A-address checksum)

**Signing**
- Ethereum: `ecrecover()`, `ecrecover_digest()` — recover signer from signature
- Ethereum: `sign_with_chain_id()`, `sign_digest_with_chain_id()` — EIP-155 replay protection
- Ethereum: `personal_sign_with_chain_id()` — EIP-191 + EIP-155
- Bitcoin: `sign_message()`, `bitcoin_message_hash()` — BIP-137 message signing

**Testnet Addresses**
- Bitcoin: `p2pkh_testnet_address()` (m/n...), `p2wpkh_testnet_address()` (tb1q...)
- Schnorr: `p2tr_testnet_address()` (tb1p...)

**BIP-39 Mnemonic**
- `Mnemonic::generate(word_count)` — 12/15/18/21/24 words
- `Mnemonic::from_entropy()` — from raw entropy bytes
- `Mnemonic::from_phrase()` — parse + validate checksum
- `Mnemonic::to_seed(passphrase)` — PBKDF2-SHA512

**BIP-32**
- `ExtendedPrivateKey::to_xprv()` — Base58Check serialization
- `ExtendedPrivateKey::to_xpub()` — public key serialization
- `ExtendedPrivateKey::from_xprv()` — deserialization + validation

### Dependencies
- Added: `bs58` v0.5, `bech32` v0.11, `pbkdf2` v0.12
- Added: `ripemd` to `bitcoin` and `neo` features

### Tests
- 216+ tests across lib, address, integration, SDK features, and serde suites
- BIP-39 official test vectors (entropy → phrase, phrase → seed)
- BIP-32 known vector: privkey=1 → P2PKH 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
- EIP-55 spec vectors, ecrecover round-trips

## [0.2.0] — 2026-03-07

### Added
- Initial release: 6 chain signers + BLS + HD key derivation
- Full serde support
- Security hardening: forbid(unsafe), deny(unwrap/expect/panic), zeroize
