# Fuzzing Harness for chains-sdk

This directory contains `cargo-fuzz` targets for critical parsing and encoding operations.

## Setup

```bash
cargo install cargo-fuzz
```

## Running

```bash
# Run all fuzz targets
cargo fuzz list

# Run a specific target
cargo fuzz run fuzz_abi_decode -- -max_total_time=300

# Run with sanitizers
cargo fuzz run fuzz_abi_decode -- -max_total_time=300 -sanitizer=address
```

## Targets

| Target | Description |
|--------|-------------|
| `fuzz_abi_decode` | Ethereum ABI decoding (uint256, address, bytes, string) |
| `fuzz_rlp_decode` | RLP decoding of nested structures |
| `fuzz_ct_hex` | Constant-time hex encode/decode roundtrip |
| `fuzz_bip39_mnemonic` | BIP-39 mnemonic parsing and validation |
| `fuzz_psbt_parse` | PSBTv2 deserilization from raw bytes |
| `fuzz_permit2_hash` | Permit2 EIP-712 struct hashing |
