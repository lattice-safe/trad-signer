# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.9.x   | ✅ Current release |
| < 0.9   | ❌ Not supported   |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities via email:

📧 **security@lattice-safe.dev**

### What to include

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Impact assessment
- Suggested fix (if any)

### Response timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgement | 48 hours |
| Initial assessment | 7 days |
| Fix development | 14–30 days |
| Public disclosure | After fix is released |

## Security Model

### Threat Model

This library protects against:
- **Secret key extraction** via memory dumps (zeroization on drop)
- **Timing side-channels** via constant-time comparisons (subtle crate)
- **Swap-to-disk leakage** via optional memory locking (mlock feature)
- **Nonce reuse** via Rust's move semantics (FROST/MuSig2 nonces consumed on use)
- **Weak entropy** via pluggable CSPRNG (secure_random)

### What this library does NOT protect against

- Physical side-channels (power analysis, EM emanation)
- Compromised OS / kernel
- Software bugs in dependencies (k256, blst, ed25519-dalek)
- Application-level logic errors (e.g., sending to wrong address)

### Security Properties

| Property | Mechanism |
|----------|-----------|
| No unsafe code | `#![deny(unsafe_code)]` — 2 exceptions for `mlock`/`munlock` |
| Secret zeroization | `zeroize::Zeroize` / `ZeroizeOnDrop` on all key structs |
| Constant-time comparison | `subtle::ConstantTimeEq` for checksums, MACs, preimages |
| Constant-time hex | Branchless `ct_hex_encode` / `ct_hex_decode` |
| Memory locking | Feature-gated `mlock(2)` via `GuardedMemory` |
| Redacted Debug | `GuardedMemory` prints `[REDACTED]` in Debug output |
| Deterministic nonces | RFC 6979 (Bitcoin/Ethereum via k256) |
| Single-use nonces | FROST `SigningNonces` / MuSig2 `SecNonce` consumed by `sign()` |

## Audits

This library has not yet undergone a formal third-party security audit. Use in production at your own risk.
