//! **FROST** — Flexible Round-Optimized Schnorr Threshold Signatures (RFC 9591).
//!
//! T-of-N threshold Schnorr signature protocol. Any `t` of `n` participants
//! can collaboratively produce a valid Schnorr signature without any single
//! party holding the full secret key.
//!
//! Implements the `FROST(secp256k1, SHA-256)` ciphersuite.
//!
//! # Protocol Overview
//!
//! 1. **Key Generation**: A trusted dealer splits a group secret into `n` shares
//!    using Shamir secret sharing. Each participant receives a `KeyPackage`.
//!
//! 2. **Round 1 — Commitment**: Each participant generates random nonces and
//!    broadcasts commitments: `(D_i, E_i) = (G*d_i, G*e_i)`.
//!
//! 3. **Round 2 — Signing**: Each participant computes a partial signature share
//!    `z_i = d_i + ρ_i*e_i + λ_i*s_i*c`.
//!
//! 4. **Aggregation**: The coordinator sums all signature shares to produce
//!    a standard Schnorr signature `(R, s)`.
//!
//! # Example
//! ```no_run
//! use chains_sdk::threshold::frost::{keygen, signing};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Dealer generates 2-of-3 key shares
//!     let secret = [0x42u8; 32];
//!     let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3)?;
//!
//!     // Participants 1 and 3 sign a message
//!     let msg = b"Hello FROST";
//!     let nonce1 = signing::commit(&kgen.key_packages[0])?;
//!     let nonce3 = signing::commit(&kgen.key_packages[2])?;
//!
//!     let commitments = vec![nonce1.commitments.clone(), nonce3.commitments.clone()];
//!     let share1 = signing::sign(&kgen.key_packages[0], nonce1, &commitments, msg)?;
//!     let share3 = signing::sign(&kgen.key_packages[2], nonce3, &commitments, msg)?;
//!
//!     let sig = signing::aggregate(&commitments, &[share1, share3], &kgen.group_public_key, msg)?;
//!     assert!(signing::verify(&sig, &kgen.group_public_key, msg)?);
//!     Ok(())
//! }
//! ```

pub mod dkg;
pub mod keygen;
pub mod refresh;
pub mod signing;
