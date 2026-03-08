//! **MuSig2** — Multi-party Schnorr Signatures (BIP-327).
//!
//! N-of-N multi-party Schnorr signature protocol. All signers must participate
//! to produce a signature that is indistinguishable from a single-signer Schnorr
//! signature on the blockchain.
//!
//! # Protocol Overview
//!
//! 1. **Key Aggregation**: Combine N public keys into a single aggregate key.
//! 2. **Nonce Generation**: Each signer generates 2 secret nonces.
//! 3. **Nonce Aggregation**: Combine all public nonces.
//! 4. **Partial Signing**: Each signer produces a partial signature.
//! 5. **Signature Aggregation**: Combine partial signatures into final Schnorr sig.
//!
//! # Example
//! ```no_run
//! use trad_signer::threshold::musig2;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Two signers with their own key pairs
//!     let sk1 = [0x01u8; 32]; // signer 1 secret key
//!     let sk2 = [0x02u8; 32]; // signer 2 secret key
//!     let pk1 = musig2::individual_pubkey(&sk1)?;
//!     let pk2 = musig2::individual_pubkey(&sk2)?;
//!
//!     // Key aggregation
//!     let key_agg = musig2::key_agg(&[pk1, pk2])?;
//!
//!     // Nonce generation (round 1)
//!     let (secnonce1, pubnonce1) = musig2::nonce_gen(&sk1, &pk1, &key_agg, b"msg", &[])?;
//!     let (secnonce2, pubnonce2) = musig2::nonce_gen(&sk2, &pk2, &key_agg, b"msg", &[])?;
//!
//!     // Nonce aggregation
//!     let agg_nonce = musig2::nonce_agg(&[pubnonce1.clone(), pubnonce2.clone()])?;
//!
//!     // Partial signing (round 2)
//!     let psig1 = musig2::sign(secnonce1, &sk1, &key_agg, &agg_nonce, b"msg")?;
//!     let psig2 = musig2::sign(secnonce2, &sk2, &key_agg, &agg_nonce, b"msg")?;
//!
//!     // Aggregate
//!     let sig = musig2::partial_sig_agg(&[psig1, psig2], &agg_nonce, &key_agg, b"msg")?;
//!     Ok(())
//! }
//! ```

pub mod signing;

pub use signing::*;
