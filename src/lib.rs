//! # trad-signer
//!
//! Unified, secure multi-chain signing library for ECDSA, EdDSA, BLS, and Schnorr.
//!
//! Each blockchain module is feature-gated so consumers only compile what they need.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_docs)]

pub mod error;
pub mod traits;

#[cfg(feature = "serde")]
pub(crate) mod serde_zeroizing;

#[cfg(feature = "ethereum")]
pub mod ethereum;

#[cfg(feature = "bitcoin")]
pub mod bitcoin;

#[cfg(feature = "neo")]
pub mod neo;

#[cfg(feature = "xrp")]
pub mod xrp;

#[cfg(feature = "solana")]
pub mod solana;

#[cfg(feature = "bls")]
pub mod bls;

#[cfg(feature = "hd_key")]
pub mod hd_key;

#[cfg(feature = "mnemonic")]
pub mod mnemonic;

#[cfg(feature = "bip85")]
pub mod bip85;

#[cfg(feature = "psbt")]
pub mod psbt;

#[cfg(feature = "descriptor")]
pub mod descriptor;

#[cfg(any(feature = "frost", feature = "musig2"))]
pub mod threshold;
