//! **Threshold Signatures** — Multi-party Schnorr signing protocols.
//!
//! This module contains implementations of threshold and multi-party
//! signature schemes for secp256k1:
//!
//! - **FROST** (`frost`) — T-of-N threshold Schnorr signatures (RFC 9591)
//! - **MuSig2** (`musig2`) — N-of-N multi-party Schnorr signatures (BIP-327)

#[cfg(feature = "frost")]
pub mod frost;

#[cfg(feature = "musig2")]
pub mod musig2;
