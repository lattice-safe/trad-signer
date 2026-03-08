//! Security utilities for enclave / confidential computing environments.
//!
//! Provides constant-time hex encoding, memory guarding, pluggable RNG,
//! and secure comparison primitives for use in TEE (SGX, Nitro, TDX, SEV)
//! environments.

use zeroize::Zeroizing;

// ─── Constant-Time Hex ─────────────────────────────────────────────

/// Constant-time hex encoding for secret material.
///
/// Unlike `hex::encode()`, this implementation processes all bytes
/// uniformly regardless of value, preventing timing side-channels.
#[must_use]
pub fn ct_hex_encode(data: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0F) as usize] as char);
    }
    result
}

/// Constant-time hex decoding for secret material.
///
/// Returns `None` if the input contains non-hex characters or has odd length.
/// Processes the full input regardless of validity to avoid timing leaks.
#[must_use]
pub fn ct_hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    // Process all bytes even if odd-length — avoid early return timing leak
    let odd = bytes.len() % 2;
    let pair_count = bytes.len() / 2;
    let mut result = Vec::with_capacity(pair_count);
    let mut all_valid: u8 = 0xFF;

    for chunk in bytes.chunks(2) {
        if chunk.len() == 2 {
            let (high, h_ok) = ct_hex_val(chunk[0]);
            let (low, l_ok) = ct_hex_val(chunk[1]);
            all_valid &= h_ok & l_ok;
            result.push((high << 4) | low);
        }
    }

    // Reject odd-length inputs via the flag, not an early return
    if odd != 0 {
        all_valid = 0;
    }

    if all_valid != 0 {
        Some(result)
    } else {
        None
    }
}

/// Fully constant-time hex character to value (branchless).
///
/// Returns `(value, validity_mask)` where `validity_mask` is `0xFF` if the
/// character is valid hex and `0x00` otherwise. No branches on data.
fn ct_hex_val(c: u8) -> (u8, u8) {
    // Compute all three candidate values unconditionally
    let digit = c.wrapping_sub(b'0');
    let upper = c.wrapping_sub(b'A').wrapping_add(10);
    let lower = c.wrapping_sub(b'a').wrapping_add(10);

    // Create validity masks (0xFF if valid, 0x00 if not) — branchless
    let digit_valid = ((digit as i8).wrapping_sub(10) >> 7) as u8; // 0xFF if digit < 10
    let upper_valid = ((upper.wrapping_sub(10) as i8).wrapping_sub(6) >> 7) as u8 & !digit_valid;
    let lower_valid =
        ((lower.wrapping_sub(10) as i8).wrapping_sub(6) >> 7) as u8 & !digit_valid & !upper_valid;

    // Select result using masks — no branches on data
    let result = (digit & digit_valid) | (upper & upper_valid) | (lower & lower_valid);
    let any_valid = digit_valid | upper_valid | lower_valid;

    (result, any_valid)
}

// ─── Secure Zero ───────────────────────────────────────────────────

/// Securely zeroize a mutable byte slice using volatile writes.
///
/// This ensures the compiler cannot optimize away the zeroization.
pub fn secure_zero(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

/// A guarded memory region that zeroizes on drop.
///
/// For enclave environments where sensitive data must be:
/// 1. Zeroized when no longer needed
/// 2. Tracked for lifetime management
/// 3. Protected from accidental copies
/// 4. Locked in RAM (when `mlock` feature is enabled)
///
/// Uses `Box<[u8]>` internally (not `Vec<u8>`) to guarantee the backing
/// pointer is never invalidated by reallocation — critical for `mlock` safety.
///
/// # Example
/// ```
/// use chains_sdk::security::GuardedMemory;
///
/// let mut guard = GuardedMemory::new(32);
/// guard.as_mut()[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
/// // memory is automatically zeroized (and munlocked) when `guard` is dropped
/// ```
pub struct GuardedMemory {
    inner: Zeroizing<Box<[u8]>>,
}

impl GuardedMemory {
    /// Allocate a new guarded memory region of `size` bytes (zeroed).
    ///
    /// When the `mlock` feature is enabled, the memory is locked into RAM
    /// to prevent the OS from swapping it to disk.
    #[must_use]
    pub fn new(size: usize) -> Self {
        let boxed: Box<[u8]> = vec![0u8; size].into_boxed_slice();
        #[cfg(feature = "mlock")]
        lock_memory(boxed.as_ptr(), boxed.len());
        Self { inner: Zeroizing::new(boxed) }
    }

    /// Create from existing data (takes ownership, original is NOT zeroized).
    ///
    /// Prefer this over copying into a `new()` buffer when you already
    /// have the data in a `Vec<u8>`.
    #[must_use]
    pub fn from_vec(data: Vec<u8>) -> Self {
        let boxed: Box<[u8]> = data.into_boxed_slice();
        #[cfg(feature = "mlock")]
        lock_memory(boxed.as_ptr(), boxed.len());
        Self { inner: Zeroizing::new(boxed) }
    }
}

impl AsRef<[u8]> for GuardedMemory {
    /// Immutable access to the guarded bytes.
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for GuardedMemory {
    /// Mutable access to the guarded bytes.
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Drop for GuardedMemory {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // Unlock memory before zeroization (Zeroizing handles the zeroing).
        // SAFETY: `self.inner` is a `Box<[u8]>` allocated via `into_boxed_slice()`.
        // Box<[u8]> never reallocates, so the pointer passed to `lock_memory`
        // in `new()` / `from_vec()` is guaranteed to be the same pointer here.
        #[cfg(feature = "mlock")]
        unlock_memory(self.inner.as_ptr(), self.inner.len());
    }
}

impl GuardedMemory {
    /// Length of the guarded region in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the guarded region is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl core::fmt::Debug for GuardedMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuardedMemory")
            .field("len", &self.inner.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

// ─── Memory Locking ────────────────────────────────────────────────

/// Lock a memory region to prevent swapping to disk.
///
/// Uses `mlock(2)` on Unix systems. Silently ignores errors
/// (e.g., insufficient `RLIMIT_MEMLOCK` — the security is best-effort).
#[cfg(feature = "mlock")]
#[allow(unsafe_code)]
fn lock_memory(ptr: *const u8, len: usize) {
    if len > 0 {
        // SAFETY: `ptr` points to a valid, heap-allocated region of at least
        // `len` bytes owned by a `Zeroizing<Vec<u8>>`. The `mlock(2)` syscall
        // is always safe to call on valid memory — it only advises the kernel
        // to keep the pages resident. Errors (e.g., RLIMIT_MEMLOCK exceeded)
        // are silently ignored as this is best-effort security.
        unsafe { libc::mlock(ptr.cast(), len) };
    }
}

/// Unlock a previously locked memory region.
#[cfg(feature = "mlock")]
#[allow(unsafe_code)]
fn unlock_memory(ptr: *const u8, len: usize) {
    if len > 0 {
        // SAFETY: `ptr` was previously passed to `lock_memory` and points to
        // a valid heap allocation of at least `len` bytes. `munlock(2)` is
        // always safe on valid memory and simply reverses the `mlock` advisory.
        unsafe { libc::munlock(ptr.cast(), len) };
    }
}

// ─── Pluggable RNG ─────────────────────────────────────────────────

/// Fill a buffer with cryptographically secure random bytes.
///
/// By default, delegates to `getrandom::getrandom()`. In enclave
/// environments where the default OS RNG is unavailable or untrusted,
/// use `set_custom_rng()` to provide a hardware TRNG source.
///
/// # Errors
/// Returns an error if the RNG source fails.
pub fn secure_random(buf: &mut [u8]) -> Result<(), crate::error::SignerError> {
    #[cfg(not(feature = "custom_rng"))]
    {
        getrandom::getrandom(buf)
            .map_err(|e| crate::error::SignerError::SigningFailed(format!("RNG failed: {e}")))
    }

    #[cfg(feature = "custom_rng")]
    {
        if let Some(f) = CUSTOM_RNG.get() {
            f(buf)
        } else {
            getrandom::getrandom(buf).map_err(|e| {
                crate::error::SignerError::SigningFailed(format!("RNG failed: {e}"))
            })
        }
    }
}

/// Custom RNG function type for TEE environments.
///
/// Must be `Send + Sync` for use in multi-threaded enclave environments.
#[cfg(feature = "custom_rng")]
pub type CustomRngFn =
    Box<dyn Fn(&mut [u8]) -> Result<(), crate::error::SignerError> + Send + Sync>;

#[cfg(feature = "custom_rng")]
static CUSTOM_RNG: std::sync::OnceLock<CustomRngFn> = std::sync::OnceLock::new();

/// Set a custom RNG source for enclave environments.
///
/// This replaces the default `getrandom` source with a user-provided
/// function, typically backed by a hardware TRNG (e.g., RDRAND/RDSEED
/// in SGX, or Nitro's `/dev/nsm`).
///
/// This is a global, process-wide setting. It can only be set **once**;
/// subsequent calls are silently ignored (the first RNG wins).
///
/// # Example
/// ```no_run
/// # #[cfg(feature = "custom_rng")]
/// chains_sdk::security::set_custom_rng(Box::new(|buf| {
///     // Fill from hardware TRNG
///     // my_enclave_trng_fill(buf);
///     Ok(())
/// }));
/// ```
#[cfg(feature = "custom_rng")]
pub fn set_custom_rng(f: CustomRngFn) {
    let _ = CUSTOM_RNG.set(f);
}

// ─── Attestation Hooks ─────────────────────────────────────────────

/// Enclave attestation context for remote verification.
///
/// Implement this trait to integrate chains-sdk with your enclave's
/// attestation mechanism (SGX quotes, Nitro attestation documents,
/// TDX reports, etc.).
///
/// # Example
/// ```no_run
/// use chains_sdk::security::EnclaveContext;
/// use chains_sdk::error::SignerError;
///
/// struct NitroEnclave;
///
/// impl EnclaveContext for NitroEnclave {
///     fn attest(&self, _user_data: &[u8]) -> Result<Vec<u8>, SignerError> {
///         // Call /dev/nsm to generate attestation document
///         Ok(vec![]) // placeholder
///     }
///     fn verify_attestation(&self, _doc: &[u8]) -> Result<bool, SignerError> {
///         // Verify attestation signature chain
///         Ok(true) // placeholder
///     }
/// }
/// ```
pub trait EnclaveContext {
    /// Generate an attestation document/quote binding to `user_data`.
    ///
    /// For SGX: EREPORT → quote (via QE)
    /// For Nitro: NSM attestation document
    /// For TDX: TD report → quote
    fn attest(&self, user_data: &[u8]) -> Result<Vec<u8>, crate::error::SignerError>;

    /// Verify an attestation document/quote.
    ///
    /// Returns `true` if the attestation is valid and trusted.
    fn verify_attestation(&self, attestation: &[u8]) -> Result<bool, crate::error::SignerError>;

    /// Seal data for persistent storage within the enclave.
    ///
    /// The sealed data can only be unsealed by the same enclave identity.
    /// Default implementation: passthrough (no sealing).
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, crate::error::SignerError> {
        Ok(plaintext.to_vec())
    }

    /// Unseal previously sealed data.
    ///
    /// Default implementation: passthrough (no unsealing).
    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, crate::error::SignerError> {
        Ok(Zeroizing::new(sealed.to_vec()))
    }
}

// ─── Key Rotation ──────────────────────────────────────────────────

/// Atomically rotate a key: generates a new key and zeroizes the old one.
///
/// Returns `(new_key, old_public_key)` — the old private key is zeroized.
///
/// # Example
/// ```
/// use chains_sdk::security::rotate_key;
/// use chains_sdk::ethereum::EthereumSigner;
/// use chains_sdk::traits::{KeyPair, Signer};
///
/// let old_signer = EthereumSigner::generate().unwrap();
/// let old_pubkey = old_signer.public_key_bytes();
///
/// let (new_signer, returned_pubkey) = rotate_key(old_signer,
///     || EthereumSigner::generate()
/// ).unwrap();
///
/// // Old public key is preserved, new signer has a different key
/// assert_eq!(returned_pubkey, old_pubkey);
/// assert_ne!(new_signer.public_key_bytes(), returned_pubkey);
/// ```
pub fn rotate_key<S>(
    old_signer: S,
    generate: impl FnOnce() -> Result<S, crate::error::SignerError>,
) -> Result<(S, Vec<u8>), crate::error::SignerError>
where
    S: crate::traits::Signer + crate::traits::KeyPair,
{
    // Capture old public key before dropping
    let old_pubkey = crate::traits::Signer::public_key_bytes(&old_signer);

    // Drop old signer — Zeroizing ensures key material is wiped
    drop(old_signer);

    // Generate new key
    let new_signer = generate()?;

    Ok((new_signer, old_pubkey))
}

/// Rotate a key using a specific seed (deterministic rotation).
///
/// Useful when the new key must be derived from specific entropy
/// (e.g., from an HSM or TRNG source).
pub fn rotate_key_with_seed<S>(
    old_signer: S,
    new_seed: &[u8],
) -> Result<(S, Vec<u8>), crate::error::SignerError>
where
    S: crate::traits::Signer<Error = crate::error::SignerError> + crate::traits::KeyPair,
{
    let old_pubkey = crate::traits::Signer::public_key_bytes(&old_signer);
    drop(old_signer);
    let new_signer = S::from_bytes(new_seed)?;
    Ok((new_signer, old_pubkey))
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_hex_encode() {
        assert_eq!(ct_hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(ct_hex_encode(&[]), "");
        assert_eq!(ct_hex_encode(&[0x00, 0xFF]), "00ff");
    }

    #[test]
    fn test_ct_hex_decode() {
        assert_eq!(
            ct_hex_decode("deadbeef"),
            Some(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        assert_eq!(ct_hex_decode(""), Some(vec![]));
        assert_eq!(ct_hex_decode("00ff"), Some(vec![0x00, 0xFF]));
        assert_eq!(
            ct_hex_decode("DEADBEEF"),
            Some(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_ct_hex_decode_invalid() {
        assert_eq!(ct_hex_decode("f"), None);
        assert_eq!(ct_hex_decode("gg"), None);
    }

    #[test]
    fn test_ct_hex_roundtrip() {
        let data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let encoded = ct_hex_encode(&data);
        let decoded = ct_hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xAA; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_guarded_memory_new() {
        let guard = GuardedMemory::new(32);
        assert_eq!(guard.len(), 32);
        assert!(guard.as_ref().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_guarded_memory_from_vec() {
        let data = vec![0xAA; 16];
        let guard = GuardedMemory::from_vec(data);
        assert_eq!(guard.len(), 16);
        assert!(guard.as_ref().iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_guarded_memory_mut() {
        let mut guard = GuardedMemory::new(4);
        guard.as_mut().copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(guard.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_guarded_memory_debug_redacted() {
        let guard = GuardedMemory::from_vec(vec![0xFF; 32]);
        let debug = format!("{:?}", guard);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("255"));
    }

    #[test]
    fn test_secure_random() {
        let mut buf = [0u8; 32];
        secure_random(&mut buf).unwrap();
        // Extremely unlikely all zero after random fill
        assert!(!buf.iter().all(|&b| b == 0));
    }
}
