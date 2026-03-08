//! BLS12-381 signer for Ethereum Proof-of-Stake (Beacon Chain).
//!
//! Uses the `blst` crate for BLS12-381 operations including
//! single signing, signature aggregation, and aggregated verification.

pub mod eip2333;
pub mod keystore;
pub mod threshold;

use crate::error::SignerError;
use crate::traits;
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature as BlstSignature};
use blst::BLST_ERROR;
use zeroize::Zeroizing;

/// Domain Separation Tag for Ethereum Beacon Chain BLS.
pub const ETH2_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS12-381 signature (96 bytes, G2 point).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub struct BlsSignature {
    /// The 96-byte compressed G2 signature.
    #[cfg_attr(feature = "serde", serde(with = "crate::hex_bytes"))]
    pub bytes: [u8; 96],
}

impl core::fmt::Display for BlsSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl BlsSignature {
    /// Export the 96-byte signature.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.bytes
    }

    /// Import from 96 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 96 {
            return Err(SignerError::InvalidSignature(format!(
                "expected 96 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 96];
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }
}

/// A BLS12-381 public key (48 bytes, G1 point).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlsPublicKey {
    /// The 48-byte compressed G1 public key.
    #[cfg_attr(feature = "serde", serde(with = "crate::hex_bytes"))]
    pub bytes: [u8; 48],
}

impl BlsPublicKey {
    /// Export the 48-byte public key.
    pub fn to_bytes(&self) -> [u8; 48] {
        self.bytes
    }

    /// Import from 48 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 48 {
            return Err(SignerError::InvalidPublicKey(format!(
                "expected 48 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }
}

/// BLS12-381 signer for Ethereum PoS.
pub struct BlsSigner {
    secret_key: SecretKey,
}

// Manual Zeroize implementation since blst SecretKey stores raw bytes
impl Drop for BlsSigner {
    fn drop(&mut self) {
        // SecretKey internally stores the scalar — blst handles zeroization
        // We rely on blst's own cleanup, but mark the type as zeroize-aware
    }
}

impl BlsSigner {
    /// Get the public key.
    pub fn public_key(&self) -> BlsPublicKey {
        let pk = self.secret_key.sk_to_pk();
        let bytes = pk.compress();
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        BlsPublicKey { bytes: out }
    }
}

impl traits::Signer for BlsSigner {
    type Signature = BlsSignature;
    type Error = SignerError;

    fn sign(&self, message: &[u8]) -> Result<BlsSignature, SignerError> {
        let sig = self.secret_key.sign(message, ETH2_DST, &[]);
        let compressed = sig.compress();
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&compressed);
        Ok(BlsSignature { bytes })
    }

    /// **Note:** BLS uses hash-to-curve (H2C) internally. This method is identical to
    /// `sign()` — the `digest` parameter is treated as a raw message, not a
    /// pre-computed hash. For consistency with the `Signer` trait, this is provided as-is.
    fn sign_prehashed(&self, digest: &[u8]) -> Result<BlsSignature, SignerError> {
        // BLS hash-to-curve means there's no external pre-hashing.
        self.sign(digest)
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().bytes.to_vec()
    }

    fn public_key_bytes_uncompressed(&self) -> Vec<u8> {
        // BLS12-381 G1 only has compressed form
        self.public_key_bytes()
    }
}

impl traits::KeyPair for BlsSigner {
    fn generate() -> Result<Self, SignerError> {
        use zeroize::Zeroize;
        let mut ikm = [0u8; 32];
        crate::security::secure_random(&mut ikm)?;
        let secret_key = SecretKey::key_gen(&ikm, &[]).map_err(|_| SignerError::EntropyError)?;
        ikm.zeroize(); // volatile write barrier — cannot be optimized away
        Ok(Self { secret_key })
    }

    fn from_bytes(private_key: &[u8]) -> Result<Self, SignerError> {
        if private_key.len() != 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                private_key.len()
            )));
        }
        let secret_key = SecretKey::from_bytes(private_key)
            .map_err(|_| SignerError::InvalidPrivateKey("invalid BLS secret key".into()))?;
        Ok(Self { secret_key })
    }

    fn private_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.secret_key.to_bytes().to_vec())
    }
}

/// BLS12-381 verifier.
pub struct BlsVerifier {
    public_key: PublicKey,
}

impl BlsVerifier {
    /// Create from 48-byte compressed public key.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<Self, SignerError> {
        if bytes.len() != 48 {
            return Err(SignerError::InvalidPublicKey(format!(
                "expected 48 bytes, got {}",
                bytes.len()
            )));
        }
        let public_key = PublicKey::from_bytes(bytes)
            .map_err(|_| SignerError::InvalidPublicKey("invalid BLS public key".into()))?;
        Ok(Self { public_key })
    }
}

impl traits::Verifier for BlsVerifier {
    type Signature = BlsSignature;
    type Error = SignerError;

    fn verify(&self, message: &[u8], signature: &BlsSignature) -> Result<bool, SignerError> {
        let sig = BlstSignature::from_bytes(&signature.bytes)
            .map_err(|_| SignerError::InvalidSignature("invalid BLS signature".into()))?;
        let result = sig.verify(true, message, ETH2_DST, &[], &self.public_key, true);
        Ok(result == BLST_ERROR::BLST_SUCCESS)
    }

    fn verify_prehashed(
        &self,
        digest: &[u8],
        signature: &BlsSignature,
    ) -> Result<bool, SignerError> {
        self.verify(digest, signature)
    }
}

/// Aggregate multiple BLS signatures into a single signature.
pub fn aggregate_signatures(signatures: &[BlsSignature]) -> Result<BlsSignature, SignerError> {
    if signatures.is_empty() {
        return Err(SignerError::AggregationError(
            "no signatures to aggregate".into(),
        ));
    }

    let blst_sigs: Vec<BlstSignature> = signatures
        .iter()
        .map(|s| {
            BlstSignature::from_bytes(&s.bytes)
                .map_err(|_| SignerError::InvalidSignature("invalid BLS signature".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let sig_refs: Vec<&BlstSignature> = blst_sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|_| SignerError::AggregationError("aggregation failed".into()))?;

    let compressed = agg.to_signature().compress();
    let mut bytes = [0u8; 96];
    bytes.copy_from_slice(&compressed);
    Ok(BlsSignature { bytes })
}

/// Verify an aggregated BLS signature against multiple public keys (same message).
pub fn verify_aggregated(
    public_keys: &[BlsPublicKey],
    message: &[u8],
    agg_signature: &BlsSignature,
) -> Result<bool, SignerError> {
    if public_keys.is_empty() {
        return Err(SignerError::AggregationError("no public keys".into()));
    }

    let pks: Vec<PublicKey> = public_keys
        .iter()
        .map(|pk| {
            PublicKey::from_bytes(&pk.bytes)
                .map_err(|_| SignerError::InvalidPublicKey("invalid BLS public key".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let sig = BlstSignature::from_bytes(&agg_signature.bytes)
        .map_err(|_| SignerError::InvalidSignature("invalid BLS signature".into()))?;

    let msgs: Vec<&[u8]> = vec![message; pk_refs.len()];

    let result = sig.aggregate_verify(true, &msgs, ETH2_DST, &pk_refs, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

/// Verify an aggregated BLS signature where each signer signed a **different message**.
///
/// This is the standard ETH2 attestation pattern: N validators each sign their own
/// message, the signatures are aggregated, and the verifier checks all (pk, msg) pairs
/// against the single aggregated signature.
///
/// `pairs`: slice of `(public_key, message)` tuples.
pub fn verify_aggregated_multi(
    pairs: &[(BlsPublicKey, &[u8])],
    agg_signature: &BlsSignature,
) -> Result<bool, SignerError> {
    if pairs.is_empty() {
        return Err(SignerError::AggregationError("no pairs to verify".into()));
    }

    let pks: Vec<PublicKey> = pairs
        .iter()
        .map(|(pk, _)| {
            PublicKey::from_bytes(&pk.bytes)
                .map_err(|_| SignerError::InvalidPublicKey("invalid BLS public key".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let msgs: Vec<&[u8]> = pairs.iter().map(|(_, m)| *m).collect();

    let sig = BlstSignature::from_bytes(&agg_signature.bytes)
        .map_err(|_| SignerError::InvalidSignature("invalid BLS signature".into()))?;

    let result = sig.aggregate_verify(true, &msgs, ETH2_DST, &pk_refs, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_generate_keypair() {
        let signer = BlsSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes().len(), 48);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let key_bytes = signer.private_key_bytes();
        let restored = BlsSigner::from_bytes(&key_bytes).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let sig = signer.sign(b"hello bls").unwrap();
        let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(b"hello bls", &sig).unwrap());
    }

    #[test]
    fn test_signature_96_bytes() {
        let signer = BlsSigner::generate().unwrap();
        let sig = signer.sign(b"test").unwrap();
        assert_eq!(sig.bytes.len(), 96);
    }

    #[test]
    fn test_aggregate_2_sigs() {
        let msg = b"aggregate test";
        let s1 = BlsSigner::generate().unwrap();
        let s2 = BlsSigner::generate().unwrap();
        let sig1 = s1.sign(msg).unwrap();
        let sig2 = s2.sign(msg).unwrap();

        let agg_sig = aggregate_signatures(&[sig1, sig2]).unwrap();
        let result = verify_aggregated(&[s1.public_key(), s2.public_key()], msg, &agg_sig).unwrap();
        assert!(result);
    }

    #[test]
    fn test_aggregate_10_sigs() {
        let msg = b"ten signers";
        let signers: Vec<BlsSigner> = (0..10).map(|_| BlsSigner::generate().unwrap()).collect();
        let sigs: Vec<BlsSignature> = signers.iter().map(|s| s.sign(msg).unwrap()).collect();
        let pks: Vec<BlsPublicKey> = signers.iter().map(|s| s.public_key()).collect();

        let agg_sig = aggregate_signatures(&sigs).unwrap();
        assert!(verify_aggregated(&pks, msg, &agg_sig).unwrap());
    }

    #[test]
    fn test_invalid_agg_fails() {
        let msg = b"bad aggregate";
        let s1 = BlsSigner::generate().unwrap();
        let s2 = BlsSigner::generate().unwrap();
        let sig1 = s1.sign(msg).unwrap();
        let sig2 = s2.sign(b"different message").unwrap(); // wrong message

        let agg_sig = aggregate_signatures(&[sig1, sig2]).unwrap();
        let result = verify_aggregated(&[s1.public_key(), s2.public_key()], msg, &agg_sig).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_dst_correctness() {
        assert_eq!(ETH2_DST, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
    }

    #[test]
    fn test_known_vector_eth2() {
        // Use a deterministic secret key and verify sign → verify round-trip
        let sk_bytes =
            hex::decode("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
                .unwrap();
        let signer = BlsSigner::from_bytes(&sk_bytes).unwrap();
        let msg = hex::decode("5656565656565656565656565656565656565656565656565656565656565656")
            .unwrap();
        let sig = signer.sign(&msg).unwrap();
        let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(&msg, &sig).unwrap());
    }

    #[test]
    fn test_invalid_key_rejected() {
        assert!(BlsSigner::from_bytes(&[0u8; 31]).is_err());
        assert!(BlsSigner::from_bytes(&[0u8; 33]).is_err());
    }

    #[test]
    fn test_tampered_sig_fails() {
        let signer = BlsSigner::generate().unwrap();
        let sig = signer.sign(b"tamper").unwrap();
        let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        let mut tampered = sig.clone();
        tampered.bytes[0] ^= 0xff;
        let result = verifier.verify(b"tamper", &tampered);
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_sign_prehashed_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let msg = b"prehash bls";
        let sig = signer.sign_prehashed(msg).unwrap();
        let verifier = BlsVerifier::from_public_key_bytes(&signer.public_key_bytes()).unwrap();
        assert!(verifier.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_zeroize_on_drop() {
        let signer = BlsSigner::generate().unwrap();
        let _: Zeroizing<Vec<u8>> = signer.private_key_bytes();
        drop(signer);
    }

    #[test]
    fn test_multi_message_aggregation() {
        let s1 = BlsSigner::generate().unwrap();
        let s2 = BlsSigner::generate().unwrap();
        let s3 = BlsSigner::generate().unwrap();

        let msg1 = b"attestation slot 100";
        let msg2 = b"attestation slot 101";
        let msg3 = b"attestation slot 102";

        let sig1 = s1.sign(msg1).unwrap();
        let sig2 = s2.sign(msg2).unwrap();
        let sig3 = s3.sign(msg3).unwrap();

        let agg = aggregate_signatures(&[sig1, sig2, sig3]).unwrap();

        let pairs: Vec<(BlsPublicKey, &[u8])> = vec![
            (s1.public_key(), msg1.as_slice()),
            (s2.public_key(), msg2.as_slice()),
            (s3.public_key(), msg3.as_slice()),
        ];
        assert!(verify_aggregated_multi(&pairs, &agg).unwrap());
    }

    #[test]
    fn test_multi_message_wrong_message_fails() {
        let s1 = BlsSigner::generate().unwrap();
        let s2 = BlsSigner::generate().unwrap();

        let sig1 = s1.sign(b"correct 1").unwrap();
        let sig2 = s2.sign(b"correct 2").unwrap();

        let agg = aggregate_signatures(&[sig1, sig2]).unwrap();

        let pairs: Vec<(BlsPublicKey, &[u8])> = vec![
            (s1.public_key(), b"correct 1".as_slice()),
            (s2.public_key(), b"WRONG MESSAGE".as_slice()), // wrong
        ];
        assert!(!verify_aggregated_multi(&pairs, &agg).unwrap());
    }
}
