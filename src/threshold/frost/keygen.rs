//! FROST key generation using Shamir secret sharing.
//!
//! Implements trusted dealer key generation per RFC 9591 Appendix C.
//! Splits a group signing key into shares using polynomial evaluation,
//! with verifiable secret sharing (VSS) commitments.

use crate::error::SignerError;
use k256::elliptic_curve::ops::Reduce;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::Zeroizing;

/// A participant's key package containing their secret share and group info.
#[derive(Clone)]
pub struct KeyPackage {
    /// Participant identifier (1-based, non-zero).
    pub identifier: u16,
    /// The participant's secret signing share `sk_i = f(i)`.
    secret_share: Zeroizing<Scalar>,
    /// The group's combined public key `PK = G * s`.
    pub group_public_key: AffinePoint,
    /// Min participants required to sign (threshold).
    pub min_participants: u16,
    /// Max participants that hold shares.
    pub max_participants: u16,
}

impl Drop for KeyPackage {
    fn drop(&mut self) {
        // secret_share is Zeroizing, automatically zeroed
    }
}

impl KeyPackage {
    /// Get the secret share scalar.
    pub fn secret_share(&self) -> &Scalar {
        &self.secret_share
    }

    /// Compute the public key corresponding to this share: `PK_i = G * sk_i`.
    pub fn public_key(&self) -> AffinePoint {
        (ProjectivePoint::GENERATOR * *self.secret_share).to_affine()
    }

    /// Get the secret share bytes (for serialization).
    pub fn secret_share_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&self.secret_share.to_bytes());
        bytes
    }
}

/// VSS (Verifiable Secret Sharing) commitments.
///
/// Each commitment `C_k = G * a_k` where `a_k` is the k-th polynomial coefficient.
/// Participants can verify their shares without learning the secret.
#[derive(Clone, Debug)]
pub struct VssCommitments {
    /// The commitments `[G*a_0, G*a_1, ..., G*a_{t-1}]`.
    pub commitments: Vec<AffinePoint>,
}

impl VssCommitments {
    /// Verify a participant's share against the VSS commitments.
    ///
    /// Checks: `G * share == C_0 + i*C_1 + i^2*C_2 + ...`
    pub fn verify_share(&self, identifier: u16, share: &Scalar) -> bool {
        if identifier == 0 || self.commitments.is_empty() {
            return false;
        }

        let i_scalar = Scalar::from(u64::from(identifier));
        let lhs = ProjectivePoint::GENERATOR * *share;

        // Evaluate the polynomial of commitments at point i using Horner's method
        let mut rhs = ProjectivePoint::IDENTITY;
        for ck in self.commitments.iter().rev() {
            rhs = rhs * i_scalar + ProjectivePoint::from(*ck);
        }

        lhs == rhs
    }
}

/// Output of trusted dealer key generation.
pub struct KeyGenOutput {
    /// Key packages for each participant.
    pub key_packages: Vec<KeyPackage>,
    /// VSS commitments for share verification.
    pub vss_commitments: VssCommitments,
    /// The group public key.
    pub group_public_key: AffinePoint,
}

/// Generate key shares using a trusted dealer (RFC 9591 Appendix C).
///
/// The dealer holds the group secret key `s` and splits it into `max_participants`
/// shares using a degree `(min_participants - 1)` polynomial, such that any
/// `min_participants` shares can reconstruct the secret.
///
/// # Arguments
/// * `group_secret` - The group signing key `s` (32-byte scalar)
/// * `min_participants` - Minimum signers required (threshold `t`)
/// * `max_participants` - Total number of shares to generate (`n`)
///
/// # Returns
/// `KeyGenOutput` containing key packages and VSS commitments.
pub fn trusted_dealer_keygen(
    group_secret: &[u8; 32],
    min_participants: u16,
    max_participants: u16,
) -> Result<KeyGenOutput, SignerError> {
    if min_participants < 2 {
        return Err(SignerError::InvalidPrivateKey(
            "min_participants must be >= 2".into(),
        ));
    }
    if max_participants < min_participants {
        return Err(SignerError::InvalidPrivateKey(
            "max_participants must be >= min_participants".into(),
        ));
    }

    let s = scalar_from_bytes(group_secret)?;
    let group_public_key = (ProjectivePoint::GENERATOR * s).to_affine();

    // Generate random coefficients a_1, ..., a_{t-1}
    let mut coefficients = Vec::with_capacity(min_participants as usize);
    coefficients.push(s); // a_0 = s (the secret)

    for _ in 1..min_participants {
        let coeff = random_scalar()?;
        coefficients.push(coeff);
    }

    // VSS commitments: C_k = G * a_k
    let vss_commitments = VssCommitments {
        commitments: coefficients
            .iter()
            .map(|a| (ProjectivePoint::GENERATOR * *a).to_affine())
            .collect(),
    };

    // Generate shares: sk_i = f(i) for i = 1..=n
    let mut key_packages = Vec::with_capacity(max_participants as usize);
    for i in 1..=max_participants {
        let x = Scalar::from(u64::from(i));
        let share = polynomial_evaluate(&x, &coefficients);

        key_packages.push(KeyPackage {
            identifier: i,
            secret_share: Zeroizing::new(share),
            group_public_key,
            min_participants,
            max_participants,
        });
    }

    // Zeroize coefficients
    for c in coefficients.iter_mut() {
        *c = Scalar::ZERO;
    }

    Ok(KeyGenOutput {
        key_packages,
        vss_commitments,
        group_public_key,
    })
}

/// Evaluate a polynomial at point `x` using Horner's method.
///
/// `f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}`
pub fn polynomial_evaluate(x: &Scalar, coefficients: &[Scalar]) -> Scalar {
    let mut result = Scalar::ZERO;
    for c in coefficients.iter().rev() {
        result = result * x + c;
    }
    result
}

/// Compute the Lagrange interpolation coefficient for participant `x_i`
/// given the set of participant identifiers.
///
/// `L_i(0) = Π_{j≠i} (x_j / (x_j - x_i))`
pub fn derive_interpolating_value(
    x_i: &Scalar,
    participant_identifiers: &[Scalar],
) -> Result<Scalar, SignerError> {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for x_j in participant_identifiers {
        if x_j == x_i {
            continue;
        }
        numerator *= x_j;
        denominator *= *x_j - x_i;
    }

    // denominator must not be zero
    if denominator == Scalar::ZERO {
        return Err(SignerError::InvalidPrivateKey(
            "duplicate participant identifiers".into(),
        ));
    }

    Ok(numerator * denominator.invert().unwrap_or(Scalar::ZERO))
}

/// Parse a scalar from 32 bytes.
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, SignerError> {
    let wide = k256::U256::from_be_slice(bytes);
    let scalar = <Scalar as Reduce<k256::U256>>::reduce(wide);
    if scalar == Scalar::ZERO {
        return Err(SignerError::InvalidPrivateKey("scalar is zero".into()));
    }
    Ok(scalar)
}

/// Generate a random non-zero scalar.
pub fn random_scalar() -> Result<Scalar, SignerError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| SignerError::EntropyError)?;
    let wide = k256::U256::from_be_slice(&bytes);
    let scalar = <Scalar as Reduce<k256::U256>>::reduce(wide);
    if scalar == Scalar::ZERO {
        // Extremely unlikely, retry
        return random_scalar();
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_evaluate() {
        // f(x) = 3 + 2x + x^2 → f(2) = 3 + 4 + 4 = 11
        let coeffs = [
            Scalar::from(3u64),
            Scalar::from(2u64),
            Scalar::from(1u64),
        ];
        let result = polynomial_evaluate(&Scalar::from(2u64), &coeffs);
        assert_eq!(result, Scalar::from(11u64));
    }

    #[test]
    fn test_trusted_dealer_keygen_2_of_3() {
        let secret = [0x42u8; 32];
        let out = trusted_dealer_keygen(&secret, 2, 3).unwrap();
        assert_eq!(out.key_packages.len(), 3);
        assert_eq!(out.vss_commitments.commitments.len(), 2);

        // Verify each share against VSS commitments
        for pkg in &out.key_packages {
            assert!(out
                .vss_commitments
                .verify_share(pkg.identifier, pkg.secret_share()));
        }
    }

    #[test]
    fn test_share_reconstruction_lagrange() {
        let secret = [0x42u8; 32];
        let out = trusted_dealer_keygen(&secret, 2, 3).unwrap();

        // Use shares 1 and 3 to reconstruct the secret
        let ids = [Scalar::from(1u64), Scalar::from(3u64)];
        let shares = [
            *out.key_packages[0].secret_share(),
            *out.key_packages[2].secret_share(),
        ];

        let mut reconstructed = Scalar::ZERO;
        for (i, share) in shares.iter().enumerate() {
            let lambda = derive_interpolating_value(&ids[i], &ids).unwrap();
            reconstructed += lambda * share;
        }

        let original = scalar_from_bytes(&[0x42u8; 32]).unwrap();
        assert_eq!(reconstructed, original);
    }

    #[test]
    fn test_invalid_params() {
        let secret = [0x42u8; 32];
        assert!(trusted_dealer_keygen(&secret, 1, 3).is_err()); // min < 2
        assert!(trusted_dealer_keygen(&secret, 3, 2).is_err()); // max < min
    }
}
