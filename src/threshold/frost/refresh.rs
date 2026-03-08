//! FROST Proactive Secret Sharing — share refresh without changing the group key.
//!
//! Allows participants to refresh their key shares periodically to limit
//! the window of compromise. After refresh, old shares become useless
//! but the group public key remains unchanged.
//!
//! # Protocol
//!
//! Each participant generates a zero-secret polynomial (constant term = 0)
//! of degree (t-1), evaluates it at each other participant's identifier,
//! and distributes the "refresh deltas". Each participant adds all received
//! deltas to their existing share.
//!
//! Because the constant term is zero, the group secret `s = f(0)` is unchanged.

use crate::error::SignerError;
use super::keygen::{self, KeyPackage, VssCommitments};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use zeroize::Zeroizing;

/// A refresh package from one participant to distribute refresh deltas.
#[derive(Clone)]
pub struct RefreshPackage {
    /// Participant identifier of the sender.
    pub sender: u16,
    /// VSS commitments for the zero-secret polynomial.
    pub commitments: VssCommitments,
    /// Secret refresh deltas (one per participant, in order).
    deltas: Vec<Zeroizing<Scalar>>,
}

impl Drop for RefreshPackage {
    fn drop(&mut self) {
        // Zeroizing handles cleanup
    }
}

/// Generate a refresh package for proactive share refresh.
///
/// Each participant calls this to generate their contribution to the
/// refresh protocol. The generated polynomial has constant term = 0,
/// meaning it adds zero to the reconstructed secret.
///
/// # Arguments
/// - `min_signers` — Threshold (t)
/// - `max_signers` — Total participants (n)
/// - `my_id` — This participant's identifier
pub fn generate_refresh(
    min_signers: u16,
    max_signers: u16,
    my_id: u16,
) -> Result<RefreshPackage, SignerError> {
    if min_signers < 2 || max_signers < min_signers {
        return Err(SignerError::ParseError(
            "refresh requires min >= 2, max >= min".into(),
        ));
    }

    // Generate random polynomial with constant term = 0
    // f(x) = a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
    let mut coefficients = vec![Scalar::ZERO]; // a_0 = 0 (preserves group secret)
    for _ in 1..min_signers {
        coefficients.push(keygen::random_scalar()?);
    }

    // VSS commitments: C_k = G * a_k (C_0 = identity since a_0 = 0)
    let commitment_points = coefficients
        .iter()
        .map(|c| (ProjectivePoint::GENERATOR * c).to_affine())
        .collect();

    // Evaluate polynomial at each participant's identifier
    let mut deltas = Vec::with_capacity(max_signers as usize);
    for i in 1..=max_signers {
        let x = Scalar::from(u64::from(i));
        let delta = keygen::polynomial_evaluate(&x, &coefficients);
        deltas.push(Zeroizing::new(delta));
    }

    Ok(RefreshPackage {
        sender: my_id,
        commitments: VssCommitments { commitments: commitment_points },
        deltas,
    })
}

/// Apply refresh deltas to an existing key package.
///
/// Each participant collects their delta from each refresh package
/// and adds it to their existing secret share.
///
/// # Arguments
/// - `key_package` — The existing key package to refresh
/// - `refresh_packages` — All refresh packages from all participants
///
/// # Returns
/// A new `KeyPackage` with the refreshed secret share (same group key).
pub fn apply_refresh(
    key_package: &KeyPackage,
    refresh_packages: &[RefreshPackage],
) -> Result<KeyPackage, SignerError> {
    let my_idx = (key_package.identifier - 1) as usize;

    // Verify each refresh package's delta against VSS commitments
    for pkg in refresh_packages {
        if my_idx >= pkg.deltas.len() {
            return Err(SignerError::ParseError("refresh package missing delta".into()));
        }
        // Verify: the commitment at index 0 should be identity (zero secret)
        let c0 = pkg.commitments.commitments[0];
        if ProjectivePoint::from(c0) != ProjectivePoint::IDENTITY {
            return Err(SignerError::SigningFailed(format!(
                "refresh package from {} has non-zero constant term", pkg.sender
            )));
        }
        // Verify delta against VSS commitments
        let valid = pkg.commitments.verify_share(key_package.identifier, &pkg.deltas[my_idx]);
        if !valid {
            return Err(SignerError::SigningFailed(format!(
                "VSS verification failed for refresh from participant {}", pkg.sender
            )));
        }
    }

    // Sum all deltas for this participant
    let mut delta_sum = Scalar::ZERO;
    for pkg in refresh_packages {
        delta_sum += pkg.deltas[my_idx].as_ref();
    }

    // New share = old share + delta
    let new_share = *key_package.secret_share() + delta_sum;

    Ok(KeyPackage {
        identifier: key_package.identifier,
        secret_share: Zeroizing::new(new_share),
        group_public_key: key_package.group_public_key,
        min_participants: key_package.min_participants,
        max_participants: key_package.max_participants,
    })
}

/// Verify that a refresh package is valid (zero-secret invariant).
///
/// Checks that the constant term commitment is the identity point,
/// ensuring the group secret is preserved.
#[must_use]
pub fn verify_refresh_package(pkg: &RefreshPackage) -> bool {
    if pkg.commitments.commitments.is_empty() {
        return false;
    }
    // C_0 must be identity (G * 0)
    ProjectivePoint::from(pkg.commitments.commitments[0]) == ProjectivePoint::IDENTITY
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::threshold::frost::signing;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn test_refresh_preserves_group_key() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let original_gpk = kgen.group_public_key;

        // All 3 participants generate refresh packages
        let r1 = generate_refresh(2, 3, 1).unwrap();
        let r2 = generate_refresh(2, 3, 2).unwrap();
        let r3 = generate_refresh(2, 3, 3).unwrap();
        let refresh_pkgs = vec![r1, r2, r3];

        // Each participant applies the refresh
        let new_kp1 = apply_refresh(&kgen.key_packages[0], &refresh_pkgs).unwrap();
        let new_kp2 = apply_refresh(&kgen.key_packages[1], &refresh_pkgs).unwrap();
        let new_kp3 = apply_refresh(&kgen.key_packages[2], &refresh_pkgs).unwrap();

        // Group public key must be preserved
        assert_eq!(new_kp1.group_public_key, original_gpk);
        assert_eq!(new_kp2.group_public_key, original_gpk);

        // Shares should have changed
        assert_ne!(*new_kp1.secret_share(), *kgen.key_packages[0].secret_share());
    }

    #[test]
    fn test_refreshed_shares_can_sign() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let group_pk = kgen.group_public_key;

        let r1 = generate_refresh(2, 3, 1).unwrap();
        let r2 = generate_refresh(2, 3, 2).unwrap();
        let r3 = generate_refresh(2, 3, 3).unwrap();
        let refresh_pkgs = vec![r1, r2, r3];

        let new_kp1 = apply_refresh(&kgen.key_packages[0], &refresh_pkgs).unwrap();
        let new_kp2 = apply_refresh(&kgen.key_packages[1], &refresh_pkgs).unwrap();

        // Sign with refreshed shares
        let msg = b"signing with refreshed shares";
        let n1 = signing::commit(&new_kp1).unwrap();
        let n2 = signing::commit(&new_kp2).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = signing::sign(&new_kp1, n1, &comms, msg).unwrap();
        let s2 = signing::sign(&new_kp2, n2, &comms, msg).unwrap();
        let sig = signing::aggregate(&comms, &[s1, s2], &group_pk, msg).unwrap();

        assert!(signing::verify(&sig, &group_pk, msg).unwrap(),
            "refreshed shares must produce valid signatures");
    }

    #[test]
    fn test_refresh_package_verification() {
        let pkg = generate_refresh(2, 3, 1).unwrap();
        assert!(verify_refresh_package(&pkg));
    }

    #[test]
    fn test_refresh_invalid_params() {
        assert!(generate_refresh(1, 3, 1).is_err());
        assert!(generate_refresh(4, 3, 1).is_err());
    }

    #[test]
    fn test_multiple_refreshes() {
        let secret = [0x42u8; 32];
        let kgen = keygen::trusted_dealer_keygen(&secret, 2, 3).unwrap();
        let original_gpk = kgen.group_public_key;

        // First refresh
        let r1 = vec![
            generate_refresh(2, 3, 1).unwrap(),
            generate_refresh(2, 3, 2).unwrap(),
            generate_refresh(2, 3, 3).unwrap(),
        ];
        let kp1_r1 = apply_refresh(&kgen.key_packages[0], &r1).unwrap();
        let kp2_r1 = apply_refresh(&kgen.key_packages[1], &r1).unwrap();

        // Second refresh
        let r2 = vec![
            generate_refresh(2, 3, 1).unwrap(),
            generate_refresh(2, 3, 2).unwrap(),
            generate_refresh(2, 3, 3).unwrap(),
        ];
        let kp1_r2 = apply_refresh(&kp1_r1, &r2).unwrap();
        let kp2_r2 = apply_refresh(&kp2_r1, &r2).unwrap();

        // Still the same group key
        assert_eq!(kp1_r2.group_public_key, original_gpk);

        // Can still sign
        let msg = b"after two refreshes";
        let n1 = signing::commit(&kp1_r2).unwrap();
        let n2 = signing::commit(&kp2_r2).unwrap();
        let comms = vec![n1.commitments.clone(), n2.commitments.clone()];
        let s1 = signing::sign(&kp1_r2, n1, &comms, msg).unwrap();
        let s2 = signing::sign(&kp2_r2, n2, &comms, msg).unwrap();
        let sig = signing::aggregate(&comms, &[s1, s2], &original_gpk, msg).unwrap();
        assert!(signing::verify(&sig, &original_gpk, msg).unwrap());
    }
}
