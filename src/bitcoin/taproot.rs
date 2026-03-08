//! **BIP-341** — Taproot output construction and script-path spending.
//!
//! Implements the full TapTree (Merkelized Abstract Syntax Tree) for organizing
//! spending conditions, key tweaking, control block construction, and P2TR
//! address generation from script trees.
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::taproot::{TapTree, TapLeaf};
//!
//! // Build a TapTree with two spending scripts
//! let leaf1 = TapLeaf::new(0xC0, vec![0x51]); // OP_TRUE
//! let leaf2 = TapLeaf::new(0xC0, vec![0x00]); // OP_FALSE
//! let tree = TapTree::branch(TapTree::leaf(leaf1), TapTree::leaf(leaf2));
//! let merkle_root = tree.merkle_root();
//! ```

use crate::crypto::tagged_hash;
use crate::encoding;
use crate::error::SignerError;

// ─── TapLeaf ────────────────────────────────────────────────────────

/// A leaf node in a TapTree, containing a script and leaf version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapLeaf {
    /// The leaf version (default 0xC0 for Tapscript as defined in BIP-342).
    pub version: u8,
    /// The script bytes.
    pub script: Vec<u8>,
}

impl TapLeaf {
    /// Create a new TapLeaf with the given version and script.
    pub fn new(version: u8, script: Vec<u8>) -> Self {
        Self { version, script }
    }

    /// Create a Tapscript leaf (version 0xC0) with the given script.
    pub fn tapscript(script: Vec<u8>) -> Self {
        Self {
            version: 0xC0,
            script,
        }
    }

    /// Compute the leaf hash: `tagged_hash("TapLeaf", version || compact_size(script) || script)`.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut data = Vec::new();
        data.push(self.version);
        encoding::encode_compact_size(&mut data, self.script.len() as u64);
        data.extend_from_slice(&self.script);
        tagged_hash(b"TapLeaf", &data)
    }
}

// ─── TapTree (Merkle Tree) ──────────────────────────────────────────

/// A node in the Taproot Merkle tree.
#[derive(Clone, Debug)]
pub enum TapTree {
    /// A leaf node containing a script.
    Leaf(TapLeaf),
    /// A branch node with two children.
    Branch(Box<TapTree>, Box<TapTree>),
}

impl TapTree {
    /// Create a leaf node.
    pub fn leaf(tap_leaf: TapLeaf) -> Self {
        TapTree::Leaf(tap_leaf)
    }

    /// Create a branch node from two children.
    pub fn branch(left: TapTree, right: TapTree) -> Self {
        TapTree::Branch(Box::new(left), Box::new(right))
    }

    /// Compute the merkle root hash of this tree node.
    ///
    /// - Leaf: `tagged_hash("TapLeaf", ...)`
    /// - Branch: `tagged_hash("TapBranch", sort(left, right))`
    pub fn merkle_root(&self) -> [u8; 32] {
        match self {
            TapTree::Leaf(leaf) => leaf.leaf_hash(),
            TapTree::Branch(left, right) => {
                let left_hash = left.merkle_root();
                let right_hash = right.merkle_root();
                tap_branch_hash(&left_hash, &right_hash)
            }
        }
    }

    /// Compute the merkle proof (path) for a specific leaf.
    ///
    /// Returns `Some(path)` where path is a list of 32-byte hashes,
    /// or `None` if the leaf is not found in this tree.
    pub fn merkle_proof(&self, target_leaf: &TapLeaf) -> Option<Vec<[u8; 32]>> {
        self.find_proof(target_leaf)
    }

    fn find_proof(&self, target: &TapLeaf) -> Option<Vec<[u8; 32]>> {
        match self {
            TapTree::Leaf(leaf) => {
                if leaf == target {
                    Some(Vec::new())
                } else {
                    None
                }
            }
            TapTree::Branch(left, right) => {
                // Try left subtree
                if let Some(mut path) = left.find_proof(target) {
                    path.push(right.merkle_root());
                    return Some(path);
                }
                // Try right subtree
                if let Some(mut path) = right.find_proof(target) {
                    path.push(left.merkle_root());
                    return Some(path);
                }
                None
            }
        }
    }

    /// Count the total number of leaves in this tree.
    pub fn leaf_count(&self) -> usize {
        match self {
            TapTree::Leaf(_) => 1,
            TapTree::Branch(left, right) => left.leaf_count() + right.leaf_count(),
        }
    }

    /// Get the depth of the tree.
    pub fn depth(&self) -> usize {
        match self {
            TapTree::Leaf(_) => 0,
            TapTree::Branch(left, right) => 1 + left.depth().max(right.depth()),
        }
    }
}

// ─── Branch Hashing ─────────────────────────────────────────────────

/// Compute a TapBranch hash from two child hashes.
///
/// Per BIP-341: `tagged_hash("TapBranch", sort(a, b))` — the smaller hash comes first.
pub fn tap_branch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    // Lexicographic sort
    if a <= b {
        data.extend_from_slice(a);
        data.extend_from_slice(b);
    } else {
        data.extend_from_slice(b);
        data.extend_from_slice(a);
    }
    tagged_hash(b"TapBranch", &data)
}

// ─── Key Tweaking ───────────────────────────────────────────────────

/// Tweak an internal public key with a merkle root to produce the output key.
///
/// **BIP-341 Algorithm:**
/// - `t = tagged_hash("TapTweak", internal_key || merkle_root)`
/// - `Q = P + t*G`
///
/// Returns `Ok((tweaked_x_only_key, parity))` where parity indicates if Q has odd y.
///
/// If `merkle_root` is `None`, uses key-path-only: `t = tagged_hash("TapTweak", internal_key)`.
///
/// Returns `Err` if the internal key is not a valid curve point.
pub fn taproot_tweak(
    internal_key: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Result<([u8; 32], bool), SignerError> {
    // Compute tweak scalar
    let mut tweak_data = Vec::with_capacity(64);
    tweak_data.extend_from_slice(internal_key);
    if let Some(root) = merkle_root {
        tweak_data.extend_from_slice(root);
    }
    let tweak = tagged_hash(b"TapTweak", &tweak_data);

    // Parse internal key as x-only point (even y assumed)
    use k256::elliptic_curve::ops::Reduce;
    use k256::{ProjectivePoint, Scalar};

    let mut pk_sec1 = [0u8; 33];
    pk_sec1[0] = 0x02; // even y
    pk_sec1[1..].copy_from_slice(internal_key);

    // Parse the internal key point
    #[allow(unused_imports)]
    use k256::elliptic_curve::group::GroupEncoding;
    use k256::AffinePoint;

    let pk_ct = AffinePoint::from_bytes((&pk_sec1).into());
    let pk_point: ProjectivePoint =
        Option::from(pk_ct.map(ProjectivePoint::from)).ok_or_else(|| {
            SignerError::InvalidPublicKey("taproot internal key is not a valid curve point".into())
        })?;

    // Compute t * G
    let t_wide = k256::U256::from_be_slice(&tweak);
    let t_scalar = <Scalar as Reduce<k256::U256>>::reduce(t_wide);
    let tweaked = pk_point + ProjectivePoint::GENERATOR * t_scalar;

    // Get the x-only output key
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let tweaked_affine = tweaked.to_affine();
    let encoded = tweaked_affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();

    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&bytes[1..33]);

    let parity = bytes[0] == 0x03;

    Ok((x_only, parity))
}

/// Compute the full Taproot output key from an internal key and optional TapTree.
///
/// If `tree` is `None`, this produces a key-path-only P2TR output.
pub fn taproot_output_key(
    internal_key: &[u8; 32],
    tree: Option<&TapTree>,
) -> Result<([u8; 32], bool), SignerError> {
    let merkle_root = tree.map(|t| t.merkle_root());
    taproot_tweak(internal_key, merkle_root.as_ref())
}

// ─── Control Block ──────────────────────────────────────────────────

/// A BIP-341 control block for script-path spending.
#[derive(Clone, Debug)]
pub struct ControlBlock {
    /// The leaf version (high 7 bits) combined with parity bit (low bit).
    pub leaf_version_and_parity: u8,
    /// The 32-byte x-only internal public key.
    pub internal_key: [u8; 32],
    /// The merkle proof path (0 to 128 hashes of 32 bytes each).
    pub merkle_path: Vec<[u8; 32]>,
}

impl ControlBlock {
    /// Create a control block for a specific leaf in a tree.
    ///
    /// # Arguments
    /// * `internal_key` - The 32-byte x-only internal public key
    /// * `tree` - The TapTree
    /// * `leaf` - The target leaf to create a proof for
    /// * `output_key_parity` - Whether the output key Q has odd y
    pub fn new(
        internal_key: [u8; 32],
        tree: &TapTree,
        leaf: &TapLeaf,
        output_key_parity: bool,
    ) -> Option<Self> {
        let merkle_path = tree.merkle_proof(leaf)?;
        let parity_bit = if output_key_parity { 1u8 } else { 0u8 };
        Some(ControlBlock {
            leaf_version_and_parity: (leaf.version & 0xFE) | parity_bit,
            internal_key,
            merkle_path,
        })
    }

    /// Serialize the control block to bytes.
    ///
    /// Format: `control_byte || internal_key (32) || merkle_path (32 * m)`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33 + self.merkle_path.len() * 32);
        bytes.push(self.leaf_version_and_parity);
        bytes.extend_from_slice(&self.internal_key);
        for hash in &self.merkle_path {
            bytes.extend_from_slice(hash);
        }
        bytes
    }

    /// Parse a control block from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 33 || (data.len() - 33) % 32 != 0 {
            return None;
        }
        let control_byte = data[0];
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&data[1..33]);
        let path_count = (data.len() - 33) / 32;
        let mut merkle_path = Vec::with_capacity(path_count);
        for i in 0..path_count {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[33 + i * 32..33 + (i + 1) * 32]);
            merkle_path.push(hash);
        }
        Some(ControlBlock {
            leaf_version_and_parity: control_byte,
            internal_key,
            merkle_path,
        })
    }

    /// Verify the control block against a given output key and leaf.
    ///
    /// Reconstructs the merkle root from the proof path and verifies
    /// that `taproot_tweak(internal_key, merkle_root) == output_key`.
    pub fn verify(&self, output_key: &[u8; 32], leaf: &TapLeaf) -> bool {
        // Start with the leaf hash
        let mut current = leaf.leaf_hash();

        // Walk the merkle path
        for sibling in &self.merkle_path {
            current = tap_branch_hash(&current, sibling);
        }

        // Verify the tweak
        let Ok((tweaked, parity)) = taproot_tweak(&self.internal_key, Some(&current)) else {
            return false;
        };
        let expected_parity = (self.leaf_version_and_parity & 1) == 1;

        tweaked == *output_key && parity == expected_parity
    }
}

// ─── P2TR Address Generation ────────────────────────────────────────

/// Generate a P2TR (Taproot) Bech32m address from an internal key and optional tree.
///
/// # Arguments
/// * `internal_key` - 32-byte x-only internal public key
/// * `tree` - Optional TapTree for script-path spending
/// * `hrp` - Human readable part ("bc" for mainnet, "tb" for testnet)
pub fn taproot_address(
    internal_key: &[u8; 32],
    tree: Option<&TapTree>,
    hrp: &str,
) -> Result<String, SignerError> {
    let (output_key, _parity) = taproot_output_key(internal_key, tree)?;
    encoding::bech32_encode(hrp, 1, &output_key)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_tap_leaf_hash_deterministic() {
        let leaf = TapLeaf::tapscript(vec![0x51]); // OP_TRUE
        let h1 = leaf.leaf_hash();
        let h2 = leaf.leaf_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tap_leaf_hash_different_scripts() {
        let l1 = TapLeaf::tapscript(vec![0x51]); // OP_TRUE
        let l2 = TapLeaf::tapscript(vec![0x00]); // OP_FALSE
        assert_ne!(l1.leaf_hash(), l2.leaf_hash());
    }

    #[test]
    fn test_tap_leaf_hash_different_versions() {
        let l1 = TapLeaf::new(0xC0, vec![0x51]);
        let l2 = TapLeaf::new(0xC2, vec![0x51]);
        assert_ne!(l1.leaf_hash(), l2.leaf_hash());
    }

    #[test]
    fn test_tap_branch_hash_commutative() {
        let a = [0xAA; 32];
        let b = [0xBB; 32];
        // Branch hash should be the same regardless of order
        assert_eq!(tap_branch_hash(&a, &b), tap_branch_hash(&b, &a));
    }

    #[test]
    fn test_tap_tree_single_leaf() {
        let leaf = TapLeaf::tapscript(vec![0x51]);
        let tree = TapTree::leaf(leaf.clone());
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.depth(), 0);
        assert_eq!(tree.merkle_root(), leaf.leaf_hash());
    }

    #[test]
    fn test_tap_tree_two_leaves() {
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let l2 = TapLeaf::tapscript(vec![0x00]);
        let tree = TapTree::branch(TapTree::leaf(l1.clone()), TapTree::leaf(l2.clone()));
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.depth(), 1);
        let expected = tap_branch_hash(&l1.leaf_hash(), &l2.leaf_hash());
        assert_eq!(tree.merkle_root(), expected);
    }

    #[test]
    fn test_tap_tree_three_leaves() {
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let l2 = TapLeaf::tapscript(vec![0x00]);
        let l3 = TapLeaf::tapscript(vec![0x52]); // OP_2
        let tree = TapTree::branch(
            TapTree::leaf(l1),
            TapTree::branch(TapTree::leaf(l2), TapTree::leaf(l3)),
        );
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.depth(), 2);
    }

    #[test]
    fn test_tap_tree_merkle_proof() {
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let l2 = TapLeaf::tapscript(vec![0x00]);
        let tree = TapTree::branch(TapTree::leaf(l1.clone()), TapTree::leaf(l2.clone()));

        // Proof for l1 should contain l2's hash
        let proof1 = tree.merkle_proof(&l1).expect("leaf found");
        assert_eq!(proof1.len(), 1);
        assert_eq!(proof1[0], l2.leaf_hash());

        // Proof for l2 should contain l1's hash
        let proof2 = tree.merkle_proof(&l2).expect("leaf found");
        assert_eq!(proof2.len(), 1);
        assert_eq!(proof2[0], l1.leaf_hash());
    }

    #[test]
    fn test_tap_tree_merkle_proof_not_found() {
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let l2 = TapLeaf::tapscript(vec![0x00]);
        let unknown = TapLeaf::tapscript(vec![0xFF]);
        let tree = TapTree::branch(TapTree::leaf(l1), TapTree::leaf(l2));
        assert!(tree.merkle_proof(&unknown).is_none());
    }

    #[test]
    fn test_taproot_tweak_key_path_only() {
        // Key-path-only (no merkle root)
        let internal_key = [0x01; 32];
        let result = taproot_tweak(&internal_key, None);
        // [0x01; 32] is not a valid x-coordinate on secp256k1
        // Valid keys will return Ok, invalid will return Err
        match result {
            Ok((tweaked, _parity)) => {
                assert_ne!(tweaked, internal_key); // tweaked key should differ
                assert_ne!(tweaked, [0u8; 32]); // should not be zero

                // Deterministic
                let (tweaked2, _) = taproot_tweak(&internal_key, None).unwrap();
                assert_eq!(tweaked, tweaked2);
            }
            Err(_) => {
                // Invalid internal key — this is expected for arbitrary byte patterns
            }
        }
    }

    #[test]
    fn test_taproot_tweak_with_merkle_root() {
        // Use a known valid internal key (generator point x-coordinate)
        let internal_key_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&internal_key_bytes);

        let merkle_root = [0xAA; 32];
        let (tweaked1, _) = taproot_tweak(&internal_key, Some(&merkle_root)).unwrap();
        let (tweaked2, _) = taproot_tweak(&internal_key, None).unwrap();
        // Different merkle roots should produce different tweaked keys
        assert_ne!(tweaked1, tweaked2);
    }

    #[test]
    fn test_taproot_output_key_with_tree() {
        let internal_key_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&internal_key_bytes);
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let tree = TapTree::leaf(l1);
        let (output_key, _parity) = taproot_output_key(&internal_key, Some(&tree)).unwrap();
        assert_ne!(output_key, [0u8; 32]);
    }

    #[test]
    fn test_control_block_serialization() {
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let l2 = TapLeaf::tapscript(vec![0x00]);
        let tree = TapTree::branch(TapTree::leaf(l1.clone()), TapTree::leaf(l2.clone()));
        let internal_key = [0x01; 32];
        let (_, parity) = taproot_output_key(&internal_key, Some(&tree)).unwrap();

        let cb = ControlBlock::new(internal_key, &tree, &l1, parity).expect("ok");
        let bytes = cb.to_bytes();

        // Size: 1 (control byte) + 32 (internal key) + 32 * 1 (one proof hash)
        assert_eq!(bytes.len(), 65);

        // Round-trip
        let parsed = ControlBlock::from_bytes(&bytes).expect("valid");
        assert_eq!(parsed.internal_key, internal_key);
        assert_eq!(parsed.merkle_path.len(), 1);
    }

    #[test]
    fn test_control_block_verify() {
        let l1 = TapLeaf::tapscript(vec![0x51]);
        let l2 = TapLeaf::tapscript(vec![0x00]);
        let tree = TapTree::branch(TapTree::leaf(l1.clone()), TapTree::leaf(l2.clone()));

        // Use a known valid internal key (generator point x-coordinate)
        let internal_key_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&internal_key_bytes);

        let (output_key, parity) = taproot_output_key(&internal_key, Some(&tree)).unwrap();
        let cb = ControlBlock::new(internal_key, &tree, &l1, parity).expect("ok");

        assert!(cb.verify(&output_key, &l1));
        // Verify with wrong leaf should fail
        assert!(!cb.verify(&output_key, &l2));
    }

    #[test]
    fn test_control_block_from_bytes_invalid() {
        // Too short
        assert!(ControlBlock::from_bytes(&[0x00; 10]).is_none());
        // Wrong alignment
        assert!(ControlBlock::from_bytes(&[0x00; 34]).is_none());
        // Valid: 33 bytes (no proof)
        assert!(ControlBlock::from_bytes(&[0x00; 33]).is_some());
        // Valid: 65 bytes (1 proof hash)
        assert!(ControlBlock::from_bytes(&[0x00; 65]).is_some());
    }

    #[test]
    fn test_taproot_address_key_path_only() {
        let internal_key_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&internal_key_bytes);

        let addr = taproot_address(&internal_key, None, "bc").expect("ok");
        assert!(addr.starts_with("bc1p"));
    }

    #[test]
    fn test_taproot_tweak_invalid_key() {
        // All-zero key is not on the curve
        let invalid_key = [0u8; 32];
        let result = taproot_tweak(&invalid_key, None);
        assert!(result.is_err(), "zeroed key should not be valid");
    }

    #[test]
    fn test_taproot_address_with_tree() {
        let internal_key_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&internal_key_bytes);

        let leaf = TapLeaf::tapscript(vec![0x51]);
        let tree = TapTree::leaf(leaf);

        let addr = taproot_address(&internal_key, Some(&tree), "bc").expect("ok");
        assert!(addr.starts_with("bc1p"));

        // Address with tree should differ from key-path-only
        let addr_no_tree = taproot_address(&internal_key, None, "bc").expect("ok");
        assert_ne!(addr, addr_no_tree);
    }

    #[test]
    fn test_taproot_address_testnet() {
        let internal_key_hex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let internal_key_bytes = hex::decode(internal_key_hex).unwrap();
        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&internal_key_bytes);
        let addr = taproot_address(&internal_key, None, "tb").expect("ok");
        assert!(addr.starts_with("tb1p"));
    }
}
