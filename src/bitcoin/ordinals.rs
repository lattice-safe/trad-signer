//! Bitcoin Ordinals & Inscriptions (BIP-???).
//!
//! Implements inscription envelope encoding for Tapscript-based
//! ordinal inscriptions, including content embedding, reveal witness
//! construction, and virtual size estimation for fee calculation.
//!
//! # Example
//! ```no_run
//! use chains_sdk::bitcoin::ordinals::*;
//!
//! let inscription = Inscription::new("text/plain", b"Hello, Ordinals!");
//! let script = inscription.to_tapscript();
//! let vsize = inscription.estimate_vsize();
//! ```

use crate::crypto;

// ═══════════════════════════════════════════════════════════════════
// Opcodes (inscription-specific subset)
// ═══════════════════════════════════════════════════════════════════

const OP_FALSE: u8 = 0x00;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;

// Inscription envelope protocol marker
const ORD_MARKER: &[u8] = b"ord";

// Tag constants per ordinal protocol
const TAG_CONTENT_TYPE: u8 = 0x01;
const TAG_BODY: u8 = 0x00; // OP_0 separates header from body
const TAG_POINTER: u8 = 0x02;
const TAG_PARENT: u8 = 0x03;
const TAG_METADATA: u8 = 0x05;
const TAG_METAPROTOCOL: u8 = 0x07;
const TAG_CONTENT_ENCODING: u8 = 0x09;
#[allow(dead_code)]
const TAG_DELEGATE: u8 = 0x0b;
#[allow(dead_code)]
const TAG_RUNE: u8 = 0x0d;

// ═══════════════════════════════════════════════════════════════════
// Inscription
// ═══════════════════════════════════════════════════════════════════

/// An Ordinal inscription with content and metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inscription {
    /// MIME type (e.g., "text/plain", "image/png", "application/json").
    pub content_type: String,
    /// Raw inscription body bytes.
    pub body: Vec<u8>,
    /// Optional parent inscription ID (for collection children).
    pub parent: Option<InscriptionId>,
    /// Optional CBOR-encoded metadata.
    pub metadata: Option<Vec<u8>>,
    /// Optional metaprotocol identifier (e.g., "brc-20").
    pub metaprotocol: Option<String>,
    /// Optional content encoding (e.g., "br" for Brotli).
    pub content_encoding: Option<String>,
    /// Optional delegate inscription ID.
    pub delegate: Option<InscriptionId>,
    /// Optional pointer (output index for the inscription to be bound to).
    pub pointer: Option<u64>,
    /// Optional rune data.
    pub rune: Option<Vec<u8>>,
}

/// An inscription identifier: `txid:index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InscriptionId {
    /// Transaction ID (32 bytes, internal byte order).
    pub txid: [u8; 32],
    /// Inscription index within the transaction.
    pub index: u32,
}

impl InscriptionId {
    /// Create a new inscription ID.
    #[must_use]
    pub const fn new(txid: [u8; 32], index: u32) -> Self {
        Self { txid, index }
    }

    /// Format as `txid:index` string (hex-encoded txid in display order).
    #[must_use]
    pub fn to_string_id(&self) -> String {
        let mut txid_display = self.txid;
        txid_display.reverse(); // Internal → display byte order
        let hex: String = txid_display.iter().map(|b| format!("{b:02x}")).collect();
        if self.index == 0 {
            hex
        } else {
            format!("{hex}i{}", self.index)
        }
    }
}

impl Inscription {
    /// Create a simple inscription with content type and body.
    #[must_use]
    pub fn new(content_type: &str, body: &[u8]) -> Self {
        Self {
            content_type: content_type.to_string(),
            body: body.to_vec(),
            parent: None,
            metadata: None,
            metaprotocol: None,
            content_encoding: None,
            delegate: None,
            pointer: None,
            rune: None,
        }
    }

    /// Set the parent inscription (for collection children).
    #[must_use]
    pub fn with_parent(mut self, parent: InscriptionId) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Set CBOR metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set metaprotocol (e.g., "brc-20").
    #[must_use]
    pub fn with_metaprotocol(mut self, proto: &str) -> Self {
        self.metaprotocol = Some(proto.to_string());
        self
    }

    /// Set content encoding (e.g., "br" for Brotli compression).
    #[must_use]
    pub fn with_content_encoding(mut self, encoding: &str) -> Self {
        self.content_encoding = Some(encoding.to_string());
        self
    }

    /// Encode the inscription as a Tapscript envelope.
    ///
    /// ```text
    /// OP_FALSE OP_IF
    ///   OP_PUSH "ord"
    ///   OP_PUSH 0x01        // content type tag
    ///   OP_PUSH <content_type>
    ///   [optional tags...]
    ///   OP_0                 // body separator
    ///   OP_PUSH <body_chunk_1>
    ///   [OP_PUSH <body_chunk_n>...]
    /// OP_ENDIF
    /// ```
    #[must_use]
    pub fn to_tapscript(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(self.body.len() + 128);

        // Envelope start
        script.push(OP_FALSE);
        script.push(OP_IF);

        // Protocol marker: "ord"
        push_data(&mut script, ORD_MARKER);

        // Content type tag
        script.push(1); // push 1 byte
        script.push(TAG_CONTENT_TYPE);
        push_data(&mut script, self.content_type.as_bytes());

        // Optional tags
        if let Some(ref parent) = self.parent {
            script.push(1);
            script.push(TAG_PARENT);
            let mut parent_data = Vec::with_capacity(36);
            parent_data.extend_from_slice(&parent.txid);
            if parent.index > 0 {
                // Little-endian varint
                push_le_u32(&mut parent_data, parent.index);
            }
            push_data(&mut script, &parent_data);
        }

        if let Some(ref metadata) = self.metadata {
            script.push(1);
            script.push(TAG_METADATA);
            push_data(&mut script, metadata);
        }

        if let Some(ref proto) = self.metaprotocol {
            script.push(1);
            script.push(TAG_METAPROTOCOL);
            push_data(&mut script, proto.as_bytes());
        }

        if let Some(ref encoding) = self.content_encoding {
            script.push(1);
            script.push(TAG_CONTENT_ENCODING);
            push_data(&mut script, encoding.as_bytes());
        }

        if let Some(ref delegate) = self.delegate {
            script.push(1);
            script.push(TAG_DELEGATE);
            let mut del_data = Vec::with_capacity(36);
            del_data.extend_from_slice(&delegate.txid);
            if delegate.index > 0 {
                push_le_u32(&mut del_data, delegate.index);
            }
            push_data(&mut script, &del_data);
        }

        if let Some(pointer) = self.pointer {
            script.push(1);
            script.push(TAG_POINTER);
            let bytes = pointer.to_le_bytes();
            // Trim trailing zeros for minimal encoding
            let len = 8 - bytes.iter().rev().take_while(|&&b| b == 0).count();
            let len = len.max(1);
            push_data(&mut script, &bytes[..len]);
        }

        if let Some(ref rune) = self.rune {
            script.push(1);
            script.push(TAG_RUNE);
            push_data(&mut script, rune);
        }

        // Body separator (OP_0 / OP_FALSE)
        script.push(TAG_BODY);

        // Body — split into 520-byte chunks (max push size)
        for chunk in self.body.chunks(520) {
            push_data(&mut script, chunk);
        }

        // Envelope end
        script.push(OP_ENDIF);

        script
    }

    /// Build a commit script: `<x_only_pubkey> OP_CHECKSIG` followed by the inscription envelope.
    ///
    /// This is the full script placed in a TapLeaf for the commit transaction.
    #[must_use]
    pub fn build_commit_script(&self, x_only_pubkey: &[u8; 32]) -> Vec<u8> {
        let mut script = Vec::with_capacity(34 + self.body.len() + 128);
        // Key check first
        script.push(32); // push 32 bytes
        script.extend_from_slice(x_only_pubkey);
        script.push(OP_CHECKSIG);
        // Then inscription envelope
        script.extend_from_slice(&self.to_tapscript());
        script
    }

    /// Build the reveal transaction witness stack.
    ///
    /// Returns `[signature, commit_script, control_block]`.
    #[must_use]
    pub fn build_reveal_witness(
        &self,
        signature: &[u8],
        x_only_pubkey: &[u8; 32],
        control_block: &[u8],
    ) -> Vec<Vec<u8>> {
        vec![
            signature.to_vec(),
            self.build_commit_script(x_only_pubkey),
            control_block.to_vec(),
        ]
    }

    /// SHA-256 hash of the inscription body.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        crypto::sha256(&self.body)
    }

    /// Estimate the virtual size (vbytes) of the reveal transaction.
    ///
    /// Formula: `vsize = (weight + 3) / 4`
    /// where `weight = base_size * 3 + total_size`
    ///
    /// The witness data (inscription) gets the 4x discount.
    #[must_use]
    pub fn estimate_vsize(&self) -> usize {
        // Base transaction overhead (non-witness): ~68 bytes
        // 1 input, 1 output typical reveal
        let base_size: usize = 68;

        // Witness size: signature (~64) + commit script + control block (~33)
        let commit_script = self.build_commit_script(&[0u8; 32]);
        let witness_size = 64 + commit_script.len() + 33;

        // Weight = base_size * 4 + witness_size (witness counted at 1/4 weight)
        let weight = base_size * 4 + witness_size;
        weight.div_ceil(4)
    }

    /// Total inscription size (body + content type).
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.body.len() + self.content_type.len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Push data with appropriate Bitcoin push operation.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(OP_FALSE);
        return;
    }

    if len <= 75 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(0x4C); // OP_PUSHDATA1
        script.push(len as u8);
    } else if len <= 0xFFFF {
        script.push(0x4D); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        script.push(0x4E); // OP_PUSHDATA4
        if len > u32::MAX as usize {
            #[allow(clippy::panic)]
            {
                panic!("script push length exceeds u32::MAX");
            }
        }
        script.extend_from_slice(&(len as u32).to_le_bytes());
    }

    script.extend_from_slice(data);
}

/// Push a u32 in little-endian, trimming trailing zeros.
fn push_le_u32(buf: &mut Vec<u8>, val: u32) {
    let bytes = val.to_le_bytes();
    let len = 4 - bytes.iter().rev().take_while(|&&b| b == 0).count();
    buf.extend_from_slice(&bytes[..len.max(1)]);
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── Inscription Creation ───────────────────────────────────

    #[test]
    fn test_new_inscription() {
        let ins = Inscription::new("text/plain", b"hello");
        assert_eq!(ins.content_type, "text/plain");
        assert_eq!(ins.body, b"hello");
        assert!(ins.parent.is_none());
        assert!(ins.metadata.is_none());
    }

    #[test]
    fn test_inscription_with_parent() {
        let parent = InscriptionId::new([0xAA; 32], 0);
        let ins = Inscription::new("text/plain", b"child").with_parent(parent.clone());
        assert_eq!(ins.parent.unwrap().txid, [0xAA; 32]);
    }

    #[test]
    fn test_inscription_with_metadata() {
        let ins =
            Inscription::new("text/plain", b"x").with_metadata(vec![0xA1, 0x63, 0x66, 0x6F, 0x6F]); // CBOR: {"foo"}
        assert!(ins.metadata.is_some());
    }

    #[test]
    fn test_inscription_with_metaprotocol() {
        let ins = Inscription::new("text/plain", b"x").with_metaprotocol("brc-20");
        assert_eq!(ins.metaprotocol.as_deref(), Some("brc-20"));
    }

    #[test]
    fn test_inscription_with_content_encoding() {
        let ins = Inscription::new("text/plain", b"x").with_content_encoding("br");
        assert_eq!(ins.content_encoding.as_deref(), Some("br"));
    }

    // ─── Tapscript Encoding ─────────────────────────────────────

    #[test]
    fn test_tapscript_envelope_structure() {
        let ins = Inscription::new("text/plain", b"hello");
        let script = ins.to_tapscript();

        // Must start with OP_FALSE OP_IF
        assert_eq!(script[0], OP_FALSE);
        assert_eq!(script[1], OP_IF);
        // Must end with OP_ENDIF
        assert_eq!(*script.last().unwrap(), OP_ENDIF);
    }

    #[test]
    fn test_tapscript_contains_ord_marker() {
        let ins = Inscription::new("text/plain", b"hi");
        let script = ins.to_tapscript();
        // "ord" marker should be in the script
        let has_ord = script.windows(3).any(|w| w == b"ord");
        assert!(has_ord, "script must contain 'ord' marker");
    }

    #[test]
    fn test_tapscript_contains_content_type() {
        let ins = Inscription::new("image/png", b"\x89PNG");
        let script = ins.to_tapscript();
        let has_ct = script.windows(9).any(|w| w == b"image/png");
        assert!(has_ct, "script must contain content type");
    }

    #[test]
    fn test_tapscript_contains_body() {
        let body = b"Hello, World!";
        let ins = Inscription::new("text/plain", body);
        let script = ins.to_tapscript();
        let has_body = script.windows(body.len()).any(|w| w == body);
        assert!(has_body, "script must contain body");
    }

    #[test]
    fn test_tapscript_body_chunking_520() {
        // Body larger than 520 bytes should be split
        let body = vec![0xAA; 1040]; // 2 × 520
        let ins = Inscription::new("text/plain", &body);
        let script = ins.to_tapscript();
        // Script should contain OP_PUSHDATA2 for 520-byte chunks
        let pushdata2_count = script.iter().filter(|&&b| b == 0x4D).count();
        assert_eq!(
            pushdata2_count, 2,
            "should have 2 OP_PUSHDATA2 for 1040 bytes"
        );
    }

    #[test]
    fn test_tapscript_empty_body() {
        let ins = Inscription::new("text/plain", b"");
        let script = ins.to_tapscript();
        assert!(script.len() > 10); // envelope + header
    }

    #[test]
    fn test_tapscript_with_parent() {
        let parent = InscriptionId::new([0xFF; 32], 5);
        let ins = Inscription::new("text/plain", b"child").with_parent(parent);
        let script = ins.to_tapscript();
        assert!(script.contains(&TAG_PARENT));
    }

    #[test]
    fn test_tapscript_with_metaprotocol() {
        let ins = Inscription::new("text/plain", b"x").with_metaprotocol("brc-20");
        let script = ins.to_tapscript();
        assert!(script.contains(&TAG_METAPROTOCOL));
        let has_brc20 = script.windows(6).any(|w| w == b"brc-20");
        assert!(has_brc20);
    }

    #[test]
    fn test_tapscript_deterministic() {
        let ins1 = Inscription::new("text/plain", b"test");
        let ins2 = Inscription::new("text/plain", b"test");
        assert_eq!(ins1.to_tapscript(), ins2.to_tapscript());
    }

    // ─── Commit Script ──────────────────────────────────────────

    #[test]
    fn test_commit_script_starts_with_key() {
        let key = [0x02; 32];
        let ins = Inscription::new("text/plain", b"test");
        let script = ins.build_commit_script(&key);
        assert_eq!(script[0], 32); // push 32 bytes
        assert_eq!(&script[1..33], &key);
        assert_eq!(script[33], OP_CHECKSIG);
    }

    #[test]
    fn test_commit_script_contains_envelope() {
        let key = [0x02; 32];
        let ins = Inscription::new("text/plain", b"test");
        let script = ins.build_commit_script(&key);
        // After key+checksig, should have OP_FALSE OP_IF...
        assert_eq!(script[34], OP_FALSE);
        assert_eq!(script[35], OP_IF);
        assert_eq!(*script.last().unwrap(), OP_ENDIF);
    }

    // ─── Reveal Witness ─────────────────────────────────────────

    #[test]
    fn test_reveal_witness_structure() {
        let ins = Inscription::new("text/plain", b"test");
        let sig = vec![0xBB; 64];
        let key = [0x02; 32];
        let control = vec![0xCC; 33];
        let witness = ins.build_reveal_witness(&sig, &key, &control);
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[0], sig);
        assert_eq!(witness[2], control);
    }

    #[test]
    fn test_reveal_witness_commit_script_matches() {
        let ins = Inscription::new("text/plain", b"test");
        let key = [0x02; 32];
        let witness = ins.build_reveal_witness(&[0; 64], &key, &[0; 33]);
        let expected_script = ins.build_commit_script(&key);
        assert_eq!(witness[1], expected_script);
    }

    // ─── Content Hash ───────────────────────────────────────────

    #[test]
    fn test_content_hash_deterministic() {
        let ins = Inscription::new("text/plain", b"hello");
        let h1 = ins.content_hash();
        let h2 = ins.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_content_hash_different_bodies() {
        let ins1 = Inscription::new("text/plain", b"hello");
        let ins2 = Inscription::new("text/plain", b"world");
        assert_ne!(ins1.content_hash(), ins2.content_hash());
    }

    #[test]
    fn test_content_hash_matches_sha256() {
        let body = b"test body";
        let ins = Inscription::new("text/plain", body);
        assert_eq!(ins.content_hash(), crypto::sha256(body));
    }

    // ─── VSize Estimation ───────────────────────────────────────

    #[test]
    fn test_vsize_positive() {
        let ins = Inscription::new("text/plain", b"hello");
        assert!(ins.estimate_vsize() > 0);
    }

    #[test]
    fn test_vsize_larger_body_means_larger_vsize() {
        let small = Inscription::new("text/plain", b"hi");
        let large = Inscription::new("text/plain", &vec![0xAA; 10_000]);
        assert!(large.estimate_vsize() > small.estimate_vsize());
    }

    #[test]
    fn test_vsize_witness_discount() {
        // Witness data should be cheaper than non-witness
        let ins = Inscription::new("text/plain", &vec![0xAA; 1000]);
        let vsize = ins.estimate_vsize();
        // vsize should be significantly less than raw body size + overhead
        assert!(vsize < 1200, "witness discount should apply");
    }

    // ─── Total Size ─────────────────────────────────────────────

    #[test]
    fn test_total_size() {
        let ins = Inscription::new("text/plain", b"hello");
        assert_eq!(ins.total_size(), 10 + 5); // "text/plain" + "hello"
    }

    // ─── InscriptionId ──────────────────────────────────────────

    #[test]
    fn test_inscription_id_to_string() {
        let id = InscriptionId::new([0; 32], 0);
        let s = id.to_string_id();
        assert_eq!(s.len(), 64); // 32 bytes × 2 hex chars
        assert_eq!(s, "0".repeat(64));
    }

    #[test]
    fn test_inscription_id_with_index() {
        let id = InscriptionId::new([0; 32], 5);
        let s = id.to_string_id();
        assert!(s.ends_with("i5"));
    }

    #[test]
    fn test_inscription_id_display_order() {
        // Internal order [0x01, 0x00, ..., 0x00] → display "00...01"
        let mut txid = [0u8; 32];
        txid[0] = 0x01;
        let id = InscriptionId::new(txid, 0);
        let s = id.to_string_id();
        assert!(s.ends_with("01"), "last chars should be 01, got {s}");
    }

    // ─── Push Data Helper ───────────────────────────────────────

    #[test]
    fn test_push_data_small() {
        let mut s = Vec::new();
        push_data(&mut s, b"abc");
        assert_eq!(s[0], 3); // length
        assert_eq!(&s[1..4], b"abc");
    }

    #[test]
    fn test_push_data_76_bytes() {
        let mut s = Vec::new();
        let data = vec![0xAA; 76];
        push_data(&mut s, &data);
        assert_eq!(s[0], 0x4C); // OP_PUSHDATA1
        assert_eq!(s[1], 76);
        assert_eq!(&s[2..78], &data[..]);
    }

    #[test]
    fn test_push_data_256_bytes() {
        let mut s = Vec::new();
        let data = vec![0xBB; 256];
        push_data(&mut s, &data);
        assert_eq!(s[0], 0x4D); // OP_PUSHDATA2
        let len = u16::from_le_bytes([s[1], s[2]]);
        assert_eq!(len, 256);
    }

    #[test]
    fn test_push_data_empty() {
        let mut s = Vec::new();
        push_data(&mut s, b"");
        assert_eq!(s, vec![OP_FALSE]);
    }

    #[test]
    fn test_push_data_over_520_not_dropped() {
        let mut s = Vec::new();
        let data = vec![0xCC; 600];
        push_data(&mut s, &data);
        assert_eq!(s[0], 0x4D); // OP_PUSHDATA2
        let len = u16::from_le_bytes([s[1], s[2]]);
        assert_eq!(len, 600);
        assert_eq!(&s[3..], &data[..]);
    }

    #[test]
    fn test_tapscript_large_metadata_not_dropped() {
        let metadata = vec![0xA5; 600];
        let ins = Inscription::new("text/plain", b"x").with_metadata(metadata.clone());
        let script = ins.to_tapscript();
        assert!(script.windows(3).any(|w| w == [0x4D, 0x58, 0x02]));
        assert!(script.windows(600).any(|w| w == metadata.as_slice()));
    }
}
