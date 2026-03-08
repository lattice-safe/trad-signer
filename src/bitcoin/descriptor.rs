//! **BIP-380-386** — Output Script Descriptors.
//!
//! Human-readable descriptors for Bitcoin output scripts, supporting
//! legacy (pkh), SegWit (wpkh, wsh), and Taproot (tr) formats.
//!
//! # Example
//! ```ignore
//! use trad_signer::bitcoin::descriptor::{Descriptor, DescriptorKey};
//!
//! let key = DescriptorKey::from_hex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")?;
//! let desc = Descriptor::wpkh(key);
//! println!("Address: {}", desc.address("bc")?);
//! ```

use crate::crypto;
use crate::encoding;
use crate::error::SignerError;

// ─── Descriptor Key ─────────────────────────────────────────────────

/// A public key for use in descriptors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptorKey {
    /// A compressed public key (33 bytes).
    Compressed([u8; 33]),
    /// An x-only public key (32 bytes, for Taproot).
    XOnly([u8; 32]),
}

impl DescriptorKey {
    /// Parse a hex-encoded public key.
    pub fn from_hex(hex_str: &str) -> Result<Self, SignerError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| SignerError::ParseError(format!("hex: {e}")))?;
        match bytes.len() {
            33 => {
                let mut key = [0u8; 33];
                key.copy_from_slice(&bytes);
                Ok(DescriptorKey::Compressed(key))
            }
            32 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(DescriptorKey::XOnly(key))
            }
            _ => Err(SignerError::ParseError(format!(
                "invalid key length: {}",
                bytes.len()
            ))),
        }
    }

    /// Get the compressed public key bytes.
    pub fn compressed_bytes(&self) -> Option<&[u8; 33]> {
        match self {
            DescriptorKey::Compressed(k) => Some(k),
            DescriptorKey::XOnly(_) => None,
        }
    }

    /// Get the x-only key bytes.
    pub fn x_only_bytes(&self) -> Option<&[u8; 32]> {
        match self {
            DescriptorKey::XOnly(k) => Some(k),
            DescriptorKey::Compressed(_) => None,
        }
    }

    /// Calculate HASH160 of the compressed key (for P2PKH / P2WPKH).
    pub fn hash160(&self) -> Option<[u8; 20]> {
        match self {
            DescriptorKey::Compressed(key) => Some(crypto::hash160(key)),
            DescriptorKey::XOnly(_) => None,
        }
    }
}

// ─── Descriptor Types ───────────────────────────────────────────────

/// A Bitcoin output script descriptor.
#[derive(Clone, Debug)]
pub enum Descriptor {
    /// BIP-381: Pay to Public Key Hash — `pkh(KEY)`.
    Pkh(DescriptorKey),
    /// BIP-382: Pay to Witness Public Key Hash — `wpkh(KEY)`.
    Wpkh(DescriptorKey),
    /// BIP-381: Pay to Script Hash wrapping wpkh — `sh(wpkh(KEY))`.
    ShWpkh(DescriptorKey),
    /// BIP-386: Pay to Taproot — `tr(KEY)` (key-path only).
    Tr(DescriptorKey),
    /// Raw script — `raw(HEX)`.
    Raw(Vec<u8>),
    /// OP_RETURN data — `raw(6a...)`.
    OpReturn(Vec<u8>),
}

impl Descriptor {
    /// Create a `pkh(KEY)` descriptor (BIP-381).
    pub fn pkh(key: DescriptorKey) -> Self {
        Descriptor::Pkh(key)
    }

    /// Create a `wpkh(KEY)` descriptor (BIP-382).
    pub fn wpkh(key: DescriptorKey) -> Self {
        Descriptor::Wpkh(key)
    }

    /// Create a `sh(wpkh(KEY))` descriptor (BIP-381).
    pub fn sh_wpkh(key: DescriptorKey) -> Self {
        Descriptor::ShWpkh(key)
    }

    /// Create a `tr(KEY)` descriptor (BIP-386, key-path only).
    pub fn tr(key: DescriptorKey) -> Self {
        Descriptor::Tr(key)
    }

    /// Compute the scriptPubKey for this descriptor.
    pub fn script_pubkey(&self) -> Result<Vec<u8>, SignerError> {
        match self {
            Descriptor::Pkh(key) => {
                let hash = key
                    .hash160()
                    .ok_or(SignerError::ParseError("pkh requires compressed key".into()))?;
                // OP_DUP OP_HASH160 OP_PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
                let mut script = Vec::with_capacity(25);
                script.push(0x76); // OP_DUP
                script.push(0xa9); // OP_HASH160
                script.push(0x14); // OP_PUSH20
                script.extend_from_slice(&hash);
                script.push(0x88); // OP_EQUALVERIFY
                script.push(0xac); // OP_CHECKSIG
                Ok(script)
            }
            Descriptor::Wpkh(key) => {
                let hash = key
                    .hash160()
                    .ok_or(SignerError::ParseError("wpkh requires compressed key".into()))?;
                // OP_0 OP_PUSH20 <hash>
                let mut script = Vec::with_capacity(22);
                script.push(0x00); // OP_0
                script.push(0x14); // OP_PUSH20
                script.extend_from_slice(&hash);
                Ok(script)
            }
            Descriptor::ShWpkh(key) => {
                let hash = key.hash160().ok_or(SignerError::ParseError(
                    "sh(wpkh) requires compressed key".into(),
                ))?;
                // Witness script: OP_0 OP_PUSH20 <hash>
                let mut witness_script = Vec::with_capacity(22);
                witness_script.push(0x00);
                witness_script.push(0x14);
                witness_script.extend_from_slice(&hash);
                // P2SH: OP_HASH160 OP_PUSH20 HASH160(witness_script) OP_EQUAL
                let script_hash = crypto::hash160(&witness_script);
                let mut script = Vec::with_capacity(23);
                script.push(0xa9); // OP_HASH160
                script.push(0x14); // OP_PUSH20
                script.extend_from_slice(&script_hash);
                script.push(0x87); // OP_EQUAL
                Ok(script)
            }
            Descriptor::Tr(key) => {
                let xonly = match key {
                    DescriptorKey::XOnly(k) => *k,
                    DescriptorKey::Compressed(k) => {
                        let mut xonly = [0u8; 32];
                        xonly.copy_from_slice(&k[1..]);
                        xonly
                    }
                };
                // OP_1 OP_PUSH32 <x_only_key>
                let mut script = Vec::with_capacity(34);
                script.push(0x51); // OP_1
                script.push(0x20); // OP_PUSH32
                script.extend_from_slice(&xonly);
                Ok(script)
            }
            Descriptor::Raw(script) => Ok(script.clone()),
            Descriptor::OpReturn(data) => {
                let mut script = Vec::with_capacity(2 + data.len());
                script.push(0x6a); // OP_RETURN
                if data.len() <= 75 {
                    script.push(data.len() as u8);
                }
                script.extend_from_slice(data);
                Ok(script)
            }
        }
    }

    /// Generate the Bitcoin address for this descriptor.
    pub fn address(&self, hrp: &str) -> Result<String, SignerError> {
        match self {
            Descriptor::Pkh(key) => {
                let hash = key
                    .hash160()
                    .ok_or(SignerError::ParseError("pkh requires compressed key".into()))?;
                let prefix = if hrp == "bc" || hrp == "mainnet" {
                    0x00u8
                } else {
                    0x6Fu8
                };
                Ok(encoding::base58check_encode(prefix, &hash))
            }
            Descriptor::Wpkh(key) => {
                let hash = key
                    .hash160()
                    .ok_or(SignerError::ParseError("wpkh requires compressed key".into()))?;
                encoding::bech32_encode(hrp, 0, &hash)
            }
            Descriptor::ShWpkh(_) => {
                let script = self.script_pubkey()?;
                let hash = &script[2..22];
                let prefix = if hrp == "bc" || hrp == "mainnet" {
                    0x05u8
                } else {
                    0xC4u8
                };
                Ok(encoding::base58check_encode(prefix, hash))
            }
            Descriptor::Tr(key) => {
                let xonly = match key {
                    DescriptorKey::XOnly(k) => *k,
                    DescriptorKey::Compressed(k) => {
                        let mut xo = [0u8; 32];
                        xo.copy_from_slice(&k[1..]);
                        xo
                    }
                };
                encoding::bech32_encode(hrp, 1, &xonly)
            }
            Descriptor::Raw(_) | Descriptor::OpReturn(_) => Err(SignerError::EncodingError(
                "raw/op_return descriptors have no address".into(),
            )),
        }
    }

    /// Convert the descriptor to its string representation.
    pub fn to_string_repr(&self) -> String {
        match self {
            Descriptor::Pkh(key) => format!("pkh({})", key_to_hex(key)),
            Descriptor::Wpkh(key) => format!("wpkh({})", key_to_hex(key)),
            Descriptor::ShWpkh(key) => format!("sh(wpkh({}))", key_to_hex(key)),
            Descriptor::Tr(key) => format!("tr({})", key_to_hex(key)),
            Descriptor::Raw(script) => format!("raw({})", hex::encode(script)),
            Descriptor::OpReturn(data) => format!("raw(6a{})", hex::encode(data)),
        }
    }

    /// Compute the descriptor checksum (BIP-380).
    pub fn checksum(&self) -> String {
        let desc_str = self.to_string_repr();
        descriptor_checksum(&desc_str)
    }

    /// Get the full descriptor string with checksum.
    pub fn to_string_with_checksum(&self) -> String {
        let desc = self.to_string_repr();
        let checksum = descriptor_checksum(&desc);
        format!("{desc}#{checksum}")
    }
}

// ─── Descriptor Parsing ─────────────────────────────────────────────

/// Parse a descriptor string.
///
/// Supports `pkh(KEY)`, `wpkh(KEY)`, `sh(wpkh(KEY))`, `tr(KEY)`.
pub fn parse(descriptor: &str) -> Result<Descriptor, SignerError> {
    // Strip checksum
    let desc = if let Some(pos) = descriptor.find('#') {
        &descriptor[..pos]
    } else {
        descriptor
    };

    if let Some(inner) = strip_wrapper(desc, "pkh(", ")") {
        let key = DescriptorKey::from_hex(inner)?;
        Ok(Descriptor::pkh(key))
    } else if let Some(inner) = strip_wrapper(desc, "wpkh(", ")") {
        let key = DescriptorKey::from_hex(inner)?;
        Ok(Descriptor::wpkh(key))
    } else if let Some(inner) = strip_wrapper(desc, "sh(wpkh(", "))") {
        let key = DescriptorKey::from_hex(inner)?;
        Ok(Descriptor::sh_wpkh(key))
    } else if let Some(inner) = strip_wrapper(desc, "tr(", ")") {
        let key = DescriptorKey::from_hex(inner)?;
        Ok(Descriptor::tr(key))
    } else if let Some(inner) = strip_wrapper(desc, "raw(", ")") {
        let bytes =
            hex::decode(inner).map_err(|e| SignerError::ParseError(format!("hex: {e}")))?;
        Ok(Descriptor::Raw(bytes))
    } else {
        Err(SignerError::ParseError(format!(
            "unsupported descriptor: {desc}"
        )))
    }
}

/// Strip a prefix and suffix from a string, returning the inner content.
fn strip_wrapper<'a>(s: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    s.strip_prefix(prefix).and_then(|s| s.strip_suffix(suffix))
}

// ─── Checksum (BIP-380) ────────────────────────────────────────────

/// Compute the BIP-380 descriptor checksum.
///
/// Uses a modified polymod with the character set from BIP-380.
fn descriptor_checksum(desc: &str) -> String {
    const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    fn polymod(c: u64, val: u64) -> u64 {
        let c0 = c >> 35;
        let mut c = ((c & 0x7FFFFFFFF) << 5) ^ val;
        if c0 & 1 != 0 {
            c ^= 0xf5dee51989;
        }
        if c0 & 2 != 0 {
            c ^= 0xa9fdca3312;
        }
        if c0 & 4 != 0 {
            c ^= 0x1bab10e32d;
        }
        if c0 & 8 != 0 {
            c ^= 0x3706b1677a;
        }
        if c0 & 16 != 0 {
            c ^= 0x644d626ffd;
        }
        c
    }

    let mut c = 1u64;
    let mut cls = 0u64;
    let mut clscount = 0u64;

    for ch in desc.chars() {
        if let Some(pos) = INPUT_CHARSET.find(ch) {
            c = polymod(c, pos as u64 & 31);
            cls = cls * 3 + (pos as u64 >> 5);
            clscount += 1;
            if clscount == 3 {
                c = polymod(c, cls);
                cls = 0;
                clscount = 0;
            }
        }
    }
    if clscount > 0 {
        c = polymod(c, cls);
    }
    for _ in 0..8 {
        c = polymod(c, 0);
    }
    c ^= 1;

    let mut result = String::with_capacity(8);
    for j in 0..8 {
        result.push(CHECKSUM_CHARSET[((c >> (5 * (7 - j))) & 31) as usize] as char);
    }
    result
}

// ─── Helpers ────────────────────────────────────────────────────────

fn key_to_hex(key: &DescriptorKey) -> String {
    match key {
        DescriptorKey::Compressed(k) => hex::encode(k),
        DescriptorKey::XOnly(k) => hex::encode(k),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBKEY: &str = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

    fn test_key() -> DescriptorKey {
        DescriptorKey::from_hex(TEST_PUBKEY).expect("valid key")
    }

    #[test]
    fn test_descriptor_key_from_hex_compressed() {
        let key = test_key();
        assert!(key.compressed_bytes().is_some());
        assert!(key.x_only_bytes().is_none());
    }

    #[test]
    fn test_descriptor_key_from_hex_xonly() {
        let key = DescriptorKey::from_hex(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        )
        .expect("valid");
        assert!(key.x_only_bytes().is_some());
    }

    #[test]
    fn test_descriptor_key_from_hex_invalid() {
        assert!(DescriptorKey::from_hex("0102").is_err());
        assert!(DescriptorKey::from_hex("invalid").is_err());
    }

    #[test]
    fn test_descriptor_key_hash160() {
        let key = test_key();
        let h = key.hash160().expect("compressed key");
        assert_eq!(h.len(), 20);
        // Generator point HASH160 is well-known
        assert_eq!(
            hex::encode(h),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    #[test]
    fn test_descriptor_pkh_script_pubkey() {
        let key = test_key();
        let desc = Descriptor::pkh(key);
        let script = desc.script_pubkey().expect("ok");
        assert_eq!(script.len(), 25);
        assert_eq!(script[0], 0x76); // OP_DUP
        assert_eq!(script[1], 0xa9); // OP_HASH160
        assert_eq!(script[2], 0x14); // OP_PUSH20
        assert_eq!(script[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(script[24], 0xac); // OP_CHECKSIG
    }

    #[test]
    fn test_descriptor_wpkh_script_pubkey() {
        let key = test_key();
        let desc = Descriptor::wpkh(key);
        let script = desc.script_pubkey().expect("ok");
        assert_eq!(script.len(), 22);
        assert_eq!(script[0], 0x00); // OP_0
        assert_eq!(script[1], 0x14); // OP_PUSH20
    }

    #[test]
    fn test_descriptor_sh_wpkh_script_pubkey() {
        let key = test_key();
        let desc = Descriptor::sh_wpkh(key);
        let script = desc.script_pubkey().expect("ok");
        assert_eq!(script.len(), 23);
        assert_eq!(script[0], 0xa9); // OP_HASH160
        assert_eq!(script[1], 0x14); // OP_PUSH20
        assert_eq!(script[22], 0x87); // OP_EQUAL
    }

    #[test]
    fn test_descriptor_tr_script_pubkey() {
        let key = DescriptorKey::from_hex(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        )
        .expect("valid");
        let desc = Descriptor::tr(key);
        let script = desc.script_pubkey().expect("ok");
        assert_eq!(script.len(), 34);
        assert_eq!(script[0], 0x51); // OP_1
        assert_eq!(script[1], 0x20); // OP_PUSH32
    }

    #[test]
    fn test_descriptor_pkh_address_mainnet() {
        let key = test_key();
        let desc = Descriptor::pkh(key);
        let addr = desc.address("bc").expect("ok");
        // Generator point P2PKH address
        assert_eq!(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_descriptor_wpkh_address_mainnet() {
        let key = test_key();
        let desc = Descriptor::wpkh(key);
        let addr = desc.address("bc").expect("ok");
        assert!(addr.starts_with("bc1q"));
        // Generator point P2WPKH address
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_descriptor_sh_wpkh_address() {
        let key = test_key();
        let desc = Descriptor::sh_wpkh(key);
        let addr = desc.address("bc").expect("ok");
        assert!(addr.starts_with('3'));
    }

    #[test]
    fn test_descriptor_tr_address() {
        let key = DescriptorKey::from_hex(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        )
        .expect("valid");
        let desc = Descriptor::tr(key);
        let addr = desc.address("bc").expect("ok");
        assert!(addr.starts_with("bc1p"));
    }

    #[test]
    fn test_descriptor_parse_pkh() {
        let desc = parse(&format!("pkh({TEST_PUBKEY})")).expect("ok");
        assert!(matches!(desc, Descriptor::Pkh(_)));
    }

    #[test]
    fn test_descriptor_parse_wpkh() {
        let desc = parse(&format!("wpkh({TEST_PUBKEY})")).expect("ok");
        assert!(matches!(desc, Descriptor::Wpkh(_)));
    }

    #[test]
    fn test_descriptor_parse_sh_wpkh() {
        let desc = parse(&format!("sh(wpkh({TEST_PUBKEY}))")).expect("ok");
        assert!(matches!(desc, Descriptor::ShWpkh(_)));
    }

    #[test]
    fn test_descriptor_parse_tr() {
        let xonly = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let desc = parse(&format!("tr({xonly})")).expect("ok");
        assert!(matches!(desc, Descriptor::Tr(_)));
    }

    #[test]
    fn test_descriptor_parse_raw() {
        let desc = parse("raw(6a0568656c6c6f)").expect("ok");
        assert!(matches!(desc, Descriptor::Raw(_)));
    }

    #[test]
    fn test_descriptor_parse_with_checksum() {
        let desc_str = format!("pkh({TEST_PUBKEY})#something");
        let desc = parse(&desc_str).expect("ok");
        assert!(matches!(desc, Descriptor::Pkh(_)));
    }

    #[test]
    fn test_descriptor_parse_invalid() {
        assert!(parse("unknown(key)").is_err());
    }

    #[test]
    fn test_descriptor_to_string_roundtrip() {
        let key = test_key();
        let desc = Descriptor::pkh(key);
        let s = desc.to_string_repr();
        let reparsed = parse(&s).expect("roundtrip");
        assert!(matches!(reparsed, Descriptor::Pkh(_)));
    }

    #[test]
    fn test_descriptor_checksum_length() {
        let key = test_key();
        let desc = Descriptor::pkh(key);
        let cs = desc.checksum();
        assert_eq!(cs.len(), 8);
        assert!(cs.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_descriptor_with_checksum() {
        let key = test_key();
        let desc = Descriptor::wpkh(key);
        let full = desc.to_string_with_checksum();
        assert!(full.contains('#'));
        let parts: Vec<&str> = full.split('#').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].len(), 8);
    }

    #[test]
    fn test_descriptor_testnet_address() {
        let key = test_key();
        let mainnet = Descriptor::pkh(key.clone()).address("bc").expect("ok");
        let testnet = Descriptor::pkh(key).address("tb").expect("ok");
        assert_ne!(mainnet, testnet);
        assert!(testnet.starts_with('m') || testnet.starts_with('n'));
    }

    #[test]
    fn test_descriptor_op_return() {
        let data = vec![0x01, 0x02, 0x03];
        let desc = Descriptor::OpReturn(data);
        let script = desc.script_pubkey().expect("ok");
        assert_eq!(script[0], 0x6a); // OP_RETURN
        assert!(desc.address("bc").is_err()); // no address for OP_RETURN
    }

    #[test]
    fn test_descriptor_xonly_key_no_hash160() {
        let key = DescriptorKey::from_hex(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        )
        .expect("valid");
        assert!(key.hash160().is_none()); // x-only keys don't support HASH160
        assert!(Descriptor::pkh(key).script_pubkey().is_err()); // pkh with x-only should error
    }
}
