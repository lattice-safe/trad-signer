//! **RLP (Recursive Length Prefix)** encoding and decoding for Ethereum.
//!
//! Implements the Ethereum Yellow Paper Appendix B encoding used for
//! transactions, state tries, and wire protocol messages.
//!
//! # Encoding Rules
//! - Single byte `[0x00..0x7F]` → itself
//! - String 0–55 bytes → `(0x80 + len) || data`
//! - String >55 bytes → `(0xB7 + len_of_len) || BE(len) || data`
//! - List 0–55 bytes → `(0xC0 + len) || items`
//! - List >55 bytes → `(0xF7 + len_of_len) || BE(len) || items`

use crate::error::SignerError;

// ─── Encoding ──────────────────────────────────────────────────────

/// Encode a byte slice as an RLP string.
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] <= 0x7F {
        // Single byte in [0x00, 0x7F] range
        vec![data[0]]
    } else if data.len() <= 55 {
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(0x80 + data.len() as u8);
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = encode_length_be(data.len());
        let mut out = Vec::with_capacity(1 + len_bytes.len() + data.len());
        out.push(0xB7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

/// Encode a `u64` as an RLP string (big-endian, no leading zeros).
pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return encode_bytes(&[]);
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(7);
    encode_bytes(&be[start..])
}

/// Encode a `u128` as an RLP string (big-endian, no leading zeros).
pub fn encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return encode_bytes(&[]);
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(15);
    encode_bytes(&be[start..])
}

/// Encode the empty list `0xC0`.
pub fn encode_empty_list() -> Vec<u8> {
    vec![0xC0]
}

/// Wrap already-encoded RLP items into an RLP list.
pub fn encode_list(items: &[u8]) -> Vec<u8> {
    if items.len() <= 55 {
        let mut out = Vec::with_capacity(1 + items.len());
        out.push(0xC0 + items.len() as u8);
        out.extend_from_slice(items);
        out
    } else {
        let len_bytes = encode_length_be(items.len());
        let mut out = Vec::with_capacity(1 + len_bytes.len() + items.len());
        out.push(0xF7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(items);
        out
    }
}

/// Encode an access list: `[[address, [storageKey, ...]]]`.
///
/// Each entry is `(address: [u8; 20], storage_keys: Vec<[u8; 32]>)`.
pub fn encode_access_list(list: &[([u8; 20], Vec<[u8; 32]>)]) -> Vec<u8> {
    let mut items = Vec::new();
    for (addr, keys) in list {
        let mut entry = Vec::new();
        entry.extend_from_slice(&encode_bytes(addr));
        let mut key_items = Vec::new();
        for key in keys {
            key_items.extend_from_slice(&encode_bytes(key));
        }
        entry.extend_from_slice(&encode_list(&key_items));
        items.extend_from_slice(&encode_list(&entry));
    }
    encode_list(&items)
}

// ─── Decoding ──────────────────────────────────────────────────────

/// A decoded RLP item: either a byte string or a list of items.
#[derive(Debug, Clone, PartialEq)]
pub enum RlpItem {
    /// Raw byte string.
    Bytes(Vec<u8>),
    /// List of RLP items.
    List(Vec<RlpItem>),
}

impl RlpItem {
    /// Interpret this item as bytes. Returns `Err` if it's a list.
    pub fn as_bytes(&self) -> Result<&[u8], SignerError> {
        match self {
            RlpItem::Bytes(b) => Ok(b),
            RlpItem::List(_) => Err(SignerError::ParseError(
                "expected RLP bytes, got list".into(),
            )),
        }
    }

    /// Interpret this item as a list. Returns `Err` if it's bytes.
    pub fn as_list(&self) -> Result<&[RlpItem], SignerError> {
        match self {
            RlpItem::List(items) => Ok(items),
            RlpItem::Bytes(_) => Err(SignerError::ParseError(
                "expected RLP list, got bytes".into(),
            )),
        }
    }

    /// Interpret as a big-endian unsigned integer.
    pub fn as_u64(&self) -> Result<u64, SignerError> {
        let bytes = self.as_bytes()?;
        if bytes.len() > 8 {
            return Err(SignerError::ParseError(
                "RLP integer too large for u64".into(),
            ));
        }
        let mut buf = [0u8; 8];
        buf[8 - bytes.len()..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(buf))
    }
}

/// Decode a complete RLP-encoded byte string.
///
/// Returns the decoded item and verifies no trailing bytes remain.
pub fn decode(data: &[u8]) -> Result<RlpItem, SignerError> {
    let (item, consumed) = decode_item(data, 0)?;
    if consumed != data.len() {
        return Err(SignerError::ParseError(format!(
            "RLP: {} trailing bytes",
            data.len() - consumed
        )));
    }
    Ok(item)
}

/// Decode multiple RLP items from a stream (e.g. a transaction payload).
pub fn decode_list_items(data: &[u8]) -> Result<Vec<RlpItem>, SignerError> {
    let item = decode(data)?;
    match item {
        RlpItem::List(items) => Ok(items),
        _ => Err(SignerError::ParseError(
            "expected RLP list at top level".into(),
        )),
    }
}

// ─── Internal Helpers ──────────────────────────────────────────────

fn encode_length_be(len: usize) -> Vec<u8> {
    let be = (len as u64).to_be_bytes();
    let start = be.iter().position(|b| *b != 0).unwrap_or(7);
    be[start..].to_vec()
}

fn decode_item(data: &[u8], offset: usize) -> Result<(RlpItem, usize), SignerError> {
    if offset >= data.len() {
        return Err(SignerError::ParseError("RLP: unexpected EOF".into()));
    }
    let prefix = data[offset];

    match prefix {
        // Single byte [0x00, 0x7F]
        0x00..=0x7F => Ok((RlpItem::Bytes(vec![prefix]), offset + 1)),

        // Short string: 0x80 + len, data (0–55 bytes)
        0x80..=0xB7 => {
            let len = (prefix - 0x80) as usize;
            let start = offset + 1;
            let end = start + len;
            if end > data.len() {
                return Err(SignerError::ParseError("RLP: string truncated".into()));
            }
            // Canonical check: single byte <= 0x7F must not use short-string form
            if len == 1 && data[start] <= 0x7F {
                return Err(SignerError::ParseError(
                    "RLP: non-canonical single byte in short-string form".into(),
                ));
            }
            Ok((RlpItem::Bytes(data[start..end].to_vec()), end))
        }

        // Long string: 0xB7 + len_of_len
        0xB8..=0xBF => {
            let len_of_len = (prefix - 0xB7) as usize;
            let len = read_be_usize(data, offset + 1, len_of_len)?;
            // Canonical checks
            if len <= 55 {
                return Err(SignerError::ParseError(
                    "RLP: non-canonical long-form for short string".into(),
                ));
            }
            let start = offset + 1 + len_of_len;
            let end = start.checked_add(len).ok_or_else(|| {
                SignerError::ParseError("RLP: long string length overflow".into())
            })?;
            if end > data.len() {
                return Err(SignerError::ParseError("RLP: long string truncated".into()));
            }
            Ok((RlpItem::Bytes(data[start..end].to_vec()), end))
        }

        // Short list: 0xC0 + len
        0xC0..=0xF7 => {
            let list_len = (prefix - 0xC0) as usize;
            let start = offset + 1;
            let end = start + list_len;
            if end > data.len() {
                return Err(SignerError::ParseError("RLP: list truncated".into()));
            }
            let items = decode_items_in_range(data, start, end)?;
            Ok((RlpItem::List(items), end))
        }

        // Long list: 0xF7 + len_of_len
        0xF8..=0xFF => {
            let len_of_len = (prefix - 0xF7) as usize;
            let list_len = read_be_usize(data, offset + 1, len_of_len)?;
            // Canonical check: long form only for len > 55
            if list_len <= 55 {
                return Err(SignerError::ParseError(
                    "RLP: non-canonical long-form for short list".into(),
                ));
            }
            let start = offset + 1 + len_of_len;
            let end = start.checked_add(list_len).ok_or_else(|| {
                SignerError::ParseError("RLP: long list length overflow".into())
            })?;
            if end > data.len() {
                return Err(SignerError::ParseError("RLP: long list truncated".into()));
            }
            let items = decode_items_in_range(data, start, end)?;
            Ok((RlpItem::List(items), end))
        }
    }
}

fn decode_items_in_range(
    data: &[u8],
    start: usize,
    end: usize,
) -> Result<Vec<RlpItem>, SignerError> {
    let mut items = Vec::new();
    let mut pos = start;
    while pos < end {
        let (item, next) = decode_item(data, pos)?;
        items.push(item);
        pos = next;
    }
    if pos != end {
        return Err(SignerError::ParseError("RLP: list items overrun".into()));
    }
    Ok(items)
}

fn read_be_usize(data: &[u8], offset: usize, len: usize) -> Result<usize, SignerError> {
    if offset + len > data.len() {
        return Err(SignerError::ParseError("RLP: length truncated".into()));
    }
    if len > 8 {
        return Err(SignerError::ParseError("RLP: length too large".into()));
    }
    // Reject leading zeros in length encoding (non-canonical)
    if len > 1 && data[offset] == 0 {
        return Err(SignerError::ParseError(
            "RLP: non-canonical length with leading zeros".into(),
        ));
    }
    let mut buf = [0u8; 8];
    buf[8 - len..].copy_from_slice(&data[offset..offset + len]);
    Ok(u64::from_be_bytes(buf) as usize)
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Yellow Paper Appendix B vectors

    #[test]
    fn test_rlp_single_byte() {
        // "a" (0x61) → 0x61
        assert_eq!(encode_bytes(&[0x61]), vec![0x61]);
    }

    #[test]
    fn test_rlp_empty_string() {
        // "" → 0x80
        assert_eq!(encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn test_rlp_short_string() {
        // "dog" → 0x83 d o g
        let dog = b"dog";
        let encoded = encode_bytes(dog);
        assert_eq!(encoded, vec![0x83, b'd', b'o', b'g']);
    }

    #[test]
    fn test_rlp_empty_list() {
        // [] → 0xC0
        assert_eq!(encode_list(&[]), vec![0xC0]);
    }

    #[test]
    fn test_rlp_integer_zero() {
        // 0 → 0x80 (empty string)
        assert_eq!(encode_u64(0), vec![0x80]);
    }

    #[test]
    fn test_rlp_integer_15() {
        // 15 → 0x0f (single byte)
        assert_eq!(encode_u64(15), vec![0x0F]);
    }

    #[test]
    fn test_rlp_integer_1024() {
        // 1024 → 0x82 0x04 0x00
        assert_eq!(encode_u64(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn test_rlp_nested_list() {
        // [ [], [[]], [ [], [[]] ] ]
        let empty = encode_list(&[]);
        let nested1 = encode_list(&empty);
        let mut inner = Vec::new();
        inner.extend_from_slice(&empty);
        inner.extend_from_slice(&nested1);
        let nested2 = encode_list(&inner);
        let mut top = Vec::new();
        top.extend_from_slice(&empty);
        top.extend_from_slice(&nested1);
        top.extend_from_slice(&nested2);
        let result = encode_list(&top);
        assert_eq!(result, vec![0xC7, 0xC0, 0xC1, 0xC0, 0xC3, 0xC0, 0xC1, 0xC0]);
    }

    #[test]
    fn test_rlp_long_string() {
        // String of 56 bytes → 0xB8 0x38 || data
        let data = vec![0xAA; 56];
        let encoded = encode_bytes(&data);
        assert_eq!(encoded[0], 0xB8);
        assert_eq!(encoded[1], 56);
        assert_eq!(&encoded[2..], &data[..]);
    }

    #[test]
    fn test_rlp_decode_roundtrip_bytes() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x7F],
            vec![0x80],
            b"hello world".to_vec(),
            vec![0xAA; 56],
            vec![0xBB; 200],
        ];
        for data in &cases {
            let encoded = encode_bytes(data);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded.as_bytes().unwrap(), data.as_slice());
        }
    }

    #[test]
    fn test_rlp_decode_roundtrip_list() {
        // Encode [0x01, "dog", 1024]
        let mut items = Vec::new();
        items.extend_from_slice(&encode_u64(1));
        items.extend_from_slice(&encode_bytes(b"dog"));
        items.extend_from_slice(&encode_u64(1024));
        let encoded = encode_list(&items);
        let decoded = decode(&encoded).unwrap();
        let list = decoded.as_list().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].as_u64().unwrap(), 1);
        assert_eq!(list[1].as_bytes().unwrap(), b"dog");
        assert_eq!(list[2].as_u64().unwrap(), 1024);
    }

    #[test]
    fn test_rlp_decode_trailing_bytes_rejected() {
        let mut encoded = encode_bytes(b"hello");
        encoded.push(0xFF); // trailing junk
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn test_rlp_integer_roundtrip() {
        for val in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            1024,
            0xFFFF,
            0xFFFFFFFF,
            u64::MAX,
        ] {
            let encoded = encode_u64(val);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded.as_u64().unwrap(), val, "failed for {val}");
        }
    }

    #[test]
    fn test_rlp_u128() {
        let val = 1_000_000_000_000_000_000u128; // 1 ETH in wei
        let encoded = encode_u128(val);
        let decoded = decode(&encoded).unwrap();
        let bytes = decoded.as_bytes().unwrap();
        let mut buf = [0u8; 16];
        buf[16 - bytes.len()..].copy_from_slice(bytes);
        assert_eq!(u128::from_be_bytes(buf), val);
    }

    #[test]
    fn test_rlp_access_list() {
        let al = vec![([0xAA; 20], vec![[0xBB; 32]])];
        let encoded = encode_access_list(&al);
        let decoded = decode(&encoded).unwrap();
        let list = decoded.as_list().unwrap();
        assert_eq!(list.len(), 1); // one entry
        let entry = list[0].as_list().unwrap();
        assert_eq!(entry[0].as_bytes().unwrap(), &[0xAA; 20]);
        let keys = entry[1].as_list().unwrap();
        assert_eq!(keys[0].as_bytes().unwrap(), &[0xBB; 32]);
    }
}
