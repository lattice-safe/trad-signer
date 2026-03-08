//! Serde helper for fixed-size byte arrays as hex strings.
//!
//! Serde natively only supports `[u8; N]` for N ≤ 32. This module
//! provides `serialize` / `deserialize` functions that encode/decode
//! any `[u8; N]` as a hex string, enabling `#[serde(with = "hex_bytes")]`.

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a byte slice as a hex string.
#[cfg(feature = "serde")]
pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserialize a hex string into a fixed-size byte array.
#[cfg(feature = "serde")]
pub fn deserialize<'de, const N: usize, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom(format!("expected {N} bytes, got different length")))
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestStruct {
        #[serde(with = "super")]
        data: [u8; 64],
    }

    #[test]
    fn test_hex_bytes_roundtrip_64() {
        let original = TestStruct { data: [0xAB; 64] };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("abab"));
        let decoded: TestStruct = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Test96 {
        #[serde(with = "super")]
        data: [u8; 96],
    }

    #[test]
    fn test_hex_bytes_roundtrip_96() {
        let original = Test96 { data: [0xCD; 96] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Test96 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Test48 {
        #[serde(with = "super")]
        data: [u8; 48],
    }

    #[test]
    fn test_hex_bytes_roundtrip_48() {
        let original = Test48 { data: [0xEF; 48] };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: Test48 = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
