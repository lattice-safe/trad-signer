//! Shared encoding utilities used across all chain modules.
//!
//! Centralizes Bitcoin compact-size (varint), Bech32/Bech32m, and Base58Check
//! encoding so chain modules don't duplicate these building blocks.

use crate::crypto;
use crate::error::SignerError;

// ─── Compact Size (Bitcoin VarInt) ──────────────────────────────────

/// Encode a Bitcoin compact-size integer into a buffer.
///
/// | Range | Encoding |
/// |-------|----------|
/// | 0–0xFC | 1 byte |
/// | 0xFD–0xFFFF | 0xFD + 2 bytes LE |
/// | 0x10000–0xFFFFFFFF | 0xFE + 4 bytes LE |
/// | 0x100000000+ | 0xFF + 8 bytes LE |
pub fn encode_compact_size(buf: &mut Vec<u8>, value: u64) {
    if value < 0xFD {
        buf.push(value as u8);
    } else if value <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

/// Read a Bitcoin compact-size integer from a byte slice at the given offset.
///
/// Advances `offset` past the consumed bytes.
pub fn read_compact_size(data: &[u8], offset: &mut usize) -> Result<u64, SignerError> {
    if *offset >= data.len() {
        return Err(SignerError::EncodingError(
            "compact size: unexpected EOF".into(),
        ));
    }
    let first = data[*offset];
    *offset += 1;
    match first {
        0x00..=0xFC => Ok(first as u64),
        0xFD => {
            if *offset + 2 > data.len() {
                return Err(SignerError::EncodingError(
                    "compact size: truncated u16".into(),
                ));
            }
            let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            Ok(val as u64)
        }
        0xFE => {
            if *offset + 4 > data.len() {
                return Err(SignerError::EncodingError(
                    "compact size: truncated u32".into(),
                ));
            }
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&data[*offset..*offset + 4]);
            *offset += 4;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xFF => {
            if *offset + 8 > data.len() {
                return Err(SignerError::EncodingError(
                    "compact size: truncated u64".into(),
                ));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[*offset..*offset + 8]);
            *offset += 8;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

// ─── Bech32 / Bech32m ───────────────────────────────────────────────

/// Encode a SegWit/Taproot address using Bech32 (v0) or Bech32m (v1+).
///
/// Automatically selects the correct variant based on witness version.
pub fn bech32_encode(
    hrp: &str,
    witness_version: u8,
    program: &[u8],
) -> Result<String, SignerError> {
    use bech32::Hrp;
    let hrp = Hrp::parse(hrp)
        .map_err(|e| SignerError::EncodingError(format!("bech32 hrp: {e}")))?;
    let version = bech32::Fe32::try_from(witness_version)
        .map_err(|e| SignerError::EncodingError(format!("witness version: {e}")))?;
    bech32::segwit::encode(hrp, version, program)
        .map_err(|e| SignerError::EncodingError(format!("bech32 encode: {e}")))
}

// ─── Base58Check ────────────────────────────────────────────────────

/// Encode data with Base58Check: `Base58(version ‖ payload ‖ checksum[0..4])`.
///
/// Used by Bitcoin P2PKH, WIF, xprv/xpub, XRP, and NEO addresses.
pub fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(version);
    data.extend_from_slice(payload);
    let checksum = crypto::double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);
    bs58::encode(&data).into_string()
}

/// Decode a Base58Check string. Returns `(version, payload)`.
///
/// Validates the 4-byte checksum.
pub fn base58check_decode(s: &str) -> Result<(u8, Vec<u8>), SignerError> {
    let decoded = bs58::decode(s)
        .into_vec()
        .map_err(|e| SignerError::EncodingError(format!("base58: {e}")))?;
    if decoded.len() < 5 {
        return Err(SignerError::EncodingError("base58check too short".into()));
    }
    let payload_end = decoded.len() - 4;
    let checksum = crypto::double_sha256(&decoded[..payload_end]);
    if checksum[..4] != decoded[payload_end..] {
        return Err(SignerError::EncodingError(
            "base58check: invalid checksum".into(),
        ));
    }
    Ok((decoded[0], decoded[1..payload_end].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_size_roundtrip() {
        for val in [0u64, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFF_FFFF, 0x1_0000_0000] {
            let mut buf = Vec::new();
            encode_compact_size(&mut buf, val);
            let mut offset = 0;
            let parsed = read_compact_size(&buf, &mut offset).expect("ok");
            assert_eq!(parsed, val, "failed for {val}");
            assert_eq!(offset, buf.len());
        }
    }

    #[test]
    fn test_compact_size_single_byte() {
        let mut buf = Vec::new();
        encode_compact_size(&mut buf, 42);
        assert_eq!(buf, vec![42]);
    }

    #[test]
    fn test_compact_size_eof() {
        let mut offset = 0;
        assert!(read_compact_size(&[], &mut offset).is_err());
    }

    #[test]
    fn test_base58check_roundtrip() {
        let encoded = base58check_encode(0x00, &[0xAA; 20]);
        let (version, payload) = base58check_decode(&encoded).expect("ok");
        assert_eq!(version, 0x00);
        assert_eq!(payload, vec![0xAA; 20]);
    }

    #[test]
    fn test_base58check_invalid_checksum() {
        let mut encoded = base58check_encode(0x00, &[0xBB; 20]);
        // Corrupt the last character
        encoded.pop();
        encoded.push('1');
        // Might decode but checksum should fail (or bs58 decode fails)
        let result = base58check_decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_base58check_too_short() {
        assert!(base58check_decode("1").is_err());
    }

    #[test]
    fn test_bech32_encode_v0() {
        let addr = bech32_encode("bc", 0, &[0xAA; 20]).expect("ok");
        assert!(addr.starts_with("bc1q"));
    }

    #[test]
    fn test_bech32_encode_v1() {
        let addr = bech32_encode("bc", 1, &[0xBB; 32]).expect("ok");
        assert!(addr.starts_with("bc1p"));
    }

    #[test]
    fn test_bech32_encode_testnet() {
        let addr = bech32_encode("tb", 0, &[0xCC; 20]).expect("ok");
        assert!(addr.starts_with("tb1q"));
    }

    // ─── Bech32 Known Address Vectors ───────────────────────────

    #[test]
    fn test_bech32_bip173_p2wpkh_vector() {
        // BIP-173 test vector: P2WPKH bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        let program = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = bech32_encode("bc", 0, &program).unwrap();
        assert_eq!(addr, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }

    #[test]
    fn test_bech32_bip350_p2tr_vector() {
        // BIP-350: P2TR address with witness version 1
        let program = hex::decode("a60869f0dbcf1dc659c9cecbee736b12006a35d655ac7e1caeff5ebc1085a044").unwrap();
        let addr = bech32_encode("bc", 1, &program).unwrap();
        assert!(addr.starts_with("bc1p"));
        assert_eq!(addr.len(), 62); // Bech32m P2TR addresses are 62 chars
    }

    #[test]
    fn test_bech32_invalid_hrp() {
        assert!(bech32_encode("", 0, &[0; 20]).is_err());
    }

    // ─── Base58Check Known Address Vectors ──────────────────────

    #[test]
    fn test_base58check_bitcoin_p2pkh_genesis() {
        // Bitcoin genesis coinbase P2PKH: HASH160 of generator pubkey
        // Version 0x00 + 751e76e8199196d454941c45d1b3a323f1433bd6
        let hash160 = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        let addr = base58check_encode(0x00, &hash160);
        assert_eq!(addr, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    }

    #[test]
    fn test_base58check_decode_known_address() {
        let (version, payload) = base58check_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH").unwrap();
        assert_eq!(version, 0x00);
        assert_eq!(
            hex::encode(payload),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
    }

    // ─── Compact Size Boundary Values ───────────────────────────

    #[test]
    fn test_compact_size_boundary_252() {
        let mut buf = Vec::new();
        encode_compact_size(&mut buf, 252);
        assert_eq!(buf.len(), 1); // single byte
        assert_eq!(buf[0], 252);
    }

    #[test]
    fn test_compact_size_boundary_253() {
        let mut buf = Vec::new();
        encode_compact_size(&mut buf, 253);
        assert_eq!(buf[0], 0xFD); // 3 bytes: 0xFD + u16 LE
        assert_eq!(buf.len(), 3);
        let mut offset = 0;
        assert_eq!(read_compact_size(&buf, &mut offset).unwrap(), 253);
    }

    #[test]
    fn test_compact_size_truncated_u16() {
        let buf = vec![0xFD, 0x01]; // need 2 bytes, only 1
        let mut offset = 0;
        assert!(read_compact_size(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_compact_size_truncated_u32() {
        let buf = vec![0xFE, 0x01, 0x00]; // need 4 bytes, only 2
        let mut offset = 0;
        assert!(read_compact_size(&buf, &mut offset).is_err());
    }

    #[test]
    fn test_compact_size_truncated_u64() {
        let buf = vec![0xFF, 0x01, 0x00, 0x00, 0x00]; // need 8 bytes, only 4
        let mut offset = 0;
        assert!(read_compact_size(&buf, &mut offset).is_err());
    }
}
