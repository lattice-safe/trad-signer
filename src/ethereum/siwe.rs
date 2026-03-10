//! **EIP-4361** — Sign-In with Ethereum (SIWE) message construction and parsing.
//!
//! Provides typed SIWE message building and signing, following the standard
//! used by dApps for off-chain authentication.
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::siwe::SiweMessage;
//! use chains_sdk::ethereum::EthereumSigner;
//! use chains_sdk::traits::KeyPair;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let signer = EthereumSigner::generate()?;
//!     let msg = SiweMessage {
//!         domain: "example.com".to_string(),
//!         address: signer.address_checksum(),
//!         statement: Some("Sign in to Example App".to_string()),
//!         uri: "https://example.com/login".to_string(),
//!         version: "1".to_string(),
//!         chain_id: 1,
//!         nonce: "abc123".to_string(),
//!         issued_at: "2024-01-01T00:00:00Z".to_string(),
//!         expiration_time: None,
//!         not_before: None,
//!         request_id: None,
//!         resources: vec![],
//!     };
//!     let text = msg.to_message();
//!     let sig = signer.personal_sign(text.as_bytes())?;
//!     Ok(())
//! }
//! ```

use crate::error::SignerError;

/// An EIP-4361 Sign-In with Ethereum message.
#[derive(Debug, Clone)]
pub struct SiweMessage {
    /// RFC 4501 dNS authority (e.g., `example.com`).
    pub domain: String,
    /// EIP-55 checksummed Ethereum address.
    pub address: String,
    /// Optional human-readable statement.
    pub statement: Option<String>,
    /// RFC 3986 URI for the signing request.
    pub uri: String,
    /// SIWE protocol version (currently `"1"`).
    pub version: String,
    /// EIP-155 chain ID.
    pub chain_id: u64,
    /// Randomized nonce to prevent replay.
    pub nonce: String,
    /// ISO 8601 datetime when the message was issued.
    pub issued_at: String,
    /// Optional ISO 8601 expiration time.
    pub expiration_time: Option<String>,
    /// Optional ISO 8601 "not before" time.
    pub not_before: Option<String>,
    /// Optional request ID for session correlation.
    pub request_id: Option<String>,
    /// Optional list of resource URIs.
    pub resources: Vec<String>,
}

impl SiweMessage {
    /// Serialize the SIWE message to the EIP-4361 text format.
    ///
    /// This is the string that gets signed via `personal_sign` (EIP-191).
    #[must_use]
    pub fn to_message(&self) -> String {
        let mut msg = format!(
            "{domain} wants you to sign in with your Ethereum account:\n\
             {address}\n",
            domain = self.domain,
            address = self.address,
        );

        if let Some(stmt) = &self.statement {
            msg.push('\n');
            msg.push_str(stmt);
            msg.push('\n');
        }

        msg.push_str(&format!(
            "\nURI: {uri}\n\
             Version: {version}\n\
             Chain ID: {chain_id}\n\
             Nonce: {nonce}\n\
             Issued At: {issued_at}",
            uri = self.uri,
            version = self.version,
            chain_id = self.chain_id,
            nonce = self.nonce,
            issued_at = self.issued_at,
        ));

        if let Some(exp) = &self.expiration_time {
            msg.push_str(&format!("\nExpiration Time: {exp}"));
        }
        if let Some(nb) = &self.not_before {
            msg.push_str(&format!("\nNot Before: {nb}"));
        }
        if let Some(rid) = &self.request_id {
            msg.push_str(&format!("\nRequest ID: {rid}"));
        }
        if !self.resources.is_empty() {
            msg.push_str("\nResources:");
            for r in &self.resources {
                msg.push_str(&format!("\n- {r}"));
            }
        }

        msg
    }

    /// Parse an EIP-4361 SIWE message from its text representation.
    pub fn from_message(text: &str) -> Result<Self, SignerError> {
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() < 7 {
            return Err(SignerError::ParseError("SIWE message too short".into()));
        }

        // Line 0: "{domain} wants you to sign in with your Ethereum account:"
        let domain_line = lines[0];
        let domain = domain_line
            .strip_suffix(" wants you to sign in with your Ethereum account:")
            .ok_or_else(|| SignerError::ParseError("invalid SIWE domain line".into()))?
            .to_string();
        if !validate_domain(&domain) {
            return Err(SignerError::ParseError("invalid SIWE domain".into()));
        }

        // Line 1: address
        let address = lines[1].to_string();
        if !super::validate_address(&address) {
            return Err(SignerError::ParseError("invalid SIWE address".into()));
        }
        let address_bytes = parse_eth_address_bytes(&address)
            .ok_or_else(|| SignerError::ParseError("invalid SIWE address".into()))?;
        if super::eip55_checksum(&address_bytes) != address {
            return Err(SignerError::ParseError(
                "SIWE address must be EIP-55 checksummed".into(),
            ));
        }

        // Parse optional statement (between address and URI block).
        let mut idx = 2;
        if idx >= lines.len() || !lines[idx].is_empty() {
            return Err(SignerError::ParseError(
                "missing blank line after SIWE address".into(),
            ));
        }
        idx += 1;

        let mut statement = None;
        if idx < lines.len() && !lines[idx].starts_with("URI: ") {
            if lines[idx].is_empty() {
                return Err(SignerError::ParseError(
                    "invalid empty SIWE statement".into(),
                ));
            }
            statement = Some(lines[idx].to_string());
            idx += 1;
            if idx >= lines.len() || !lines[idx].is_empty() {
                return Err(SignerError::ParseError(
                    "missing blank line after SIWE statement".into(),
                ));
            }
            idx += 1;
        }

        let uri = parse_prefixed_line(lines.get(idx), "URI: ", "URI")?;
        if !validate_uri(&uri) {
            return Err(SignerError::ParseError("invalid SIWE URI".into()));
        }
        idx += 1;

        let version = parse_prefixed_line(lines.get(idx), "Version: ", "Version")?;
        if version != "1" {
            return Err(SignerError::ParseError(
                "unsupported SIWE version (must be 1)".into(),
            ));
        }
        idx += 1;

        let chain_id = parse_prefixed_line(lines.get(idx), "Chain ID: ", "Chain ID")?
            .parse::<u64>()
            .map_err(|_| SignerError::ParseError("invalid SIWE chain ID".into()))?;
        if chain_id == 0 {
            return Err(SignerError::ParseError(
                "invalid SIWE chain ID (must be non-zero)".into(),
            ));
        }
        idx += 1;

        let nonce = parse_prefixed_line(lines.get(idx), "Nonce: ", "Nonce")?;
        if !validate_nonce(&nonce) {
            return Err(SignerError::ParseError("invalid SIWE nonce".into()));
        }
        idx += 1;

        let issued_at = parse_prefixed_line(lines.get(idx), "Issued At: ", "Issued At")?;
        if !validate_rfc3339_datetime(&issued_at) {
            return Err(SignerError::ParseError("invalid SIWE issued-at".into()));
        }
        idx += 1;

        let mut expiration_time: Option<String> = None;
        if let Some(line) = lines.get(idx) {
            if let Some(v) = line.strip_prefix("Expiration Time: ") {
                if !validate_rfc3339_datetime(v) {
                    return Err(SignerError::ParseError(
                        "invalid SIWE expiration time".into(),
                    ));
                }
                expiration_time = Some(v.to_string());
                idx += 1;
            }
        }

        let mut not_before: Option<String> = None;
        if let Some(line) = lines.get(idx) {
            if let Some(v) = line.strip_prefix("Not Before: ") {
                if !validate_rfc3339_datetime(v) {
                    return Err(SignerError::ParseError("invalid SIWE not-before".into()));
                }
                not_before = Some(v.to_string());
                idx += 1;
            }
        }

        let mut request_id: Option<String> = None;
        if let Some(line) = lines.get(idx) {
            if let Some(v) = line.strip_prefix("Request ID: ") {
                if !validate_request_id(v) {
                    return Err(SignerError::ParseError("invalid SIWE request ID".into()));
                }
                request_id = Some(v.to_string());
                idx += 1;
            }
        }

        let mut resources = Vec::new();
        if let Some(line) = lines.get(idx) {
            if *line == "Resources:" {
                idx += 1;
                while idx < lines.len() {
                    let resource_line = lines[idx];
                    let resource = resource_line.strip_prefix("- ").ok_or_else(|| {
                        SignerError::ParseError("invalid SIWE resources list entry".into())
                    })?;
                    if !validate_uri(resource) {
                        return Err(SignerError::ParseError("invalid SIWE resource URI".into()));
                    }
                    resources.push(resource.to_string());
                    idx += 1;
                }
                if resources.is_empty() {
                    return Err(SignerError::ParseError(
                        "SIWE resources section must contain at least one URI".into(),
                    ));
                }
            }
        }

        if idx != lines.len() {
            return Err(SignerError::ParseError(
                "unexpected trailing SIWE content".into(),
            ));
        }

        Ok(Self {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }

    /// Sign this SIWE message using EIP-191 `personal_sign`.
    ///
    /// Returns the 65-byte signature.
    pub fn sign(
        &self,
        signer: &super::EthereumSigner,
    ) -> Result<super::EthereumSignature, SignerError> {
        let msg = self.to_message();
        signer.personal_sign(msg.as_bytes())
    }

    /// Verify a SIWE signature against this message.
    ///
    /// Uses EIP-191 `personal_sign` hashing for recovery, matching how the message was signed.
    pub fn verify(&self, signature: &super::EthereumSignature) -> Result<bool, SignerError> {
        let msg = self.to_message();
        let hash = super::eip191_hash(msg.as_bytes());
        let recovered = super::ecrecover_digest(&hash, signature)?;
        let expected = super::eip55_checksum(&recovered);
        Ok(expected == self.address)
    }
}

fn parse_prefixed_line(
    line: Option<&&str>,
    prefix: &str,
    field_name: &str,
) -> Result<String, SignerError> {
    let line = line.ok_or_else(|| SignerError::ParseError(format!("missing SIWE {field_name}")))?;
    line.strip_prefix(prefix)
        .map(ToString::to_string)
        .ok_or_else(|| SignerError::ParseError(format!("missing SIWE {field_name}")))
}

fn validate_domain(domain: &str) -> bool {
    !domain.is_empty()
        && !domain.contains("://")
        && domain.chars().any(|c| c.is_ascii_alphanumeric())
        && !domain.chars().any(|c| c.is_ascii_whitespace())
}

fn validate_nonce(nonce: &str) -> bool {
    nonce.len() >= 8 && nonce.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn validate_uri(uri: &str) -> bool {
    if uri.is_empty() || uri.chars().any(|c| c.is_ascii_whitespace()) {
        return false;
    }
    let mut parts = uri.splitn(2, ':');
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(_) = parts.next() else {
        return false;
    };
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

fn validate_request_id(request_id: &str) -> bool {
    request_id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn validate_rfc3339_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    if !(bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
        && bytes[10] == b'T'
        && bytes[11].is_ascii_digit()
        && bytes[12].is_ascii_digit()
        && bytes[13] == b':'
        && bytes[14].is_ascii_digit()
        && bytes[15].is_ascii_digit()
        && bytes[16] == b':'
        && bytes[17].is_ascii_digit()
        && bytes[18].is_ascii_digit())
    {
        return false;
    }

    let month = parse_two_digits(&bytes[5..7]);
    let day = parse_two_digits(&bytes[8..10]);
    let hour = parse_two_digits(&bytes[11..13]);
    let minute = parse_two_digits(&bytes[14..16]);
    let second = parse_two_digits(&bytes[17..19]);
    let Some(month) = month else { return false };
    let Some(day) = day else { return false };
    let Some(hour) = hour else { return false };
    let Some(minute) = minute else { return false };
    let Some(second) = second else { return false };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return false;
    }

    let mut idx = 19;
    if bytes[idx] == b'.' {
        idx += 1;
        let frac_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == frac_start {
            return false;
        }
    }

    if idx >= bytes.len() {
        return false;
    }

    match bytes[idx] {
        b'Z' => idx + 1 == bytes.len(),
        b'+' | b'-' => {
            if idx + 6 != bytes.len() {
                return false;
            }
            let tz_hour = parse_two_digits(&bytes[idx + 1..idx + 3]);
            let tz_minute = parse_two_digits(&bytes[idx + 4..idx + 6]);
            bytes[idx + 3] == b':'
                && tz_hour.is_some_and(|h| h <= 23)
                && tz_minute.is_some_and(|m| m <= 59)
        }
        _ => false,
    }
}

fn parse_two_digits(bytes: &[u8]) -> Option<u8> {
    if bytes.len() != 2 || !bytes[0].is_ascii_digit() || !bytes[1].is_ascii_digit() {
        return None;
    }
    Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
}

fn parse_eth_address_bytes(address: &str) -> Option<[u8; 20]> {
    if address.len() != 42 || !address.starts_with("0x") {
        return None;
    }
    let mut out = [0u8; 20];
    let hex = address.as_bytes();
    for i in 0..20 {
        let hi = decode_hex_nibble(hex[2 + i * 2])?;
        let lo = decode_hex_nibble(hex[2 + i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::KeyPair;

    fn sample_message() -> SiweMessage {
        SiweMessage {
            domain: "example.com".to_string(),
            address: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B".to_string(),
            statement: Some("Sign in to the app".to_string()),
            uri: "https://example.com/login".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            nonce: "32891756".to_string(),
            issued_at: "2024-01-01T00:00:00Z".to_string(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: vec![],
        }
    }

    #[test]
    fn test_siwe_to_message_format() {
        let msg = sample_message();
        let text = msg.to_message();
        assert!(text.contains("example.com wants you to sign in with your Ethereum account:"));
        assert!(text.contains("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B"));
        assert!(text.contains("Sign in to the app"));
        assert!(text.contains("URI: https://example.com/login"));
        assert!(text.contains("Chain ID: 1"));
        assert!(text.contains("Nonce: 32891756"));
    }

    #[test]
    fn test_siwe_roundtrip_parse() {
        let msg = sample_message();
        let text = msg.to_message();
        let parsed = SiweMessage::from_message(&text).unwrap();
        assert_eq!(parsed.domain, msg.domain);
        assert_eq!(parsed.address, msg.address);
        assert_eq!(parsed.statement, msg.statement);
        assert_eq!(parsed.uri, msg.uri);
        assert_eq!(parsed.chain_id, msg.chain_id);
        assert_eq!(parsed.nonce, msg.nonce);
    }

    #[test]
    fn test_siwe_with_resources() {
        let mut msg = sample_message();
        msg.resources = vec![
            "https://example.com/resource1".to_string(),
            "https://example.com/resource2".to_string(),
        ];
        let text = msg.to_message();
        assert!(text.contains("Resources:"));
        assert!(text.contains("- https://example.com/resource1"));
        let parsed = SiweMessage::from_message(&text).unwrap();
        assert_eq!(parsed.resources.len(), 2);
    }

    #[test]
    fn test_siwe_with_optional_fields() {
        let mut msg = sample_message();
        msg.expiration_time = Some("2025-01-01T00:00:00Z".to_string());
        msg.not_before = Some("2023-01-01T00:00:00Z".to_string());
        msg.request_id = Some("req-123".to_string());
        let text = msg.to_message();
        let parsed = SiweMessage::from_message(&text).unwrap();
        assert_eq!(
            parsed.expiration_time.as_deref(),
            Some("2025-01-01T00:00:00Z")
        );
        assert_eq!(parsed.not_before.as_deref(), Some("2023-01-01T00:00:00Z"));
        assert_eq!(parsed.request_id.as_deref(), Some("req-123"));
    }

    #[test]
    fn test_siwe_no_statement() {
        let mut msg = sample_message();
        msg.statement = None;
        let text = msg.to_message();
        let parsed = SiweMessage::from_message(&text).unwrap();
        assert_eq!(parsed.statement, None);
        assert_eq!(parsed.domain, "example.com");
    }

    #[test]
    fn test_siwe_reject_invalid_version() {
        let mut msg = sample_message();
        msg.version = "2".to_string();
        let err = SiweMessage::from_message(&msg.to_message()).unwrap_err();
        assert!(err.to_string().contains("unsupported SIWE version"));
    }

    #[test]
    fn test_siwe_reject_short_nonce() {
        let mut msg = sample_message();
        msg.nonce = "abc".to_string();
        let err = SiweMessage::from_message(&msg.to_message()).unwrap_err();
        assert!(err.to_string().contains("invalid SIWE nonce"));
    }

    #[test]
    fn test_siwe_reject_invalid_address() {
        let mut msg = sample_message();
        msg.address = "0x1234".to_string();
        let err = SiweMessage::from_message(&msg.to_message()).unwrap_err();
        assert!(err.to_string().contains("invalid SIWE address"));
    }

    #[test]
    fn test_siwe_reject_non_checksummed_address() {
        let mut msg = sample_message();
        msg.address = "0xab5801a7d398351b8be11c439e05c5b3259aec9b".to_string();
        let err = SiweMessage::from_message(&msg.to_message()).unwrap_err();
        assert!(err.to_string().contains("EIP-55 checksummed"));
    }

    #[test]
    fn test_siwe_sign_verify_roundtrip() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let msg = SiweMessage {
            domain: "test.app".to_string(),
            address: signer.address_checksum(),
            statement: Some("Please sign in".to_string()),
            uri: "https://test.app".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            nonce: "abc123".to_string(),
            issued_at: "2024-06-01T12:00:00Z".to_string(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: vec![],
        };
        let sig = msg.sign(&signer).unwrap();
        assert!(msg.verify(&sig).unwrap());
    }

    #[test]
    fn test_siwe_wrong_address_fails() {
        let signer = super::super::EthereumSigner::generate().unwrap();
        let msg = SiweMessage {
            domain: "test.app".to_string(),
            address: "0x0000000000000000000000000000000000000000".to_string(), // wrong
            statement: None,
            uri: "https://test.app".to_string(),
            version: "1".to_string(),
            chain_id: 1,
            nonce: "xyz".to_string(),
            issued_at: "2024-01-01T00:00:00Z".to_string(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: vec![],
        };
        let sig = msg.sign(&signer).unwrap();
        // Address doesn't match signer → should fail
        assert!(!msg.verify(&sig).unwrap());
    }
}
