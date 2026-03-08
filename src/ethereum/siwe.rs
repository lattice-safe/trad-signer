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

        // Line 1: address
        let address = lines[1].to_string();

        // Parse optional statement (between address and URI block)
        let mut idx = 2;
        let mut statement = None;

        // Skip empty line after address
        if idx < lines.len() && lines[idx].is_empty() {
            idx += 1;
        }

        // Check if next non-empty line is a statement (not a field)
        if idx < lines.len() && !lines[idx].is_empty() && !lines[idx].starts_with("URI:") {
            statement = Some(lines[idx].to_string());
            idx += 1;
        }

        // Skip empty line after statement
        if idx < lines.len() && lines[idx].is_empty() {
            idx += 1;
        }

        // Parse fields
        let mut uri = String::new();
        let mut version = String::new();
        let mut chain_id = 0u64;
        let mut nonce = String::new();
        let mut issued_at = String::new();
        let mut expiration_time = None;
        let mut not_before = None;
        let mut request_id = None;
        let mut resources = Vec::new();
        let mut in_resources = false;

        while idx < lines.len() {
            let line = lines[idx];
            if in_resources {
                if let Some(r) = line.strip_prefix("- ") {
                    resources.push(r.to_string());
                }
            } else if let Some(v) = line.strip_prefix("URI: ") {
                uri = v.to_string();
            } else if let Some(v) = line.strip_prefix("Version: ") {
                version = v.to_string();
            } else if let Some(v) = line.strip_prefix("Chain ID: ") {
                chain_id = v
                    .parse::<u64>()
                    .map_err(|_| SignerError::ParseError("invalid chain ID".into()))?;
            } else if let Some(v) = line.strip_prefix("Nonce: ") {
                nonce = v.to_string();
            } else if let Some(v) = line.strip_prefix("Issued At: ") {
                issued_at = v.to_string();
            } else if let Some(v) = line.strip_prefix("Expiration Time: ") {
                expiration_time = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("Not Before: ") {
                not_before = Some(v.to_string());
            } else if let Some(v) = line.strip_prefix("Request ID: ") {
                request_id = Some(v.to_string());
            } else if line == "Resources:" {
                in_resources = true;
            }
            idx += 1;
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
