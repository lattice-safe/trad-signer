//! SDK serialization tests — validates all to_bytes/from_bytes,
//! compressed/uncompressed pubkeys, keypair import/export, and scalar export.

#[cfg(feature = "ethereum")]
mod eth_serde {
    use trad_signer::ethereum::{EthereumSigner, EthereumVerifier, EthereumSignature};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_uncompressed_pubkey_65_bytes() {
        let signer = EthereumSigner::generate().unwrap();
        let unc = signer.public_key_bytes_uncompressed();
        assert_eq!(unc.len(), 65);
        assert_eq!(unc[0], 0x04); // uncompressed prefix
    }

    #[test]
    fn test_verifier_accepts_uncompressed() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"test").unwrap();
        // Create verifier from uncompressed key
        let verifier = EthereumVerifier::from_public_key_bytes(
            &signer.public_key_bytes_uncompressed(),
        ).unwrap();
        assert!(verifier.verify(b"test", &sig).unwrap());
    }

    #[test]
    fn test_sig_bytes_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = EthereumSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.r, restored.r);
        assert_eq!(sig.s, restored.s);
        assert_eq!(sig.v, restored.v);
    }

    #[test]
    fn test_sig_from_bytes_invalid() {
        assert!(EthereumSignature::from_bytes(&[0u8; 10]).is_err());
        assert!(EthereumSignature::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_keypair_bytes_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let kp = signer.keypair_bytes();
        assert!(kp.len() >= 64); // 32B priv + 33B pub
        let restored = EthereumSigner::from_keypair_bytes(&kp).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }
}

#[cfg(feature = "bitcoin")]
mod btc_serde {
    use trad_signer::bitcoin::{BitcoinSigner, BitcoinVerifier, BitcoinSignature};
    use trad_signer::bitcoin::schnorr::{SchnorrSigner, SchnorrSignature};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_uncompressed_pubkey_65_bytes() {
        let signer = BitcoinSigner::generate().unwrap();
        let unc = signer.public_key_bytes_uncompressed();
        assert_eq!(unc.len(), 65);
        assert_eq!(unc[0], 0x04);
    }

    #[test]
    fn test_verifier_accepts_uncompressed() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign(b"test").unwrap();
        let verifier = BitcoinVerifier::from_public_key_bytes(
            &signer.public_key_bytes_uncompressed(),
        ).unwrap();
        assert!(verifier.verify(b"test", &sig).unwrap());
    }

    #[test]
    fn test_der_sig_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign(b"der roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = BitcoinSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.der_bytes(), restored.der_bytes());
    }

    #[test]
    fn test_der_sig_invalid() {
        assert!(BitcoinSignature::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_schnorr_sig_roundtrip() {
        let signer = SchnorrSigner::generate().unwrap();
        let sig = signer.sign(b"schnorr roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = SchnorrSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }

    #[test]
    fn test_schnorr_sig_invalid_length() {
        assert!(SchnorrSignature::from_bytes(&[0u8; 32]).is_err());
    }
}

#[cfg(feature = "neo")]
mod neo_serde {
    use trad_signer::neo::{NeoSigner, NeoVerifier, NeoSignature};
    use trad_signer::traits::{KeyPair, Signer, Verifier};

    #[test]
    fn test_uncompressed_pubkey_65_bytes() {
        let signer = NeoSigner::generate().unwrap();
        let unc = signer.public_key_bytes_uncompressed();
        assert_eq!(unc.len(), 65);
        assert_eq!(unc[0], 0x04);
    }

    #[test]
    fn test_verifier_accepts_uncompressed() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"test").unwrap();
        let verifier = NeoVerifier::from_public_key_bytes(
            &signer.public_key_bytes_uncompressed(),
        ).unwrap();
        assert!(verifier.verify(b"test", &sig).unwrap());
    }

    #[test]
    fn test_sig_roundtrip() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"neo roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = NeoSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }
}

#[cfg(feature = "solana")]
mod solana_serde {
    use trad_signer::solana::{SolanaSigner, SolanaSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_keypair_64_roundtrip() {
        let signer = SolanaSigner::generate().unwrap();
        let kp = signer.keypair_bytes();
        assert_eq!(kp.len(), 64);
        let restored = SolanaSigner::from_keypair_bytes(&kp).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_keypair_invalid_pubkey_rejected() {
        let signer = SolanaSigner::generate().unwrap();
        let mut kp = signer.keypair_bytes().to_vec();
        // Corrupt the pubkey portion
        kp[63] ^= 0xFF;
        assert!(SolanaSigner::from_keypair_bytes(&kp).is_err());
    }

    #[test]
    fn test_keypair_wrong_length_rejected() {
        assert!(SolanaSigner::from_keypair_bytes(&[0u8; 32]).is_err());
        assert!(SolanaSigner::from_keypair_bytes(&[0u8; 128]).is_err());
    }

    #[test]
    fn test_scalar_export() {
        let signer = SolanaSigner::generate().unwrap();
        let scalar = signer.scalar_bytes();
        assert_eq!(scalar.len(), 32);
        // Ed25519 clamping: bit 0,1,2 of first byte cleared, bit 254 set, bit 255 cleared
        assert_eq!(scalar[0] & 0x07, 0); // low 3 bits cleared
        assert_eq!(scalar[31] & 0x80, 0); // bit 255 cleared
        assert_ne!(scalar[31] & 0x40, 0); // bit 254 set
    }

    #[test]
    fn test_scalar_deterministic() {
        let seed = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ).unwrap();
        let s1 = SolanaSigner::from_bytes(&seed).unwrap();
        let s2 = SolanaSigner::from_bytes(&seed).unwrap();
        assert_eq!(s1.scalar_bytes().to_vec(), s2.scalar_bytes().to_vec());
    }

    #[test]
    fn test_sig_roundtrip() {
        let signer = SolanaSigner::generate().unwrap();
        let sig = signer.sign(b"solana roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = SolanaSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }

    #[test]
    fn test_pubkey_is_32_compressed_and_uncompressed() {
        let signer = SolanaSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes().len(), 32);
        assert_eq!(signer.public_key_bytes_uncompressed().len(), 32);
        assert_eq!(signer.public_key_bytes(), signer.public_key_bytes_uncompressed());
    }
}

#[cfg(feature = "xrp")]
mod xrp_serde {
    use trad_signer::xrp::{XrpEcdsaSigner, XrpEddsaSigner, XrpSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_ecdsa_uncompressed_65() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let unc = signer.public_key_bytes_uncompressed();
        assert_eq!(unc.len(), 65);
        assert_eq!(unc[0], 0x04);
    }

    #[test]
    fn test_eddsa_pubkey_same() {
        let signer = XrpEddsaSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes(), signer.public_key_bytes_uncompressed());
    }

    #[test]
    fn test_sig_roundtrip() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let sig = signer.sign(b"xrp roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = XrpSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }

    #[test]
    fn test_sig_empty_rejected() {
        assert!(XrpSignature::from_bytes(&[]).is_err());
    }
}

#[cfg(feature = "bls")]
mod bls_serde {
    use trad_signer::bls::{BlsSigner, BlsSignature, BlsPublicKey};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_sig_96_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let sig = signer.sign(b"bls roundtrip").unwrap();
        let bytes = sig.to_bytes();
        let restored = BlsSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }

    #[test]
    fn test_sig_invalid_length() {
        assert!(BlsSignature::from_bytes(&[0u8; 48]).is_err());
    }

    #[test]
    fn test_pubkey_48_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let pk = signer.public_key();
        let bytes = pk.to_bytes();
        let restored = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.bytes, restored.bytes);
    }

    #[test]
    fn test_pubkey_invalid_length() {
        assert!(BlsPublicKey::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_pubkey_same_compressed_uncompressed() {
        let signer = BlsSigner::generate().unwrap();
        assert_eq!(signer.public_key_bytes(), signer.public_key_bytes_uncompressed());
    }
}

// ─── JSON Serde Round-Trip Tests ─────────────────────────────────

#[cfg(all(feature = "serde", feature = "ethereum"))]
mod json_eth {
    use trad_signer::ethereum::{EthereumSigner, EthereumSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_ethereum_sig_json_roundtrip() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: EthereumSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.r, restored.r);
        assert_eq!(sig.s, restored.s);
        assert_eq!(sig.v, restored.v);
    }
}

#[cfg(all(feature = "serde", feature = "bitcoin"))]
mod json_btc {
    use trad_signer::bitcoin::{BitcoinSigner, BitcoinSignature};
    use trad_signer::bitcoin::schnorr::{SchnorrSigner, SchnorrSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_bitcoin_sig_json_roundtrip() {
        let signer = BitcoinSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: BitcoinSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.der_bytes(), restored.der_bytes());
    }

    #[test]
    fn test_schnorr_sig_json_roundtrip() {
        let signer = SchnorrSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("bytes")); // hex-encoded string
        let restored: SchnorrSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }
}

#[cfg(all(feature = "serde", feature = "solana"))]
mod json_sol {
    use trad_signer::solana::{SolanaSigner, SolanaSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_solana_sig_json_roundtrip() {
        let signer = SolanaSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: SolanaSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }
}

#[cfg(all(feature = "serde", feature = "neo"))]
mod json_neo {
    use trad_signer::neo::{NeoSigner, NeoSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_neo_sig_json_roundtrip() {
        let signer = NeoSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: NeoSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }
}

#[cfg(all(feature = "serde", feature = "xrp"))]
mod json_xrp {
    use trad_signer::xrp::{XrpEcdsaSigner, XrpSignature};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_xrp_sig_json_roundtrip() {
        let signer = XrpEcdsaSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: XrpSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }
}

#[cfg(all(feature = "serde", feature = "bls"))]
mod json_bls {
    use trad_signer::bls::{BlsSigner, BlsSignature, BlsPublicKey};
    use trad_signer::traits::{KeyPair, Signer};

    #[test]
    fn test_bls_sig_json_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let sig = signer.sign(b"json test").unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: BlsSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.bytes, restored.bytes);
    }

    #[test]
    fn test_bls_pubkey_json_roundtrip() {
        let signer = BlsSigner::generate().unwrap();
        let pk = signer.public_key();
        let json = serde_json::to_string(&pk).unwrap();
        let restored: BlsPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk.bytes, restored.bytes);
    }
}
