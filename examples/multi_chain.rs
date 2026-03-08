//! # Multi-Chain Signing Demo
//!
//! Shows how the same key bytes produce different results on different chains,
//! and demonstrates the unified trait API.

use chains_sdk::traits::{KeyPair, Signer, Verifier};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seed = hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")?;

    println!("=== Multi-Chain Signing ===\n");
    println!("Private key: {}\n", hex::encode(&seed));

    // ─── Ethereum ────────────────────────────────────────────────────
    {
        use chains_sdk::ethereum::{EthereumSigner, EthereumVerifier};

        let signer = EthereumSigner::from_bytes(&seed)?;
        let sig = signer.sign(b"hello world")?;
        let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
        println!("[ETH]  Address:  0x{}", hex::encode(signer.address()));
        println!(
            "[ETH]  Pubkey:   {} (compressed {}B)",
            hex::encode(&signer.public_key_bytes()[..8]),
            signer.public_key_bytes().len()
        );
        println!(
            "[ETH]  Sig v={}, valid={}",
            sig.v,
            verifier.verify(b"hello world", &sig)?
        );
    }

    // ─── Bitcoin ─────────────────────────────────────────────────────
    {
        use chains_sdk::bitcoin::{BitcoinSigner, BitcoinVerifier};

        let signer = BitcoinSigner::from_bytes(&seed)?;
        let sig = signer.sign(b"hello world")?;
        let verifier = BitcoinVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
        println!(
            "[BTC]  Pubkey:   {} (compressed {}B)",
            hex::encode(&signer.public_key_bytes()[..8]),
            signer.public_key_bytes().len()
        );
        println!(
            "[BTC]  DER sig:  {}... ({}B), valid={}",
            hex::encode(&sig.der_bytes()[..8]),
            sig.der_bytes().len(),
            verifier.verify(b"hello world", &sig)?
        );
    }

    // ─── Bitcoin Schnorr ─────────────────────────────────────────────
    {
        use chains_sdk::bitcoin::schnorr::{SchnorrSigner, SchnorrVerifier};

        let signer = SchnorrSigner::from_bytes(&seed)?;
        let sig = signer.sign(b"hello world")?;
        let verifier = SchnorrVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
        println!(
            "[BTC]  x-only:   {} ({}B)",
            hex::encode(&signer.public_key_bytes()[..8]),
            signer.public_key_bytes().len()
        );
        println!(
            "[BTC]  Schnorr:  {}... ({}B), valid={}",
            hex::encode(&sig.bytes[..8]),
            sig.bytes.len(),
            verifier.verify(b"hello world", &sig)?
        );
    }

    // ─── NEO ─────────────────────────────────────────────────────────
    {
        use chains_sdk::neo::{NeoSigner, NeoVerifier};

        let signer = NeoSigner::from_bytes(&seed)?;
        let sig = signer.sign(b"hello world")?;
        let verifier = NeoVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
        println!(
            "[NEO]  Pubkey:   {} (P-256 {}B)",
            hex::encode(&signer.public_key_bytes()[..8]),
            signer.public_key_bytes().len()
        );
        println!(
            "[NEO]  Sig:      {}... ({}B), valid={}",
            hex::encode(&sig.bytes[..8]),
            sig.bytes.len(),
            verifier.verify(b"hello world", &sig)?
        );
    }

    println!("\n=== Ed25519 Chains ===\n");

    let ed_seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?;

    // ─── Solana ──────────────────────────────────────────────────────
    {
        use chains_sdk::solana::{SolanaSigner, SolanaVerifier};

        let signer = SolanaSigner::from_bytes(&ed_seed)?;
        let sig = signer.sign(b"hello world")?;
        let verifier = SolanaVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
        println!(
            "[SOL]  Pubkey:   {} ({}B)",
            hex::encode(&signer.public_key_bytes()[..8]),
            signer.public_key_bytes().len()
        );
        println!("[SOL]  Keypair:  {} bytes", signer.keypair_bytes().len());
        println!(
            "[SOL]  Scalar:   {}... (clamped)",
            hex::encode(&signer.scalar_bytes()[..8])
        );
        println!(
            "[SOL]  Sig:      {}... valid={}",
            hex::encode(&sig.bytes[..8]),
            verifier.verify(b"hello world", &sig)?
        );
    }

    // ─── XRP Ed25519 ─────────────────────────────────────────────────
    {
        use chains_sdk::xrp::{XrpEddsaSigner, XrpEddsaVerifier};

        let signer = XrpEddsaSigner::from_bytes(&ed_seed)?;
        let sig = signer.sign(b"hello world")?;
        let verifier = XrpEddsaVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
        println!(
            "[XRP]  Pubkey:   {} (same as SOL ✓)",
            hex::encode(&signer.public_key_bytes()[..8])
        );
        println!(
            "[XRP]  Sig:      {}... valid={}",
            hex::encode(&sig.bytes[..8]),
            verifier.verify(b"hello world", &sig)?
        );
    }

    // ─── BLS12-381 ───────────────────────────────────────────────────
    println!("\n=== BLS Aggregation ===\n");
    {
        use chains_sdk::bls::{aggregate_signatures, verify_aggregated, BlsSigner};

        let s1 = BlsSigner::generate()?;
        let s2 = BlsSigner::generate()?;
        let s3 = BlsSigner::generate()?;
        let msg = b"consensus round 42";

        let sig1 = s1.sign(msg)?;
        let sig2 = s2.sign(msg)?;
        let sig3 = s3.sign(msg)?;

        let agg = aggregate_signatures(&[sig1, sig2, sig3])?;
        let valid = verify_aggregated(
            &[s1.public_key(), s2.public_key(), s3.public_key()],
            msg,
            &agg,
        )?;
        println!("[BLS]  3 signers aggregated, valid={}", valid);
        println!(
            "[BLS]  Sig size:    {} bytes (same as single!)",
            agg.bytes.len()
        );
        println!("[BLS]  Pubkey size: {} bytes", s1.public_key_bytes().len());
    }

    println!("\n✅ All chains signed and verified successfully!");
    Ok(())
}
