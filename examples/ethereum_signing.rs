//! # Ethereum Signing Example
//!
//! Demonstrates key generation, signing, verification,
//! address derivation, and EIP-712 typed data signing.

use chains_sdk::ethereum::{eip712_hash, Eip712Domain, EthereumSigner, EthereumVerifier};
use chains_sdk::traits::{KeyPair, Signer, Verifier};
use sha3::{Digest, Keccak256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ─── Key Generation ──────────────────────────────────────────────
    let signer = EthereumSigner::generate()?;
    println!(
        "Address:                0x{}",
        hex::encode(signer.address())
    );
    println!(
        "Compressed pubkey:      {} bytes",
        signer.public_key_bytes().len()
    );
    println!(
        "Uncompressed pubkey:    {} bytes",
        signer.public_key_bytes_uncompressed().len()
    );
    println!(
        "Private key:            {} bytes (zeroized on drop)",
        signer.private_key_bytes().len()
    );

    // ─── Sign & Verify ───────────────────────────────────────────────
    let message = b"Hello from chains-sdk!";
    let sig = signer.sign(message)?;
    println!("\nSignature:");
    println!("  r: {}", hex::encode(sig.r));
    println!("  s: {}", hex::encode(sig.s));
    println!("  v: {}", sig.v);

    let verifier = EthereumVerifier::from_public_key_bytes(&signer.public_key_bytes())?;
    let valid = verifier.verify(message, &sig)?;
    println!("  Valid: {}", valid);

    // ─── EIP-712 Typed Data ──────────────────────────────────────────
    let contract_addr: [u8; 20] = [0xCC; 20];
    let domain = Eip712Domain {
        name: "ExampleDapp",
        version: "1",
        chain_id: 1,
        verifying_contract: &contract_addr,
    };
    let domain_sep = domain.separator();

    // Simulate a Permit struct hash
    let mut struct_hash = [0u8; 32];
    struct_hash.copy_from_slice(&Keccak256::digest(b"example struct data"));

    let typed_sig = signer.sign_typed_data(&domain_sep, &struct_hash)?;
    let valid = verifier.verify_typed_data(&domain_sep, &struct_hash, &typed_sig)?;
    println!("\nEIP-712 signature valid: {}", valid);

    // Show the full signing hash
    let full_hash = eip712_hash(&domain_sep, &struct_hash);
    println!("EIP-712 hash: 0x{}", hex::encode(full_hash));

    Ok(())
}
