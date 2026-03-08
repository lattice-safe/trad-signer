//! chains-sdk CLI — key generation, signing, and verification.
//!
//! Usage:
//!   chains-sdk keygen <chain>
//!   chains-sdk sign <chain> <hex-key> <message>
//!   chains-sdk verify <chain> <hex-pubkey> <hex-signature> <message>
//!   chains-sdk address <chain> <hex-key>

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage();
        process::exit(1);
    }

    let command = args[1].as_str();
    let chain = args[2].as_str();

    match command {
        "keygen" => cmd_keygen(chain),
        "sign" => {
            if args.len() < 5 {
                eprintln!("Usage: chains-sdk sign <chain> <hex-key> <message>");
                process::exit(1);
            }
            cmd_sign(chain, &args[3], &args[4]);
        }
        "verify" => {
            if args.len() < 6 {
                eprintln!("Usage: chains-sdk verify <chain> <hex-pubkey> <hex-sig> <message>");
                process::exit(1);
            }
            cmd_verify(chain, &args[3], &args[4], &args[5]);
        }
        "address" => {
            if args.len() < 4 {
                eprintln!("Usage: chains-sdk address <chain> <hex-key>");
                process::exit(1);
            }
            cmd_address(chain, &args[3]);
        }
        _ => {
            eprintln!("Unknown command: {command}");
            print_usage();
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("chains-sdk CLI v{}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  keygen  <chain>                          Generate a new key pair");
    eprintln!("  sign    <chain> <hex-key> <message>      Sign a message");
    eprintln!("  verify  <chain> <hex-pubkey> <hex-sig> <message>  Verify");
    eprintln!("  address <chain> <hex-key>                Derive address");
    eprintln!();
    eprintln!("Chains: ethereum, bitcoin, solana, xrp, neo, bls");
}

#[allow(unused_variables)]
fn cmd_keygen(chain: &str) {
    match chain {
        #[cfg(feature = "ethereum")]
        "ethereum" | "eth" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::ethereum::EthereumSigner::generate().expect("keygen failed");
            let pk = hex::encode(Signer::public_key_bytes(&signer));
            let sk = hex::encode(&*signer.private_key_bytes());
            println!("private_key: {sk}");
            println!("public_key:  {pk}");
            println!("address:     {}", signer.address_checksum());
        }
        #[cfg(feature = "bitcoin")]
        "bitcoin" | "btc" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::bitcoin::BitcoinSigner::generate().expect("keygen failed");
            let pk = hex::encode(Signer::public_key_bytes(&signer));
            let sk = hex::encode(&*signer.private_key_bytes());
            let wif = signer.to_wif();
            println!("private_key: {sk}");
            println!("public_key:  {pk}");
            println!("wif:         {}", &*wif);
            println!("p2pkh:       {}", signer.p2pkh_address());
            if let Ok(addr) = signer.p2wpkh_address() {
                println!("p2wpkh:      {addr}");
            }
        }
        #[cfg(feature = "solana")]
        "solana" | "sol" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::solana::SolanaSigner::generate().expect("keygen failed");
            let pk = hex::encode(Signer::public_key_bytes(&signer));
            let sk = hex::encode(&*signer.private_key_bytes());
            println!("private_key: {sk}");
            println!("public_key:  {pk}");
            println!("address:     {}", signer.address());
        }
        #[cfg(feature = "xrp")]
        "xrp" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::xrp::XrpEcdsaSigner::generate().expect("keygen failed");
            let pk = hex::encode(Signer::public_key_bytes(&signer));
            let sk = hex::encode(&*signer.private_key_bytes());
            println!("private_key: {sk}");
            println!("public_key:  {pk}");
            if let Ok(addr) = signer.address() {
                println!("address:     {addr}");
            }
        }
        #[cfg(feature = "neo")]
        "neo" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::neo::NeoSigner::generate().expect("keygen failed");
            let pk = hex::encode(Signer::public_key_bytes(&signer));
            let sk = hex::encode(&*signer.private_key_bytes());
            println!("private_key: {sk}");
            println!("public_key:  {pk}");
            println!("address:     {}", signer.address());
        }
        #[cfg(feature = "bls")]
        "bls" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::bls::BlsSigner::generate().expect("keygen failed");
            let pk = hex::encode(Signer::public_key_bytes(&signer));
            let sk = hex::encode(&*signer.private_key_bytes());
            println!("private_key: {sk}");
            println!("public_key:  {pk}");
        }
        _ => {
            eprintln!("Unknown or disabled chain: {chain}");
            eprintln!("Supported: ethereum, bitcoin, solana, xrp, neo, bls");
            process::exit(1);
        }
    }
}

#[allow(unused_variables)]
fn cmd_sign(chain: &str, hex_key: &str, message: &str) {
    let key_bytes = hex::decode(hex_key).expect("invalid hex key");
    let msg = message.as_bytes();

    match chain {
        #[cfg(feature = "ethereum")]
        "ethereum" | "eth" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer =
                chains_sdk::ethereum::EthereumSigner::from_bytes(&key_bytes).expect("invalid key");
            let sig = signer.sign(msg).expect("sign failed");
            println!("r: {}", hex::encode(sig.r));
            println!("s: {}", hex::encode(sig.s));
            println!("v: {}", sig.v);
        }
        #[cfg(feature = "bitcoin")]
        "bitcoin" | "btc" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer =
                chains_sdk::bitcoin::BitcoinSigner::from_bytes(&key_bytes).expect("invalid key");
            let sig = signer.sign(msg).expect("sign failed");
            println!("signature: {}", hex::encode(sig.to_bytes()));
        }
        #[cfg(feature = "solana")]
        "solana" | "sol" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer =
                chains_sdk::solana::SolanaSigner::from_bytes(&key_bytes).expect("invalid key");
            let sig = signer.sign(msg).expect("sign failed");
            println!("signature: {}", hex::encode(sig.to_bytes()));
        }
        #[cfg(feature = "bls")]
        "bls" => {
            use chains_sdk::traits::{KeyPair, Signer};
            let signer = chains_sdk::bls::BlsSigner::from_bytes(&key_bytes).expect("invalid key");
            let sig = signer.sign(msg).expect("sign failed");
            println!("signature: {}", hex::encode(sig.to_bytes()));
        }
        _ => {
            eprintln!("Signing not supported or disabled for chain: {chain}");
            process::exit(1);
        }
    }
}

#[allow(unused_variables)]
fn cmd_verify(chain: &str, hex_pubkey: &str, hex_sig: &str, message: &str) {
    let pk_bytes = hex::decode(hex_pubkey).expect("invalid hex pubkey");
    let sig_bytes = hex::decode(hex_sig).expect("invalid hex signature");
    let msg = message.as_bytes();

    match chain {
        #[cfg(feature = "solana")]
        "solana" | "sol" => {
            use chains_sdk::traits::Verifier;
            let verifier = chains_sdk::solana::SolanaVerifier::from_public_key_bytes(&pk_bytes)
                .expect("invalid pubkey");
            let sig =
                chains_sdk::solana::SolanaSignature::from_bytes(&sig_bytes).expect("invalid sig");
            match verifier.verify(msg, &sig) {
                Ok(true) => println!("✓ valid"),
                _ => println!("✗ invalid"),
            }
        }
        #[cfg(feature = "bls")]
        "bls" => {
            use chains_sdk::traits::Verifier;
            let verifier = chains_sdk::bls::BlsVerifier::from_public_key_bytes(&pk_bytes)
                .expect("invalid pubkey");
            let sig = chains_sdk::bls::BlsSignature::from_bytes(&sig_bytes).expect("invalid sig");
            match verifier.verify(msg, &sig) {
                Ok(true) => println!("✓ valid"),
                _ => println!("✗ invalid"),
            }
        }
        _ => {
            eprintln!("Verification not supported or disabled for chain: {chain}");
            process::exit(1);
        }
    }
}

#[allow(unused_variables)]
fn cmd_address(chain: &str, hex_key: &str) {
    let key_bytes = hex::decode(hex_key).expect("invalid hex key");

    match chain {
        #[cfg(feature = "ethereum")]
        "ethereum" | "eth" => {
            use chains_sdk::traits::KeyPair;
            let signer =
                chains_sdk::ethereum::EthereumSigner::from_bytes(&key_bytes).expect("invalid key");
            println!("{}", signer.address_checksum());
        }
        #[cfg(feature = "bitcoin")]
        "bitcoin" | "btc" => {
            use chains_sdk::traits::KeyPair;
            let signer =
                chains_sdk::bitcoin::BitcoinSigner::from_bytes(&key_bytes).expect("invalid key");
            println!("p2pkh:  {}", signer.p2pkh_address());
            if let Ok(addr) = signer.p2wpkh_address() {
                println!("p2wpkh: {addr}");
            }
        }
        #[cfg(feature = "solana")]
        "solana" | "sol" => {
            use chains_sdk::traits::KeyPair;
            let signer =
                chains_sdk::solana::SolanaSigner::from_bytes(&key_bytes).expect("invalid key");
            println!("{}", signer.address());
        }
        #[cfg(feature = "neo")]
        "neo" => {
            use chains_sdk::traits::KeyPair;
            let signer = chains_sdk::neo::NeoSigner::from_bytes(&key_bytes).expect("invalid key");
            println!("{}", signer.address());
        }
        _ => {
            eprintln!("Address derivation not supported or disabled for chain: {chain}");
            process::exit(1);
        }
    }
}
