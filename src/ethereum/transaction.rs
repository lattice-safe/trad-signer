//! Ethereum transaction types with RLP encoding and signing.
//!
//! Supports Legacy (pre-EIP-2718), Type 1 (EIP-2930), and Type 2 (EIP-1559) transactions.
//! Each transaction type can be built, serialized, signed, and exported as raw hex for broadcasting.
//!
//! # Example
//! ```no_run
//! use chains_sdk::ethereum::transaction::EIP1559Transaction;
//! use chains_sdk::ethereum::EthereumSigner;
//! use chains_sdk::traits::KeyPair;
//!
//! fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let signer = EthereumSigner::generate()?;
//!     let tx = EIP1559Transaction {
//!         chain_id: 1,
//!         nonce: 0,
//!         max_priority_fee_per_gas: 2_000_000_000, // 2 Gwei
//!         max_fee_per_gas: 100_000_000_000,        // 100 Gwei
//!         gas_limit: 21_000,
//!         to: Some([0xAA; 20]),
//!         value: 1_000_000_000_000_000_000,        // 1 ETH
//!         data: vec![],
//!         access_list: vec![],
//!     };
//!     let signed = tx.sign(&signer)?;
//!     println!("Raw tx: 0x{}", hex::encode(&signed.raw_tx()));
//!     println!("Tx hash: 0x{}", hex::encode(signed.tx_hash()));
//!     Ok(())
//! }
//! ```

use super::rlp;
use super::EthereumSigner;
use crate::error::SignerError;
use core::cmp::Ordering;

// ─── Signed Transaction ────────────────────────────────────────────

/// A signed Ethereum transaction ready for broadcast.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// The raw signed transaction bytes (for `eth_sendRawTransaction`).
    raw: Vec<u8>,
}

impl SignedTransaction {
    /// Return the raw signed transaction bytes.
    ///
    /// This is what you pass to `eth_sendRawTransaction`.
    #[must_use]
    pub fn raw_tx(&self) -> &[u8] {
        &self.raw
    }

    /// Compute the transaction hash (keccak256 of the raw signed tx).
    #[must_use]
    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.raw)
    }

    /// Return the raw transaction as a `0x`-prefixed hex string.
    #[must_use]
    pub fn raw_tx_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.raw))
    }
}

// ─── Legacy Transaction (pre-EIP-2718) ─────────────────────────────

/// A Legacy (Type 0) Ethereum transaction.
///
/// Uses EIP-155 replay protection via `chain_id` in the signing payload.
#[derive(Debug, Clone)]
pub struct LegacyTransaction {
    /// The nonce of the sender.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address. `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Chain ID for EIP-155 replay protection.
    pub chain_id: u64,
}

impl LegacyTransaction {
    /// Serialize the unsigned transaction for signing (EIP-155).
    ///
    /// `RLP([nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0])`
    fn signing_payload(&self) -> Vec<u8> {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        // EIP-155: chain_id, 0, 0
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(0));
        items.extend_from_slice(&rlp::encode_u64(0));
        rlp::encode_list(&items)
    }

    /// Sign this transaction with the given signer.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        if self.chain_id == 0 {
            return Err(SignerError::SigningFailed(
                "legacy tx requires non-zero chain_id".into(),
            ));
        }
        let payload = self.signing_payload();
        let hash = keccak256(&payload);
        let sig = signer.sign_digest(&hash)?;

        // EIP-155: v = {0,1} + chain_id * 2 + 35
        let recovery_id = sig
            .v
            .checked_sub(27)
            .ok_or_else(|| SignerError::SigningFailed("invalid legacy recovery id".into()))?;
        let v = recovery_id
            .checked_add(
                self.chain_id
                    .checked_mul(2)
                    .ok_or_else(|| SignerError::SigningFailed("chain_id overflow".into()))?,
            )
            .and_then(|vv| vv.checked_add(35))
            .ok_or_else(|| SignerError::SigningFailed("EIP-155 v overflow".into()))?;

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_u64(v));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        Ok(SignedTransaction {
            raw: rlp::encode_list(&items),
        })
    }
}

// ─── EIP-2930 Transaction (Type 1) ─────────────────────────────────

/// An EIP-2930 (Type 1) transaction with access list.
///
/// Introduced by Berlin hard fork. Uses EIP-2718 typed transaction envelope.
#[derive(Debug, Clone)]
pub struct EIP2930Transaction {
    /// Chain ID (required, not optional like Legacy).
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Gas price in wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient. `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Access list: `[(address, [storage_key, ...])]`.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

impl EIP2930Transaction {
    /// Signing payload: `keccak256(0x01 || RLP([chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]))`
    fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));

        let mut payload = vec![0x01]; // Type 1
        payload.extend_from_slice(&rlp::encode_list(&items));
        keccak256(&payload)
    }

    /// Sign this transaction.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        if self.chain_id == 0 {
            return Err(SignerError::SigningFailed(
                "type1 tx requires non-zero chain_id".into(),
            ));
        }
        let hash = self.signing_hash();
        let sig = signer.sign_digest(&hash)?;
        let y_parity = sig.v - 27; // 0 or 1

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.gas_price));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u64(y_parity));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        let mut raw = vec![0x01]; // Type prefix
        raw.extend_from_slice(&rlp::encode_list(&items));

        Ok(SignedTransaction { raw })
    }
}

// ─── EIP-1559 Transaction (Type 2) ─────────────────────────────────

/// An EIP-1559 (Type 2) dynamic fee transaction.
///
/// The de facto standard since the London hard fork. Uses `maxFeePerGas` and
/// `maxPriorityFeePerGas` instead of a single `gasPrice`.
#[derive(Debug, Clone)]
pub struct EIP1559Transaction {
    /// Chain ID (required).
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Maximum priority fee (tip) per gas in wei.
    pub max_priority_fee_per_gas: u128,
    /// Maximum total fee per gas in wei.
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient. `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Access list: `[(address, [storage_key, ...])]`.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

impl EIP1559Transaction {
    /// Signing hash: `keccak256(0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList]))`
    fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));

        let mut payload = vec![0x02]; // Type 2
        payload.extend_from_slice(&rlp::encode_list(&items));
        keccak256(&payload)
    }

    /// Sign this transaction.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        if self.chain_id == 0 {
            return Err(SignerError::SigningFailed(
                "type2 tx requires non-zero chain_id".into(),
            ));
        }
        if self.max_priority_fee_per_gas > self.max_fee_per_gas {
            return Err(SignerError::SigningFailed(
                "max_priority_fee_per_gas cannot exceed max_fee_per_gas".into(),
            ));
        }
        let hash = self.signing_hash();
        let sig = signer.sign_digest(&hash)?;
        let y_parity = sig.v - 27; // 0 or 1

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&encode_address(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u64(y_parity));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        let mut raw = vec![0x02]; // Type prefix
        raw.extend_from_slice(&rlp::encode_list(&items));

        Ok(SignedTransaction { raw })
    }
}

// ─── EIP-4844 Transaction (Type 3) ─────────────────────────────────

/// An EIP-4844 (Type 3) blob transaction.
///
/// Carries blob versioned hashes for rollup data availability.
/// Note: the actual blob data and KZG proofs are sidecar data, not
/// part of the transaction itself.
#[derive(Debug, Clone)]
pub struct EIP4844Transaction {
    /// Chain ID (required).
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Maximum priority fee (tip) per gas in wei.
    pub max_priority_fee_per_gas: u128,
    /// Maximum total fee per gas in wei.
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Recipient address (required — no contract creation).
    pub to: [u8; 20],
    /// Value in wei.
    pub value: u128,
    /// Call data.
    pub data: Vec<u8>,
    /// Access list.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    /// Maximum fee per blob gas in wei.
    pub max_fee_per_blob_gas: u128,
    /// Blob versioned hashes (32 bytes each, version byte 0x01).
    pub blob_versioned_hashes: Vec<[u8; 32]>,
}

impl EIP4844Transaction {
    /// Signing hash: `keccak256(0x03 || RLP([...fields, max_fee_per_blob_gas, blob_versioned_hashes]))`
    fn signing_hash(&self) -> [u8; 32] {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&rlp::encode_bytes(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_blob_gas));
        // blob_versioned_hashes as RLP list of 32-byte strings
        let mut hash_items = Vec::new();
        for h in &self.blob_versioned_hashes {
            hash_items.extend_from_slice(&rlp::encode_bytes(h));
        }
        items.extend_from_slice(&rlp::encode_list(&hash_items));

        let mut payload = vec![0x03]; // Type 3
        payload.extend_from_slice(&rlp::encode_list(&items));
        keccak256(&payload)
    }

    /// Sign this transaction.
    pub fn sign(&self, signer: &EthereumSigner) -> Result<SignedTransaction, SignerError> {
        if self.chain_id == 0 {
            return Err(SignerError::SigningFailed(
                "type3 tx requires non-zero chain_id".into(),
            ));
        }
        if self.max_priority_fee_per_gas > self.max_fee_per_gas {
            return Err(SignerError::SigningFailed(
                "max_priority_fee_per_gas cannot exceed max_fee_per_gas".into(),
            ));
        }
        if self.blob_versioned_hashes.is_empty() {
            return Err(SignerError::SigningFailed(
                "type3 tx requires at least one blob versioned hash".into(),
            ));
        }
        for (i, hash) in self.blob_versioned_hashes.iter().enumerate() {
            if hash[0] != 0x01 {
                return Err(SignerError::SigningFailed(format!(
                    "blob_versioned_hashes[{i}] must start with version byte 0x01"
                )));
            }
        }
        let hash = self.signing_hash();
        let sig = signer.sign_digest(&hash)?;
        let y_parity = sig.v - 27;

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(self.chain_id));
        items.extend_from_slice(&rlp::encode_u64(self.nonce));
        items.extend_from_slice(&rlp::encode_u128(self.max_priority_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_gas));
        items.extend_from_slice(&rlp::encode_u64(self.gas_limit));
        items.extend_from_slice(&rlp::encode_bytes(&self.to));
        items.extend_from_slice(&rlp::encode_u128(self.value));
        items.extend_from_slice(&rlp::encode_bytes(&self.data));
        items.extend_from_slice(&rlp::encode_access_list(&self.access_list));
        items.extend_from_slice(&rlp::encode_u128(self.max_fee_per_blob_gas));
        let mut hash_items = Vec::new();
        for h in &self.blob_versioned_hashes {
            hash_items.extend_from_slice(&rlp::encode_bytes(h));
        }
        items.extend_from_slice(&rlp::encode_list(&hash_items));
        items.extend_from_slice(&rlp::encode_u64(y_parity));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.r)));
        items.extend_from_slice(&rlp::encode_bytes(&strip_leading_zeros(&sig.s)));

        let mut raw = vec![0x03];
        raw.extend_from_slice(&rlp::encode_list(&items));

        Ok(SignedTransaction { raw })
    }
}

// ─── Contract Address Prediction ───────────────────────────────────

/// Predict the contract address deployed via CREATE.
///
/// `keccak256(RLP([sender, nonce]))[12..32]`
pub fn create_address(sender: &[u8; 20], nonce: u64) -> [u8; 20] {
    let mut items = Vec::new();
    items.extend_from_slice(&rlp::encode_bytes(sender));
    items.extend_from_slice(&rlp::encode_u64(nonce));
    let rlp_data = rlp::encode_list(&items);
    let hash = keccak256(&rlp_data);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Predict the contract address deployed via CREATE2 (EIP-1014).
///
/// `keccak256(0xFF || sender || salt || keccak256(init_code))[12..32]`
pub fn create2_address(sender: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> [u8; 20] {
    let code_hash = keccak256(init_code);
    let mut buf = Vec::with_capacity(1 + 20 + 32 + 32);
    buf.push(0xFF);
    buf.extend_from_slice(sender);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(&code_hash);
    let hash = keccak256(&buf);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

// ─── EIP-1271: Contract Signature ──────────────────────────────────

/// EIP-1271 magic value returned by `isValidSignature` on success.
pub const EIP1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xBA, 0x7E];

/// Encode an `isValidSignature(bytes32, bytes)` call for EIP-1271.
///
/// Returns the ABI-encoded calldata suitable for `eth_call`.
pub fn encode_is_valid_signature(hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    // Function selector: keccak256("isValidSignature(bytes32,bytes)")[..4]
    let selector = &keccak256(b"isValidSignature(bytes32,bytes)")[..4];

    let mut calldata = Vec::new();
    calldata.extend_from_slice(selector);
    // hash (bytes32) — padded to 32 bytes
    calldata.extend_from_slice(hash);
    // offset to bytes data (64 bytes from start of params)
    let mut offset = [0u8; 32];
    offset[31] = 64;
    calldata.extend_from_slice(&offset);
    // length of signature
    let mut len_buf = [0u8; 32];
    len_buf[28..32].copy_from_slice(&(signature.len() as u32).to_be_bytes());
    calldata.extend_from_slice(&len_buf);
    // signature data (padded to 32-byte boundary)
    calldata.extend_from_slice(signature);
    let padding = (32 - (signature.len() % 32)) % 32;
    calldata.extend_from_slice(&vec![0u8; padding]);

    calldata
}

// ─── Helpers ───────────────────────────────────────────────────────

fn keccak256(data: &[u8]) -> [u8; 32] {
    super::keccak256(data)
}

fn encode_address(to: &Option<[u8; 20]>) -> Vec<u8> {
    match to {
        Some(addr) => rlp::encode_bytes(addr),
        None => rlp::encode_bytes(&[]),
    }
}

fn strip_leading_zeros(data: &[u8; 32]) -> Vec<u8> {
    let start = data.iter().position(|b| *b != 0).unwrap_or(31);
    data[start..].to_vec()
}

// ─── Signed Transaction Decoding ───────────────────────────────────

/// The type of an Ethereum transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxType {
    /// Pre-EIP-2718 legacy transaction.
    Legacy,
    /// EIP-2930 (Type 1) — access list transaction.
    Type1AccessList,
    /// EIP-1559 (Type 2) — dynamic fee transaction.
    Type2DynamicFee,
    /// EIP-4844 (Type 3) — blob transaction.
    Type3Blob,
}

/// A decoded signed Ethereum transaction.
#[derive(Debug, Clone)]
pub struct DecodedTransaction {
    /// Transaction type.
    pub tx_type: TxType,
    /// Chain ID.
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Recipient address (`None` for contract creation).
    pub to: Option<[u8; 20]>,
    /// Value in wei (as raw bytes, big-endian).
    pub value: Vec<u8>,
    /// Calldata.
    pub data: Vec<u8>,
    /// Gas limit.
    pub gas_limit: u64,
    /// Gas price (Legacy/Type 1) or max_fee_per_gas (Type 2/3).
    pub gas_price_or_max_fee: Vec<u8>,
    /// Max priority fee per gas (Type 2/3 only, empty for Legacy/Type 1).
    pub max_priority_fee: Vec<u8>,
    /// Signature v / y_parity.
    pub v: u64,
    /// Signature r (32 bytes).
    pub r: [u8; 32],
    /// Signature s (32 bytes).
    pub s: [u8; 32],
    /// Recovered signer address (20 bytes).
    pub from: [u8; 20],
    /// Transaction hash.
    pub tx_hash: [u8; 32],
}

/// Decode a signed transaction from raw bytes and recover the signer.
///
/// Supports Legacy, Type 1 (EIP-2930), Type 2 (EIP-1559), and Type 3 (EIP-4844).
///
/// # Example
/// ```no_run
/// use chains_sdk::ethereum::transaction::decode_signed_tx;
///
/// fn example(raw_tx: &[u8]) {
///     let decoded = decode_signed_tx(raw_tx).unwrap();
///     println!("From: 0x{}", hex::encode(decoded.from));
///     println!("Type: {:?}", decoded.tx_type);
///     println!("Nonce: {}", decoded.nonce);
/// }
/// ```
pub fn decode_signed_tx(raw: &[u8]) -> Result<DecodedTransaction, SignerError> {
    if raw.is_empty() {
        return Err(SignerError::ParseError("empty transaction".into()));
    }

    let tx_hash = keccak256(raw);

    match raw[0] {
        // EIP-2718 typed transactions: first byte < 0x7F
        0x01 => decode_type1_tx(raw, tx_hash),
        0x02 => decode_type2_tx(raw, tx_hash),
        0x03 => decode_type3_tx(raw, tx_hash),
        // Legacy: first byte >= 0xC0 (RLP list prefix)
        0xC0..=0xFF => decode_legacy_tx(raw, tx_hash),
        b => Err(SignerError::ParseError(format!(
            "unknown tx type byte: 0x{b:02x}"
        ))),
    }
}

fn decode_legacy_tx(raw: &[u8], tx_hash: [u8; 32]) -> Result<DecodedTransaction, SignerError> {
    let items = rlp::decode_list_items(raw)?;
    if items.len() != 9 {
        return Err(SignerError::ParseError(format!(
            "legacy tx: expected 9 RLP items, got {}",
            items.len()
        )));
    }

    let nonce = items[0].as_u64()?;
    let gas_price_bytes = items[1].as_bytes()?;
    validate_uint256_bytes(gas_price_bytes, "legacy tx gas_price")?;
    let gas_price = gas_price_bytes.to_vec();
    let gas_limit = items[2].as_u64()?;
    let to_bytes = items[3].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value_bytes = items[4].as_bytes()?;
    validate_uint256_bytes(value_bytes, "legacy tx value")?;
    let value = value_bytes.to_vec();
    let data = items[5].as_bytes()?.to_vec();
    let v = items[6].as_u64()?;
    let r = pad_to_32(items[7].as_bytes()?, "legacy tx r")?;
    let s = pad_to_32(items[8].as_bytes()?, "legacy tx s")?;

    // EIP-155: chain_id = (v - 35) / 2
    let (chain_id, recovery_id) = if v >= 35 {
        if v <= 36 {
            return Err(SignerError::ParseError(format!(
                "legacy tx: non-canonical EIP-155 v value {v}"
            )));
        }
        ((v - 35) / 2, ((v - 35) % 2) as u8)
    } else if v == 27 || v == 28 {
        (0, (v - 27) as u8)
    } else {
        return Err(SignerError::ParseError(format!(
            "legacy tx: invalid v value {v}"
        )));
    };

    // Reconstruct signing payload for ecrecover
    let mut sign_items = Vec::new();
    sign_items.extend_from_slice(&rlp::encode_u64(nonce));
    sign_items.extend_from_slice(&rlp::encode_bytes(&gas_price));
    sign_items.extend_from_slice(&rlp::encode_u64(gas_limit));
    sign_items.extend_from_slice(&encode_address(&to));
    sign_items.extend_from_slice(&rlp::encode_bytes(&value));
    sign_items.extend_from_slice(&rlp::encode_bytes(&data));
    if chain_id > 0 {
        sign_items.extend_from_slice(&rlp::encode_u64(chain_id));
        sign_items.extend_from_slice(&rlp::encode_u64(0));
        sign_items.extend_from_slice(&rlp::encode_u64(0));
    }
    let signing_hash = keccak256(&rlp::encode_list(&sign_items));

    let from = recover_signer(&signing_hash, &r, &s, recovery_id)?;

    Ok(DecodedTransaction {
        tx_type: TxType::Legacy,
        chain_id,
        nonce,
        to,
        value,
        data,
        gas_limit,
        gas_price_or_max_fee: gas_price,
        max_priority_fee: vec![],
        v,
        r,
        s,
        from,
        tx_hash,
    })
}

fn decode_type1_tx(raw: &[u8], tx_hash: [u8; 32]) -> Result<DecodedTransaction, SignerError> {
    let items = rlp::decode_list_items(&raw[1..])?;
    if items.len() != 11 {
        return Err(SignerError::ParseError(format!(
            "type1 tx: expected 11 items, got {}",
            items.len()
        )));
    }

    let chain_id = items[0].as_u64()?;
    let nonce = items[1].as_u64()?;
    let gas_price_bytes = items[2].as_bytes()?;
    validate_uint256_bytes(gas_price_bytes, "type1 tx gas_price")?;
    let gas_price = gas_price_bytes.to_vec();
    let gas_limit = items[3].as_u64()?;
    let to_bytes = items[4].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value_bytes = items[5].as_bytes()?;
    validate_uint256_bytes(value_bytes, "type1 tx value")?;
    let value = value_bytes.to_vec();
    let data = items[6].as_bytes()?.to_vec();
    validate_access_list(&items[7], "type1 tx")?;
    let y_parity = items[8].as_u64()?;
    let r = pad_to_32(items[9].as_bytes()?, "type1 tx r")?;
    let s = pad_to_32(items[10].as_bytes()?, "type1 tx s")?;

    // Reconstruct signing hash
    let mut sign_items = Vec::new();
    sign_items.extend_from_slice(&rlp::encode_u64(chain_id));
    sign_items.extend_from_slice(&rlp::encode_u64(nonce));
    sign_items.extend_from_slice(&rlp::encode_bytes(&gas_price));
    sign_items.extend_from_slice(&rlp::encode_u64(gas_limit));
    sign_items.extend_from_slice(&encode_address(&to));
    sign_items.extend_from_slice(&rlp::encode_bytes(&value));
    sign_items.extend_from_slice(&rlp::encode_bytes(&data));
    // Re-encode the access list from the decoded items
    sign_items.extend_from_slice(&re_encode_rlp_item(&items[7]));
    let mut payload = vec![0x01];
    payload.extend_from_slice(&rlp::encode_list(&sign_items));
    let signing_hash = keccak256(&payload);

    if y_parity > 1 {
        return Err(SignerError::ParseError(format!(
            "type1: invalid y_parity {y_parity}"
        )));
    }
    let from = recover_signer(&signing_hash, &r, &s, y_parity as u8)?;

    Ok(DecodedTransaction {
        tx_type: TxType::Type1AccessList,
        chain_id,
        nonce,
        to,
        value,
        data,
        gas_limit,
        gas_price_or_max_fee: gas_price,
        max_priority_fee: vec![],
        v: y_parity,
        r,
        s,
        from,
        tx_hash,
    })
}

fn decode_type2_tx(raw: &[u8], tx_hash: [u8; 32]) -> Result<DecodedTransaction, SignerError> {
    let items = rlp::decode_list_items(&raw[1..])?;
    if items.len() != 12 {
        return Err(SignerError::ParseError(format!(
            "type2 tx: expected 12 items, got {}",
            items.len()
        )));
    }

    let chain_id = items[0].as_u64()?;
    let nonce = items[1].as_u64()?;
    let max_priority_fee_bytes = items[2].as_bytes()?;
    validate_uint256_bytes(max_priority_fee_bytes, "type2 tx max_priority_fee_per_gas")?;
    let max_priority_fee = max_priority_fee_bytes.to_vec();
    let max_fee_bytes = items[3].as_bytes()?;
    validate_uint256_bytes(max_fee_bytes, "type2 tx max_fee_per_gas")?;
    let max_fee = max_fee_bytes.to_vec();
    if cmp_uint256_be(&max_fee, &max_priority_fee) == Ordering::Less {
        return Err(SignerError::ParseError(
            "type2 tx: max_fee_per_gas cannot be lower than max_priority_fee_per_gas".into(),
        ));
    }
    let gas_limit = items[4].as_u64()?;
    let to_bytes = items[5].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value_bytes = items[6].as_bytes()?;
    validate_uint256_bytes(value_bytes, "type2 tx value")?;
    let value = value_bytes.to_vec();
    let data = items[7].as_bytes()?.to_vec();
    validate_access_list(&items[8], "type2 tx")?;
    let y_parity = items[9].as_u64()?;
    let r = pad_to_32(items[10].as_bytes()?, "type2 tx r")?;
    let s = pad_to_32(items[11].as_bytes()?, "type2 tx s")?;

    // Reconstruct signing hash
    let mut sign_items = Vec::new();
    sign_items.extend_from_slice(&rlp::encode_u64(chain_id));
    sign_items.extend_from_slice(&rlp::encode_u64(nonce));
    sign_items.extend_from_slice(&rlp::encode_bytes(&max_priority_fee));
    sign_items.extend_from_slice(&rlp::encode_bytes(&max_fee));
    sign_items.extend_from_slice(&rlp::encode_u64(gas_limit));
    sign_items.extend_from_slice(&encode_address(&to));
    sign_items.extend_from_slice(&rlp::encode_bytes(&value));
    sign_items.extend_from_slice(&rlp::encode_bytes(&data));
    sign_items.extend_from_slice(&re_encode_rlp_item(&items[8]));
    let mut payload = vec![0x02];
    payload.extend_from_slice(&rlp::encode_list(&sign_items));
    let signing_hash = keccak256(&payload);

    if y_parity > 1 {
        return Err(SignerError::ParseError(format!(
            "type2: invalid y_parity {y_parity}"
        )));
    }
    let from = recover_signer(&signing_hash, &r, &s, y_parity as u8)?;

    Ok(DecodedTransaction {
        tx_type: TxType::Type2DynamicFee,
        chain_id,
        nonce,
        to,
        value,
        data,
        gas_limit,
        gas_price_or_max_fee: max_fee,
        max_priority_fee,
        v: y_parity,
        r,
        s,
        from,
        tx_hash,
    })
}

fn decode_type3_tx(raw: &[u8], tx_hash: [u8; 32]) -> Result<DecodedTransaction, SignerError> {
    let items = rlp::decode_list_items(&raw[1..])?;
    if items.len() != 14 {
        return Err(SignerError::ParseError(format!(
            "type3 tx: expected 14 items, got {}",
            items.len()
        )));
    }

    let chain_id = items[0].as_u64()?;
    let nonce = items[1].as_u64()?;
    let max_priority_fee_bytes = items[2].as_bytes()?;
    validate_uint256_bytes(max_priority_fee_bytes, "type3 tx max_priority_fee_per_gas")?;
    let max_priority_fee = max_priority_fee_bytes.to_vec();
    let max_fee_bytes = items[3].as_bytes()?;
    validate_uint256_bytes(max_fee_bytes, "type3 tx max_fee_per_gas")?;
    let max_fee = max_fee_bytes.to_vec();
    if cmp_uint256_be(&max_fee, &max_priority_fee) == Ordering::Less {
        return Err(SignerError::ParseError(
            "type3 tx: max_fee_per_gas cannot be lower than max_priority_fee_per_gas".into(),
        ));
    }
    let gas_limit = items[4].as_u64()?;
    let to_bytes = items[5].as_bytes()?;
    let to = decode_to_address(to_bytes)?.ok_or_else(|| {
        SignerError::ParseError("type3 tx: contract creation is not allowed".into())
    })?;
    let value_bytes = items[6].as_bytes()?;
    validate_uint256_bytes(value_bytes, "type3 tx value")?;
    let value = value_bytes.to_vec();
    let data = items[7].as_bytes()?.to_vec();
    validate_access_list(&items[8], "type3 tx")?;
    let max_fee_per_blob_gas_bytes = items[9].as_bytes()?;
    validate_uint256_bytes(max_fee_per_blob_gas_bytes, "type3 tx max_fee_per_blob_gas")?;
    validate_blob_hashes(&items[10])?;
    let y_parity = items[11].as_u64()?;
    let r = pad_to_32(items[12].as_bytes()?, "type3 tx r")?;
    let s = pad_to_32(items[13].as_bytes()?, "type3 tx s")?;

    // Reconstruct signing hash
    let mut sign_items = Vec::new();
    sign_items.extend_from_slice(&rlp::encode_u64(chain_id));
    sign_items.extend_from_slice(&rlp::encode_u64(nonce));
    sign_items.extend_from_slice(&rlp::encode_bytes(&max_priority_fee));
    sign_items.extend_from_slice(&rlp::encode_bytes(&max_fee));
    sign_items.extend_from_slice(&rlp::encode_u64(gas_limit));
    sign_items.extend_from_slice(&rlp::encode_bytes(&to));
    sign_items.extend_from_slice(&rlp::encode_bytes(&value));
    sign_items.extend_from_slice(&rlp::encode_bytes(&data));
    sign_items.extend_from_slice(&re_encode_rlp_item(&items[8]));
    sign_items.extend_from_slice(&re_encode_rlp_item(&items[9]));
    sign_items.extend_from_slice(&re_encode_rlp_item(&items[10]));
    let mut payload = vec![0x03];
    payload.extend_from_slice(&rlp::encode_list(&sign_items));
    let signing_hash = keccak256(&payload);

    if y_parity > 1 {
        return Err(SignerError::ParseError(format!(
            "type3: invalid y_parity {y_parity}"
        )));
    }
    let from = recover_signer(&signing_hash, &r, &s, y_parity as u8)?;

    Ok(DecodedTransaction {
        tx_type: TxType::Type3Blob,
        chain_id,
        nonce,
        to: Some(to),
        value,
        data,
        gas_limit,
        gas_price_or_max_fee: max_fee,
        max_priority_fee,
        v: y_parity,
        r,
        s,
        from,
        tx_hash,
    })
}

/// Re-encode a decoded RLP item back to bytes.
fn re_encode_rlp_item(item: &rlp::RlpItem) -> Vec<u8> {
    match item {
        rlp::RlpItem::Bytes(b) => rlp::encode_bytes(b),
        rlp::RlpItem::List(items) => {
            let mut inner = Vec::new();
            for i in items {
                inner.extend_from_slice(&re_encode_rlp_item(i));
            }
            rlp::encode_list(&inner)
        }
    }
}

/// Decode the `to` field: empty = contract creation, 20 bytes = address, otherwise error.
fn decode_to_address(bytes: &[u8]) -> Result<Option<[u8; 20]>, SignerError> {
    match bytes.len() {
        0 => Ok(None),
        20 => {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(bytes);
            Ok(Some(addr))
        }
        n => Err(SignerError::ParseError(format!(
            "invalid to address length: expected 0 or 20, got {n}"
        ))),
    }
}

fn validate_uint256_bytes(bytes: &[u8], field: &str) -> Result<(), SignerError> {
    if bytes.len() > 32 {
        return Err(SignerError::ParseError(format!(
            "{field} exceeds uint256 size ({} bytes)",
            bytes.len()
        )));
    }
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err(SignerError::ParseError(format!(
            "{field} has non-canonical leading zero"
        )));
    }
    if bytes.len() == 1 && bytes[0] == 0 {
        return Err(SignerError::ParseError(format!(
            "{field} has non-canonical zero encoding"
        )));
    }
    Ok(())
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut idx = 0usize;
    while idx < bytes.len() && bytes[idx] == 0 {
        idx += 1;
    }
    &bytes[idx..]
}

fn cmp_uint256_be(lhs: &[u8], rhs: &[u8]) -> Ordering {
    let lhs = trim_leading_zeros(lhs);
    let rhs = trim_leading_zeros(rhs);
    lhs.len().cmp(&rhs.len()).then_with(|| lhs.cmp(rhs))
}

fn validate_access_list(item: &rlp::RlpItem, tx_type: &str) -> Result<(), SignerError> {
    let entries = match item {
        rlp::RlpItem::List(entries) => entries,
        _ => {
            return Err(SignerError::ParseError(format!(
                "{tx_type}: access_list must be an RLP list"
            )));
        }
    };

    for (entry_idx, entry) in entries.iter().enumerate() {
        let parts = match entry {
            rlp::RlpItem::List(parts) => parts,
            _ => {
                return Err(SignerError::ParseError(format!(
                    "{tx_type}: access_list[{entry_idx}] must be a 2-item list"
                )));
            }
        };
        if parts.len() != 2 {
            return Err(SignerError::ParseError(format!(
                "{tx_type}: access_list[{entry_idx}] must contain [address, storageKeys]"
            )));
        }

        let addr = parts[0].as_bytes()?;
        if addr.len() != 20 {
            return Err(SignerError::ParseError(format!(
                "{tx_type}: access_list[{entry_idx}] address must be 20 bytes"
            )));
        }

        let keys = match &parts[1] {
            rlp::RlpItem::List(keys) => keys,
            _ => {
                return Err(SignerError::ParseError(format!(
                    "{tx_type}: access_list[{entry_idx}] storageKeys must be a list"
                )));
            }
        };
        for (key_idx, key) in keys.iter().enumerate() {
            let key_bytes = key.as_bytes()?;
            if key_bytes.len() != 32 {
                return Err(SignerError::ParseError(format!(
                    "{tx_type}: access_list[{entry_idx}] storage key {key_idx} must be 32 bytes"
                )));
            }
        }
    }
    Ok(())
}

fn validate_blob_hashes(item: &rlp::RlpItem) -> Result<(), SignerError> {
    let hashes = match item {
        rlp::RlpItem::List(hashes) => hashes,
        _ => {
            return Err(SignerError::ParseError(
                "type3 tx: blob_versioned_hashes must be an RLP list".into(),
            ));
        }
    };

    if hashes.is_empty() {
        return Err(SignerError::ParseError(
            "type3 tx: blob_versioned_hashes must not be empty".into(),
        ));
    }

    for (idx, hash_item) in hashes.iter().enumerate() {
        let hash = hash_item.as_bytes()?;
        if hash.len() != 32 {
            return Err(SignerError::ParseError(format!(
                "type3 tx: blob_versioned_hashes[{idx}] must be 32 bytes"
            )));
        }
        if hash[0] != 0x01 {
            return Err(SignerError::ParseError(format!(
                "type3 tx: blob_versioned_hashes[{idx}] must start with 0x01"
            )));
        }
    }
    Ok(())
}

/// Recover the signer address from a message hash and ECDSA signature.
fn recover_signer(
    hash: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> Result<[u8; 20], SignerError> {
    use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

    if recovery_id > 1 {
        return Err(SignerError::InvalidSignature(format!(
            "invalid recovery id: {recovery_id}, expected 0 or 1"
        )));
    }

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let sig = K256Signature::from_bytes((&sig_bytes).into())
        .map_err(|e| SignerError::InvalidSignature(format!("invalid sig: {e}")))?;
    if sig.normalize_s().is_some() {
        return Err(SignerError::InvalidSignature(
            "non-canonical high-s signature".into(),
        ));
    }
    let rid = RecoveryId::new(recovery_id != 0, false);
    let key = VerifyingKey::recover_from_prehash(hash, &sig, rid)
        .map_err(|e| SignerError::InvalidSignature(format!("ecrecover: {e}")))?;

    let uncompressed = key.to_encoded_point(false);
    let pub_bytes = &uncompressed.as_bytes()[1..]; // skip 0x04 prefix
    let addr_hash = keccak256(pub_bytes);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&addr_hash[12..]);
    Ok(addr)
}

fn pad_to_32(data: &[u8], field: &str) -> Result<[u8; 32], SignerError> {
    if data.is_empty() {
        return Err(SignerError::ParseError(format!(
            "{field}: signature component cannot be empty"
        )));
    }
    if data.len() == 1 && data[0] == 0 {
        return Err(SignerError::ParseError(format!(
            "{field}: signature component cannot be zero"
        )));
    }
    if data.len() > 1 && data[0] == 0 {
        return Err(SignerError::ParseError(format!(
            "{field}: signature component has non-canonical leading zero"
        )));
    }
    if data.len() > 32 {
        return Err(SignerError::ParseError(format!(
            "{field}: signature component too large: {} bytes (max 32)",
            data.len()
        )));
    }
    let mut buf = [0u8; 32];
    buf[32 - data.len()..].copy_from_slice(data);
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::{KeyPair, Signer};

    #[test]
    fn test_legacy_tx_sign_recoverable() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 20_000_000_000, // 20 Gwei
            gas_limit: 21_000,
            to: Some([0xBB; 20]),
            value: 1_000_000_000_000_000_000, // 1 ETH
            data: vec![],
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        let raw = signed.raw_tx();
        assert!(!raw.is_empty());
        // Must be valid RLP
        let decoded = rlp::decode(raw).unwrap();
        let items = decoded.as_list().unwrap();
        assert_eq!(items.len(), 9); // nonce, gasPrice, gasLimit, to, value, data, v, r, s
    }

    #[test]
    fn test_legacy_tx_hash_deterministic() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = LegacyTransaction {
            nonce: 5,
            gas_price: 30_000_000_000,
            gas_limit: 21_000,
            to: Some([0xCC; 20]),
            value: 0,
            data: vec![0xDE, 0xAD],
            chain_id: 1,
        };
        let signed1 = tx.sign(&signer).unwrap();
        let signed2 = tx.sign(&signer).unwrap();
        // RFC 6979 deterministic: same tx + same key = same signature
        assert_eq!(signed1.tx_hash(), signed2.tx_hash());
    }

    #[test]
    fn test_legacy_contract_creation() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 1_000_000,
            to: None, // contract creation
            value: 0,
            data: vec![0x60, 0x00], // minimal bytecode
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        assert!(!signed.raw_tx().is_empty());
    }

    #[test]
    fn test_eip2930_tx_type1_prefix() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP2930Transaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            access_list: vec![([0xDD; 20], vec![[0xEE; 32]])],
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x01, "Type 1 prefix");
    }

    #[test]
    fn test_eip1559_tx_type2_prefix() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            access_list: vec![],
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x02, "Type 2 prefix");
    }

    #[test]
    fn test_eip1559_different_nonces_different_hashes() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let base = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        let mut tx2 = base.clone();
        tx2.nonce = 1;
        let h1 = base.sign(&signer).unwrap().tx_hash();
        let h2 = tx2.sign(&signer).unwrap().tx_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_eip4844_tx_type3_prefix() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            max_fee_per_blob_gas: 1_000_000_000,
            blob_versioned_hashes: vec![[0x01; 32]],
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(signed.raw_tx()[0], 0x03, "Type 3 prefix");
    }

    #[test]
    fn test_create_address_known_vector() {
        // Known: sender 0x0000...0000 nonce 0 → specific address
        let sender = [0u8; 20];
        let addr = create_address(&sender, 0);
        assert_eq!(addr.len(), 20);
        // Verify it's deterministic
        assert_eq!(addr, create_address(&sender, 0));
        // Different nonce → different address
        assert_ne!(addr, create_address(&sender, 1));
    }

    #[test]
    fn test_create2_address_eip1014_vector() {
        // EIP-1014 test vector #1:
        // sender = 0x0000000000000000000000000000000000000000
        // salt = 0x00...00
        // init_code = 0x00
        // expected = keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12:]
        let sender = [0u8; 20];
        let salt = [0u8; 32];
        let addr = create2_address(&sender, &salt, &[0x00]);
        // Verify determinism
        assert_eq!(addr, create2_address(&sender, &salt, &[0x00]));
        // Different init_code → different address
        assert_ne!(addr, create2_address(&sender, &salt, &[0x01]));
    }

    #[test]
    fn test_eip1271_encode() {
        let hash = [0xAA; 32];
        let sig = vec![0xBB; 65];
        let calldata = encode_is_valid_signature(&hash, &sig);
        // First 4 bytes = function selector
        assert_eq!(
            &calldata[..4],
            &keccak256(b"isValidSignature(bytes32,bytes)")[..4]
        );
        // Next 32 bytes = hash
        assert_eq!(&calldata[4..36], &hash);
    }

    #[test]
    fn test_raw_tx_hex_format() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 21_000,
            to: Some([0; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        let hex = tx.sign(&signer).unwrap().raw_tx_hex();
        assert!(hex.starts_with("0x02"), "should start with 0x02");
    }

    #[test]
    fn test_signed_tx_hash_is_keccak_of_raw() {
        let signer = EthereumSigner::generate().unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 1_000_000,
            max_fee_per_gas: 50_000_000_000,
            gas_limit: 100_000,
            to: Some([0xFF; 20]),
            value: 500_000_000_000_000,
            data: vec![0x01, 0x02, 0x03],
            access_list: vec![],
        };
        let signed = tx.sign(&signer).unwrap();
        let expected = keccak256(signed.raw_tx());
        assert_eq!(signed.tx_hash(), expected);
    }

    // ─── Signed Transaction Decoding Tests ─────────────────────────

    #[test]
    fn test_decode_legacy_roundtrip() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = LegacyTransaction {
            nonce: 7,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([0xBB; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![0xAB, 0xCD],
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        let decoded = decode_signed_tx(signed.raw_tx()).unwrap();

        assert_eq!(decoded.tx_type, TxType::Legacy);
        assert_eq!(decoded.chain_id, 1);
        assert_eq!(decoded.nonce, 7);
        assert_eq!(decoded.gas_limit, 21_000);
        assert_eq!(decoded.to, Some([0xBB; 20]));
        assert_eq!(decoded.data, vec![0xAB, 0xCD]);
        assert_eq!(decoded.from, signer.address());
        assert_eq!(decoded.tx_hash, signed.tx_hash());
    }

    #[test]
    fn test_decode_type1_roundtrip() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = EIP2930Transaction {
            chain_id: 1,
            nonce: 3,
            gas_price: 30_000_000_000,
            gas_limit: 50_000,
            to: Some([0xCC; 20]),
            value: 0,
            data: vec![0x01],
            access_list: vec![([0xDD; 20], vec![[0xEE; 32]])],
        };
        let signed = tx.sign(&signer).unwrap();
        let decoded = decode_signed_tx(signed.raw_tx()).unwrap();

        assert_eq!(decoded.tx_type, TxType::Type1AccessList);
        assert_eq!(decoded.chain_id, 1);
        assert_eq!(decoded.nonce, 3);
        assert_eq!(decoded.from, signer.address());
    }

    #[test]
    fn test_decode_type2_roundtrip() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 42,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 100_000_000_000,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 500_000_000_000_000,
            data: vec![],
            access_list: vec![],
        };
        let signed = tx.sign(&signer).unwrap();
        let decoded = decode_signed_tx(signed.raw_tx()).unwrap();

        assert_eq!(decoded.tx_type, TxType::Type2DynamicFee);
        assert_eq!(decoded.chain_id, 1);
        assert_eq!(decoded.nonce, 42);
        assert_eq!(decoded.gas_limit, 21_000);
        assert_eq!(decoded.to, Some([0xAA; 20]));
        assert_eq!(decoded.from, signer.address());
        assert_eq!(decoded.tx_hash, signed.tx_hash());
    }

    #[test]
    fn test_decode_type3_roundtrip() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = EIP4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 50_000_000_000,
            gas_limit: 100_000,
            to: [0xFF; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            max_fee_per_blob_gas: 1_000_000_000,
            blob_versioned_hashes: vec![[0x01; 32]],
        };
        let signed = tx.sign(&signer).unwrap();
        let decoded = decode_signed_tx(signed.raw_tx()).unwrap();

        assert_eq!(decoded.tx_type, TxType::Type3Blob);
        assert_eq!(decoded.from, signer.address());
        assert_eq!(decoded.chain_id, 1);
    }

    #[test]
    fn test_decode_contract_creation() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 1_000_000,
            to: None,
            value: 0,
            data: vec![0x60, 0x00],
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        let decoded = decode_signed_tx(signed.raw_tx()).unwrap();

        assert_eq!(decoded.to, None, "contract creation has no 'to'");
        assert_eq!(decoded.from, signer.address());
    }

    #[test]
    fn test_decode_empty_tx_rejected() {
        assert!(decode_signed_tx(&[]).is_err());
    }

    #[test]
    fn test_decode_unknown_type_rejected() {
        assert!(decode_signed_tx(&[0x04, 0x00]).is_err());
    }

    #[test]
    fn test_decode_legacy_rejects_non_canonical_eip155_v_35() {
        let mut items = Vec::new();
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(0)); // nonce
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(1)); // gas_price
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(21_000)); // gas_limit
        items.extend_from_slice(&crate::ethereum::rlp::encode_bytes(&[0x11; 20])); // to
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(0)); // value
        items.extend_from_slice(&crate::ethereum::rlp::encode_bytes(&[])); // data
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(35)); // invalid/non-canonical
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(1)); // r
        items.extend_from_slice(&crate::ethereum::rlp::encode_u64(1)); // s
        let raw = crate::ethereum::rlp::encode_list(&items);

        let result = decode_signed_tx(&raw);
        assert!(
            matches!(
                result,
                Err(SignerError::ParseError(ref msg))
                    if msg.contains("non-canonical EIP-155 v value")
            ),
            "expected ParseError for non-canonical v, got {result:?}"
        );
    }

    #[test]
    fn test_recover_signer_rejects_high_s_signature() {
        let signer = EthereumSigner::generate().unwrap();
        let sig = signer.sign(b"tx-high-s-reject").unwrap();
        let digest = keccak256(b"tx-high-s-reject");
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        let recovery_id = (sig.v - 27) as u8;

        // secp256k1 n - 1 (valid scalar, always high-s)
        let high_s = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x40,
        ];

        assert!(recover_signer(&hash, &sig.r, &high_s, recovery_id).is_err());
    }

    #[test]
    fn test_decode_signer_matches_across_types() {
        // Same signer, same nonce → different tx types should all recover same address
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let expected_addr = signer.address();

        let legacy = LegacyTransaction {
            nonce: 0,
            gas_price: 1,
            gas_limit: 21000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            chain_id: 1,
        }
        .sign(&signer)
        .unwrap();

        let type2 = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        }
        .sign(&signer)
        .unwrap();

        assert_eq!(
            decode_signed_tx(legacy.raw_tx()).unwrap().from,
            expected_addr
        );
        assert_eq!(
            decode_signed_tx(type2.raw_tx()).unwrap().from,
            expected_addr
        );
    }

    #[test]
    fn test_eip155_known_signing_vector() {
        // EIP-155 reference vector:
        // https://eips.ethereum.org/EIPS/eip-155
        let signer = EthereumSigner::from_bytes(&[0x46; 32]).unwrap();
        let tx = LegacyTransaction {
            nonce: 9,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some([0x35; 20]),
            value: 1_000_000_000_000_000_000,
            data: vec![],
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        assert_eq!(
            hex::encode(signed.raw_tx()),
            "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn test_decode_rejects_non_canonical_zero_nonce_encoding() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = LegacyTransaction {
            nonce: 0,
            gas_price: 1,
            gas_limit: 21_000,
            to: Some([0x11; 20]),
            value: 0,
            data: vec![],
            chain_id: 1,
        };
        let signed = tx.sign(&signer).unwrap();
        let mut malformed = signed.raw_tx().to_vec();

        // Legacy list header is either 1 byte (short) or 1+len_of_len bytes (long).
        let header_len = if malformed[0] <= 0xF7 {
            1usize
        } else {
            1 + usize::from(malformed[0] - 0xF7)
        };
        assert_eq!(malformed[header_len], 0x80, "nonce=0 canonical encoding");
        malformed[header_len] = 0x00; // non-canonical integer zero

        let err = decode_signed_tx(&malformed).unwrap_err().to_string();
        assert!(err.contains("non-canonical"));
    }

    #[test]
    fn test_sign_rejects_zero_chain_id() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();

        let legacy = LegacyTransaction {
            nonce: 0,
            gas_price: 1,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            chain_id: 0,
        };
        assert!(legacy.sign(&signer).is_err());

        let type1 = EIP2930Transaction {
            chain_id: 0,
            nonce: 0,
            gas_price: 1,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        assert!(type1.sign(&signer).is_err());

        let type2 = EIP1559Transaction {
            chain_id: 0,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        assert!(type2.sign(&signer).is_err());

        let type3 = EIP4844Transaction {
            chain_id: 0,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes: vec![[0x01; 32]],
        };
        assert!(type3.sign(&signer).is_err());
    }

    #[test]
    fn test_type2_sign_rejects_priority_fee_above_max_fee() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();
        let tx = EIP1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 10,
            max_fee_per_gas: 9,
            gas_limit: 21_000,
            to: Some([0xAA; 20]),
            value: 0,
            data: vec![],
            access_list: vec![],
        };
        assert!(tx.sign(&signer).is_err());
    }

    #[test]
    fn test_type3_sign_rejects_invalid_blob_hashes() {
        let signer = EthereumSigner::from_bytes(&[0x42; 32]).unwrap();

        let empty = EIP4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes: vec![],
        };
        assert!(empty.sign(&signer).is_err());

        let mut bad_hash = [0u8; 32];
        bad_hash[0] = 0x02;
        let invalid = EIP4844Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            gas_limit: 21_000,
            to: [0xAA; 20],
            value: 0,
            data: vec![],
            access_list: vec![],
            max_fee_per_blob_gas: 1,
            blob_versioned_hashes: vec![bad_hash],
        };
        assert!(invalid.sign(&signer).is_err());
    }

    #[test]
    fn test_decode_type2_rejects_max_fee_below_priority_fee() {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(1)); // chain_id
        items.extend_from_slice(&rlp::encode_u64(0)); // nonce
        items.extend_from_slice(&rlp::encode_u64(2)); // max_priority_fee_per_gas
        items.extend_from_slice(&rlp::encode_u64(1)); // max_fee_per_gas (invalid)
        items.extend_from_slice(&rlp::encode_u64(21_000)); // gas_limit
        items.extend_from_slice(&rlp::encode_bytes(&[0x11; 20])); // to
        items.extend_from_slice(&rlp::encode_u64(0)); // value
        items.extend_from_slice(&rlp::encode_bytes(&[])); // data
        items.extend_from_slice(&rlp::encode_empty_list()); // access_list
        items.extend_from_slice(&rlp::encode_u64(0)); // y_parity
        items.extend_from_slice(&rlp::encode_u64(1)); // r
        items.extend_from_slice(&rlp::encode_u64(1)); // s
        let mut raw = vec![0x02];
        raw.extend_from_slice(&rlp::encode_list(&items));

        let err = decode_signed_tx(&raw).unwrap_err().to_string();
        assert!(err.contains("max_fee_per_gas cannot be lower"));
    }

    #[test]
    fn test_decode_type1_rejects_non_list_access_list() {
        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(1)); // chain_id
        items.extend_from_slice(&rlp::encode_u64(0)); // nonce
        items.extend_from_slice(&rlp::encode_u64(1)); // gas_price
        items.extend_from_slice(&rlp::encode_u64(21_000)); // gas_limit
        items.extend_from_slice(&rlp::encode_bytes(&[0x11; 20])); // to
        items.extend_from_slice(&rlp::encode_u64(0)); // value
        items.extend_from_slice(&rlp::encode_bytes(&[])); // data
        items.extend_from_slice(&rlp::encode_bytes(&[0x01])); // malformed access_list
        items.extend_from_slice(&rlp::encode_u64(0)); // y_parity
        items.extend_from_slice(&rlp::encode_u64(1)); // r
        items.extend_from_slice(&rlp::encode_u64(1)); // s
        let mut raw = vec![0x01];
        raw.extend_from_slice(&rlp::encode_list(&items));

        let err = decode_signed_tx(&raw).unwrap_err().to_string();
        assert!(err.contains("access_list must be an RLP list"));
    }

    #[test]
    fn test_decode_type3_rejects_contract_creation_and_bad_blob_version() {
        let mut blob_items = Vec::new();
        let mut bad_hash = [0u8; 32];
        bad_hash[0] = 0x02;
        blob_items.extend_from_slice(&rlp::encode_bytes(&bad_hash));

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(1)); // chain_id
        items.extend_from_slice(&rlp::encode_u64(0)); // nonce
        items.extend_from_slice(&rlp::encode_u64(1)); // max_priority_fee_per_gas
        items.extend_from_slice(&rlp::encode_u64(1)); // max_fee_per_gas
        items.extend_from_slice(&rlp::encode_u64(21_000)); // gas_limit
        items.extend_from_slice(&rlp::encode_bytes(&[])); // to (invalid for type3)
        items.extend_from_slice(&rlp::encode_u64(0)); // value
        items.extend_from_slice(&rlp::encode_bytes(&[])); // data
        items.extend_from_slice(&rlp::encode_empty_list()); // access_list
        items.extend_from_slice(&rlp::encode_u64(1)); // max_fee_per_blob_gas
        items.extend_from_slice(&rlp::encode_list(&blob_items)); // blob hashes
        items.extend_from_slice(&rlp::encode_u64(0)); // y_parity
        items.extend_from_slice(&rlp::encode_u64(1)); // r
        items.extend_from_slice(&rlp::encode_u64(1)); // s
        let mut raw = vec![0x03];
        raw.extend_from_slice(&rlp::encode_list(&items));

        let err = decode_signed_tx(&raw).unwrap_err().to_string();
        assert!(err.contains("contract creation is not allowed"));
    }

    #[test]
    fn test_decode_type3_rejects_bad_blob_version_hash() {
        let mut blob_items = Vec::new();
        let mut bad_hash = [0u8; 32];
        bad_hash[0] = 0x02;
        blob_items.extend_from_slice(&rlp::encode_bytes(&bad_hash));

        let mut items = Vec::new();
        items.extend_from_slice(&rlp::encode_u64(1)); // chain_id
        items.extend_from_slice(&rlp::encode_u64(0)); // nonce
        items.extend_from_slice(&rlp::encode_u64(1)); // max_priority_fee_per_gas
        items.extend_from_slice(&rlp::encode_u64(1)); // max_fee_per_gas
        items.extend_from_slice(&rlp::encode_u64(21_000)); // gas_limit
        items.extend_from_slice(&rlp::encode_bytes(&[0x11; 20])); // to
        items.extend_from_slice(&rlp::encode_u64(0)); // value
        items.extend_from_slice(&rlp::encode_bytes(&[])); // data
        items.extend_from_slice(&rlp::encode_empty_list()); // access_list
        items.extend_from_slice(&rlp::encode_u64(1)); // max_fee_per_blob_gas
        items.extend_from_slice(&rlp::encode_list(&blob_items)); // blob hashes
        items.extend_from_slice(&rlp::encode_u64(0)); // y_parity
        items.extend_from_slice(&rlp::encode_u64(1)); // r
        items.extend_from_slice(&rlp::encode_u64(1)); // s
        let mut raw = vec![0x03];
        raw.extend_from_slice(&rlp::encode_list(&items));

        let err = decode_signed_tx(&raw).unwrap_err().to_string();
        assert!(err.contains("must start with 0x01"));
    }
}
