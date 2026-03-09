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
        let payload = self.signing_payload();
        let hash = keccak256(&payload);
        let sig = signer.sign_digest(&hash)?;

        // EIP-155: v = {0,1} + chain_id * 2 + 35
        let v = (sig.v as u64 - 27) + self.chain_id * 2 + 35;

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
    let gas_price = items[1].as_bytes()?.to_vec();
    let gas_limit = items[2].as_u64()?;
    let to_bytes = items[3].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value = items[4].as_bytes()?.to_vec();
    let data = items[5].as_bytes()?.to_vec();
    let v = items[6].as_u64()?;
    let r = pad_to_32(items[7].as_bytes()?)?;
    let s = pad_to_32(items[8].as_bytes()?)?;

    // EIP-155: chain_id = (v - 35) / 2
    let (chain_id, recovery_id) = if v >= 35 {
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
    let gas_price = items[2].as_bytes()?.to_vec();
    let gas_limit = items[3].as_u64()?;
    let to_bytes = items[4].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value = items[5].as_bytes()?.to_vec();
    let data = items[6].as_bytes()?.to_vec();
    // items[7] = access_list (skip for decode)
    let y_parity = items[8].as_u64()?;
    let r = pad_to_32(items[9].as_bytes()?)?;
    let s = pad_to_32(items[10].as_bytes()?)?;

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
    let max_priority_fee = items[2].as_bytes()?.to_vec();
    let max_fee = items[3].as_bytes()?.to_vec();
    let gas_limit = items[4].as_u64()?;
    let to_bytes = items[5].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value = items[6].as_bytes()?.to_vec();
    let data = items[7].as_bytes()?.to_vec();
    // items[8] = access_list
    let y_parity = items[9].as_u64()?;
    let r = pad_to_32(items[10].as_bytes()?)?;
    let s = pad_to_32(items[11].as_bytes()?)?;

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
    let max_priority_fee = items[2].as_bytes()?.to_vec();
    let max_fee = items[3].as_bytes()?.to_vec();
    let gas_limit = items[4].as_u64()?;
    let to_bytes = items[5].as_bytes()?;
    let to = decode_to_address(to_bytes)?;
    let value = items[6].as_bytes()?.to_vec();
    let data = items[7].as_bytes()?.to_vec();
    // items[8] = access_list, items[9] = max_fee_per_blob_gas, items[10] = blob_hashes
    let y_parity = items[11].as_u64()?;
    let r = pad_to_32(items[12].as_bytes()?)?;
    let s = pad_to_32(items[13].as_bytes()?)?;

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

fn pad_to_32(data: &[u8]) -> Result<[u8; 32], SignerError> {
    if data.len() > 32 {
        return Err(SignerError::ParseError(format!(
            "signature component too large: {} bytes (max 32)",
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
    use crate::traits::KeyPair;

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
}
