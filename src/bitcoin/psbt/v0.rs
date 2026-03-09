//! **PSBT v0** — Core PSBT structure (BIP-174) with BIP-371 Taproot extensions.
//!
//! Implements serialization, deserialization, input/output maps, and
//! key-value encoding for Partially Signed Bitcoin Transactions.

use crate::crypto;
use crate::encoding;
use crate::error::SignerError;
use std::collections::BTreeMap;

/// PSBT magic bytes: `0x70736274` ("psbt" in ASCII).
const PSBT_MAGIC: [u8; 4] = [0x70, 0x73, 0x62, 0x74];

/// PSBT separator byte.
const PSBT_SEPARATOR: u8 = 0xff;

// ─── Key Types ──────────────────────────────────────────────────────

/// PSBT global key types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GlobalKey {
    /// The unsigned transaction.
    UnsignedTx = 0x00,
    /// Extended public key (xpub) for BIP-32 derivation.
    Xpub = 0x01,
    /// PSBT version number.
    Version = 0xFB,
}

/// PSBT per-input key types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InputKey {
    /// Non-witness UTXO (full previous transaction).
    NonWitnessUtxo = 0x00,
    /// Witness UTXO (previous output value + scriptPubKey).
    WitnessUtxo = 0x01,
    /// Partial signature.
    PartialSig = 0x02,
    /// Sighash type.
    SighashType = 0x03,
    /// Input redeem script.
    RedeemScript = 0x04,
    /// Input witness script.
    WitnessScript = 0x05,
    /// BIP-32 derivation path for a pubkey.
    Bip32Derivation = 0x06,
    /// Finalized scriptSig.
    FinalScriptSig = 0x07,
    /// Finalized scriptWitness.
    FinalScriptWitness = 0x08,
    /// BIP-371: Taproot key-path signature.
    TapKeySig = 0x13,
    /// BIP-371: Taproot script-path signature.
    TapScriptSig = 0x14,
    /// BIP-371: Taproot leaf script.
    TapLeafScript = 0x15,
    /// BIP-371: Taproot BIP-32 derivation.
    TapBip32Derivation = 0x16,
    /// BIP-371: Taproot internal key.
    TapInternalKey = 0x17,
    /// BIP-371: Taproot merkle root.
    TapMerkleRoot = 0x18,
}

/// PSBT per-output key types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OutputKey {
    /// Output redeem script.
    RedeemScript = 0x00,
    /// Output witness script.
    WitnessScript = 0x01,
    /// BIP-32 derivation path.
    Bip32Derivation = 0x02,
    /// BIP-371: Taproot internal key.
    TapInternalKey = 0x05,
    /// BIP-371: Taproot tree.
    TapTree = 0x06,
    /// BIP-371: Taproot BIP-32 derivation.
    TapBip32Derivation = 0x07,
}

// ─── Key-Value Pair ─────────────────────────────────────────────────

/// A PSBT key-value pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValuePair {
    /// The key bytes (key_type || key_data).
    pub key: Vec<u8>,
    /// The value bytes.
    pub value: Vec<u8>,
}

// ─── PSBT Structure ─────────────────────────────────────────────────

/// A Partially Signed Bitcoin Transaction.
#[derive(Clone, Debug)]
pub struct Psbt {
    /// Global key-value pairs (keyed by full key bytes).
    pub global: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Per-input key-value pairs.
    pub inputs: Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
    /// Per-output key-value pairs.
    pub outputs: Vec<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl Psbt {
    /// Create a new empty PSBT.
    pub fn new() -> Self {
        Self {
            global: BTreeMap::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Set the unsigned transaction.
    pub fn set_unsigned_tx(&mut self, raw_tx: &[u8]) {
        self.global
            .insert(vec![GlobalKey::UnsignedTx as u8], raw_tx.to_vec());
    }

    /// Get the unsigned transaction bytes.
    pub fn unsigned_tx(&self) -> Option<&Vec<u8>> {
        self.global.get(&vec![GlobalKey::UnsignedTx as u8])
    }

    /// Add an input with an empty key-value map.
    pub fn add_input(&mut self) -> usize {
        let idx = self.inputs.len();
        self.inputs.push(BTreeMap::new());
        idx
    }

    /// Add an output with an empty key-value map.
    pub fn add_output(&mut self) -> usize {
        let idx = self.outputs.len();
        self.outputs.push(BTreeMap::new());
        idx
    }

    /// Set a key-value pair for a specific input.
    pub fn set_input_kv(&mut self, input_idx: usize, key: Vec<u8>, value: Vec<u8>) {
        if let Some(map) = self.inputs.get_mut(input_idx) {
            map.insert(key, value);
        }
    }

    /// Set a key-value pair for a specific output.
    pub fn set_output_kv(&mut self, output_idx: usize, key: Vec<u8>, value: Vec<u8>) {
        if let Some(map) = self.outputs.get_mut(output_idx) {
            map.insert(key, value);
        }
    }

    /// Set witness UTXO for an input.
    pub fn set_witness_utxo(&mut self, input_idx: usize, amount: u64, script_pubkey: &[u8]) {
        let mut value = Vec::new();
        value.extend_from_slice(&amount.to_le_bytes());
        encoding::encode_compact_size(&mut value, script_pubkey.len() as u64);
        value.extend_from_slice(script_pubkey);
        self.set_input_kv(input_idx, vec![InputKey::WitnessUtxo as u8], value);
    }

    /// Set the Taproot internal key for an input (BIP-371).
    pub fn set_tap_internal_key(&mut self, input_idx: usize, x_only_key: &[u8; 32]) {
        self.set_input_kv(
            input_idx,
            vec![InputKey::TapInternalKey as u8],
            x_only_key.to_vec(),
        );
    }

    /// Set the Taproot merkle root for an input (BIP-371).
    pub fn set_tap_merkle_root(&mut self, input_idx: usize, merkle_root: &[u8; 32]) {
        self.set_input_kv(
            input_idx,
            vec![InputKey::TapMerkleRoot as u8],
            merkle_root.to_vec(),
        );
    }

    /// Set the Taproot key-path signature for an input (BIP-371).
    pub fn set_tap_key_sig(&mut self, input_idx: usize, signature: &[u8]) {
        self.set_input_kv(
            input_idx,
            vec![InputKey::TapKeySig as u8],
            signature.to_vec(),
        );
    }

    /// Sign a SegWit v0 (P2WPKH) input using the provided signer.
    ///
    /// Reads the witness UTXO from the input map, computes the BIP-143 sighash,
    /// signs with ECDSA, and stores the partial signature in the PSBT.
    ///
    /// # Arguments
    /// - `input_idx` — The input index to sign
    /// - `signer` — A `BitcoinSigner` whose public key matches the input
    /// - `sighash_type` — Sighash flag (typically `All`)
    pub fn sign_segwit_input(
        &mut self,
        input_idx: usize,
        signer: &crate::bitcoin::BitcoinSigner,
        sighash_type: crate::bitcoin::tapscript::SighashType,
    ) -> Result<(), SignerError> {
        use crate::bitcoin::sighash;
        use crate::bitcoin::transaction::*;
        use crate::traits::Signer;

        // Extract witness UTXO from input map
        let witness_utxo_key = vec![InputKey::WitnessUtxo as u8];
        let utxo_data = self
            .inputs
            .get(input_idx)
            .and_then(|m| m.get(&witness_utxo_key))
            .ok_or_else(|| SignerError::SigningFailed("missing witness UTXO for input".into()))?
            .clone();

        // Parse witness UTXO: amount (8 bytes LE) + scriptPubKey
        if utxo_data.len() < 9 {
            return Err(SignerError::SigningFailed("witness UTXO too short".into()));
        }
        let mut amount_bytes = [0u8; 8];
        amount_bytes.copy_from_slice(&utxo_data[..8]);
        let amount = u64::from_le_bytes(amount_bytes);

        // Extract scriptPubKey (skip compact size)
        let mut utxo_off = 8usize;
        let script_len = encoding::read_compact_size(&utxo_data, &mut utxo_off)? as usize;
        let script_end = utxo_off.checked_add(script_len).ok_or_else(|| {
            SignerError::SigningFailed("witness UTXO script length overflow".into())
        })?;
        if script_end > utxo_data.len() {
            return Err(SignerError::SigningFailed(
                "witness UTXO script truncated".into(),
            ));
        }
        let script_pk = &utxo_data[utxo_off..script_end];

        // Extract pubkey hash from P2WPKH scriptPubKey: OP_0 OP_PUSH20 <hash>
        if script_pk.len() != 22 || script_pk[0] != 0x00 || script_pk[1] != 0x14 {
            return Err(SignerError::SigningFailed(
                "input is not P2WPKH (expected OP_0 OP_PUSH20)".into(),
            ));
        }
        let mut pubkey_hash = [0u8; 20];
        pubkey_hash.copy_from_slice(&script_pk[2..22]);

        // Verify the signer's pubkey matches this input
        let expected_hash = crate::crypto::hash160(&signer.public_key_bytes());
        if pubkey_hash != expected_hash {
            return Err(SignerError::SigningFailed(
                "signer public key does not match the P2WPKH input".into(),
            ));
        }

        // Get the unsigned transaction
        let tx_bytes = self
            .unsigned_tx()
            .ok_or_else(|| SignerError::SigningFailed("missing unsigned tx".into()))?
            .clone();

        // Minimal tx parsing for sighash: we need to build a Transaction struct
        let tx = parse_unsigned_tx(&tx_bytes)?;

        // Compute BIP-143 sighash
        let script_code = sighash::p2wpkh_script_code(&pubkey_hash);
        let prev_out = sighash::PrevOut {
            script_code,
            value: amount,
        };
        let sighash_value = sighash::segwit_v0_sighash(&tx, input_idx, &prev_out, sighash_type)?;

        // Sign
        let sig = signer.sign_prehashed(&sighash_value)?;
        let mut sig_bytes = sig.to_bytes();
        sig_bytes.push(sighash_type.to_byte());

        // Store as partial signature: key = 0x02 || compressed_pubkey
        let pubkey = signer.public_key_bytes();
        let mut key = vec![InputKey::PartialSig as u8];
        key.extend_from_slice(&pubkey);
        self.set_input_kv(input_idx, key, sig_bytes);

        Ok(())
    }

    /// Sign a Taproot (P2TR) input using the provided Schnorr signer.
    ///
    /// Reads the witness UTXO from the input map, computes the BIP-341 sighash,
    /// signs with Schnorr, and stores the key-path signature in the PSBT.
    pub fn sign_taproot_input(
        &mut self,
        input_idx: usize,
        signer: &crate::bitcoin::schnorr::SchnorrSigner,
        sighash_type: crate::bitcoin::tapscript::SighashType,
    ) -> Result<(), SignerError> {
        use crate::bitcoin::sighash;
        use crate::bitcoin::transaction::*;
        use crate::traits::Signer;

        // Extract all witness UTXOs for taproot sighash (needs all prevouts)
        let mut prevouts = Vec::new();
        let witness_utxo_key = vec![InputKey::WitnessUtxo as u8];
        for (i, input_map) in self.inputs.iter().enumerate() {
            let utxo_data = input_map.get(&witness_utxo_key).ok_or_else(|| {
                SignerError::SigningFailed(format!("missing witness UTXO for input {i}"))
            })?;
            if utxo_data.len() < 9 {
                return Err(SignerError::SigningFailed(format!(
                    "witness UTXO {i} too short"
                )));
            }
            let mut amount_bytes = [0u8; 8];
            amount_bytes.copy_from_slice(&utxo_data[..8]);
            let amount = u64::from_le_bytes(amount_bytes);
            let mut utxo_off = 8usize;
            let script_len = encoding::read_compact_size(utxo_data, &mut utxo_off)? as usize;
            let script_end = utxo_off.checked_add(script_len).ok_or_else(|| {
                SignerError::SigningFailed(format!(
                    "witness UTXO {i} script length overflow"
                ))
            })?;
            if script_end > utxo_data.len() {
                return Err(SignerError::SigningFailed(format!(
                    "witness UTXO {i} script truncated"
                )));
            }
            let script_pk = utxo_data[utxo_off..script_end].to_vec();
            prevouts.push(TxOut {
                value: amount,
                script_pubkey: script_pk,
            });
        }

        // Get the unsigned transaction
        let tx_bytes = self
            .unsigned_tx()
            .ok_or_else(|| SignerError::SigningFailed("missing unsigned tx".into()))?
            .clone();
        let tx = parse_unsigned_tx(&tx_bytes)?;

        // Compute BIP-341 sighash
        let sighash_value =
            sighash::taproot_key_path_sighash(&tx, input_idx, &prevouts, sighash_type)?;

        // Sign with Schnorr
        let sig = signer.sign(&sighash_value)?;
        let mut sig_bytes = sig.bytes.to_vec();
        // Append sighash byte only if not Default (0x00)
        if sighash_type.to_byte() != 0x00 {
            sig_bytes.push(sighash_type.to_byte());
        }

        // Store as BIP-371 tap key sig
        self.set_tap_key_sig(input_idx, &sig_bytes);
        Ok(())
    }

    /// Serialize the PSBT to binary format.
    ///
    /// Format: `magic || 0xFF || global_map || 0x00 || input_maps... || output_maps...`
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Magic
        data.extend_from_slice(&PSBT_MAGIC);
        data.push(PSBT_SEPARATOR);

        // Global map
        for (key, value) in &self.global {
            encoding::encode_compact_size(&mut data, key.len() as u64);
            data.extend_from_slice(key);
            encoding::encode_compact_size(&mut data, value.len() as u64);
            data.extend_from_slice(value);
        }
        data.push(0x00); // end of global map

        // Input maps
        for input in &self.inputs {
            for (key, value) in input {
                encoding::encode_compact_size(&mut data, key.len() as u64);
                data.extend_from_slice(key);
                encoding::encode_compact_size(&mut data, value.len() as u64);
                data.extend_from_slice(value);
            }
            data.push(0x00); // end of input map
        }

        // Output maps
        for output in &self.outputs {
            for (key, value) in output {
                encoding::encode_compact_size(&mut data, key.len() as u64);
                data.extend_from_slice(key);
                encoding::encode_compact_size(&mut data, value.len() as u64);
                data.extend_from_slice(value);
            }
            data.push(0x00); // end of output map
        }

        data
    }

    /// Deserialize a PSBT from binary format.
    ///
    /// Parses the unsigned transaction from the global map (key `0x00`) to
    /// determine the exact number of input and output maps, then reads
    /// that many maps in order. Falls back to heuristic classification
    /// if the unsigned transaction is missing or invalid.
    pub fn deserialize(data: &[u8]) -> Result<Self, SignerError> {
        if data.len() < 5 {
            return Err(SignerError::ParseError("PSBT too short".into()));
        }
        if data[..4] != PSBT_MAGIC {
            return Err(SignerError::ParseError("invalid PSBT magic".into()));
        }
        if data[4] != PSBT_SEPARATOR {
            return Err(SignerError::ParseError("missing PSBT separator".into()));
        }

        let mut offset = 5;
        let mut psbt = Psbt::new();

        // Parse global map
        psbt.global = parse_kv_map(data, &mut offset)?;

        // Try to extract input/output counts from the unsigned transaction (key 0x00)
        let counts = psbt
            .global
            .get(&vec![0x00])
            .and_then(|raw_tx| extract_tx_io_counts(raw_tx));

        let (num_inputs, num_outputs) = counts.ok_or_else(|| {
            SignerError::ParseError(
                "PSBT: missing or malformed unsigned transaction (key 0x00)".into(),
            )
        })?;

        // Parse exactly num_inputs input maps, then num_outputs output maps
        for i in 0..num_inputs {
            if offset >= data.len() {
                return Err(SignerError::ParseError(format!(
                    "PSBT truncated: expected {} inputs, got {}",
                    num_inputs, i
                )));
            }
            psbt.inputs.push(parse_kv_map(data, &mut offset)?);
        }
        for i in 0..num_outputs {
            if offset >= data.len() {
                return Err(SignerError::ParseError(format!(
                    "PSBT truncated: expected {} outputs, got {}",
                    num_outputs, i
                )));
            }
            psbt.outputs.push(parse_kv_map(data, &mut offset)?);
        }

        // Reject trailing bytes
        if offset != data.len() {
            return Err(SignerError::ParseError(format!(
                "PSBT has {} trailing bytes",
                data.len() - offset
            )));
        }

        Ok(psbt)
    }

    /// Compute the PSBT ID (SHA256 of the serialized PSBT).
    pub fn psbt_id(&self) -> [u8; 32] {
        let serialized = self.serialize();
        crypto::sha256(&serialized)
    }
}

impl Default for Psbt {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Parsing Helpers ────────────────────────────────────────────────

/// Parse a key-value map from PSBT binary data.
fn parse_kv_map(
    data: &[u8],
    offset: &mut usize,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, SignerError> {
    let mut map = BTreeMap::new();

    loop {
        if *offset >= data.len() {
            return Ok(map);
        }

        // Read key length
        let key_len = encoding::read_compact_size(data, offset)?;
        if key_len == 0 {
            // End of map
            return Ok(map);
        }

        // Read key
        let key_len_usize = key_len as usize;
        let end = offset.checked_add(key_len_usize).ok_or_else(|| {
            SignerError::ParseError("PSBT key length overflow".into())
        })?;
        if end > data.len() {
            return Err(SignerError::ParseError("PSBT key truncated".into()));
        }
        let key = data[*offset..end].to_vec();
        *offset = end;

        // Read value length
        let val_len = encoding::read_compact_size(data, offset)?;

        // Read value
        let val_len_usize = val_len as usize;
        let end = offset.checked_add(val_len_usize).ok_or_else(|| {
            SignerError::ParseError("PSBT value length overflow".into())
        })?;
        if end > data.len() {
            return Err(SignerError::ParseError("PSBT value truncated".into()));
        }
        let value = data[*offset..end].to_vec();
        *offset = end;

        // Reject duplicate keys (BIP-174 requirement)
        if map.contains_key(&key) {
            return Err(SignerError::ParseError(
                "PSBT: duplicate key in map".into(),
            ));
        }
        map.insert(key, value);
    }
}

/// Extract input and output counts from a raw unsigned transaction.
///
/// Parses just enough of the transaction to read the varint counts.
/// Returns `None` if the data is too short or malformed.
fn extract_tx_io_counts(raw_tx: &[u8]) -> Option<(usize, usize)> {
    if raw_tx.len() < 10 {
        return None; // Too short for any valid tx
    }
    // Skip version (4 bytes)
    let mut offset = 4;
    // Read input count
    let num_inputs = encoding::read_compact_size(raw_tx, &mut offset).ok()? as usize;
    // Skip all inputs: each has outpoint(36) + varint(script_len) + script + sequence(4)
    for _ in 0..num_inputs {
        // outpoint (32 txid + 4 vout)
        if offset + 36 > raw_tx.len() {
            return None;
        }
        offset += 36;
        // scriptSig length + data
        let script_len = encoding::read_compact_size(raw_tx, &mut offset).ok()? as usize;
        if offset + script_len + 4 > raw_tx.len() {
            return None;
        }
        offset += script_len;
        // sequence
        offset += 4;
    }
    // Read output count
    let num_outputs = encoding::read_compact_size(raw_tx, &mut offset).ok()? as usize;
    // Sanity check
    if num_inputs > 10_000 || num_outputs > 10_000 {
        return None;
    }
    Some((num_inputs, num_outputs))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_psbt_new() {
        let psbt = Psbt::new();
        assert!(psbt.global.is_empty());
        assert!(psbt.inputs.is_empty());
        assert!(psbt.outputs.is_empty());
    }

    #[test]
    fn test_psbt_set_unsigned_tx() {
        let mut psbt = Psbt::new();
        let fake_tx = vec![0x01, 0x02, 0x03, 0x04];
        psbt.set_unsigned_tx(&fake_tx);
        assert_eq!(psbt.unsigned_tx(), Some(&fake_tx));
    }

    #[test]
    fn test_psbt_add_input_output() {
        let mut psbt = Psbt::new();
        let idx_in = psbt.add_input();
        assert_eq!(idx_in, 0);
        let idx_out = psbt.add_output();
        assert_eq!(idx_out, 0);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 1);
    }

    #[test]
    fn test_psbt_serialize_magic() {
        let psbt = Psbt::new();
        let data = psbt.serialize();
        assert_eq!(&data[..4], &PSBT_MAGIC);
        assert_eq!(data[4], PSBT_SEPARATOR);
    }

    #[test]
    fn test_psbt_serialize_deserialize_roundtrip() {
        let mut psbt = Psbt::new();
        // Build a minimal valid unsigned tx: version(4) + 0 inputs + 0 outputs + locktime(4)
        let mut raw_tx = Vec::new();
        raw_tx.extend_from_slice(&1i32.to_le_bytes()); // version
        raw_tx.push(0x01); // 1 input
        raw_tx.extend_from_slice(&[0xAA; 32]); // txid
        raw_tx.extend_from_slice(&0u32.to_le_bytes()); // vout
        raw_tx.push(0x00); // empty scriptSig
        raw_tx.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // sequence
        raw_tx.push(0x01); // 1 output
        raw_tx.extend_from_slice(&50000u64.to_le_bytes()); // value
        raw_tx.push(0x00); // empty scriptPubKey
        raw_tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        psbt.set_unsigned_tx(&raw_tx);
        let idx = psbt.add_input();
        psbt.add_output();
        let script_pk = [
            0x00u8, 0x14, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];
        psbt.set_witness_utxo(idx, 50000, &script_pk);

        let serialized = psbt.serialize();
        let parsed = Psbt::deserialize(&serialized).expect("valid PSBT");

        // Global should match
        assert_eq!(parsed.global.len(), psbt.global.len());
        assert_eq!(parsed.unsigned_tx(), psbt.unsigned_tx());
    }

    #[test]
    fn test_psbt_deserialize_invalid() {
        assert!(Psbt::deserialize(&[]).is_err());
        assert!(Psbt::deserialize(&[0x00, 0x01, 0x02, 0x03, 0xFF]).is_err());
        assert!(Psbt::deserialize(&[0x70, 0x73, 0x62, 0x74, 0x00]).is_err()); // wrong separator
    }

    #[test]
    fn test_psbt_set_taproot_fields() {
        let mut psbt = Psbt::new();
        let idx = psbt.add_input();
        let key = [0xAA; 32];
        let root = [0xBB; 32];
        let sig = [0xCC; 64];

        psbt.set_tap_internal_key(idx, &key);
        psbt.set_tap_merkle_root(idx, &root);
        psbt.set_tap_key_sig(idx, &sig);

        let input = &psbt.inputs[0];
        assert_eq!(
            input.get(&vec![InputKey::TapInternalKey as u8]),
            Some(&key.to_vec())
        );
        assert_eq!(
            input.get(&vec![InputKey::TapMerkleRoot as u8]),
            Some(&root.to_vec())
        );
        assert_eq!(
            input.get(&vec![InputKey::TapKeySig as u8]),
            Some(&sig.to_vec())
        );
    }

    #[test]
    fn test_psbt_psbt_id_deterministic() {
        let mut psbt = Psbt::new();
        psbt.set_unsigned_tx(&[0x01, 0x00]);
        let id1 = psbt.psbt_id();
        let id2 = psbt.psbt_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_psbt_empty_roundtrip() {
        let psbt = Psbt::new();
        let data = psbt.serialize();
        // Empty PSBT without unsigned tx should now be rejected
        assert!(Psbt::deserialize(&data).is_err());
    }

    #[test]
    fn test_psbt_multiple_inputs() {
        let mut psbt = Psbt::new();
        psbt.add_input();
        psbt.add_input();
        psbt.add_input();
        assert_eq!(psbt.inputs.len(), 3);
    }

    #[test]
    fn test_compact_size_roundtrip() {
        for val in [0u64, 1, 252, 253, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000] {
            let mut buf = Vec::new();
            encoding::encode_compact_size(&mut buf, val);
            let mut offset = 0;
            let parsed = encoding::read_compact_size(&buf, &mut offset).expect("valid");
            assert_eq!(parsed, val, "failed for value {val}");
        }
    }

    #[test]
    fn test_psbt_witness_utxo() {
        let mut psbt = Psbt::new();
        let idx = psbt.add_input();
        let script_pk = vec![0x00, 0x14, 0xAA, 0xBB, 0xCC]; // simplified
        psbt.set_witness_utxo(idx, 100000, &script_pk);

        let input = &psbt.inputs[0];
        let value = input
            .get(&vec![InputKey::WitnessUtxo as u8])
            .expect("exists");
        // First 8 bytes should be amount in LE
        assert_eq!(&value[..8], &100000u64.to_le_bytes());
    }
}
