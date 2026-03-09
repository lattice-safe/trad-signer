//! **PSBT v2** — BIP-370 Constructor-based PSBT.
//!
//! PSBTv2 separates the global unsigned transaction into per-input/output
//! fields, enabling interactive construction (CoinJoin, Payjoin) where
//! inputs and outputs can be added independently.
//!
//! # Key Differences from v0
//! - No `PSBT_GLOBAL_UNSIGNED_TX` — inputs/outputs use per-map fields
//! - `PSBT_GLOBAL_TX_VERSION`, `PSBT_GLOBAL_FALLBACK_LOCKTIME`
//! - `PSBT_GLOBAL_INPUT_COUNT`, `PSBT_GLOBAL_OUTPUT_COUNT`
//! - `PSBT_GLOBAL_TX_MODIFIABLE` flag for interactive construction
//! - Per-input: `PREVIOUS_TXID`, `OUTPUT_INDEX`, `SEQUENCE`
//! - Per-output: `AMOUNT`, `SCRIPT`

use crate::error::SignerError;

// ═══════════════════════════════════════════════════════════════════
// Constants — Global Key Types (BIP-370)
// ═══════════════════════════════════════════════════════════════════

/// PSBT v2 global key types.
pub mod global_key {
    /// Transaction version (4-byte LE uint32).
    pub const TX_VERSION: u8 = 0x02;
    /// Fallback locktime (4-byte LE uint32).
    pub const FALLBACK_LOCKTIME: u8 = 0x03;
    /// Number of inputs (compact-size uint).
    pub const INPUT_COUNT: u8 = 0x04;
    /// Number of outputs (compact-size uint).
    pub const OUTPUT_COUNT: u8 = 0x05;
    /// Modifiable flags (1 byte).
    pub const TX_MODIFIABLE: u8 = 0x06;
    /// PSBT version (4-byte LE uint32, must be 2).
    pub const VERSION: u8 = 0xFB;
}

/// PSBT v2 per-input key types.
pub mod input_key {
    /// Previous txid (32 bytes, reversed).
    pub const PREVIOUS_TXID: u8 = 0x0E;
    /// Output index (4-byte LE uint32).
    pub const OUTPUT_INDEX: u8 = 0x0F;
    /// Sequence number (4-byte LE uint32).
    pub const SEQUENCE: u8 = 0x10;
    /// Required time-based locktime.
    pub const REQUIRED_TIME_LOCKTIME: u8 = 0x11;
    /// Required height-based locktime.
    pub const REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
    // v0-compatible keys reused in v2:
    /// Non-witness UTXO.
    pub const NON_WITNESS_UTXO: u8 = 0x00;
    /// Witness UTXO.
    pub const WITNESS_UTXO: u8 = 0x01;
    /// Partial signature.
    pub const PARTIAL_SIG: u8 = 0x02;
    /// Sighash type.
    pub const SIGHASH_TYPE: u8 = 0x03;
}

/// PSBT v2 per-output key types.
pub mod output_key {
    /// Output amount (8-byte LE int64).
    pub const AMOUNT: u8 = 0x03;
    /// Output script (variable length).
    pub const SCRIPT: u8 = 0x04;
    // v0-compatible keys:
    /// Redeem script.
    pub const REDEEM_SCRIPT: u8 = 0x00;
    /// Witness script.
    pub const WITNESS_SCRIPT: u8 = 0x01;
}

// ═══════════════════════════════════════════════════════════════════
// Modifiable Flags
// ═══════════════════════════════════════════════════════════════════

/// Flags indicating which parts of the PSBT can be modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModifiableFlags(u8);

impl ModifiableFlags {
    /// No modifications allowed.
    pub const NONE: Self = Self(0);
    /// Inputs can be added/removed.
    pub const INPUTS_MODIFIABLE: Self = Self(0x01);
    /// Outputs can be added/removed.
    pub const OUTPUTS_MODIFIABLE: Self = Self(0x02);
    /// Sighash type can include ANYONECANPAY.
    pub const HAS_SIGHASH_SINGLE: Self = Self(0x04);

    /// Create flags from raw byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Get the raw byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    /// Check if inputs are modifiable.
    #[must_use]
    pub const fn inputs_modifiable(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Check if outputs are modifiable.
    #[must_use]
    pub const fn outputs_modifiable(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Combine two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ═══════════════════════════════════════════════════════════════════
// PSBT v2 Input
// ═══════════════════════════════════════════════════════════════════

/// A PSBTv2 input with explicit fields.
#[derive(Debug, Clone)]
pub struct PsbtV2Input {
    /// Previous transaction ID (32 bytes, internal byte order).
    pub previous_txid: [u8; 32],
    /// Output index being spent.
    pub output_index: u32,
    /// Sequence number (default: 0xFFFFFFFF).
    pub sequence: u32,
    /// Required time-based locktime for this input.
    pub required_time_locktime: Option<u32>,
    /// Required height-based locktime for this input.
    pub required_height_locktime: Option<u32>,
    /// Additional key-value pairs (witness UTXO, sigs, etc.).
    pub extra: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PsbtV2Input {
    /// Create a new input referencing a specific UTXO.
    #[must_use]
    pub fn new(previous_txid: [u8; 32], output_index: u32) -> Self {
        Self {
            previous_txid,
            output_index,
            sequence: 0xFFFFFFFF,
            required_time_locktime: None,
            required_height_locktime: None,
            extra: Vec::new(),
        }
    }

    /// Set the sequence number.
    #[must_use]
    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = sequence;
        self
    }

    /// Set a witness UTXO for this input.
    pub fn set_witness_utxo(&mut self, amount: u64, script_pubkey: &[u8]) {
        let mut value = Vec::with_capacity(8 + script_pubkey.len() + 1);
        value.extend_from_slice(&amount.to_le_bytes());
        // CompactSize for script length
        value.push(script_pubkey.len() as u8);
        value.extend_from_slice(script_pubkey);
        self.extra.push((vec![input_key::WITNESS_UTXO], value));
    }

    /// Serialize this input map to PSBTv2 format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // PREVIOUS_TXID
        write_kv(&mut buf, &[input_key::PREVIOUS_TXID], &self.previous_txid);
        // OUTPUT_INDEX
        write_kv(
            &mut buf,
            &[input_key::OUTPUT_INDEX],
            &self.output_index.to_le_bytes(),
        );
        // SEQUENCE
        write_kv(
            &mut buf,
            &[input_key::SEQUENCE],
            &self.sequence.to_le_bytes(),
        );

        // Optional timelocks
        if let Some(t) = self.required_time_locktime {
            write_kv(
                &mut buf,
                &[input_key::REQUIRED_TIME_LOCKTIME],
                &t.to_le_bytes(),
            );
        }
        if let Some(h) = self.required_height_locktime {
            write_kv(
                &mut buf,
                &[input_key::REQUIRED_HEIGHT_LOCKTIME],
                &h.to_le_bytes(),
            );
        }

        // Extra KVs
        for (k, v) in &self.extra {
            write_kv(&mut buf, k, v);
        }

        // Terminator
        buf.push(0x00);
        buf
    }
}

// ═══════════════════════════════════════════════════════════════════
// PSBT v2 Output
// ═══════════════════════════════════════════════════════════════════

/// A PSBTv2 output with explicit fields.
#[derive(Debug, Clone)]
pub struct PsbtV2Output {
    /// Output amount in satoshis.
    pub amount: u64,
    /// Output scriptPubKey.
    pub script: Vec<u8>,
    /// Additional key-value pairs.
    pub extra: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PsbtV2Output {
    /// Create a new output.
    #[must_use]
    pub fn new(amount: u64, script: Vec<u8>) -> Self {
        Self {
            amount,
            script,
            extra: Vec::new(),
        }
    }

    /// Serialize this output map to PSBTv2 format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // AMOUNT
        write_kv(&mut buf, &[output_key::AMOUNT], &self.amount.to_le_bytes());
        // SCRIPT
        write_kv(&mut buf, &[output_key::SCRIPT], &self.script);

        // Extra KVs
        for (k, v) in &self.extra {
            write_kv(&mut buf, k, v);
        }

        // Terminator
        buf.push(0x00);
        buf
    }
}

// ═══════════════════════════════════════════════════════════════════
// PSBT v2 Constructor
// ═══════════════════════════════════════════════════════════════════

/// A PSBTv2 (BIP-370) container.
#[derive(Debug, Clone)]
pub struct PsbtV2 {
    /// Transaction version (typically 2).
    pub tx_version: u32,
    /// Fallback locktime.
    pub fallback_locktime: u32,
    /// Modifiable flags.
    pub modifiable: ModifiableFlags,
    /// Per-input data.
    pub inputs: Vec<PsbtV2Input>,
    /// Per-output data.
    pub outputs: Vec<PsbtV2Output>,
    /// Additional global key-value pairs.
    pub global_extra: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PsbtV2 {
    /// Create a new PSBTv2 with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx_version: 2,
            fallback_locktime: 0,
            modifiable: ModifiableFlags::NONE,
            inputs: Vec::new(),
            outputs: Vec::new(),
            global_extra: Vec::new(),
        }
    }

    /// Create a PSBTv2 for interactive construction (CoinJoin/Payjoin).
    ///
    /// Sets inputs and outputs as modifiable.
    #[must_use]
    pub fn new_interactive() -> Self {
        Self {
            modifiable: ModifiableFlags::INPUTS_MODIFIABLE
                .union(ModifiableFlags::OUTPUTS_MODIFIABLE),
            ..Self::new()
        }
    }

    /// Add an input. Returns the input index.
    pub fn add_input(&mut self, input: PsbtV2Input) -> usize {
        self.inputs.push(input);
        self.inputs.len() - 1
    }

    /// Add an output. Returns the output index.
    pub fn add_output(&mut self, output: PsbtV2Output) -> usize {
        self.outputs.push(output);
        self.outputs.len() - 1
    }

    /// Compute the effective locktime.
    ///
    /// Per BIP-370: uses the maximum of all required timelocks,
    /// falling back to the global fallback_locktime.
    #[must_use]
    pub fn computed_locktime(&self) -> u32 {
        let mut max_time: Option<u32> = None;
        let mut max_height: Option<u32> = None;

        for input in &self.inputs {
            if let Some(t) = input.required_time_locktime {
                max_time = Some(max_time.map_or(t, |m: u32| m.max(t)));
            }
            if let Some(h) = input.required_height_locktime {
                max_height = Some(max_height.map_or(h, |m: u32| m.max(h)));
            }
        }

        // Height-based takes priority if both present
        if let Some(h) = max_height {
            return h;
        }
        if let Some(t) = max_time {
            return t;
        }

        self.fallback_locktime
    }

    /// Serialize to PSBTv2 binary format.
    ///
    /// Format: `magic || 0xFF || global_map || input_maps... || output_maps...`
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Magic bytes
        buf.extend_from_slice(b"psbt\xFF");

        // ─── Global Map ─────────────────────────────────────────
        // Version = 2
        write_kv(
            &mut buf,
            &[global_key::VERSION],
            &2u32.to_le_bytes(),
        );
        // TX_VERSION
        write_kv(
            &mut buf,
            &[global_key::TX_VERSION],
            &self.tx_version.to_le_bytes(),
        );
        // FALLBACK_LOCKTIME
        write_kv(
            &mut buf,
            &[global_key::FALLBACK_LOCKTIME],
            &self.fallback_locktime.to_le_bytes(),
        );
        // INPUT_COUNT
        write_kv(
            &mut buf,
            &[global_key::INPUT_COUNT],
            &compact_size(self.inputs.len()),
        );
        // OUTPUT_COUNT
        write_kv(
            &mut buf,
            &[global_key::OUTPUT_COUNT],
            &compact_size(self.outputs.len()),
        );
        // TX_MODIFIABLE
        if self.modifiable.to_byte() != 0 {
            write_kv(
                &mut buf,
                &[global_key::TX_MODIFIABLE],
                &[self.modifiable.to_byte()],
            );
        }

        // Extra global KVs
        for (k, v) in &self.global_extra {
            write_kv(&mut buf, k, v);
        }

        // Global map terminator
        buf.push(0x00);

        // ─── Input Maps ─────────────────────────────────────────
        for input in &self.inputs {
            buf.extend_from_slice(&input.serialize());
        }

        // ─── Output Maps ────────────────────────────────────────
        for output in &self.outputs {
            buf.extend_from_slice(&output.serialize());
        }

        buf
    }

    /// Deserialize a PSBTv2 from binary format.
    pub fn deserialize(data: &[u8]) -> Result<Self, SignerError> {
        if data.len() < 5 || &data[0..5] != b"psbt\xFF" {
            return Err(SignerError::ParseError("invalid PSBT magic".into()));
        }

        let mut pos = 5;
        let mut psbt = PsbtV2::new();
        let mut input_count: Option<usize> = None;
        let mut output_count: Option<usize> = None;
        let mut found_version = false;

        // Parse global map
        while pos < data.len() {
            if data[pos] == 0x00 {
                pos += 1;
                break;
            }

            let (key, val, consumed) = read_kv(&data[pos..])?;
            pos += consumed;

            if key.len() == 1 {
                match key[0] {
                    global_key::VERSION => {
                        if val.len() == 4 {
                            let v = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                            if v != 2 {
                                return Err(SignerError::ParseError(
                                    format!("expected PSBT version 2, got {v}"),
                                ));
                            }
                            found_version = true;
                        }
                    }
                    global_key::TX_VERSION => {
                        if val.len() == 4 {
                            psbt.tx_version =
                                u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                        }
                    }
                    global_key::FALLBACK_LOCKTIME => {
                        if val.len() == 4 {
                            psbt.fallback_locktime =
                                u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                        }
                    }
                    global_key::INPUT_COUNT => {
                        input_count = Some(read_compact_size(&val));
                    }
                    global_key::OUTPUT_COUNT => {
                        output_count = Some(read_compact_size(&val));
                    }
                    global_key::TX_MODIFIABLE => {
                        if !val.is_empty() {
                            psbt.modifiable = ModifiableFlags::from_byte(val[0]);
                        }
                    }
                    _ => {
                        psbt.global_extra.push((key, val));
                    }
                }
            } else {
                psbt.global_extra.push((key, val));
            }
        }

        if !found_version {
            return Err(SignerError::ParseError("missing PSBT version".into()));
        }

        let n_inputs = input_count
            .ok_or_else(|| SignerError::ParseError("missing input count".into()))?;
        let n_outputs = output_count
            .ok_or_else(|| SignerError::ParseError("missing output count".into()))?;

        // Parse input maps
        for _ in 0..n_inputs {
            let mut input = PsbtV2Input::new([0; 32], 0);
            while pos < data.len() {
                if data[pos] == 0x00 {
                    pos += 1;
                    break;
                }
                let (key, val, consumed) = read_kv(&data[pos..])?;
                pos += consumed;

                if key.len() == 1 {
                    match key[0] {
                        input_key::PREVIOUS_TXID => {
                            if val.len() == 32 {
                                input.previous_txid.copy_from_slice(&val);
                            }
                        }
                        input_key::OUTPUT_INDEX => {
                            if val.len() == 4 {
                                input.output_index =
                                    u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                            }
                        }
                        input_key::SEQUENCE => {
                            if val.len() == 4 {
                                input.sequence =
                                    u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                            }
                        }
                        input_key::REQUIRED_TIME_LOCKTIME => {
                            if val.len() == 4 {
                                input.required_time_locktime = Some(u32::from_le_bytes([
                                    val[0], val[1], val[2], val[3],
                                ]));
                            }
                        }
                        input_key::REQUIRED_HEIGHT_LOCKTIME => {
                            if val.len() == 4 {
                                input.required_height_locktime = Some(u32::from_le_bytes([
                                    val[0], val[1], val[2], val[3],
                                ]));
                            }
                        }
                        _ => {
                            input.extra.push((key, val));
                        }
                    }
                } else {
                    input.extra.push((key, val));
                }
            }
            psbt.inputs.push(input);
        }

        // Parse output maps
        for _ in 0..n_outputs {
            let mut output = PsbtV2Output::new(0, Vec::new());
            while pos < data.len() {
                if data[pos] == 0x00 {
                    pos += 1;
                    break;
                }
                let (key, val, consumed) = read_kv(&data[pos..])?;
                pos += consumed;

                if key.len() == 1 {
                    match key[0] {
                        output_key::AMOUNT => {
                            if val.len() == 8 {
                                output.amount = u64::from_le_bytes([
                                    val[0], val[1], val[2], val[3], val[4], val[5], val[6],
                                    val[7],
                                ]);
                            }
                        }
                        output_key::SCRIPT => {
                            output.script = val;
                        }
                        _ => {
                            output.extra.push((key, val));
                        }
                    }
                } else {
                    output.extra.push((key, val));
                }
            }
            psbt.outputs.push(output);
        }

        Ok(psbt)
    }
}

impl Default for PsbtV2 {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Write a PSBT key-value pair: `compact_size(key_len) || key || compact_size(val_len) || val`
fn write_kv(buf: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    buf.extend_from_slice(&compact_size(key.len()));
    buf.extend_from_slice(key);
    buf.extend_from_slice(&compact_size(value.len()));
    buf.extend_from_slice(value);
}

/// Read a PSBT key-value pair. Returns (key, value, bytes_consumed).
fn read_kv(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, usize), SignerError> {
    let mut pos = 0;

    // Key length
    let (key_len, consumed) = read_compact_size_at(data, pos)?;
    pos += consumed;
    if pos + key_len > data.len() {
        return Err(SignerError::ParseError("truncated PSBT key".into()));
    }
    let key = data[pos..pos + key_len].to_vec();
    pos += key_len;

    // Value length
    let (val_len, consumed) = read_compact_size_at(data, pos)?;
    pos += consumed;
    if pos + val_len > data.len() {
        return Err(SignerError::ParseError("truncated PSBT value".into()));
    }
    let value = data[pos..pos + val_len].to_vec();
    pos += val_len;

    Ok((key, value, pos))
}

/// Encode a compact size integer.
fn compact_size(n: usize) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    }
}

/// Read a compact_size from a serialized value.
fn read_compact_size(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    if data[0] < 0xFD {
        data[0] as usize
    } else if data[0] == 0xFD && data.len() >= 3 {
        u16::from_le_bytes([data[1], data[2]]) as usize
    } else if data[0] == 0xFE && data.len() >= 5 {
        u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize
    } else {
        0
    }
}

/// Read a compact_size at a position. Returns (value, bytes_consumed).
fn read_compact_size_at(data: &[u8], pos: usize) -> Result<(usize, usize), SignerError> {
    if pos >= data.len() {
        return Err(SignerError::ParseError("unexpected end of PSBT".into()));
    }
    let first = data[pos];
    if first < 0xFD {
        Ok((first as usize, 1))
    } else if first == 0xFD {
        if pos + 3 > data.len() {
            return Err(SignerError::ParseError("truncated compact size".into()));
        }
        let val = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
        Ok((val, 3))
    } else if first == 0xFE {
        if pos + 5 > data.len() {
            return Err(SignerError::ParseError("truncated compact size".into()));
        }
        let val = u32::from_le_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
            as usize;
        Ok((val, 5))
    } else {
        Err(SignerError::ParseError("unsupported compact size".into()))
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ─── Construction ────────────────────────────────────────────

    #[test]
    fn test_psbtv2_new_defaults() {
        let psbt = PsbtV2::new();
        assert_eq!(psbt.tx_version, 2);
        assert_eq!(psbt.fallback_locktime, 0);
        assert_eq!(psbt.modifiable.to_byte(), 0);
        assert!(psbt.inputs.is_empty());
        assert!(psbt.outputs.is_empty());
    }

    #[test]
    fn test_psbtv2_interactive() {
        let psbt = PsbtV2::new_interactive();
        assert!(psbt.modifiable.inputs_modifiable());
        assert!(psbt.modifiable.outputs_modifiable());
    }

    #[test]
    fn test_add_input() {
        let mut psbt = PsbtV2::new();
        let idx = psbt.add_input(PsbtV2Input::new([0xAA; 32], 0));
        assert_eq!(idx, 0);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.inputs[0].previous_txid, [0xAA; 32]);
    }

    #[test]
    fn test_add_multiple_inputs() {
        let mut psbt = PsbtV2::new();
        let i0 = psbt.add_input(PsbtV2Input::new([0x01; 32], 0));
        let i1 = psbt.add_input(PsbtV2Input::new([0x02; 32], 1));
        let i2 = psbt.add_input(PsbtV2Input::new([0x03; 32], 2));
        assert_eq!(i0, 0);
        assert_eq!(i1, 1);
        assert_eq!(i2, 2);
        assert_eq!(psbt.inputs[2].output_index, 2);
    }

    #[test]
    fn test_add_output() {
        let mut psbt = PsbtV2::new();
        let idx = psbt.add_output(PsbtV2Output::new(50_000, vec![0x00, 0x14]));
        assert_eq!(idx, 0);
        assert_eq!(psbt.outputs.len(), 1);
        assert_eq!(psbt.outputs[0].amount, 50_000);
    }

    #[test]
    fn test_input_default_sequence() {
        let input = PsbtV2Input::new([0; 32], 0);
        assert_eq!(input.sequence, 0xFFFFFFFF);
    }

    #[test]
    fn test_input_with_sequence() {
        let input = PsbtV2Input::new([0; 32], 0).with_sequence(0xFFFFFFFD);
        assert_eq!(input.sequence, 0xFFFFFFFD);
    }

    #[test]
    fn test_input_rbf_sequence() {
        // RBF = 0xFFFFFFFD (enables opt-in Replace-By-Fee)
        let input = PsbtV2Input::new([0; 32], 0).with_sequence(0xFFFFFFFD);
        assert_eq!(input.sequence, 0xFFFFFFFD);
        assert_ne!(input.sequence, 0xFFFFFFFF);
    }

    // ─── Witness UTXO ────────────────────────────────────────────

    #[test]
    fn test_set_witness_utxo() {
        let mut input = PsbtV2Input::new([0; 32], 0);
        let script = vec![0x00, 0x14, 0xAA, 0xBB];
        input.set_witness_utxo(100_000, &script);
        assert_eq!(input.extra.len(), 1);
        assert_eq!(input.extra[0].0, vec![input_key::WITNESS_UTXO]);
    }

    #[test]
    fn test_witness_utxo_encoding() {
        let mut input = PsbtV2Input::new([0; 32], 0);
        let script = vec![0x00, 0x14, 0xAA, 0xBB];
        input.set_witness_utxo(100_000, &script);
        let value = &input.extra[0].1;
        // First 8 bytes: amount LE
        let amount = u64::from_le_bytes(value[0..8].try_into().unwrap());
        assert_eq!(amount, 100_000);
        // Then compact size + script
        assert_eq!(value[8], 4); // script length
        assert_eq!(&value[9..13], &script[..]);
    }

    // ─── Computed Locktime ───────────────────────────────────────

    #[test]
    fn test_computed_locktime_fallback() {
        let mut psbt = PsbtV2::new();
        psbt.fallback_locktime = 800_000;
        assert_eq!(psbt.computed_locktime(), 800_000);
    }

    #[test]
    fn test_computed_locktime_no_inputs() {
        let psbt = PsbtV2::new();
        assert_eq!(psbt.computed_locktime(), 0);
    }

    #[test]
    fn test_computed_locktime_height_priority() {
        let mut psbt = PsbtV2::new();
        let mut i1 = PsbtV2Input::new([0; 32], 0);
        i1.required_time_locktime = Some(1_700_000_000);
        i1.required_height_locktime = Some(800_000);
        psbt.add_input(i1);
        assert_eq!(psbt.computed_locktime(), 800_000);
    }

    #[test]
    fn test_computed_locktime_time_only() {
        let mut psbt = PsbtV2::new();
        let mut i1 = PsbtV2Input::new([0; 32], 0);
        i1.required_time_locktime = Some(1_700_000_000);
        psbt.add_input(i1);
        assert_eq!(psbt.computed_locktime(), 1_700_000_000);
    }

    #[test]
    fn test_computed_locktime_max_across_inputs() {
        let mut psbt = PsbtV2::new();
        let mut i1 = PsbtV2Input::new([0; 32], 0);
        i1.required_height_locktime = Some(100_000);
        let mut i2 = PsbtV2Input::new([1; 32], 0);
        i2.required_height_locktime = Some(200_000);
        psbt.add_input(i1);
        psbt.add_input(i2);
        assert_eq!(psbt.computed_locktime(), 200_000);
    }

    #[test]
    fn test_computed_locktime_max_time_across_inputs() {
        let mut psbt = PsbtV2::new();
        let mut i1 = PsbtV2Input::new([0; 32], 0);
        i1.required_time_locktime = Some(1_600_000_000);
        let mut i2 = PsbtV2Input::new([1; 32], 0);
        i2.required_time_locktime = Some(1_700_000_000);
        psbt.add_input(i1);
        psbt.add_input(i2);
        assert_eq!(psbt.computed_locktime(), 1_700_000_000);
    }

    #[test]
    fn test_computed_locktime_inputs_without_timelocks() {
        let mut psbt = PsbtV2::new();
        psbt.fallback_locktime = 500_000;
        psbt.add_input(PsbtV2Input::new([0; 32], 0));
        psbt.add_input(PsbtV2Input::new([1; 32], 0));
        // No timelocks set → falls back
        assert_eq!(psbt.computed_locktime(), 500_000);
    }

    // ─── Modifiable Flags ────────────────────────────────────────

    #[test]
    fn test_modifiable_flags_none() {
        let f = ModifiableFlags::NONE;
        assert!(!f.inputs_modifiable());
        assert!(!f.outputs_modifiable());
    }

    #[test]
    fn test_modifiable_flags_inputs_only() {
        let f = ModifiableFlags::INPUTS_MODIFIABLE;
        assert!(f.inputs_modifiable());
        assert!(!f.outputs_modifiable());
    }

    #[test]
    fn test_modifiable_flags_outputs_only() {
        let f = ModifiableFlags::OUTPUTS_MODIFIABLE;
        assert!(!f.inputs_modifiable());
        assert!(f.outputs_modifiable());
    }

    #[test]
    fn test_modifiable_flags_union() {
        let f = ModifiableFlags::INPUTS_MODIFIABLE.union(ModifiableFlags::OUTPUTS_MODIFIABLE);
        assert!(f.inputs_modifiable());
        assert!(f.outputs_modifiable());
        assert_eq!(f.to_byte(), 0x03);
    }

    #[test]
    fn test_modifiable_flags_sighash_single() {
        let f = ModifiableFlags::HAS_SIGHASH_SINGLE;
        assert!(!f.inputs_modifiable());
        assert!(!f.outputs_modifiable());
        assert_eq!(f.to_byte(), 0x04);
    }

    #[test]
    fn test_modifiable_flags_all() {
        let f = ModifiableFlags::INPUTS_MODIFIABLE
            .union(ModifiableFlags::OUTPUTS_MODIFIABLE)
            .union(ModifiableFlags::HAS_SIGHASH_SINGLE);
        assert_eq!(f.to_byte(), 0x07);
    }

    #[test]
    fn test_modifiable_flags_from_byte() {
        let f = ModifiableFlags::from_byte(0xFF);
        assert!(f.inputs_modifiable());
        assert!(f.outputs_modifiable());
        assert_eq!(f.to_byte(), 0xFF);
    }

    // ─── Serialization Round-Trip ────────────────────────────────

    #[test]
    fn test_serialize_roundtrip() {
        let mut psbt = PsbtV2::new();
        psbt.tx_version = 2;
        psbt.fallback_locktime = 800_000;
        psbt.modifiable = ModifiableFlags::INPUTS_MODIFIABLE;

        let input = PsbtV2Input::new([0xBB; 32], 1).with_sequence(0xFFFFFFFD);
        psbt.add_input(input);

        let output = PsbtV2Output::new(50_000, vec![0xCC; 20]);
        psbt.add_output(output);

        let serialized = psbt.serialize();
        let deserialized = PsbtV2::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.tx_version, 2);
        assert_eq!(deserialized.fallback_locktime, 800_000);
        assert!(deserialized.modifiable.inputs_modifiable());
        assert!(!deserialized.modifiable.outputs_modifiable());
        assert_eq!(deserialized.inputs.len(), 1);
        assert_eq!(deserialized.outputs.len(), 1);
        assert_eq!(deserialized.inputs[0].previous_txid, [0xBB; 32]);
        assert_eq!(deserialized.inputs[0].output_index, 1);
        assert_eq!(deserialized.inputs[0].sequence, 0xFFFFFFFD);
        assert_eq!(deserialized.outputs[0].amount, 50_000);
    }

    #[test]
    fn test_serialize_empty_psbt_roundtrip() {
        let psbt = PsbtV2::new();
        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.tx_version, 2);
        assert_eq!(rt.inputs.len(), 0);
        assert_eq!(rt.outputs.len(), 0);
    }

    #[test]
    fn test_serialize_starts_with_magic() {
        let psbt = PsbtV2::new();
        let data = psbt.serialize();
        assert_eq!(&data[0..5], b"psbt\xFF");
    }

    #[test]
    fn test_serialize_output_script_preserved() {
        let script = vec![0x76, 0xA9, 0x14, 0xAA, 0xBB, 0xCC];
        let mut psbt = PsbtV2::new();
        psbt.add_output(PsbtV2Output::new(1_000_000, script.clone()));
        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.outputs[0].script, script);
    }

    #[test]
    fn test_serialize_large_amount() {
        let mut psbt = PsbtV2::new();
        psbt.add_output(PsbtV2Output::new(21_000_000 * 100_000_000, vec![0x00]));
        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.outputs[0].amount, 21_000_000 * 100_000_000);
    }

    #[test]
    fn test_serialize_roundtrip_with_timelocks() {
        let mut psbt = PsbtV2::new();
        let mut input = PsbtV2Input::new([0xAA; 32], 0);
        input.required_time_locktime = Some(1_700_000_000);
        input.required_height_locktime = Some(800_000);
        psbt.add_input(input);

        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.inputs[0].required_time_locktime, Some(1_700_000_000));
        assert_eq!(rt.inputs[0].required_height_locktime, Some(800_000));
    }

    // ─── Deserialization Errors ──────────────────────────────────

    #[test]
    fn test_deserialize_invalid_magic() {
        let result = PsbtV2::deserialize(b"not_a_psbt");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_too_short() {
        let result = PsbtV2::deserialize(b"psbt");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_empty() {
        let result = PsbtV2::deserialize(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_deserialize_wrong_version() {
        // Construct a valid-looking PSBT but with version=1
        let mut psbt = PsbtV2::new();
        let data = psbt.serialize();
        // Manually patch the version to 1
        let mut patched = data.clone();
        // Find version KV and change value
        // Version is first KV after magic: key_len=1, key=0xFB, val_len=4, val=02000000
        // Position: 5 (magic) + 1 (key_len) + 1(key) + 1(val_len) = 8, then 4 bytes value
        patched[8] = 1; // change version to 1
        let result = PsbtV2::deserialize(&patched);
        assert!(result.is_err());
    }

    // ─── Multiple Inputs/Outputs ─────────────────────────────────

    #[test]
    fn test_roundtrip_multiple_io() {
        let mut psbt = PsbtV2::new();
        for i in 0..3u8 {
            psbt.add_input(PsbtV2Input::new([i; 32], i as u32));
            psbt.add_output(PsbtV2Output::new(
                (i as u64 + 1) * 10_000,
                vec![0x00, 0x14, i],
            ));
        }

        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.inputs.len(), 3);
        assert_eq!(rt.outputs.len(), 3);
        assert_eq!(rt.inputs[2].previous_txid, [2; 32]);
        assert_eq!(rt.outputs[1].amount, 20_000);
    }

    #[test]
    fn test_roundtrip_10_inputs() {
        let mut psbt = PsbtV2::new();
        for i in 0..10u8 {
            psbt.add_input(PsbtV2Input::new([i; 32], i as u32));
        }
        psbt.add_output(PsbtV2Output::new(1_000_000, vec![0x00]));

        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.inputs.len(), 10);
        for i in 0..10u8 {
            assert_eq!(rt.inputs[i as usize].previous_txid, [i; 32]);
            assert_eq!(rt.inputs[i as usize].output_index, i as u32);
        }
    }

    #[test]
    fn test_roundtrip_asymmetric_io() {
        // 5 inputs, 2 outputs
        let mut psbt = PsbtV2::new();
        for i in 0..5u8 {
            psbt.add_input(PsbtV2Input::new([i; 32], 0));
        }
        for i in 0..2u8 {
            psbt.add_output(PsbtV2Output::new(50_000, vec![i]));
        }

        let data = psbt.serialize();
        let rt = PsbtV2::deserialize(&data).unwrap();
        assert_eq!(rt.inputs.len(), 5);
        assert_eq!(rt.outputs.len(), 2);
    }

    // ─── Compact Size ────────────────────────────────────────────

    #[test]
    fn test_compact_size_small() {
        assert_eq!(compact_size(0), vec![0]);
        assert_eq!(compact_size(252), vec![252]);
    }

    #[test]
    fn test_compact_size_boundary_253() {
        // 253 triggers 0xFD prefix
        let cs = compact_size(253);
        assert_eq!(cs[0], 0xFD);
        assert_eq!(u16::from_le_bytes([cs[1], cs[2]]), 253);
    }

    #[test]
    fn test_compact_size_medium() {
        let cs = compact_size(300);
        assert_eq!(cs[0], 0xFD);
        assert_eq!(u16::from_le_bytes([cs[1], cs[2]]), 300);
    }

    #[test]
    fn test_compact_size_max_u16() {
        let cs = compact_size(65535);
        assert_eq!(cs[0], 0xFD);
        assert_eq!(u16::from_le_bytes([cs[1], cs[2]]), 65535);
    }

    #[test]
    fn test_compact_size_large() {
        let cs = compact_size(70000);
        assert_eq!(cs[0], 0xFE);
        assert_eq!(
            u32::from_le_bytes([cs[1], cs[2], cs[3], cs[4]]),
            70000
        );
    }

    // ─── Read Compact Size ───────────────────────────────────────

    #[test]
    fn test_read_compact_size_small() {
        assert_eq!(read_compact_size(&[42]), 42);
        assert_eq!(read_compact_size(&[0]), 0);
        assert_eq!(read_compact_size(&[252]), 252);
    }

    #[test]
    fn test_read_compact_size_medium() {
        let data = [0xFD, 0x00, 0x01]; // 256
        assert_eq!(read_compact_size(&data), 256);
    }

    #[test]
    fn test_read_compact_size_empty() {
        assert_eq!(read_compact_size(&[]), 0);
    }

    // ─── KV Helpers ──────────────────────────────────────────────

    #[test]
    fn test_write_kv_roundtrip() {
        let mut buf = Vec::new();
        write_kv(&mut buf, &[0x42], &[0xAA, 0xBB, 0xCC]);
        let (key, val, consumed) = read_kv(&buf).unwrap();
        assert_eq!(key, vec![0x42]);
        assert_eq!(val, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_write_kv_empty_value() {
        let mut buf = Vec::new();
        write_kv(&mut buf, &[0x01], &[]);
        let (key, val, consumed) = read_kv(&buf).unwrap();
        assert_eq!(key, vec![0x01]);
        assert!(val.is_empty());
        assert_eq!(consumed, buf.len());
    }

    // ─── Input Serialization ────────────────────────────────────

    #[test]
    fn test_input_serialize_basic() {
        let input = PsbtV2Input::new([0xAA; 32], 5);
        let data = input.serialize();
        // Should end with terminator 0x00
        assert_eq!(data[data.len() - 1], 0x00);
    }

    #[test]
    fn test_input_serialize_with_witness_utxo() {
        let mut input = PsbtV2Input::new([0; 32], 0);
        input.set_witness_utxo(50_000, &[0x00, 0x14]);
        let data = input.serialize();
        assert!(data.len() > 40); // must be bigger than just basic fields
    }

    // ─── Output Serialization ───────────────────────────────────

    #[test]
    fn test_output_serialize_basic() {
        let output = PsbtV2Output::new(100_000, vec![0xAA, 0xBB]);
        let data = output.serialize();
        assert_eq!(data[data.len() - 1], 0x00);
    }

    // ─── Default Trait ───────────────────────────────────────────

    #[test]
    fn test_default_trait() {
        let psbt = PsbtV2::default();
        assert_eq!(psbt.tx_version, 2);
    }

    // ─── Global Key Constants ────────────────────────────────────

    #[test]
    fn test_global_key_values() {
        assert_eq!(global_key::TX_VERSION, 0x02);
        assert_eq!(global_key::FALLBACK_LOCKTIME, 0x03);
        assert_eq!(global_key::INPUT_COUNT, 0x04);
        assert_eq!(global_key::OUTPUT_COUNT, 0x05);
        assert_eq!(global_key::TX_MODIFIABLE, 0x06);
        assert_eq!(global_key::VERSION, 0xFB);
    }

    #[test]
    fn test_input_key_values() {
        assert_eq!(input_key::PREVIOUS_TXID, 0x0E);
        assert_eq!(input_key::OUTPUT_INDEX, 0x0F);
        assert_eq!(input_key::SEQUENCE, 0x10);
        assert_eq!(input_key::REQUIRED_TIME_LOCKTIME, 0x11);
        assert_eq!(input_key::REQUIRED_HEIGHT_LOCKTIME, 0x12);
        assert_eq!(input_key::NON_WITNESS_UTXO, 0x00);
        assert_eq!(input_key::WITNESS_UTXO, 0x01);
    }

    #[test]
    fn test_output_key_values() {
        assert_eq!(output_key::AMOUNT, 0x03);
        assert_eq!(output_key::SCRIPT, 0x04);
        assert_eq!(output_key::REDEEM_SCRIPT, 0x00);
        assert_eq!(output_key::WITNESS_SCRIPT, 0x01);
    }
}
