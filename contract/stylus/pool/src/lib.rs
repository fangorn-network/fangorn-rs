#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(feature = "contract-client-gen", allow(unused_imports))]
extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use stylus_sdk::alloy_primitives::{Address, FixedBytes, U256, U64, U32};
use stylus_sdk::alloy_sol_types::sol;
use stylus_sdk::prelude::*;
use stylus_sdk::crypto;

// ──────────────────────────────────────────────
// Events (Solidity ABI-compatible via alloy sol!)
// ──────────────────────────────────────────────
sol! {
    event RequestAdded(bytes32 indexed id, uint64 timestamp);
    event RequestFulfilled(bytes32 indexed id, bytes32 attestation_hash);
    event PartialAttestationSubmitted(bytes32 indexed request_id, address indexed worker, uint32 count);

    error RequestAlreadyExists();
    error RequestNotFound();
    error AlreadyFulfilled();
    error Unauthorized();
    error AlreadyAttested();
}

// ──────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────
const THRESHOLD: u32 = 1;
const TOTAL_WORKERS: usize = 2;

// ──────────────────────────────────────────────
// Storage layout
// ──────────────────────────────────────────────
sol_storage! {
    #[entrypoint]
    pub struct RequestPool {
        // request_id (bytes32) -> encoded DecryptionRequest (filename ++ witness ++ location lengths + data)
        mapping(bytes32 => bytes) requests;

        // track which request IDs exist, for read_all
        bytes32[] request_ids;

        // partial attestations: keccak256(request_id, worker) -> attestation bytes
        mapping(bytes32 => bytes) partial_attestations;

        // attestation count per request
        mapping(bytes32 => uint32) attestation_counts;

        // final combined attestation
        mapping(bytes32 => bytes) fulfilled_attestations;

        // whether a request exists (since we can't check mapping emptiness cheaply)
        mapping(bytes32 => bool) request_exists;

        // whether a fulfilled attestation exists
        mapping(bytes32 => bool) fulfilled_exists;

        // authorized workers (fixed-size, stored as array)
        address[] authorized_workers;

        // request count
        uint64 count;
    }
}

// ──────────────────────────────────────────────
// Helper: encode / decode a DecryptionRequest
//
// Layout: [filename_len: u32][filename][witness_len: u32][witness][location_len: u32][location]
// ──────────────────────────────────────────────
fn encode_request(filename: &[u8], witness_hex: &[u8], location: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + filename.len() + witness_hex.len() + location.len());

    buf.extend_from_slice(&(filename.len() as u32).to_be_bytes());
    buf.extend_from_slice(filename);

    buf.extend_from_slice(&(witness_hex.len() as u32).to_be_bytes());
    buf.extend_from_slice(witness_hex);

    buf.extend_from_slice(&(location.len() as u32).to_be_bytes());
    buf.extend_from_slice(location);

    buf
}

fn decode_request(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut cursor = 0usize;

    // filename
    if cursor + 4 > data.len() { return None; }
    let flen = u32::from_be_bytes(data[cursor..cursor+4].try_into().ok()?) as usize;
    cursor += 4;
    if cursor + flen > data.len() { return None; }
    let filename = data[cursor..cursor+flen].to_vec();
    cursor += flen;

    // witness_hex
    if cursor + 4 > data.len() { return None; }
    let wlen = u32::from_be_bytes(data[cursor..cursor+4].try_into().ok()?) as usize;
    cursor += 4;
    if cursor + wlen > data.len() { return None; }
    let witness_hex = data[cursor..cursor+wlen].to_vec();
    cursor += wlen;

    // location
    if cursor + 4 > data.len() { return None; }
    let llen = u32::from_be_bytes(data[cursor..cursor+4].try_into().ok()?) as usize;
    cursor += 4;
    if cursor + llen > data.len() { return None; }
    let location = data[cursor..cursor+llen].to_vec();

    Some((filename, witness_hex, location))
}

/// Compute the composite key for (request_id, worker) via keccak256.
fn attestation_key(request_id: FixedBytes<32>, worker: Address) -> FixedBytes<32> {
    let mut preimage = Vec::with_capacity(52);
    preimage.extend_from_slice(request_id.as_slice());
    preimage.extend_from_slice(worker.as_slice());
    crypto::keccak(preimage.as_slice())
}

// ──────────────────────────────────────────────
// Public interface
// ──────────────────────────────────────────────
#[public]
impl RequestPool {
    /// Initialize the contract with authorized workers.
    /// Must be called once after deployment.
    pub fn init(&mut self, workers: Vec<Address>) -> Result<(), Vec<u8>> {
        // only allow init once
        if self.authorized_workers.len() > 0 {
            return Err(b"already initialized".to_vec());
        }
        if workers.len() != TOTAL_WORKERS {
            return Err(b"wrong worker count".to_vec());
        }
        for w in &workers {
            self.authorized_workers.push(*w);
        }
        Ok(())
    }

    /// Add a decryption request.
    /// The request ID is keccak256(filename ++ witness_hex ++ location).
    pub fn add(
        &mut self,
        filename: Vec<u8>,
        witness_hex: Vec<u8>,
        location: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        // compute ID
        let mut input = Vec::with_capacity(filename.len() + witness_hex.len() + location.len());
        input.extend_from_slice(&filename);
        input.extend_from_slice(&witness_hex);
        input.extend_from_slice(&location);
        let id: FixedBytes<32> = crypto::keccak(&input);

        // check duplicate
        if self.request_exists.get(id) {
            return Err(b"RequestAlreadyExists".to_vec());
        }

        // store encoded request
        let encoded = encode_request(&filename, &witness_hex, &location);
        self.requests.setter(id).set_bytes(encoded);
        self.request_ids.push(id);
        self.request_exists.setter(id).set(true);

        let new_count = self.count.get() + U64::from(1);
        self.count.set(new_count);

        self.vm().log(RequestAdded {
            id,
            timestamp: self.vm().block_timestamp().try_into().unwrap_or(0),
        });

        Ok(())
    }

    /// Read all stored requests as ABI-encoded bytes.
    /// Returns a list of (filename, witness_hex, location) tuples encoded sequentially.
    /// Each request is prefixed with its total length as a u32.
    pub fn read_all(&self) -> Vec<u8> {
        let len = self.request_ids.len();
        let mut result = Vec::new();

        // prefix with count
        result.extend_from_slice(&(len as u32).to_be_bytes());

        for i in 0..len {
            let id = self.request_ids.get(i).unwrap();
            let data = self.requests.getter(id).get_bytes();
            // prefix each entry with its byte length
            result.extend_from_slice(&(data.len() as u32).to_be_bytes());
            result.extend_from_slice(&data);
        }

        result
    }

    /// Get current request count.
    pub fn count(&self) -> U64 {
        self.count.get()
    }

    /// Worker submits a partial attestation for a request.
    pub fn submit_partial_attestation(
        &mut self,
        request_id: FixedBytes<32>,
        attestation: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        let caller = self.vm().msg_sender();

        // check authorized
        if !self.is_authorized(caller) {
            return Err(b"Unauthorized".to_vec());
        }

        // check request exists
        if !self.request_exists.get(request_id) {
            return Err(b"RequestNotFound".to_vec());
        }

        // check not already fulfilled
        if self.fulfilled_exists.get(request_id) {
            return Err(b"AlreadyFulfilled".to_vec());
        }

        // check worker hasn't already attested
        let key = attestation_key(request_id, caller);
        let existing = self.partial_attestations.getter(key).get_bytes();
        if !existing.is_empty() {
            return Err(b"AlreadyAttested".to_vec());
        }

        // store partial attestation
        self.partial_attestations.setter(key).set_bytes(attestation);

        // increment count
        let current = self.attestation_counts.get(request_id);
        let new_count = current + U32::from(1);
        self.attestation_counts.setter(request_id).set(new_count);

        let count_u32: u32 = new_count.try_into().unwrap_or(u32::MAX);

        self.vm().log(PartialAttestationSubmitted {
            request_id,
            worker: caller,
            count: count_u32,
        });

        // check threshold
        if count_u32 >= THRESHOLD {
            self.finalize_request(request_id)?;
        }

        Ok(())
    }

    /// Get the final combined attestation (only available after threshold is met).
    pub fn get_attestation(&self, id: FixedBytes<32>) -> Vec<u8> {
        self.fulfilled_attestations.getter(id).get_bytes()
    }

    /// Get the partial attestation count for a request.
    pub fn get_attestation_count(&self, id: FixedBytes<32>) -> U32 {
        self.attestation_counts.get(id)
    }

    /// Check if a request exists.
    pub fn has_request(&self, id: FixedBytes<32>) -> bool {
        self.request_exists.get(id)
    }

    /// Check if a request has been fulfilled.
    pub fn is_fulfilled(&self, id: FixedBytes<32>) -> bool {
        self.fulfilled_exists.get(id)
    }

    /// Hash arbitrary data with keccak256 (utility, mirrors the ink! helper).
    pub fn hash_request(&self, data: Vec<u8>) -> FixedBytes<32> {
        crypto::keccak(&data)
    }
}

// ──────────────────────────────────────────────
// Internal helpers (not exposed via ABI)
// ──────────────────────────────────────────────
impl RequestPool {
    /// Check if an address is in the authorized workers list.
    fn is_authorized(&self, addr: Address) -> bool {
        let len = self.authorized_workers.len();
        for i in 0..len {
            if self.authorized_workers.get(i).unwrap() == addr {
                return true;
            }
        }
        false
    }

    /// Finalize a request once the threshold is met.
    /// Collects all partial attestations from authorized workers and concatenates them.
    fn finalize_request(&mut self, request_id: FixedBytes<32>) -> Result<(), Vec<u8>> {
        let mut combined = Vec::new();

        let worker_count = self.authorized_workers.len();
        for i in 0..worker_count {
            let worker = self.authorized_workers.get(i).unwrap();
            let key = attestation_key(request_id, worker);
            let partial = self.partial_attestations.getter(key).get_bytes();
            if !partial.is_empty() {
                combined.extend_from_slice(&partial);
            }
        }

        // store combined attestation
        self.fulfilled_attestations.setter(request_id).set_bytes(combined.clone());
        self.fulfilled_exists.setter(request_id).set(true);

        let attestation_hash = crypto::keccak(&combined);

        self.vm().log(RequestFulfilled {
            id: request_id,
            attestation_hash,
        });

        Ok(())
    }
}