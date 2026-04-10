#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(feature = "contract-client-gen", allow(unused_imports))]
extern crate alloc;

use alloc::vec::Vec;

use stylus_sdk::alloy_primitives::{FixedBytes, U256};
use stylus_sdk::alloy_sol_types::sol;
use stylus_sdk::prelude::*;
use stylus_sdk::crypto;

// ──────────────────────────────────────────────
// Storage layout
//
// Stylus mappings require fixed-size keys, so we
// hash variable-length filenames into bytes32 via
// keccak256. The raw filename bytes are stored
// separately so they can be enumerated.
//
// An "Entry" (cid + predicate) is packed into a
// single `bytes` slot using a simple length-prefixed
// encoding:
//   [cid_len: u32 BE][cid bytes][predicate bytes]
// ──────────────────────────────────────────────
sol_storage! {
    #[entrypoint]
    pub struct PredicateRegistry {
        /// filename_hash -> encoded Entry (cid + predicate)
        mapping(bytes32 => bytes) entries;

        /// whether a filename_hash has been registered
        mapping(bytes32 => bool) exists;

        /// ordered list of raw filename bytes, length-prefixed
        /// stored as a single blob so read_all is one SLOAD sequence
        bytes32[] filename_hashes;

        /// raw filename bytes keyed by hash (so we can return them)
        mapping(bytes32 => bytes) raw_filenames;
    }
}

// ──────────────────────────────────────────────
// Encoding helpers
// ──────────────────────────────────────────────

/// Pack an Entry (cid + predicate) into bytes:
///   [cid_len: 4 bytes BE][cid][predicate]
fn encode_entry(cid: &[u8], predicate: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + cid.len() + predicate.len());
    buf.extend_from_slice(&(cid.len() as u32).to_be_bytes());
    buf.extend_from_slice(cid);
    buf.extend_from_slice(predicate);
    buf
}

/// Unpack bytes back into (cid, predicate).
fn decode_entry(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if data.len() < 4 {
        return None;
    }
    let cid_len = u32::from_be_bytes(data[0..4].try_into().ok()?) as usize;
    if data.len() < 4 + cid_len {
        return None;
    }
    let cid = data[4..4 + cid_len].to_vec();
    let predicate = data[4 + cid_len..].to_vec();
    Some((cid, predicate))
}

// ──────────────────────────────────────────────
// Public interface
// ──────────────────────────────────────────────
#[public]
impl PredicateRegistry {
    /// Register a new predicate + file.
    ///
    /// * `filename`  – globally unique filename (arbitrary bytes)
    /// * `cid`       – content identifier (arbitrary bytes)
    /// * `predicate` – generic blob of data
    ///
    /// Reverts if the filename is already registered.
    pub fn register_predicate(
        &mut self,
        filename: Vec<u8>,
        cid: Vec<u8>,
        predicate: Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        let hash = crypto::keccak(&filename);

        if self.exists.get(hash) {
            return Err(b"FilenameAlreadyExists".to_vec());
        }

        let encoded = encode_entry(&cid, &predicate);
        self.entries.setter(hash).set_bytes(encoded);
        self.exists.setter(hash).set(true);
        self.filename_hashes.push(hash);
        self.raw_filenames.setter(hash).set_bytes(filename);

        Ok(())
    }

    /// Read an entry by filename.
    /// Returns the encoded entry bytes (cid_len ++ cid ++ predicate),
    /// or empty bytes if not found.
    pub fn read(&self, filename: Vec<u8>) -> Vec<u8> {
        let hash = crypto::keccak(&filename);
        if !self.exists.get(hash) {
            return Vec::new();
        }
        self.entries.getter(hash).get_bytes()
    }

    /// Read an entry's CID component by filename.
    /// Returns empty bytes if not found.
    pub fn read_cid(&self, filename: Vec<u8>) -> Vec<u8> {
        let hash = crypto::keccak(&filename);
        if !self.exists.get(hash) {
            return Vec::new();
        }
        let data = self.entries.getter(hash).get_bytes();
        match decode_entry(&data) {
            Some((cid, _)) => cid,
            None => Vec::new(),
        }
    }

    /// Read an entry's predicate component by filename.
    /// Returns empty bytes if not found.
    pub fn read_predicate(&self, filename: Vec<u8>) -> Vec<u8> {
        let hash = crypto::keccak(&filename);
        if !self.exists.get(hash) {
            return Vec::new();
        }
        let data = self.entries.getter(hash).get_bytes();
        match decode_entry(&data) {
            Some((_, predicate)) => predicate,
            None => Vec::new(),
        }
    }

    /// List all registered filenames.
    /// Returns length-prefixed list:
    ///   [count: u32 BE] then for each filename [len: u32 BE][filename bytes]
    pub fn read_all(&self) -> Vec<u8> {
        let len = self.filename_hashes.len();
        let mut result = Vec::new();
        result.extend_from_slice(&(len as u32).to_be_bytes());

        for i in 0..len {
            let hash = self.filename_hashes.get(i).unwrap();
            let name = self.raw_filenames.getter(hash).get_bytes();
            result.extend_from_slice(&(name.len() as u32).to_be_bytes());
            result.extend_from_slice(&name);
        }

        result
    }

    /// Get the total number of registered filenames.
    pub fn count(&self) -> U256 {
        U256::from(self.filename_hashes.len())
    }

    /// Remove an entry by filename.
    /// Returns the encoded entry bytes on success.
    ///
    /// Uses swap-remove on the filename list (same as the ink! version).
    pub fn remove_predicate(&mut self, filename: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        let hash = crypto::keccak(&filename);

        if !self.exists.get(hash) {
            return Err(b"FilenameNotFound".to_vec());
        }

        // read the entry before deleting
        let entry_data = self.entries.getter(hash).get_bytes();

        // clear storage
        self.entries.setter(hash).set_bytes(Vec::new());
        self.exists.setter(hash).set(false);
        self.raw_filenames.setter(hash).set_bytes(Vec::new());

        // swap-remove from the filename_hashes array
        let len = self.filename_hashes.len();
        let mut found_index: Option<usize> = None;
        for i in 0..len {
            if self.filename_hashes.get(i).unwrap() == hash {
                found_index = Some(i);
                break;
            }
        }

        if let Some(idx) = found_index {
            let last_idx = len - 1;
            if idx != last_idx {
                // move last element into the removed slot
                let last_hash = self.filename_hashes.get(last_idx).unwrap();
                self.filename_hashes.setter(idx).unwrap().set(last_hash);
            }
            self.filename_hashes.pop();
        }

        Ok(entry_data)
    }

    /// Check whether a filename is registered.
    pub fn has_filename(&self, filename: Vec<u8>) -> bool {
        let hash = crypto::keccak(&filename);
        self.exists.get(hash)
    }
}