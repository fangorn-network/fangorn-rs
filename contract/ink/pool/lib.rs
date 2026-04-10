#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::prelude::vec::Vec;

#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct GenericData(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct DecryptionRequest {
    filename: GenericData,
    witness_hex: GenericData,
    location: GenericData,
}

#[ink::contract]
mod request_pool {
    use super::*;
    use ink::storage::Mapping;

    /// Opaque attestation (caller decodes)
    pub type Attestation = Vec<u8>;

    #[ink(storage)]
    pub struct RequestPool {
        /// Requests indexed by ID
        requests: Mapping<Vec<u8>, DecryptionRequest>,
        /// All request IDs (unordered)
        request_ids: Vec<Vec<u8>>,
        /// Partial attestations: request_id -> (worker_id -> attestation)
        partial_attestations: Mapping<(Vec<u8>, AccountId), Attestation>,
        /// Count of attestations per request
        attestation_counts: Mapping<Vec<u8>, u32>,
        /// Final combined attestation (after threshold met)
        fulfilled_attestations: Mapping<Vec<u8>, Attestation>,
        /// Authorized workers
        authorized_workers: Vec<AccountId>,
        /// Count
        count: u64,
    }

    /// Threshold params (1 of 1)
    const THRESHOLD: u32 = 1;
    const TOTAL_WORKERS: u32 = 2;

    #[ink(event)]
    pub struct RequestAdded {
        #[ink(topic)]
        id: Vec<u8>,
        timestamp: u64,
    }

    #[ink(event)]
    pub struct RequestFulfilled {
        #[ink(topic)]
        id: Vec<u8>,
        attestation_hash: [u8; 32],
    }

    #[ink(event)]
    pub struct PartialAttestationSubmitted {
        #[ink(topic)]
        request_id: Vec<u8>,
        #[ink(topic)]
        worker: AccountId,
        count: u32,
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum Error {
        RequestAlreadyExists,
        RequestNotFound,
        AlreadyFulfilled,
        Unauthorized,
        AlreadyAttested,
    }

    impl RequestPool {
        #[ink(constructor)]
        pub fn new(workers: Vec<AccountId>) -> Self {
            assert_eq!(workers.len(), TOTAL_WORKERS as usize);
            Self {
                requests: Mapping::new(),
                request_ids: Vec::new(),
                partial_attestations: Mapping::new(),
                attestation_counts: Mapping::new(),
                fulfilled_attestations: Mapping::new(),
                authorized_workers: workers,
                count: 0,
            }
        }

        /// Add request (ID = hash of request bytes)
        #[ink(message)]
        pub fn add(
            &mut self,
            filename: GenericData,
            witness_hex: GenericData,
            location: GenericData,
        ) -> Result<(), Error> {
            let mut input = Vec::new();
            input.extend(filename.0.clone());
            input.extend(witness_hex.0.clone());
            input.extend(location.0.clone());

            let id = self.hash_request(&input);

            if self.requests.contains(&id) {
                return Err(Error::RequestAlreadyExists);
            }

            let request = DecryptionRequest {
                filename,
                witness_hex,
                location,
            };
            self.requests.insert(&id, &request);
            self.request_ids.push(id.clone());
            self.count = self.count.saturating_add(1);

            self.env().emit_event(RequestAdded {
                id,
                timestamp: self.env().block_timestamp(),
            });

            Ok(())
        }

        /// Read all requests (unordered)
        #[ink(message)]
        pub fn read_all(&self) -> Vec<DecryptionRequest> {
            self.request_ids
                .iter()
                .filter_map(|id| self.requests.get(id))
                .collect()
        }

        /// Get count
        #[ink(message)]
        pub fn count(&self) -> u64 {
            self.count
        }

        /// Worker submits partial attestation
        #[ink(message)]
        pub fn submit_partial_attestation(
            &mut self,
            request_id: Vec<u8>,
            attestation: Attestation,
        ) -> Result<(), Error> {
            let caller = self.env().caller();

            // Check authorized
            if !self.authorized_workers.contains(&caller) {
                return Err(Error::Unauthorized);
            }

            // Check request exists
            if !self.requests.contains(&request_id) {
                return Err(Error::RequestNotFound);
            }

            // Check not already fulfilled
            if self.fulfilled_attestations.contains(&request_id) {
                return Err(Error::AlreadyFulfilled);
            }

            // Store partial
            let key = (request_id.clone(), caller);
            if self.partial_attestations.contains(&key) {
                return Err(Error::AlreadyAttested);
            }

            self.partial_attestations.insert(&key, &attestation);

            // Increment count
            let count = self.attestation_counts.get(&request_id).unwrap_or(0);
            let new_count = count.saturating_add(1);
            self.attestation_counts.insert(&request_id, &new_count);

            self.env().emit_event(PartialAttestationSubmitted {
                request_id: request_id.clone(),
                worker: caller,
                count: new_count,
            });

            // Check if threshold met
            if new_count >= THRESHOLD {
                self.finalize_request(request_id)?;
            }

            Ok(())
        }

        /// Finalize request once threshold met (internal)
        fn finalize_request(&mut self, request_id: Vec<u8>) -> Result<(), Error> {
            // Collect all partial attestations
            let mut partials = Vec::new();
            for worker in &self.authorized_workers {
                let key = (request_id.clone(), *worker);
                if let Some(attestation) = self.partial_attestations.get(&key) {
                    partials.push(attestation);
                }
            }

            // Naive combine: just concatenate (replace with threshold crypto combine)
            let combined: Vec<u8> = partials.into_iter().flatten().collect();

            self.fulfilled_attestations.insert(&request_id, &combined);

            self.env().emit_event(RequestFulfilled {
                id: request_id,
                attestation_hash: self.hash_attestation(&combined),
            });

            Ok(())
        }

        /// Get final attestation (only if threshold met)
        #[ink(message)]
        pub fn get_attestation(&self, id: Vec<u8>) -> Option<Attestation> {
            self.fulfilled_attestations.get(&id)
        }

        /// Get partial attestation count
        #[ink(message)]
        pub fn get_attestation_count(&self, id: Vec<u8>) -> u32 {
            self.attestation_counts.get(&id).unwrap_or(0)
        }

        /// Helper: hash request to get ID
        fn hash_request(&self, data: &[u8]) -> Vec<u8> {
            use ink::env::hash::{Blake2x256, HashOutput};
            let mut output = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(data, &mut output);
            output.to_vec()
        }

        fn hash_attestation(&self, attestation: &Attestation) -> [u8; 32] {
            use ink::env::hash::{Blake2x256, HashOutput};
            let mut output = <Blake2x256 as HashOutput>::Type::default();
            ink::env::hash_bytes::<Blake2x256>(attestation, &mut output);
            output
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn test_add_request() {
            let mut pool = RequestPool::new();
            let request = b"encrypted_request".to_vec();

            assert!(pool.add(request).is_ok());
            assert_eq!(pool.count(), 1);
        }

        #[ink::test]
        fn test_fulfill_request() {
            let mut pool = RequestPool::new();
            let request = b"request".to_vec();

            pool.add(request.clone()).unwrap();
            let id = pool.hash_request(&request);

            let attestation = b"proof_of_work".to_vec();
            assert!(pool
                .fulfill_request(id.clone(), attestation.clone())
                .is_ok());
            assert_eq!(pool.get_attestation(id), Some(attestation));
        }
    }
}
