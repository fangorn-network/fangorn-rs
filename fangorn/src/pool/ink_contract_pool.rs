use crate::backend::{Backend, SubstrateBackend};
use crate::pool::pool::*;
use anyhow::Result;
use async_trait::async_trait;
use codec::{Decode, Encode};
use std::sync::Arc;
use subxt::config::polkadot::AccountId32;

pub struct InkContractPool {
    contract_address: String,
    backend: Arc<SubstrateBackend>,
}

impl InkContractPool {
    pub fn new(contract_address: String, backend: Arc<SubstrateBackend>) -> Self {
        Self {
            contract_address,
            backend,
        }
    }
}

#[async_trait]
impl RequestPool for InkContractPool {
    /// add a new message
    async fn add(&mut self, req: DecryptionRequest) -> Result<()> {
        let selector = "add";
        let mut data = req.filename.encode();
        data.extend(req.witness_hex.encode());
        data.extend(req.location.encode());

        // todo: this is not a good pattern
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);
        self.backend
            .write(
                &AccountId32(contract_addr_bytes),
                &selector.to_string(),
                &req.encode(),
            )
            .await?;

        Ok(())
    }

    /// read all messages (unordered pool)
    async fn read_all(&self) -> Result<Vec<DecryptionRequest>> {
        let selector = "read_all";
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);
        let result = self
            .backend
            .read(
                &AccountId32(contract_addr_bytes),
                &selector.to_string(),
                None,
            )
            .await?;

        let mut data = result.unwrap();
        if !data.is_empty() {
            // remove the prefix
            data.remove(0);
        }

        let decoded = <Vec<DecryptionRequest>>::decode(&mut &data[..])?;

        Ok(decoded)
    }

    /// Get the total count of messages
    async fn count(&self) -> Result<usize> {
        let selector = "count";
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);
        let result = self
            .backend
            .read(
                &&AccountId32(contract_addr_bytes),
                &selector.to_string(),
                None,
            )
            .await?;

        let mut data = result.unwrap();
        if !data.is_empty() {
            // remove the prefix
            data.remove(0);
        }

        let decoded = u64::decode(&mut &data[..])?;
        Ok(decoded as usize)
    }

    /// submit evidence that a worker has processed a work item
    async fn submit_partial_attestation(&self, id: &[u8], attestation: &[u8]) -> Result<()> {
        let mut data = id.encode();
        data.extend(attestation.encode());

        let selector = "submit_partial_decryption";
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .write(
                &AccountId32(contract_addr_bytes),
                &selector.to_string(),
                &data,
            )
            .await?;

        Ok(())
    }
}
