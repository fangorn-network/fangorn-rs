use crate::backend::substrate::ContractBackend;
use crate::gadget::*;
use async_trait::async_trait;
use std::sync::Arc;
use subxt::{config::substrate::AccountId32, ext::codec::Decode};

// #[derive(Debug)]
pub struct Psp22Gadget {
    /// The backend
    backend: Arc<dyn ContractBackend>,
}

impl Psp22Gadget {
    pub fn new(backend: Arc<dyn ContractBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl Gadget for Psp22Gadget {
    fn intent_type_id(&self) -> &'static str {
        "Psp22"
    }

    // witness = account pubkey (32 bytes)
    // statement = (contract_address, minimum_balance)
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError> {

        let pubkey_string: String =
            String::from_utf8(witness.to_vec()).expect("Invalid UTF-8 sequence");

        let witness = crate::utils::decode_public_key(&pubkey_string);

        if witness.len() != 32 {
            return Err(IntentError::VerificationError(
                "Witness must be 32-byte account ID".into(),
            ));
        }

        if statement.len() != 48 {
            return Err(IntentError::VerificationError(
                "Statement must be 48 bytes (32 addr + 16 balance)".into(),
            ));
        }

        // statement = [32 bytes + 16 bytes]
        let token_contract: [u8; 32] = statement[..32].try_into().unwrap();

        let minimum_balance = u128::from_le_bytes(statement[32..48].try_into().map_err(|_| {
            IntentError::VerificationError("The minimum balance must be a valid u128.".into())
        })?);

        //  PSP22::balance_of(witness)
        let mut call_data = Vec::new();
        call_data.extend(witness); // account_id

        let selector = "PSP22::balance_of";

        let result = self
            .backend
            .read(
                &AccountId32(token_contract),
                &selector.to_string(),
                Some(call_data),
            )
            .await
            .map_err(|e| IntentError::VerificationError(format!("Contract query failed: {}", e)))?;
        // todo
        let mut data = result.unwrap();
        if !data.is_empty() {
            data.remove(0); // remove status byte
        }

        let balance = u128::decode(&mut &data[..])
            .map_err(|e| IntentError::VerificationError(format!("Decode failed: {}", e)))?;

        // Verify: does the witness have enough tokens?
        Ok(balance >= minimum_balance)
    }

    /// defines the data format for the Psp22 command
    /// expected format: data = "contract_addr, min_balance"
    fn parse_intent_data(&self, data: &str) -> Result<Vec<u8>, IntentError> {
        // the intent is the contract_addr and min_balance encoded in a vec
        let parts: Vec<&str> = data.split(',').collect();
        if parts.len() != 2 {
            return Err(IntentError::ParseError(
                "PSP22 format: contract_address,minimum_balance".into(),
            ));
        }

        // 32 bytes
        let contract_addr = crate::utils::decode_contract_addr(parts[0].trim());

        if contract_addr.len() != 32 {
            return Err(IntentError::ParseError("Address must be 32 bytes".into()));
        }

        // 16 bytes
        let min_balance: u128 = parts[1]
            .trim()
            .parse()
            .map_err(|_| IntentError::ParseError("Minimum balance must be a valid u128.".into()))?;

        // build question: contract_address (32) || minimum_balance (16)
        let mut statement = contract_addr.to_vec();
        statement.extend(&min_balance.to_le_bytes());

        Ok(statement)
    }
}

// #[cfg(test)]
// mod test {

//     use super::*;

//     fn test_can_parse_intent_data() {}
// }
