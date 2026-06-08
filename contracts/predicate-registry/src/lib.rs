#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
#![cfg_attr(feature = "contract-client-gen", allow(unused_imports))]

extern crate alloc;

use alloy_sol_types::sol;
use stylus_sdk::{
    alloy_primitives::{Address, FixedBytes, keccak256},
    prelude::*,
    storage::*,
};

pub struct Filename(pub Vec<u8>);

pub struct CID(pub Vec<u8>);

pub struct Predicate(pub Vec<u8>);

pub struct Entry {
    pub cid: CID,
    pub predicate: Vec<u8>,
}

#[derive(SolidityError)]
pub enum DatasourceRegistryError {
    FilenameAlreadyExists,
    FilenameNotFound,
    Unauthorized,
}

// #[storage]
// pub struct Pre {
//     pub name: StorageString,
//     pub agent_id: StorageString,
//     pub manifest_cid: StorageString,
//     pub owner: StorageAddress,
// }

#[storage]
#[entrypoint]
pub struct PredicateRegistry {
    /// map filename to entry
    predicateRegistry: StorageMap<Filename, Entry>,
    /// All registered files 
    filenames: StorageVec<Filename>,
    /// A fifo queue of decryption requests
    decryption_request_pool: StorageVec<Vec<u8>>
}

#[public]
impl PredicateRegistry {
}

// sol! {
//     event DataSourceCreated(
//         bytes32 indexed id,
//         address indexed owner,
//         string name
//     );

//     event DataSourceUpdated(
//         bytes32 indexed id,
//         string newManifestCid
//     );

//     error NotOwner();
//     error DataSourceNotFound();
//     error DataSourceAlreadyExists();
// }


// pub fn add(left: u64, right: u64) -> u64 {
//     left + right
// }



// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
