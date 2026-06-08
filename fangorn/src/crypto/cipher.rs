// use crate::pool::pool::RawPartialDecryptionMessage;
use crate::Node;
use crate::storage::{
    AppStore, IntentStore, contract_store::ContractIntentStore, iroh_docstore::IrohDocStore,
    local_store::LocalPlaintextStore,
};
use crate::types::*;
use crate::{
    backend::{SubstrateBackend, iroh::IrohBackend},
    crypto::{decrypt::DecryptionClient, encrypt::EncryptionClient},
    gadget::{GadgetRegistry, PasswordGadget, Psp22Gadget, Sr25519Gadget},
    pool::ink_contract_pool::InkContractPool,
    storage::{PlaintextStore, SharedStore},
};
use ark_serialize::CanonicalDeserialize;
use silent_threshold_encryption::{
    aggregate::SystemPublicKeys, decryption::agg_dec, setup::PartialDecryption, types::Ciphertext,
};
use std::sync::Arc;
use tokio::sync::Mutex;

/// an app store that uses the iroh nodes for storage
/// against a smart contract deployed on the configured substrate backend
type TestnetAppStore = AppStore<IrohDocStore<E>, ContractIntentStore, LocalPlaintextStore>;

// /// an app store configured for all nodes running on the same machine,
// /// against a smart contract deployed on the configured substrate backend
// type LocalTestnetAppStore = AppStore<LocalDocStore, ContractIntentStore, LocalPlaintextStore>;

/// encrypt the message located at message_path
pub async fn handle_encrypt(
    message_path: &String,
    filename: &String,
    config_path: &String,
    intent_str: &String,
    contract_addr: &String,
    node: Node<E>,
    ticket: &String,
    sys_keys: SystemPublicKeys<E>,
) {
    let (gadget_registry, app_store, _) =
        iroh_testnet_setup(
            contract_addr, 
            node.clone(), 
            ticket.clone()
        ).await;

    let message = app_store
        .pt_store
        .read_plaintext(message_path)
        .await
        .expect("Something went wrong while reading PT");

    let client = EncryptionClient::new(
        config_path, 
        sys_keys, 
        app_store, 
        gadget_registry
    );

    client
        .encrypt(&message, filename.as_bytes(), &intent_str)
        .await
        .unwrap();
}

/// Handle decrypt (per node)
pub async fn handle_decrypt(
    config_path: &String,
    filename: &String,
    witness_string: &String,
    contract_addr: &String,
    request_pool_contract_addr: &String,
    node: Node<E>,
    ticket: &String,
    sys_keys: SystemPublicKeys<E>,
) {
    let (_gadget_registry, app_store, backend) =
        iroh_testnet_setup(contract_addr, node.clone(), ticket.clone()).await;
    let app_store_clone = app_store.clone();

    // Parse witnesses
    let witnesses: Vec<&str> = witness_string.trim().split(',').map(|s| s.trim()).collect();

    // let doc_ticket = DocTicket::from_str(&ticket).unwrap();
    // let doc_stream = node.docs().import(doc_ticket).await.unwrap();

    let request_pool = Arc::new(Mutex::new(InkContractPool::new(
        request_pool_contract_addr.to_string(),
        backend,
    )));

    // Build decryption client
    let client =
        DecryptionClient::new(
            config_path, 
            sys_keys, 
            app_store, 
            request_pool, 
            node.clone()
        ).unwrap();

    println!("> Requested decryption");

    if let Ok(()) = client.request_decrypt(filename, &witnesses).await {
        // setup the decryption handler
        // TODO: this assumes a threshold of 1.... 
        let node_clone = node.clone();
        // kind of hacky for now: a oneshot channel to run until we decrypt something
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        // get the ak from the node state
        // let state_lock = node.state.lock().await;
        // let sys_keys = state_lock.system_keys.clone().unwrap();
        let subset = vec![0, client.threshold as usize];
        let (ak, _ek) = client.system_keys.get_aggregate_key(
            &subset,
            &client.config.crs,
            &client.config.lag_polys,
        );

        // drop(state_lock)?
        let mut partial_decryptions = vec![PartialDecryption::zero(); ak.lag_pks.len()];

        // linting thinks this does not need to be mutable but it does
        #[allow(unused_mut)]
        let mut idx = 0;

        let pks = ak.lag_pks.clone();

        // TODO: I really don't like this here, but it works for now...
        n0_future::task::spawn(async move {
            while let Ok(raw) = node_clone.pd_rx().recv_async().await {
                println!("handling partial decryptions in the handler in the node");
                println!("Pubkeys: {:?}, {:?}", pks[idx].id, pks[idx].position);
                let filename = raw.filename;
                let partial_decryption = raw.partial_decryption;
                partial_decryptions[pks[idx].position] = partial_decryption;
                let _ = idx.saturating_add(1);
                // get cid from filename
                let (cid, _intents) = app_store_clone
                    .intent_store
                    .get_intent(&filename)
                    .await
                    // .map_err(|e| DecryptionClientError::IntentStoreError(e.to_string()))?
                    .unwrap()
                    // .ok_or_else(|| DecryptionClientError::IntentNotFound(filename.to_string()))?;
                    .unwrap();
                // use the cid to get the data
                let ciphertext_bytes = app_store_clone
                    .doc_store
                    .fetch(&cid)
                    .await
                    .unwrap()
                    .unwrap();
                // .map_err(|e| DecryptionClientError::DocstoreError(e.to_string()))?
                // .ok_or(DecryptionClientError::CiphertextNotFound)?;

                let ciphertext =
                    Ciphertext::<E>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();
                // .map_err(|_| DecryptionClientError::DeserializationError)?;

                println!("we got the ciphertext");
                // decrypt the data with partial decryptions if you have enough (assume threshold = 1 for now)
                // save to file with pt_store

                let mut selector = vec![false; MAX_COMMITTEE_SIZE];
                selector[0] = true;

                let plain_bytes = agg_dec(
                    &partial_decryptions,
                    &ciphertext,
                    &selector,
                    &ak,
                    &client.config.crs,
                )
                .unwrap();
                // .map_err(|e| DecryptionClientError::DecryptionError(e.to_string()))

                // save to store
                let filename = String::from_utf8(filename).unwrap();
                let _ = app_store_clone
                    .pt_store
                    .write_plaintext(&filename, &plain_bytes)
                    .await
                    .unwrap();

                let _ = done_tx.send(());
                break;
            }
        });

        done_rx.await.unwrap();
        println!("> Decryption complete!");
    }
}

// async fn local_testnet_setup(
//     contract_addr: &String,
//     seed: Option<&str>,
// ) -> (GadgetRegistry, LocalTestnetAppStore, Arc<SubstrateBackend>) {
//     // build the backend
//     let backend = Arc::new(
//         SubstrateBackend::new(crate::WS_URL.to_string(), seed)
//             .await
//             .unwrap(),
//     );
//     // configure the registry
//     let mut gadget_registry = GadgetRegistry::new();
//     gadget_registry.register(PasswordGadget {});
//     gadget_registry.register(Psp22Gadget::new(backend.clone()));
//     gadget_registry.register(Sr25519Gadget::new(backend.clone()));

//     let app_store = AppStore::new(
//         LocalDocStore::new("tmp/docs/"),
//         ContractIntentStore::new(contract_addr.to_string(), backend.clone()),
//         LocalPlaintextStore::new("tmp/plaintexts/"),
//     );

//     (gadget_registry, app_store, backend)
// }

async fn iroh_testnet_setup(
    contract_addr: &String,
    node: Node<E>,
    ticket: String,
) -> (GadgetRegistry, Arc<TestnetAppStore>, Arc<SubstrateBackend>) {
    
    // build the backend
    let backend = Arc::new(
        SubstrateBackend::new(
            crate::WS_URL.to_string(),
            node.vault_config.clone()
        ).await.unwrap(),
    );

    // initialize iroh backend
    let iroh_backend = Arc::new(IrohBackend::new(node.clone()));

    // configure the registry
    let mut gadget_registry = GadgetRegistry::new();
    gadget_registry.register(PasswordGadget {});
    gadget_registry.register(Psp22Gadget::new(backend.clone()));
    gadget_registry.register(Sr25519Gadget::new(backend.clone()));

    let app_store = Arc::new(AppStore::new(
        IrohDocStore::new(node, &ticket, iroh_backend).await,
        ContractIntentStore::new(contract_addr.to_string(), backend.clone()),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    ));

    (gadget_registry, app_store, backend)
}
