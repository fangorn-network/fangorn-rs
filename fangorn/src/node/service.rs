use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use codec::{Decode, Encode};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::prelude::*;
use iroh::{EndpointAddr, PublicKey as IrohPublicKey};
use iroh_docs::{
    DocTicket,
    api::{Doc, protocol::ShareMode},
    engine::LiveEvent,
    store::{FlatQuery, QueryBuilder},
};
use n0_error::StdResultExt;
use silent_threshold_encryption::{aggregate::SystemPublicKeys, types::Ciphertext};
use std::sync::Arc;
use std::{fs::OpenOptions, io::Write, thread, time::Duration};
use tokio::sync::{Mutex, RwLock};

use crate::backend::{SubstrateBackend, iroh::IrohBackend};
use crate::node::node::*;
use crate::gadget::{GadgetRegistry, PasswordGadget, Psp22Gadget, Sr25519Gadget};
use crate::pool::{ink_contract_pool::*, pool::*, watcher::*};
use crate::storage::{
    IntentStore, SharedStore, contract_store::ContractIntentStore, iroh_docstore::IrohDocStore,
};
use crate::types::*;

/// Configuration for starting a full node service
pub struct ServiceConfig {
    // port used for p2p conns
    pub bind_port: u16,
    // external rpc port
    pub rpc_port: u16,
    // node index within the group
    pub index: usize,
    // if true, then act as bootstrap 
    // note: incurs extra messaging overhead, generates a new doc ticket
    pub is_bootstrap: bool,
    // ignored if is_bootstrap
    pub ticket: Option<String>,
    // well-known bootstrap nodes
    pub bootstrap_peers: Option<Vec<EndpointAddr>>,
    // registry contracts
    // the predicate registry for reading intent
    pub predicate_registry_contract_addr: String,
    // request pool for reading requests + submitting work
    pub request_pool_contract_addr: String,
}

impl ServiceConfig {
    /// Build bootstrap peers from CLI arguments
    pub fn build_bootstrap_peers(
        pubkey: Option<String>,
        ip: Option<String>,
    ) -> Option<Vec<EndpointAddr>> {
        // TODO: error handling!
        if let (Some(pubkey_str), Some(ip_str)) = (pubkey, ip) {
            let pubkey = IrohPublicKey::from_str(&pubkey_str).ok().unwrap();
            let socket: SocketAddr = ip_str.parse().ok().unwrap();
            let addr = EndpointAddr::new(pubkey).with_ip_addr(socket);
            Some(vec![addr])
        } else {
            None
        }
    }
}

pub struct ServiceHandle<C: Pairing> {
    pub node: Node<C>,
    pub ticket: String,
}

/// Build and start the full Fangorn node service
pub async fn build_full_service<C: Pairing>(
    config: ServiceConfig,
    max_committee_size: usize,
    vault_config: VaultConfig,
) -> Result<ServiceHandle<C>> {
    // setup channels for state synchronization
    let (tx, rx) = flume::unbounded();
    // initialize node parameters and state
    let state = State::<C>::empty();
    let arc_state = Arc::new(Mutex::new(state));
    let arc_state_clone = Arc::clone(&arc_state);

    let mut node = Node::build(
        config.bind_port,
        config.index,
        rx,
        arc_state.clone(),
        vault_config.clone(),
    )
    .await;
    node.try_connect_peers(config.bootstrap_peers.clone())
        .await
        .unwrap();

    let (doc_stream, ticket) = setup_document_stream(
        &node,
        config.is_bootstrap,
        config.ticket,
        max_committee_size,
        &tx,
    )
    .await
    .unwrap();

    let iroh_backend = IrohBackend::new(node.clone());

    // TODO: replace the substrate backend with something else? 
    // or should we stand up a standalone substrate chain?
    // e.g. should Fangorn Network be....real?!?
    // I don't want to support all that infra tbh
    // but if each of these nodes can itself be a validator, then it works... 
    let substrate_backend =
        Arc::new(SubstrateBackend::new(
            crate::WS_URL.to_string(), 
            vault_config
        ).await?);

    // setup gadget registry with default gadgets
    // TODO: there should be some kind of config.yml for this
    let mut gadget_registry = GadgetRegistry::new();
    gadget_registry.register(PasswordGadget {});
    gadget_registry.register(Psp22Gadget::new(substrate_backend.clone()));
    gadget_registry.register(Sr25519Gadget::new(substrate_backend.clone()));

    // setup storage
    let doc_store = IrohDocStore::new(node.clone(), &ticket, Arc::new(iroh_backend)).await;
    // todo: migrate from ink! to solana program? stylus contract? something else?
    // realistically, this needs to also be configurable I think
    let intent_store = ContractIntentStore::new(
        config.predicate_registry_contract_addr.to_string(),
        substrate_backend.clone(),
    );

    // in-mem decryption request pool
    let pool = Arc::new(RwLock::new(InkContractPool::new(
        config.request_pool_contract_addr.clone(),
        substrate_backend,
    )));

    spawn_state_sync_service(
        doc_stream.clone(),
        node.clone(),
        tx.clone(),
        config.bootstrap_peers,
    );

    // wait for initial sync (todo: there has to be a better way)
    thread::sleep(Duration::from_secs(3));

    // sync: load and distribute config
    load_and_distribute_config(&node, doc_stream.clone(), &tx.clone())
        .await
        .unwrap();

    // sync: load previous hints (if not bootstrap)
    if !config.is_bootstrap {
        load_previous_hints(&node, doc_stream.clone(), config.index, &tx.clone())
            .await
            .unwrap();
    }

    // wait for everything to sync              
    thread::sleep(Duration::from_secs(1));

    // publish our own hint
    publish_node_hint(&node, doc_stream.clone(), config.index, &tx)
        .await
        .unwrap();

    if config.is_bootstrap {
        // same as todo above: this is bad
        thread::sleep(Duration::from_secs(1));
        // Publish initial system keys
        publish_system_keys(&node, &doc_stream.clone(), &arc_state_clone, &tx).await?;
        // monitor for new hints and auto-update system keys
        // in the future, this should be driven by consensus or something
        // so this is sort of the 'proof of authority'/bootstrap-does-it-all model
        spawn_system_keys_updater(
            node.clone(),
            doc_stream.clone(),
            arc_state.clone(),
            tx.clone(),
        )
        .await?;
        println!("System keys updater started");
    }

    // watch the request pool
    spawn_pool_watcher(
        arc_state_clone.clone(),
        gadget_registry,
        doc_store,
        intent_store,
        pool,
        node.clone(),
        config.index,
    )
    .await
    .unwrap();

    // main service loop
    Ok(ServiceHandle { node, ticket })
}

/// Setup the document stream for state synchronization
async fn setup_document_stream<C: Pairing>(
    node: &Node<C>,
    is_bootstrap: bool,
    ticket: Option<String>,
    max_committee_size: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<(Doc, String)> {
    if is_bootstrap {
        println!("Initial Startup: Generating new config");

        // Generate config and create document
        let config_bytes = generate_config(max_committee_size).unwrap();

        let doc = node.docs().create().await.unwrap();

        // Create and share ticket
        let ticket = doc
            .share(
                ShareMode::Write,
                iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
            )
            .await
            .unwrap();

        println!("Entry ticket: {}", ticket);
        let ticket_string = ticket.to_string();

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("ticket.txt")
            .unwrap();

        writeln!(&mut file, "{}", ticket_string).expect("Unable to write ticket to file.");

        // Import the document
        let doc_stream = node.docs().import(ticket.clone()).await.unwrap();

        // Publish config to document
        let config_announcement = Announcement {
            tag: Tag::Config,
            data: config_bytes,
        };

        tx.send(config_announcement.clone()).unwrap();

        doc_stream
            .set_bytes(
                // just get the first key we have
                node.docs().author_default().await.unwrap(),
                CONFIG_KEY,
                config_announcement.encode(),
            )
            .await
            .unwrap();

        let ticket_str = ticket.clone().to_string();
        Ok((doc_stream, ticket_str))
    } else {
        // Join existing network
        let ticket_str = ticket
            .ok_or_else(|| anyhow::anyhow!("Ticket required for non-bootstrap nodes"))
            .unwrap();
        let doc_ticket = DocTicket::from_str(&ticket_str).unwrap();
        let doc_stream = node.docs().import(doc_ticket).await.unwrap();
        Ok((doc_stream, ticket_str))
    }
}

/// Load config from document and distribute to state
async fn load_and_distribute_config<C: Pairing>(
    node: &Node<C>,
    doc_stream: Doc,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    let config_query = QueryBuilder::<FlatQuery>::default()
        .key_exact(CONFIG_KEY)
        .limit(1);

    let cfg_entry = doc_stream.get_many(config_query.build()).await.unwrap();
    let config = cfg_entry.collect::<Vec<_>>().await;

    let hash = config[0].as_ref().unwrap().content_hash();
    let content = node.blobs().get_bytes(hash).await.unwrap();
    let announcement = Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();

    tx.send(announcement).unwrap();

    Ok(())
}

/// Load hints from previous nodes in the network
async fn load_previous_hints<C: Pairing>(
    node: &Node<C>,
    doc_stream: Doc,
    our_index: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    println!("Loading hints from previous nodes...");

    let mut count = 0;
    for i in 1..(our_index as u32) {
        let hint_query = QueryBuilder::<FlatQuery>::default()
            .key_exact(i.to_string())
            .limit(1);
        let entry_list = doc_stream.get_many(hint_query.build()).await.unwrap();
        let entry = entry_list.collect::<Vec<_>>().await;
        let hash = entry[0].as_ref().unwrap().content_hash();
        let content = node.blobs().get_bytes(hash).await.unwrap();
        let announcement =
            Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();
        tx.send(announcement).unwrap();
        count += 1;
    }

    println!("Loaded {} previous hints", count);
    Ok(())
}

/// Publish this node's hint to the network
async fn publish_node_hint<C: Pairing>(
    node: &Node<C>,
    doc_stream: Doc,
    // automate this?
    index: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    // publish our own public key, hint, and index
    let pk = node
        .get_pk()
        .await
        .ok_or_else(|| anyhow::anyhow!("Failed to compute public key"))
        .unwrap();

    println!("Computed the hint");

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();

    let hint_announcement = Announcement {
        tag: Tag::Hint,
        data: pk_bytes,
    };

    // Send to ourselves first
    tx.send(hint_announcement.clone()).unwrap();

    // Publish to network
    doc_stream
        .set_bytes(
            node.docs().author_default().await.unwrap(),
            index.to_string(),
            hint_announcement.encode(),
        )
        .await
        .unwrap();

    println!("Published hint to network");
    Ok(())
}

/// Spawn the state synchronization background task
fn spawn_state_sync_service<C: Pairing>(
    doc_stream: Doc,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
    bootstrap_peers: Option<Vec<EndpointAddr>>,
) {
    n0_future::task::spawn(async move {
        if let Err(e) = run_state_sync(doc_stream, node, tx, bootstrap_peers).await {
            eprintln!("State sync error: {:?}", e);
        }
    });
}

/// Run the state synchronization loop
async fn run_state_sync<C: Pairing>(
    doc_stream: Doc,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
    bootstrap_peers: Option<Vec<EndpointAddr>>,
) -> Result<()> {
    // to sync the doc with peers we need to read the state of the doc and load it
    let peers = bootstrap_peers.unwrap_or_default();
    doc_stream.start_sync(peers).await.unwrap();

    // subscribe to changes to the doc_stream
    let mut sub = doc_stream.subscribe().await.unwrap();
    let blobs = node.blobs().clone();

    while let Ok(event) = sub.try_next().await {
        if let Some(evt) = event {
            println!("{:?}", evt);
            if let LiveEvent::InsertRemote { entry, .. } = evt {
                let msg_body = blobs.get_bytes(entry.content_hash()).await;
                match msg_body {
                    Ok(msg) => {
                        let bytes = msg.to_vec();
                        let announcement = Announcement::decode(&mut &bytes[..]).unwrap();
                        tx.send(announcement).unwrap();
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        // may still be syncing so try again (3x)
                        for _ in 0..3 {
                            thread::sleep(Duration::from_secs(1));
                            let message_content = blobs.get_bytes(entry.content_hash()).await;
                            if let Ok(msg) = message_content {
                                let bytes = msg.to_vec();
                                let announcement = Announcement::decode(&mut &bytes[..]).unwrap();
                                if announcement.tag != Tag::Doc {
                                    tx.send(announcement).unwrap();
                                }

                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Monitor for new hints and republish system keys
async fn spawn_system_keys_updater<C: Pairing>(
    node: Node<C>,
    doc_stream: Doc,
    state: Arc<Mutex<State<C>>>,
    tx: flume::Sender<Announcement>,
) -> Result<()> {
    n0_future::task::spawn(async move {
        let mut last_hint_count = 0;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let state_guard = state.lock().await;
            let current_hint_count = state_guard.hints.as_ref().map(|h| h.len()).unwrap_or(0);
            drop(state_guard);

            // New hint detected
            if current_hint_count > last_hint_count {
                println!(
                    "New hint detected ({} total), regenerating system keys",
                    current_hint_count
                );

                if let Err(e) = publish_system_keys(&node, &doc_stream, &state, &tx).await {
                    eprintln!("Failed to publish system keys: {:?}", e);
                } else {
                    last_hint_count = current_hint_count;
                }
            }
        }
    });

    Ok(())
}

/// Publish/update system keys (called on new hints)
async fn publish_system_keys<C: Pairing>(
    node: &Node<C>,
    doc_stream: &Doc,
    state: &Arc<Mutex<State<C>>>,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    let state_guard = state.lock().await;

    let config = state_guard
        .config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Config not available"))?;

    let hints = state_guard
        .hints
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Hints not available"))?;

    // need at least 2 nodes
    if hints.len() <= 1 {
        return Ok(());
    }

    // Generate system keys from all current hints
    let k = 1;
    let system_keys = SystemPublicKeys::<C>::new(hints.clone(), &config.crs, &config.lag_polys, k)?;

    let mut bytes = Vec::new();
    system_keys.serialize_compressed(&mut bytes)?;
    println!(
        "Published updated system keys ({} hints: {:?})",
        hints.len(),
        bytes.len()
    );
    drop(state_guard);

    // this is a bit messy
    // write to a local file
    let dir = "tmp/sys";
    let filepath = "tmp/sys/key";
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(filepath, &bytes).unwrap();

    // Publish to doc (overwrites previous)
    let announcement = Announcement {
        tag: Tag::SystemKeys,
        data: bytes,
    };

    tx.send(announcement.clone())?;

    doc_stream
        .set_bytes(
            node.docs().author_default().await?,
            SYSTEM_KEYS_KEY,
            announcement.encode(),
        )
        .await?;

    Ok(())
}

async fn spawn_pool_watcher<C: Pairing>(
    state: Arc<Mutex<State<C>>>,
    gadget_registry: GadgetRegistry,
    doc_store: IrohDocStore<C>,
    intent_store: ContractIntentStore,
    pool: Arc<RwLock<InkContractPool>>,
    node: Node<C>,
    index: usize,
) -> Result<()> {
    // poll every 100ms
    let watcher = PollingWatcher::new(pool.clone(), Duration::from_millis(100));
    // up to 100 reqs per 100ms interval (that is probably too many...)
    let (tx, rx) = flume::unbounded();

    // watcher
    let _watcher_handle = n0_future::task::spawn(async move {
        if let Err(e) = watcher.watch(tx).await {
            eprintln!("Pool watcher error: {:?}", e);
        }
    });

    // worker
    n0_future::task::spawn(async move {
        while let Ok(req) = rx.recv_async().await {
            // println!("New request received: {}", req.id());
            if let Err(e) = process_decryption_request(
                req,
                &state,
                gadget_registry.clone(),
                doc_store.clone(),
                intent_store.clone(),
                node.clone(),
                pool.clone(),
                index,
            )
            .await
            {
                eprintln!("Request processing error: {:?}", e);
            }
        }
    });

    println!("Request Pool watcher started");
    Ok(())
}

async fn process_decryption_request<C: Pairing>(
    req: DecryptionRequest,
    state: &Arc<Mutex<State<C>>>,
    registry: GadgetRegistry,
    doc_store: IrohDocStore<C>,
    intent_store: ContractIntentStore,
    node: Node<C>,
    pool: Arc<RwLock<InkContractPool>>,
    index: usize,
) -> Result<()> {
    let mut bytes = Vec::new();

    let filename = req.filename.clone();
    let witness = hex::decode(req.witness_hex.clone()).unwrap();

    let (cid, intents) = intent_store
        .get_intent(&filename)
        .await
        .expect("Something went wrong when looking for intent.")
        .expect("Intent wasn't found");

    match registry.verify_intents(intents, &witness).await {
        Ok(true) => {
            println!("Witness verification succeeded!");
            if let Some(ciphertext_bytes) = doc_store.fetch(&cid).await.unwrap() {
                let ciphertext =
                    Ciphertext::<C>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();

                println!("got the ciphertext");
                let state = state.lock().await;
                let partial_decryption = node.ste_vault.partial_decryption(&ciphertext).unwrap();
                partial_decryption.serialize_compressed(&mut bytes).unwrap();

                let pd_message = PartialDecryptionMessage {
                    filename: req.filename.clone(),
                    index: index.try_into().unwrap(),
                    partial_decryption_bytes: bytes,
                };

                let msg_bytes = pd_message.encode();

                println!("produced a partial decryption");
                drop(state);

                // todo: deliver the pd to the requested 'location'
                let endpoint = node.endpoint();
                // try to connect to the recipient
                let receiver_endpoint_addr: EndpointAddr = req.location.clone().into();
                if let Ok(conn) = endpoint
                    .connect(receiver_endpoint_addr, crate::node::node::PD_ALPN)
                    .await
                {
                    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
                    send.write_all(&msg_bytes).await.anyerr()?;
                    send.finish().anyerr()?;
                    let response = recv.read_to_end(1000).await.anyerr()?;
                    if response == msg_bytes {
                        // send attestation
                        // TODO: murmur for attestations?
                        // let mut locked_pool = pool.read().unwrap;
                        let pool_write_guard = pool.write().await;
                        pool_write_guard
                            .submit_partial_attestation(&req.id().clone(), b"")
                            .await
                            .unwrap();
                    }

                    // Explicitly close the whole connection.
                    conn.close(0u32.into(), b"Success - Goodbye!");
                }

                // then submit an attestation to the contract
            } else {
                println!("data unavailable");
            }
        }
        Ok(false) => {
            println!("Witness verification failed");
        }
        Err(e) => {
            println!("An Error occurred: {}", e);
        }
    }

    Ok(())
}

/// Generate the initial config (for bootstrap nodes)
fn generate_config(size: usize) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;

    let config = Config::<E>::rand(size);
    let mut bytes = Vec::new();
    config.serialize_compressed(&mut bytes).unwrap();

    // Save to disk for debugging
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("config.txt")
        .unwrap();

    write!(&mut file, "{}", hex::encode(&bytes)).unwrap();
    println!("> Saved config to disk");

    Ok(bytes)
}
