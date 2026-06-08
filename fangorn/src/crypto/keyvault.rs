use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bip39::Mnemonic;
use iroh::SecretKey as IrohSecretKey;
use rust_vault::Vault;
use secrecy::{ExposeSecret, SecretString};
use silent_threshold_encryption::{
    crs::CRS,
    setup::{PartialDecryption, PublicKey, SecretKey},
    types::Ciphertext,
};
use sp_core::{Pair as PairT, crypto::Ss58Codec, sr25519};
use std::{
    io::Read,
    marker::PhantomData,
    sync::{Arc, RwLock},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyVaultError {
    #[error("Keystore error: {0}")]
    Keystore(String),
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Secret string error: {0}")]
    SecretString(#[from] sp_core::crypto::SecretStringError),
}

// TODO: Password management is somewhat of a mess. We either accept passwords via the command line or they're hard coded within every method
// that interacts with the vault. 
// For production, these should be provided in some other manner, perhaps via ENV variables.
pub trait KeyVault {
    /// The public key type
    type Public: Clone + PartialEq + std::fmt::Debug;

    /// The signature type
    type Signature: Clone + PartialEq + std::fmt::Debug;

    /// The pair type (private + public key)
    type Pair: PairT;

    fn get_public_key(
        &self,
    ) -> Result<Self::Public, KeyVaultError>;

    /// Generate a new keypair and return the public key
    fn generate_key(
        &self,
    ) -> Result<Self::Public, KeyVaultError>;

    /// List all public keys in the keystore
    fn list_keys(&self) -> Result<Vec<String>, KeyVaultError>;

    /// Check if a specific key exists
    fn has_key(&self, key_name: String) -> bool;

    /// Sign a message
    fn sign(
        &self,
        message: &[u8],
    ) -> Result<Self::Signature, KeyVaultError>;

    /// Verify a signature (can be static since verification only needs the public key)
    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool;

    fn get_secure_password(&self, password_name: String) -> Result<SecretString, KeyVaultError>;
}

#[derive(Clone, Debug)]
pub struct Sr25519KeyVault {
    vault: Arc<RwLock<Vault>>,
    key_name: String,
    key_password: Option<String>,
    vault_password: Option<String>,
    storing_passwords: bool,
}

impl Sr25519KeyVault {
    pub fn new(vault: Vault, key_name: String) -> Self {
        Self {
            vault: Arc::new(RwLock::new(vault)),
            key_name,
            key_password: None,
            vault_password: None,
            storing_passwords: false,
        }
    }

    pub fn new_store_info(
        vault: Vault,
        vault_password: SecretString,
        key_name: String,
        key_password: SecretString,
    ) -> Self {
        println!("creating Iroh vault and storing info");
        let key_password_string = String::from(key_password.expose_secret());
        let vault_password_string = String::from(vault_password.expose_secret());
        Self {
            vault: Arc::new(RwLock::new(vault)),
            key_name,
            key_password: Some(key_password_string),
            vault_password: Some(vault_password_string),
            storing_passwords: true,
        }
    }

    /// Convert public key to SS58 address format
    pub fn to_ss58(&self, public: &<Sr25519KeyVault as KeyVault>::Public) -> String {
        public.to_ss58check()
    }

    /// Parse SS58 address to public key
    pub fn from_ss58(address: &str,) -> Result<<Sr25519KeyVault as KeyVault>::Public, KeyVaultError> {
        <Sr25519KeyVault as KeyVault>::Public::from_ss58check(address)
            .map_err(|_| KeyVaultError::Keystore("Invalid SS58 address".to_string()))
    }

    /// This should be used in tandem with Sr25519::new(vault)
    pub fn generate_key_print_mnemonic(&self,) -> Result<sr25519::Public, KeyVaultError> {
        if self.storing_passwords {
            let mnemonic = Mnemonic::generate(24).unwrap();
            println!("mnemonic: {:?}", mnemonic.to_string());
            let secret_mnemonic = SecretString::new(mnemonic.to_string().into());
            let (pair, seed) = sr25519::Pair::from_phrase(&secret_mnemonic.expose_secret(), None)
                .expect("Failed to generate keypair from mnemonic");
            // Lock the vault for writing and write the seed bytes
            self.vault
                .write()
                .map_err(|_| KeyVaultError::Keystore("Failed to lock vault".to_string()))?
                .store_bytes(self.key_name.as_str(), 
                &seed, 
                &mut SecretString::new(
                    self.vault_password.clone().unwrap().into_boxed_str()
                ), 
                &mut SecretString::new(
                    self.key_password.clone().unwrap().into_boxed_str()
                )
                )
                .unwrap();
            Ok(pair.public())

        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let mnemonic = Mnemonic::generate(24).unwrap();
            println!("mnemonic: {:?}", mnemonic.to_string());
            let secret_mnemonic = SecretString::new(mnemonic.to_string().into());
            let (pair, seed) = sr25519::Pair::from_phrase(&secret_mnemonic.expose_secret(), None)
                .expect("Failed to generate keypair from mnemonic");
            // Lock the vault for writing and write the seed bytes
            self.vault
                .write()
                .map_err(|_| KeyVaultError::Keystore("Failed to lock vault".to_string()))?
                .store_bytes(self.key_name.as_str(), &seed, &mut vault_password, &mut file_password)
                .unwrap();
            Ok(pair.public())
        }

    }
}

impl KeyVault for Sr25519KeyVault {
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
    type Pair = sr25519::Pair;

    /// Generate sr25519 key. Mnemonic will never be revealed to you.
    fn generate_key(&self,) -> Result<Self::Public, KeyVaultError> {
        let secret_mnemonic = SecretString::new(Mnemonic::generate(24).unwrap().to_string().into());

        let (pair, seed) = Self::Pair::from_phrase(&secret_mnemonic.expose_secret(), None)
            .expect("Failed to generate keypair from mnemonic");

        let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
        let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();

        // Lock the vault for writing and write the seed bytes
        self.vault
            .write()
            .map_err(|_| KeyVaultError::Keystore("Failed to lock vault".to_string()))?
            .store_bytes(self.key_name.as_str(), &seed, &mut vault_password, &mut file_password)
            .unwrap();

        Ok(pair.public())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyVaultError> {
        Ok(self.vault.try_read().unwrap().list())
    }

    fn has_key(&self, key_name: String) -> bool {
        self.vault.try_read().unwrap().contains(key_name.as_str())
    }

    fn get_public_key(&self,) -> Result<Self::Public, KeyVaultError> {
        if self.storing_passwords {
            // lock vault for writing since the vault state is modified on read
            let seed_bytes = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.as_str(),
                    &mut SecretString::new(self.vault_password.clone().unwrap().into_boxed_str()),
                    &mut SecretString::new(self.key_password.clone().unwrap().into_boxed_str()),
                )
                .unwrap();
            let pair = Self::Pair::from_seed_slice(seed_bytes.expose_secret()).unwrap();
            Ok(pair.public())
        } else {
            // lock vault for writing since the vault state is modified on read
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let seed_bytes = self
                .vault
                .write()
                .unwrap()
                .get(self.key_name.as_str(), &mut vault_password, &mut file_password)
                .unwrap();
            let pair = Self::Pair::from_seed_slice(seed_bytes.expose_secret()).unwrap();
            Ok(pair.public())
        }
    }

    fn sign(
        &self,
        message: &[u8],
    ) -> Result<Self::Signature, KeyVaultError> {
        // lock vault for writing since the vault state is modified on read
        if self.storing_passwords {
            let seed_bytes = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.as_str(),
                    &mut SecretString::new(self.vault_password.clone().unwrap().into_boxed_str()),
                    &mut SecretString::new(self.key_password.clone().unwrap().into_boxed_str()),
                )
                .unwrap();
            let pair = Self::Pair::from_seed_slice(seed_bytes.expose_secret()).unwrap();
            Ok(pair.sign(message))
        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let seed_bytes = self
                .vault
                .write()
                .unwrap()
                .get(self.key_name.as_str(), &mut vault_password, &mut file_password)
                .unwrap();
            let pair = Self::Pair::from_seed_slice(seed_bytes.expose_secret()).unwrap();
            Ok(pair.sign(message))
        }
    }

    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool {
        Self::Pair::verify(signature, message, public)
    }
    fn get_secure_password(&self, _password_name: String) -> Result<SecretString, KeyVaultError> {
        Err(KeyVaultError::Keystore(String::from("This function is not yet implemented")))
    }
}
#[derive(Clone, Debug)]
pub struct IrohKeyVault {
    vault: Arc<RwLock<Vault>>,
    key_name: String,
    key_password: Option<String>,
    vault_password: Option<String>,
    storing_passwords: bool,
}

impl IrohKeyVault {
    pub fn new(vault: Vault, index: usize) -> Self {
        let key_name = format!("iroh_key_idx_{}", index);
        Self {
            vault: Arc::new(RwLock::new(vault)),
            key_name,
            key_password: None,
            vault_password: None,
            storing_passwords: false,
        }
    }

    pub fn new_store_info(
        vault: Vault,
        vault_password: SecretString,
        key_password: SecretString,
        index: usize,
    ) -> Self {
        println!("creating Iroh vault and storing info");
        let key_name = format!("iroh_key_idx_{}", index);
        let key_password_string = String::from(key_password.expose_secret());
        let vault_password_string = String::from(vault_password.expose_secret());
        Self {
            vault: Arc::new(RwLock::new(vault)),
            key_name,
            key_password: Some(key_password_string),
            vault_password: Some(vault_password_string),
            storing_passwords: true,
        }
    }

    pub fn get_key_name(&self) -> String {
        self.key_name.clone()
    }

    pub fn get_secret_key(&self,) -> Result<IrohSecretKey, KeyVaultError> {
        if self.storing_passwords {
            // let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());
            println!("getting secret key for Iroh with stored info");
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            let secret_key = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let mut secret_bytes = [0u8; 32];
            secret_key.expose_secret().read(&mut secret_bytes)?;
            let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
            Ok(secret_key)
        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let secret_key = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let mut secret_bytes = [0u8; 32];
            secret_key.expose_secret().read(&mut secret_bytes)?;
            let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
            Ok(secret_key)
        }
    }
}

impl KeyVault for IrohKeyVault {
    type Public = iroh::PublicKey;
    type Signature = iroh::Signature;
    // This is not used, but must be fulfilled for the KeyVault trait
    type Pair = sp_core::ed25519::Pair;

    fn generate_key(&self,) -> Result<Self::Public, KeyVaultError> {
        let iroh_sk = IrohSecretKey::generate(&mut rand::rng());
        if self.storing_passwords {
            println!("Generating keys for Iroh with stored info");
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            self.vault
                .write()
                .unwrap()
                .store_bytes(
                    self.key_name.clone().as_str(),
                    &iroh_sk.to_bytes(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            Ok(iroh_sk.public())
        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            self.vault
                .write()
                .unwrap()
                .store_bytes(
                    self.key_name.clone().as_str(),
                    &iroh_sk.to_bytes(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            Ok(iroh_sk.public())
        }
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyVaultError> {
        Ok(self.vault.try_read().unwrap().list())
    }

    fn has_key(&self, key_name: String) -> bool {
        self.vault.try_read().unwrap().contains(key_name.as_str())
    }

    fn get_public_key(&self,) -> Result<Self::Public, KeyVaultError> {
        if self.storing_passwords {
            println!("getting public key for Iroh with stored info");
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            let secret_key = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let mut secret_bytes = [0u8; 32];
            secret_key.expose_secret().read(&mut secret_bytes)?;
            let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
            Ok(secret_key.public())
        } else {
            // lock vault for writing since the vault state is modified on read
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let secret_key = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let mut secret_bytes = [0u8; 32];
            secret_key.expose_secret().read(&mut secret_bytes)?;
            let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
            Ok(secret_key.public())
        }
    }

    fn sign(
        &self,
        message: &[u8],
    ) -> Result<Self::Signature, KeyVaultError> {
        if self.storing_passwords {
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            let secret_key = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let mut secret_bytes = [0u8; 32];
            secret_key.expose_secret().read(&mut secret_bytes)?;
            let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
            Ok(secret_key.sign(message))
        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let secret_key = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let mut secret_bytes = [0u8; 32];
            secret_key.expose_secret().read(&mut secret_bytes)?;
            let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
            Ok(secret_key.sign(message))
        }
        
    }

    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool {
        public.verify(message, signature).is_ok()
    }

    fn get_secure_password(&self, _password_name: String) -> Result<SecretString, KeyVaultError> {
        Err(KeyVaultError::Keystore(String::from("This function is not yet implemented")))
    }
}

#[derive(Error, Debug, Clone)]
pub struct SteKeyVault<E: Pairing> {
    vault: Arc<RwLock<Vault>>,
    phantom: PhantomData<E>,
    key_name: String,
    key_password: Option<String>,
    vault_password: Option<String>,
    storing_passwords: bool,
    index: usize,
}

impl<E: Pairing> SteKeyVault<E> {
    pub fn new(vault: Vault, index: usize) -> Self {
        let key_name = format!("ste_key_idx_{}", index);
        Self {
            vault: Arc::new(RwLock::new(vault)),
            phantom: PhantomData::default(),
            key_name,
            key_password: None,
            vault_password: None,
            storing_passwords: false,
            index,
            
        }
    }

    pub fn new_store_info(
        vault: Vault,
        vault_password: SecretString,
        key_password: SecretString,
        index: usize,
    ) -> Self {
        println!("creating STE vault and storing info");
        let key_name = format!("ste_key_idx_{}", index);
        let key_password_string = String::from(key_password.expose_secret());
        let vault_password_string = String::from(vault_password.expose_secret());
        Self {
            vault: Arc::new(RwLock::new(vault)),
            phantom: PhantomData::default(),
            key_name,
            key_password: Some(key_password_string),
            vault_password: Some(vault_password_string),
            storing_passwords: true,
            index,
        }
    }

    pub fn get_key_name(&self) -> String {
        self.key_name.clone()
    }

    pub fn generate_key(&self) -> Result<(), KeyVaultError> {
        if self.storing_passwords {
            println!("generating secret key for STE with stored info");
            let sk = SecretKey::<E>::new(&mut ark_std::rand::thread_rng(), self.index);
            let mut sk_bytes = Vec::new();
            sk.serialize_compressed(&mut sk_bytes).unwrap();
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            self.vault
                .write()
                .unwrap()
                .store_bytes(
                    self.key_name.clone().as_str(),
                    &mut sk_bytes.clone(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            Ok(())
        } else {
            let sk = SecretKey::<E>::new(&mut ark_std::rand::thread_rng(), self.index);
            let mut sk_bytes = Vec::new();
            sk.serialize_compressed(&mut sk_bytes).unwrap();
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            self.vault
                .write()
                .unwrap()
                .store_bytes(
                    self.key_name.clone().as_str(),
                    &mut sk_bytes.clone(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            Ok(())
        }
    }

    pub fn get_pk(&self, crs: &CRS<E>) -> Result<PublicKey<E>, KeyVaultError> {
        if self.storing_passwords {
            println!("getting public key for STE with stored info");
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            let sk_bytes = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let sk = SecretKey::<E>::deserialize_compressed(sk_bytes.expose_secret()).unwrap();
            Ok(sk.get_pk(crs))
        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let sk_bytes = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let sk = SecretKey::<E>::deserialize_compressed(sk_bytes.expose_secret()).unwrap();
            Ok(sk.get_pk(crs))
        }
    }

    pub fn partial_decryption(
        &self,
        ciphertext: &Ciphertext<E>,
    ) -> Result<PartialDecryption<E>, KeyVaultError> {
        if self.storing_passwords {
            println!("generating partial decryption with stored info");
            let mut file_password =
                SecretString::new(self.key_password.clone().unwrap().into_boxed_str());
            let mut vault_password =
                SecretString::new(self.vault_password.clone().unwrap().into_boxed_str());
            let sk_bytes = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let sk = SecretKey::<E>::deserialize_compressed(sk_bytes.expose_secret()).unwrap();

            Ok(sk.partial_decryption(&ciphertext))
        } else {
            let mut vault_password = self.get_secure_password(String::from("vault_password")).unwrap();
            let mut file_password = self.get_secure_password(String::from("file_password")).unwrap();
            let sk_bytes = self
                .vault
                .write()
                .unwrap()
                .get(
                    self.key_name.clone().as_str(),
                    &mut vault_password,
                    &mut file_password,
                )
                .unwrap();
            let sk = SecretKey::<E>::deserialize_compressed(sk_bytes.expose_secret()).unwrap();
            Ok(sk.partial_decryption(&ciphertext))
        }
    }
    fn get_secure_password(&self, _password_name: String) -> Result<SecretString, KeyVaultError> {
        Err(KeyVaultError::Keystore(String::from("This function is not yet implemented")))
    }
}
