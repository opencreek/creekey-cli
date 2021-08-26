use keyring::{Keyring, KeyringError};
use thiserror::Error;
use crate::serects::keychain::KeyChainError::ProviderMissing;



#[derive(Error, Debug)]
pub enum KeyChainError {
    #[error("Not in Keychain")]
    Missing,

    #[error("OS Keychain error: {0}")]
    OsError(#[from] KeyringError),

    #[error("No Key chain provider found")]
    ProviderMissing,
}
const SERVICE: &str = "creekey";

const SECRET_KEY: &str = "secret-key";
const PHONE_ID: &str = "phone-id";


fn get(id: &str)-> Result<String, KeyChainError> {
    let keyring = Keyring::new(&SERVICE, id);

    match keyring.get_password() {
        Ok(k) => Ok(k),
        Err(e) => match e {
            KeyringError::NoBackendFound => Err(KeyChainError::ProviderMissing),
            KeyringError::NoPasswordFound => Err(KeyChainError::Missing),
            e => Err(KeyChainError::OsError(e))
        }
    }
}

fn set(id: &str, value: String)-> Result<(), KeyChainError> {
    let keyring = Keyring::new(&SERVICE, id);

    match keyring.set_password(&value) {
        Ok(k) => Ok(()),
        Err(e) => match e {
            KeyringError::NoBackendFound => Err(KeyChainError::ProviderMissing),
            KeyringError::NoPasswordFound => Err(KeyChainError::Missing),
            e => Err(KeyChainError::OsError(e))
        }
    }
}

fn delete(id: &str)-> Result<(), KeyChainError> {
    let keyring = Keyring::new(&SERVICE, id);

    match keyring.delete_password() {
        Ok(k) => Ok(()),
        Err(e) => match e {
            KeyringError::NoBackendFound => Err(KeyChainError::ProviderMissing),
            KeyringError::NoPasswordFound => Err(KeyChainError::Missing),
            e => Err(KeyChainError::OsError(e))
        }
    }
}

pub fn get_secret_key() -> Result<String, KeyChainError> {
    get(SECRET_KEY)
}

pub fn store_secret_key(key: String) -> Result<(), KeyChainError> {
    set(SECRET_KEY, key)
}

pub fn delete_secret_key() -> Result<(), KeyChainError> {
    delete(SECRET_KEY)
}

pub fn get_phone_id() -> Result<String, KeyChainError> {
    get(PHONE_ID)
}

pub fn store_phone_id(phone_id: String) -> Result<(), KeyChainError> {
    set(PHONE_ID, phone_id)
}

pub fn delete_phone_id() -> Result<(), KeyChainError> {
    delete(PHONE_ID)
}
