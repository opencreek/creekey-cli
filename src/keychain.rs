use keyring::{Keyring, KeyringError};
use thiserror::Error;

use anyhow::Context;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Key;

#[derive(Error, Debug)]
pub enum KeyChainError {
    #[error("Not in Keychain")]
    Missing,

    #[error("OS Keychain error: {0}")]
    OsError(String),

    #[error("No Key chain provider found")]
    ProviderMissing,

    #[error("Parse Error")]
    ParseError,
}
const SERVICE: &str = "creekey";

const SECRET_KEY: &str = "secret-key";
const PHONE_ID: &str = "phone-id";
const GPG_KEY: &str = "gpg-key";

fn get(id: &str) -> Result<String, KeyChainError> {
    let keyring = Keyring::new(&SERVICE, id);

    match keyring.get_password() {
        Ok(k) => Ok(k),
        Err(e) => match e {
            KeyringError::NoBackendFound => Err(KeyChainError::ProviderMissing),
            KeyringError::NoPasswordFound => Err(KeyChainError::Missing),
            e => Err(KeyChainError::OsError(e.to_string())),
        },
    }
}

fn set(id: &str, value: String) -> Result<(), KeyChainError> {
    let keyring = Keyring::new(&SERVICE, id);

    match keyring.set_password(&value) {
        Ok(_) => Ok(()),
        Err(e) => match e {
            KeyringError::NoBackendFound => Err(KeyChainError::ProviderMissing),
            KeyringError::NoPasswordFound => Err(KeyChainError::Missing),
            e => Err(KeyChainError::OsError(e.to_string())),
        },
    }
}

fn delete(id: &str) -> Result<(), KeyChainError> {
    let keyring = Keyring::new(&SERVICE, id);

    match keyring.delete_password() {
        Ok(_) => Ok(()),
        Err(e) => match e {
            KeyringError::NoBackendFound => Err(KeyChainError::ProviderMissing),
            KeyringError::NoPasswordFound => Err(KeyChainError::Missing),
            e => Err(KeyChainError::OsError(e.to_string())),
        },
    }
}

pub fn get_secret_key() -> Result<Key, KeyChainError> {
    let value = get(SECRET_KEY)?;
    eprintln!("{:X?}", value);
    let decoded = base64::decode(value).map_err(|_| KeyChainError::ParseError)?;
    Ok(secretbox::Key::from_slice(&decoded)
        .context("")
        .map_err(|_| KeyChainError::ParseError)?)
}

pub fn store_secret_key(key: Vec<u8>) -> Result<(), KeyChainError> {
    let encoded = base64::encode(key);
    set(SECRET_KEY, encoded)
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

pub fn get_gpg_from_keychain() -> Result<String, KeyChainError> {
    get(GPG_KEY)
}

pub fn store_gpg_in_keychain(key: String) -> Result<(), KeyChainError> {
    set(GPG_KEY, key)
}

pub fn delete_gpg_from_keyychain() -> Result<(), KeyChainError> {
    delete(GPG_KEY)
}
