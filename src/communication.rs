use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Key;
use sodiumoxide::crypto::secretbox::Nonce;
use std::convert::TryInto;
use thiserror::Error;
use base64::DecodeError;
use serde::{Serialize, Deserialize};
use std::str;
use serde::de::DeserializeOwned;
use anyhow::Result;


pub fn encrypt<V: Serialize>(value: V, key: Key) -> Result<String> {
    let json = serde_json::to_string(&value)?;
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(json.as_bytes(), &nonce, &key);

    let nonce_str = base64::encode(nonce);

    return Ok(format!("{}|{}", nonce_str, base64::encode(ciphertext)));
}

#[derive(Error, Debug)]
pub enum DecryptionError {
    #[error("Invalid Cipher String")]
    InvalidString,
    #[error("Could not deserialize plain text to json")]
    DeserializeError(
        #[from] serde_json::Error
    ),
    #[error("Could not decrypt")]
    CouldNotBeDecrypted,
    #[error("Could not deserialize plain text to json")]
    Base64DecodeError(
        #[from] DecodeError
    ),
    #[error("Nonce of invalid length")]
    InvalidNonceLength,
    #[error("Could not parse plaintext to string")]
    ParseError,
}

pub fn decrypt<V: DeserializeOwned>(text: String, key: Key) -> Result<V, DecryptionError> {
    let split: Vec<&str> = text.split("|").collect();

    if split.len() != 2 {
        return Err(DecryptionError::InvalidString);
    };

    let nonce_str = split[0];
    let ciphertext_str = split[1];

    let ciphertext = base64::decode(ciphertext_str)?;

    let nonce = Nonce(nonce_str.as_bytes().try_into().map_err(|_| DecryptionError::InvalidNonceLength)?); // TODO error

    let plaintext = secretbox::open(&ciphertext, &nonce, &key).map_err(|_| DecryptionError::CouldNotBeDecrypted)?;

    let plaintext_str = String::from_utf8(plaintext).map_err(|_| DecryptionError::ParseError)?;

    Ok(serde_json::from_str::<V>(&plaintext_str)?)
}
