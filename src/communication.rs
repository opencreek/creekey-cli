use anyhow::Result;
use base64::DecodeError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Key;
use sodiumoxide::crypto::secretbox::Nonce;
use std::collections::HashMap;
use std::convert::TryInto;
use std::{str, thread, time};
use thiserror::Error;

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
    DeserializeError(#[from] serde_json::Error),
    #[error("Could not decrypt")]
    CouldNotBeDecrypted,
    #[error("Could not deserialize plain text to json")]
    Base64DecodeError(#[from] DecodeError),
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
    let nonce_bytes = base64::decode(nonce_str)?;

    let nonce = Nonce(
        nonce_bytes
            .try_into()
            .map_err(|_| DecryptionError::InvalidNonceLength)?,
    ); // TODO error

    let plaintext = secretbox::open(&ciphertext, &nonce, &key)
        .map_err(|_| DecryptionError::CouldNotBeDecrypted)?;

    let plaintext_str = String::from_utf8(plaintext).map_err(|_| DecryptionError::ParseError)?;

    Ok(serde_json::from_str::<V>(&plaintext_str)?)
}

pub async fn send_to_phone<V: Serialize>(key: Key, request: V, phone_id: String) -> Result<()> {
    let str = encrypt(&request, key)?;

    let mut map = HashMap::new();
    map.insert("message", str);
    map.insert("userId", phone_id);
    let client = reqwest::Client::new();

    let resp = client
        .post("https://ssh-proto.s.opencreek.tech/messaging/ring")
        .json(&map)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let str = resp.text().await?;
        panic!("got {}: {}", status, str)
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageRelayResponse {
    pub message: String,
}

#[derive(Error, Debug)]
pub enum PollError {
    #[error("timeout error")]
    Timeout,
    #[error("Network Error")]
    NetworkError(#[from] reqwest::Error),
}

pub async fn poll_for_message<V: DeserializeOwned>(relay_id: String) -> Result<V, PollError> {
    poll_for_message_with_timeout(relay_id, 2 * 10 * 1000).await
}
pub async fn poll_for_message_with_timeout<V: DeserializeOwned>(
    relay_id: String,
    timeout: u128,
) -> Result<V, PollError> {
    let start = time::Instant::now();
    let response: V = loop {
        if start.elapsed().as_millis() > timeout {
            return Err(PollError::Timeout);
        }
        thread::sleep(time::Duration::from_millis(1000));
        let resp = reqwest::get(
            "https://ssh-proto.s.opencreek.tech/messaging/relay/".to_owned() + &relay_id,
        )
        .await;
        let _found = match resp {
            Ok(a) => {
                if a.status().as_u16() != 404 {
                    break a.json::<V>().await?;
                }
            }
            Err(e) => println!("{}", e),
        };
    };
    Ok(response)
}
