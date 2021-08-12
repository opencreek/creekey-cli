use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Key;
use sodiumoxide::crypto::secretbox::Nonce;
use std::convert::TryInto;
use thiserror::Error;
use base64::DecodeError;
use serde::{Serialize, Deserialize};
use std::{str, thread, time};
use serde::de::DeserializeOwned;
use anyhow::Result;
use serde_json::Error;
use anyhow::anyhow;
use std::collections::HashMap;
use std::io::Read;


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
    let nonce_bytes = base64::decode(nonce_str)?;

    let nonce = Nonce(nonce_bytes.try_into().map_err(|_| DecryptionError::InvalidNonceLength)?); // TODO error

    let plaintext = secretbox::open(&ciphertext, &nonce, &key).map_err(|_| DecryptionError::CouldNotBeDecrypted)?;

    let plaintext_str = String::from_utf8(plaintext).map_err(|_| DecryptionError::ParseError)?;

    Ok(serde_json::from_str::<V>(&plaintext_str)?)
}

pub fn send_to_phone<V: Serialize>(key: Key, request: V, phone_id: String) -> Result<()> {
    let str = encrypt(&request, key)?;

    let mut map = HashMap::new();
    map.insert("message", str);
    map.insert("userId", phone_id);
    let client = reqwest::blocking::Client::new();

    let mut resp = client.
        post("https://ssh-proto.s.opencreek.tech/messaging/ring")
        .json(&map)
        .send()?;

    let mut str = String::new();
    resp.read_to_string(&mut str)?;

    if !resp.status().is_success() {
        panic!("got {}: {}", resp.status(), str)
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageRelayResponse {
    pub message: String,
}

pub fn poll_for_message<V: DeserializeOwned>(relay_id: String) -> Result<V> {
    return poll_for_message_with_timeout(relay_id, 2 * 60 * 1000)
}

pub fn poll_for_message_with_timeout<V: DeserializeOwned>(relay_id: String, timeout: u128) -> Result<V> {
    let start = time::Instant::now();
    let response: V = loop {
        if start.elapsed().as_millis() > timeout {
            return Err(anyhow!("Did not receive a response"))
        }
        thread::sleep(time::Duration::from_millis(1000));
        let resp = reqwest::blocking::get("https://ssh-proto.s.opencreek.tech/messaging/relay/".to_owned() + &relay_id);
        let found = match resp {
            Ok(a) => {
                if a.status().as_u16() != 404 {
                    break a.json::<V>()?;
                }
            }
            Err(e) => println!("{}", e)
        };
    };
    Ok(response)
}
