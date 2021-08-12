use serde::de::DeserializeOwned;
use anyhow::Result;
use crate::communication::{encrypt, MessageRelayResponse, poll_for_message, decrypt, send_to_phone};
use std::collections::HashMap;
use std::io::Read;
use crate::ssh_agent::PhoneSignResponse;
use serde::{Serialize, Deserialize};
use serde;
use sodiumoxide::crypto::secretbox::Key;

#[derive(Serialize, Deserialize, Debug)]
struct SignRequest {
    #[serde(rename = "userId")]
    user_id: String,
    message: String,
}

pub fn sign_on_phone<REQUEST: Serialize, RESPONSE: DeserializeOwned>(request: REQUEST, phone_id: String, relay_id: String, key: Key) -> Result<RESPONSE> {
    send_to_phone(key.clone(), request, phone_id)?;

    let phone_response: MessageRelayResponse = poll_for_message(relay_id)?;

    println!("Decrypting Response...");

    let data: RESPONSE = decrypt(phone_response.message, key)?;


    Ok(data)
}
