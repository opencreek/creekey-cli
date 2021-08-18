use crate::communication::{
    decrypt, encrypt, poll_for_message, send_to_phone, MessageRelayResponse,
};
use crate::ssh_agent::PhoneSignResponse;
use anyhow::Result;
use futures::executor::block_on;
use serde;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox::Key;
use std::collections::HashMap;
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
struct SignRequest {
    #[serde(rename = "userId")]
    user_id: String,
    message: String,
}

pub fn sign_on_phone<REQUEST: Serialize, RESPONSE: DeserializeOwned>(
    request: REQUEST,
    phone_id: String,
    relay_id: String,
    key: Key,
) -> Result<RESPONSE> {
    send_to_phone(key.clone(), request, phone_id)?;

    let phone_response: MessageRelayResponse = block_on(poll_for_message(relay_id))?;

    println!("Decrypting Response...");

    let data: RESPONSE = decrypt(phone_response.message, key)?;

    Ok(data)
}
