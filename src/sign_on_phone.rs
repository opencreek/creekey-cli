use serde::de::DeserializeOwned;
use anyhow::Result;
use crate::communication::{encrypt, MessageRelayResponse, poll_for_message, decrypt};
use std::collections::HashMap;
use std::io::Read;
use crate::PhoneSignResponse;
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
    let str = encrypt(&request, key.clone())?;

    let mut map = HashMap::new();
    map.insert("message", str);
    map.insert("userId", phone_id);

    let client = reqwest::blocking::Client::new();

    println!("Waiting for phone authorization...");

    let mut resp = client.
        post("https://ssh-proto.s.opencreek.tech/messaging/ring")
        .json(&map)
        .send()?;

    let mut str = String::new();
    resp.read_to_string(&mut str)?;

    if !resp.status().is_success() {
        panic!("got {}: {}", resp.status(), str)
    }

    let typ = 14u8;

    let phone_response: MessageRelayResponse = poll_for_message(relay_id)?;

    println!("Decrypting Response...");

    println!("message is {}", phone_response.message);
    let data: RESPONSE = decrypt(phone_response.message, key)?;


    Ok(data)
}
