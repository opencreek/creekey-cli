use crate::communication::{decrypt, poll_for_message, send_to_phone, MessageRelayResponse, PollError, DecryptionError};

use anyhow::Result;
use serde;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox::Key;
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug)]
struct SignRequest {
    #[serde(rename = "userId")]
    user_id: String,
    message: String,
}

#[derive(Error, Debug)]
pub enum SignError {
    #[error("Poll Error")]
    PollError(#[from] PollError),

    #[error("Error while sending message to phone")]
    PushError(),

    #[error("Could not Decrypt message")]
    DecryptionError(#[from] DecryptionError)
}
pub async fn sign_on_phone<REQUEST: Serialize, RESPONSE: DeserializeOwned>(
    request: REQUEST,
    phone_id: String,
    relay_id: String,
    key: Key,
) -> Result<RESPONSE, SignError> {
    send_to_phone(key.clone(), request, phone_id).await.map_err(|_| SignError::PushError())?;

    let phone_response: MessageRelayResponse = poll_for_message(relay_id).await?;

    println!("Decrypting Response...");

    let data: RESPONSE = decrypt(phone_response.message, key)?;

    Ok(data)
}
