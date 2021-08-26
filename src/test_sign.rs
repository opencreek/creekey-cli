use crate::communication::PollError;
use crate::keychain::{get_phone_id, get_secret_key};
use crate::output::Log;
use crate::sign_on_phone::{sign_on_phone, SignError};
use crate::ssh_agent::PhoneSignResponse;
use anyhow::Result;

use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;
use std::thread::sleep;
use tokio::time::Duration;

pub async fn test_sign() -> Result<()> {
    let mut log = Log::NONE;
    let key = match get_secret_key() {
        Ok(k) => k,
        Err(e) => {
            log.handle_keychain_error("secret key", e)?;
            return Ok(());
        }
    };

    let phone_id = match get_phone_id() {
        Ok(k) => k,
        Err(e) => {
            log.handle_keychain_error("phone id", e)?;
            return Ok(());
        }
    };
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);
    let base64_data = base64::encode(randombytes(128));

    let mut payload = HashMap::new();
    let relay_id2 = relay_id.clone();
    payload.insert("type", "sign");
    payload.insert("data", &base64_data);
    payload.insert("relayId", &relay_id2);

    log.waiting_on("Waiting on Phone Authorization...")?;

    let response: PhoneSignResponse = match sign_on_phone(payload, phone_id, relay_id, key).await {
        Ok(t) => t,
        Err(e) => {
            match e {
                SignError::PollError(poll_error) => {
                    match poll_error {
                        PollError::Timeout => {
                            log.fail("Timed out!")?;
                        }
                        _ => {}
                    };
                }
                _ => {}
            };
            return Ok(());
        }
    };
    if response.accepted {
        log.success("Request Accepted!")?;
    } else {
        log.fail("Request Rejected!")?;
    }

    Ok(())
}
