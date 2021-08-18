use crate::communication::PollError;
use crate::output::Log;
use crate::sign_on_phone::{sign_on_phone, SignError};
use crate::ssh_agent::{read_sync_key, read_sync_phone_id, PhoneSignResponse};
use anyhow::{Context, Result};
use colored::Color;
use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;

pub async fn test_sign() -> Result<()> {
    let key = read_sync_key()?;
    let phone_id = read_sync_phone_id()?;
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);
    let base64_data = base64::encode(randombytes(128));
    let log = Log::NONE;

    let mut payload = HashMap::new();
    let relay_id2 = relay_id.clone();
    payload.insert("type", "sign");
    payload.insert("data", &base64_data);
    payload.insert("relayId", &relay_id2);

    log.println("⏳ Waiting on Phone Authorization...", Color::Yellow);

    let response: PhoneSignResponse = match sign_on_phone(payload, phone_id, relay_id, key).await {
        Ok(t) => t,
        Err(e) => {
            match e {
                SignError::PollError(poll_error) => {
                    match poll_error {
                        PollError::Timeout => {
                            log.println("❌ Timed out!", Color::Red);
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
        log.println("🏁 Request Accepted!", Color::Green);
    } else {
        log.println("❌ Request Rejected!", Color::Red);
    }

    Ok(())
}
