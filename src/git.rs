mod agent;
mod communication;
mod constants;
mod me;
mod output;
mod pairing;
mod setup_ssh;
mod sign_on_phone;
mod ssh_agent;
mod ssh_proxy;
mod test_sign;
mod unpair;

use crate::communication::PollError;
use crate::output::{check_color_tty, Log};
use crate::sign_on_phone::{sign_on_phone, SignError};
use crate::ssh_agent::{read_sync_key, read_sync_phone_id};
use anyhow::Result;
use colored::Color;
use serde::{Deserialize, Serialize};
use sodiumoxide::randombytes::randombytes;
use std::env;
use std::fs;
use std::io::{stdin, stdout, Read, Write};

#[derive(Serialize, Deserialize, Debug)]
struct GgpRequest {
    data: String,
    #[serde(rename = "type")]
    message_type: String,
    #[serde(rename = "relayId")]
    relay_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GgpResponse {
    message: Option<String>,
    accepted: bool,
}

pub async fn sign_git_commit() -> Result<()> {
    let path = env::var("GPG_TTY")?;
    check_color_tty();

    let file = fs::OpenOptions::new().write(true).open(path)?;
    let log = Log::from_file(&file);
    let mut buffer = String::new();

    stdin().read_to_string(&mut buffer)?;

    let base64_data = base64::encode(&buffer);

    let phone_id = read_sync_phone_id()?;
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);
    let key = read_sync_key()?;
    let request = GgpRequest {
        data: base64_data,
        message_type: "gpg".to_string(),
        relay_id: relay_id.clone(),
    };

    log.println("⏳ Waiting on Phone Authorization...", Color::Yellow)?;
    let response: GgpResponse = match sign_on_phone(request, phone_id, relay_id, key).await {
        Ok(t) => t,
        Err(e) => {
            match e {
                SignError::PollError(poll_err) => {
                    if let PollError::Timeout = poll_err {
                        // There is an emoji at the beginning of that string!
                        log.println("❌ Timed Out\n", Color::Red)?;
                    }
                }
                _ => {}
            }
            return Ok(());
        }
    };

    if !response.accepted {
        eprintln!("Not accepted!");
        log.println("⏳ Not Accepted", Color::Green)?;
        return Ok(());
    }
    log.println("⏳ Accepted", Color::Green)?;

    if let Some(data_base64) = response.message {
        let out = base64::decode(data_base64)?;
        stdout().write(out.as_slice())?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    sign_git_commit().await?;
    Ok(())
}
