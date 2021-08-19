use crate::communication::send_to_phone;

use crate::constants::{get_phone_id_path, get_secret_key_path};
use crate::output::Log;
use crate::ssh_agent::{read_sync_key, read_sync_phone_id};

use anyhow::Result;
use colored::Color;
use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;
use std::fs;

pub async fn unpair() -> Result<()> {
    let log = Log::NONE;
    let key = match read_sync_key() {
        Ok(k) => k,
        Err(e) => {
            log.println(
                "🚨 Could not read the secret key. Probably already unpaired!",
                Color::Red,
            )?;
            log.println(format!("🚨 Error received: {}", e).as_str(), Color::Red)?;
            return Ok(());
        }
    };
    let phone_id = match read_sync_phone_id() {
        Ok(k) => k,
        Err(e) => {
            log.println(
                "🚨 Could not read the phone id. Probably already unpaired!",
                Color::Red,
            )?;
            log.println(format!("🚨 Error received: {}", e).as_str(), Color::Red)?;
            return Ok(());
        }
    };

    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);

    let mut payload = HashMap::new();
    let relay_id2 = relay_id.clone();
    payload.insert("type", "unpair");
    payload.insert("data", "");
    payload.insert("relayId", &relay_id2);

    send_to_phone(key, payload, phone_id).await?;

    fs::remove_file(get_phone_id_path()?)?;
    fs::remove_file(get_secret_key_path()?)?;

    log.println("🏁 Succesfully Unpaired", Color::Green)?;
    Ok(())
}
