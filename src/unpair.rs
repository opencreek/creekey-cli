use crate::communication::send_to_phone;

use crate::output::Log;

use crate::keychain::{
    delete_gpg_from_keyychain, delete_phone_id, delete_secret_key, get_phone_id, get_secret_key,
};
use anyhow::Result;

use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;

pub async fn unpair() -> Result<()> {
    let log = Log::NONE;
    let key = match get_secret_key() {
        Ok(k) => k,
        Err(e) => {
            log.error("Could not read the secret key. Probably already unpaired!")?;
            log.error(format!("Error received: {}", e).as_str())?;
            return Ok(());
        }
    };
    let phone_id = match get_phone_id() {
        Ok(k) => k,
        Err(e) => {
            log.error("Could not read the phone id. Probably already unpaired!")?;
            log.error(format!("Error received: {}", e).as_str())?;
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

    delete_phone_id()?;
    delete_secret_key()?;
    delete_gpg_from_keyychain()?;

    log.success("Succesfully Unpaired")?;
    Ok(())
}
