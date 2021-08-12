use anyhow::Result;
use crate::communication::send_to_phone;
use crate::constants::{get_secret_key_path, get_phone_id_path};
use sodiumoxide::randombytes::randombytes;
use crate::ssh_agent::{PhoneSignResponse, read_sync_key, read_sync_phone_id};
use std::collections::HashMap;

pub fn unpair() -> Result<()> {

    let key = read_sync_key()?;
    let phone_id = read_sync_phone_id()?;

    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);

    let mut payload = HashMap::new();
    let relay_id2 = relay_id.clone();
    payload.insert("type", "unpair");
    payload.insert("data", "");
    payload.insert("relayId", &relay_id2);

    send_to_phone(key, payload, phone_id);

    Ok(())
}
