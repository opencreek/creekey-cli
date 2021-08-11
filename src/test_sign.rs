use anyhow::Result;
use std::collections::HashMap;
use crate::{read_sync_key, read_sync_phone_id, PhoneSignResponse};
use crate::sign_on_phone::sign_on_phone;
use sodiumoxide::randombytes::randombytes;

pub fn test_sign() -> Result<()> {

    let key = read_sync_key()?;
    let phone_id = read_sync_phone_id()?;
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);
    let base64_data = base64::encode(randombytes(128));

    println!("{}", phone_id);
    let mut payload = HashMap::new();
    let relay_id2 = relay_id.clone();
    payload.insert("type", "sign");
    payload.insert("data", &base64_data);
    payload.insert("relayId", &relay_id2);

    let response: PhoneSignResponse = sign_on_phone(payload, phone_id, relay_id, key)?;
    if response.accepted {
        println!("You accepted the request");
        println!("{}", response.signature)
    } else {
        println!("You rejected the request!");
    }

    Ok(())

}
