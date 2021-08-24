use crate::communication::{decrypt, poll_for_message, PollError};
use crate::constants::{
    get_config_folder, get_phone_id_path, get_secret_key_path, get_ssh_key_path,
};
use crate::output::Log;
use anyhow::{anyhow, Result};
use colored::Color;

use qrcode::render::unicode;
use qrcode::render::Canvas;
use qrcode::{EcLevel, QrCode, Version};
use serde::{Deserialize, Serialize};
use serde_json;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::kx::PublicKey;
use sodiumoxide::crypto::kx::SecretKey;
use sodiumoxide::crypto::secretbox::Key;
use sodiumoxide::randombytes::randombytes;
use sodiumoxide::utils::memzero;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::Write;
use whoami::{hostname, username};
use byteorder::{WriteBytesExt, BigEndian};

pub fn render_qr_code(str: &[u8], small: bool) {
    let mut size = 1;
    let code = loop {
        match QrCode::with_version(str, Version::Normal(size), EcLevel::L) {
            Ok(code) => break code,
            Err(_) => {
                size = size + 1;
            }
        };
    };
    eprintln!("choose size: {}", size);
    if small {
        let image = code.render::<unicode::Dense1x2>().build();
        println!("{}", image);
    } else {
        let white = String::from("\x1B[40m  \x1B[0m");
        let dark = String::from("\x1B[47m  \x1B[0m");
        let image = code
            .render()
            .light_color(white.as_str())
            .dark_color(dark.as_str())
            .quiet_zone(false)
            .build();
        println!();
        println!("   {}", image.replace("\n", "\n   "));
        println!();
    }
}

mod public_key_serializer {
    use serde::de::Error;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};
    use sodiumoxide::crypto::kx::x25519blake2b::PublicKey;

    pub fn serialize<S: Serializer>(v: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let base64 = String::deserialize(d)?;
        PublicKey::from_slice(
            match base64::decode(base64.as_bytes()).map_err(|e| serde::de::Error::custom(e)) {
                Ok(a) => a,
                Err(a) => return Err(a),
            }
            .as_slice(),
        )
        .ok_or(D::Error::custom("test"))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingRequest {
    public_key: PublicKey,

    pairing_key: Vec<u8>,
    client_name: String,
    local_user_name: String,
    version: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingResponse {
    #[serde(with = "public_key_serializer", rename = "serverKey")]
    server_key: PublicKey,
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingData {
    #[serde(rename = "phoneId")]
    phone_id: String,
    #[serde(rename = "publicKeySSH")]
    public_key_ssh: String,
}

struct ClientPairingData {
    phone_id: String,
    public_key_ssh: String,
    rx: String, // TODO what exactly are these lol
}

fn decode_pairing_response(
    client_pk: PublicKey,
    client_sk: SecretKey,
    response: PairingResponse,
) -> Result<ClientPairingData> {
    //TODO sanity checks on server Key

    let (rx, mut tx) = kx::client_session_keys(&client_pk, &client_sk, &response.server_key)
        .map_err(|_| anyhow!("client session keys failed"))?;

    memzero(tx.0.as_mut());

    let base64rx = base64::encode(rx.as_ref());

    let data: PairingData = decrypt(response.message, Key(rx.as_ref().try_into()?))?;
    Ok(ClientPairingData {
        phone_id: data.phone_id,
        public_key_ssh: data.public_key_ssh,
        rx: base64rx,
    })
}

fn make_pairing_message(exchange: PairingRequest) ->  Vec<u8> {
    let mut ret = Vec::new();
    ret.write_u8(1);

    ret.write_all(exchange.public_key.as_ref());

    ret.write_all(exchange.pairing_key.as_ref());

    ret.write_all(exchange.client_name.as_ref());

    ret
}

pub async fn pair(small: bool) -> Result<()> {
    let (client_pk, client_sk) = kx::gen_keypair();

    create_config_folder()?;
    let log = Log::NONE;

    let pairing_id_bytes = randombytes(16);
    let pairing_id = base64::encode_config(&pairing_id_bytes, base64::URL_SAFE);
    let hostname = hostname();
    let username = username();
    let exchange = PairingRequest {
        public_key: client_pk,
        pairing_key: pairing_id_bytes,
        client_name: hostname.into(),
        local_user_name: username.into(),
        version: "0.1.0".to_string(),
    };

    // let pubic_base64 = base64::encode(exchange.public_key);
    // let string = format!("{}|{}|{}|{}|{}", exchange.version, pubic_base64, exchange.pairing_key, exchange.client_name, exchange.local_user_name);
    let json = serde_json::to_string(&exchange)?;

    let pairing_message = make_pairing_message(exchange);

    println!();
    println!();
    log.println(
        "📷",
        "Scan this QR code wit the app (https://creekey.io/app)",
        Color::White,
    )?;
    render_qr_code(&pairing_message, small);
    log.waiting_on("Waiting for pairing...")?;

    let response: PairingResponse = match poll_for_message::<PairingResponse>(pairing_id).await {
        Ok(t) => t,
        Err(e) => {
            match e {
                PollError::Timeout => {
                    // There is an emjoi at the beginning of the string
                    log.fail("Timed out. Please try again.")?;
                }
                _ => {}
            };
            return Ok(());
        }
    };

    log.success("Found Pairing!")?;

    let client_data = decode_pairing_response(client_pk, client_sk, response)?;
    log.println("💾", "Saving Pairing data...", Color::Green)?;

    write_key_to_disc(client_data.rx)?;
    write_public_ssh_to_disc(client_data.public_key_ssh)?;
    write_phone_id_to_disk(client_data.phone_id)?;
    log.println("✔️", "Done!", Color::Green)?;

    log.user_todo("Run 'creekey setup-ssh' to auto set up your ssh configuration")?;

    return Ok(());
}

fn write_phone_id_to_disk(phone_id: String) -> Result<()> {
    let path = get_phone_id_path()?;

    if path.exists() {
        fs::remove_file(path.clone())?;
    }

    let mut file = File::create(path)?;
    file.write_all(phone_id.as_bytes())?;
    Ok(())
}

fn write_public_ssh_to_disc(mut key: String) -> Result<()> {
    let path = get_ssh_key_path()?;

    if path.exists() {
        fs::remove_file(path.clone())?;
    }

    let mut file = File::create(path).unwrap();
    file.write_all(key.as_bytes())?;

    unsafe {
        memzero(key.as_bytes_mut());
    }
    Ok(())
}

fn create_config_folder() -> Result<()> {
    let path = get_config_folder()?;
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn write_key_to_disc(mut key: String) -> Result<()> {
    let path = get_secret_key_path()?;

    if path.exists() {
        fs::remove_file(path.clone())?;
    }

    let mut file = File::create(path).unwrap();
    file.write_all(key.as_bytes())?;

    unsafe {
        memzero(key.as_bytes_mut());
    }
    Ok(())
}
