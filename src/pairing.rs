use qrcode::{QrCode, EcLevel};
use qrcode::render::unicode;
use sodiumoxide::crypto::kx;
use serde_json;
use serde::{Serialize, Deserialize };
use sodiumoxide::crypto::kx::PublicKey;
use sodiumoxide::randombytes::randombytes;
use sodiumoxide::crypto::kx::SecretKey;
use crate::communication::{decrypt, poll_for_message};
use anyhow::{anyhow, Result};
use sodiumoxide::crypto::secretbox::Key;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::Write;
use sodiumoxide::utils::memzero;

pub fn render_qr_code(str: &str) {
    let code = QrCode::with_error_correction_level(str, EcLevel::L)
        .unwrap();
    let image = code.render::<unicode::Dense1x2>()
        .build();
    println!("{}", image);
}

mod public_key_serializer {
    use serde::{Serialize, Deserialize};
    use serde::{Deserializer, Serializer};
    use sodiumoxide::crypto::kx::x25519blake2b::PublicKey;
    use serde::de::Error;

    pub fn serialize<S: Serializer>(v: &PublicKey, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        let base64 = String::deserialize(d)?;
        PublicKey::from_slice(
            match base64::decode(base64.as_bytes())
                .map_err(|e| serde::de::Error::custom(e)) {
                Ok(a) => a,
                Err(a) => return Err(a)
            }.as_slice()
        )
            .ok_or(D::Error::custom("test"))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingRequest<'a> {
    #[serde(with = "public_key_serializer", rename="pk")]
    public_key: PublicKey,

    #[serde(rename = "pid")]
    pairing_key: &'a str,
    #[serde(rename = "n")]
    client_name: String,
    #[serde(rename = "v")]
    version: String,
}



#[derive(Serialize, Deserialize, Debug)]
struct PairingResponse {
    #[serde(rename="serverKey")]
    server_key: PublicKey,
    message: String
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingData {
    #[serde(rename="phoneId")]
    phone_id: String,
    #[serde(rename="publicKeySSH")]
    public_key_ssh: String
}

struct ClientPairingData {
    phone_id: String,
    public_key_ssh: String,
    rx: String, // TODO what exactly are these lol
}


fn decode_pairing_response(client_pk: PublicKey, client_sk: SecretKey, response: String) -> Result<ClientPairingData> {
    let pairing_response = serde_json::from_str::<PairingResponse>(&response)?;

    //TODO sanity checks on server Key

    let (rx, mut tx) = kx::client_session_keys(&client_pk, &client_sk, &pairing_response.server_key).map_err(|_| anyhow!("client session keys failed"))?;

    memzero(tx.0.as_mut());

    let base64rx = base64::encode(rx.as_ref());

    let data: PairingData = decrypt(response, Key(rx.as_ref().try_into()?))?;
    Ok(ClientPairingData {
        phone_id: data.phone_id,
        public_key_ssh: data.public_key_ssh,
        rx: base64rx,
    })
 }

pub fn pair() -> Result<()> {
    let (client_pk, client_sk) = kx::gen_keypair();

    let pairing_id_bytes = randombytes(32);
    let pairing_id = base64::encode_config(pairing_id_bytes, base64::URL_SAFE);
    let exchange = PairingRequest {
        public_key: client_pk,
        pairing_key: &pairing_id,
        client_name: "This is a test".to_string(),
        version: "0.1.0".to_string(),
    };

    let json = serde_json::to_string(&exchange)?;


    println!();
    println!();
    println!("Scan this QR code with the app");
    render_qr_code(json.to_string().as_str());
    println!("Waiting for Pairing...");

    let response = poll_for_message(pairing_id)?;

    println!("Found Pairing decoding data...");

    let client_data = decode_pairing_response(client_pk, client_sk, response.message)?;
    println!("Saving Pairing Data...");

    write_key_to_disc(client_data.rx)?;
    write_public_ssh_to_disc(client_data.public_key_ssh)?;

    println!("Done!");

    return Ok(());
}

fn write_public_ssh_to_disc(mut key: String) -> Result<()> {
    let mut path = dirs::home_dir().unwrap();
    path.push(".ssh");
    path.push("id_oca.pub");

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

fn write_key_to_disc(mut key: String) -> Result<()> {
    let mut path = dirs::home_dir().unwrap();
    path.push(".config");
    path.push("oca");
    path.push("key");

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