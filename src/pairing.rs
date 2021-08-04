use qrcode::QrCode;
use qrcode::render::unicode;
use sodiumoxide::crypto::kx;
use serde_json;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde_json::Error;
use sodiumoxide::crypto::kx::x25519blake2b::PublicKey;
use sodiumoxide::randombytes::randombytes;
use std::{thread, time};
use sodiumoxide::crypto::kx::SecretKey;
use crate::communication::decrypt;
use thiserror::Error;
use anyhow::{Context, anyhow, Result};
use sodiumoxide::crypto::secretbox::Key;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::Write;
use sodiumoxide::utils::{memzero, mlock};

pub fn render_qr_code(str: &str) {
    let code = QrCode::new(str).unwrap();
    let image = code.render::<unicode::Dense1x2>()
        .build();
    println!("{}", image);
}

mod PublicKeySerializer {
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
    #[serde(with = "PublicKeySerializer",alias="pk")]
    publicKey: PublicKey,

    #[serde(alias = "pid")]
    pairingKey: &'a str,
    #[serde(alias = "n")]
    clientName: String,
    #[serde(alias = "v")]
    version: String,
}


#[derive(Serialize, Deserialize, Debug)]
struct MessageRelayResponse {
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingResponse {
    serverKey: PublicKey,
    message: String
}

#[derive(Serialize, Deserialize, Debug)]
struct PairingData {
    phoneId: String,
    publicKeySSH: String
}

struct ClientPairingData {
    phone_id: String,
    public_key_ssh: String,
    rx: String, // TODO what exactly are these lol
}


fn decode_pairing_response(client_pk: PublicKey, client_sk: SecretKey, response: String) -> Result<ClientPairingData> {
    let pairingResponse = serde_json::from_str::<PairingResponse>(&response)?;

    let (rx, tx) = kx::client_session_keys(&client_pk, &client_sk, &pairingResponse.serverKey).map_err(|_| anyhow!("client session keys failed"))?;

    // TODO delete tx
    let base64rx = base64::encode(rx.as_ref()); // todo delete the base64 string in memory

    let data: PairingData = decrypt(response, Key(rx.as_ref().try_into()?))?;
    Ok(ClientPairingData {
        phone_id: data.phoneId,
        public_key_ssh: data.publicKeySSH,
        rx: base64rx,
    })
 }

pub fn pair() -> Result<()> {
    let (client_pk, client_sk) = kx::gen_keypair();

    let pairing_id_bytes = randombytes(32);
    let pairing_id = base64::encode(pairing_id_bytes);
    let exchange = PairingRequest {
        publicKey: client_pk,
        pairingKey: &pairing_id,
        clientName: "This is a test".to_string(),
        version: "0.1.0".to_string(),
    };

    let json = serde_json::to_string(&exchange)?;


    println!();
    println!();
    println!("Scan this QR code with the app");
    render_qr_code(json.to_string().as_str());
    println!("Waiting for Pairing...");

    let  response: MessageRelayResponse = loop {
        thread::sleep(time::Duration::from_millis(1000));
        let resp = reqwest::blocking::get("https://ssh-proto.s.opencreek.tech/messaging/relay/".to_owned() + &pairing_id)
            .unwrap()
            .json::<MessageRelayResponse>();
        match resp {
            Ok(a) => break a,
            Err(_) => (),
        }
    };
    println!("Found Pairing decoding data...");

    let mut client_data = decode_pairing_response(client_pk, client_sk, response.message)?;
    println!("Saving Pairing Data...");

    write_key_to_disc(client_data.rx);
    write_key_to_disc(client_data.public_key_ssh);

    println!("Done!");

    return Ok(());
}

fn write_public_ssh_to_disc(mut key: String) -> Result<()> {
    let mut path = dirs::home_dir().unwrap();
    path.push(".ssh");
    path.push("id_oca.pub");

    if path.exists() {
        fs::remove_file(path.clone());
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
        fs::remove_file(path.clone());
    }

    let mut file = File::create(path).unwrap();
    file.write_all(key.as_bytes())?;

    unsafe {
        memzero(key.as_bytes_mut());
    }
    Ok(())
}
