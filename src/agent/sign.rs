use crate::communication::{decrypt, encrypt, poll_for_message, MessageRelayResponse};
use crate::ssh_agent::{read_sync_key, read_sync_phone_id, PhoneSignResponse, SshProxy};
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use colored::Colorize;
use sodiumoxide::crypto::sign::{self, PublicKey, Signature};
use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::pin::Pin;
use tokio::net::UnixStream;
use reqwest::Proxy;
use futures::channel::mpsc::UnboundedSender;
use futures::SinkExt;

fn parse_user_name(data: Vec<u8>) -> Result<String> {
    let mut cursor = Cursor::new(data);

    let length1 = cursor.read_i32::<BigEndian>()?;
    let mut tmp = vec![0u8; length1 as usize];
    cursor.read_exact(&mut tmp);
    cursor.read_u8()?;

    let length_name = cursor.read_i32::<BigEndian>()?;
    println!("{:X?}", length_name);
    let mut name = vec![0u8; length_name as usize];
    cursor.read_exact(&mut name)?;

    println!("{:X?}", name);

    Ok(String::from_utf8(name)?)
}

struct Log<'a> {
    stream: Option<&'a std::os::unix::net::UnixStream>,
}

impl<'a> Log<'a> {
    pub fn println(&mut self, line: String) {
        println!("{}", line);
        match self.stream {
            Some(mut it) => {
                std::io::Write::write_all(&mut it, line.as_bytes());
                std::io::Write::write_all(&mut it, "\n".as_bytes());
            }
            None => (),
        }
    }
}

fn find_proxy(proxies: Vec<SshProxy>, session_hash: &[u8]) -> Option<SshProxy> {
    let ret = proxies.iter().find(|it| {
        if let Ok(sig_bytes) = it.signature.as_slice().try_into() {
            if let Some(pk) = &PublicKey::from_slice(it.key.as_slice()) {
                let sig = &Signature::new(sig_bytes);
                let verification = sign::verify_detached(sig, session_hash, pk);
                verification
            } else {
                false
            }
        } else {
            false
        }
    });

    match ret {
        Some(r) => Some(r.clone()),
        None => None,
    }
    // .map(|it| {
    //     let sig = Signature::new(it.signature.as_slice().try_into().map_err(|_| anyhow!("signature parse error"))?);
    //     let pub_key = &PublicKey::from_slice(it.key.as_slice()).context("no public key").map_err(|_| anyhow!("pk parse error"))?;
    //     let verification = sign::verify_detached(&sig, session_hash, pub_key);
    //     Some((it, verification))
    // })
    // .filter(|it| match it {
    //     Ok(_) => true,
    //     Err(_) => false,
    // })
    // .map(|it| it.unwrap().0)
    // .find(|it| true)
}

pub async fn sign_request(
    socket: &mut UnixStream,
    key_blob: Vec<u8>,
    data: Vec<u8>,
    flags: u32,
    mut proxies: Vec<SshProxy>,
    mut remove_proxy_send: UnboundedSender<SshProxy>,
) -> Result<Option<SshProxy>> {
    println!("signing");
    println!("{:X?}", key_blob);
    println!("{:X?}", data);
    println!("{:X?}", flags);

    let clone = data.clone();
    let mut cursor = Cursor::new(clone);
    let session_length = cursor.read_i32::<BigEndian>()?;
    let mut session_hash = vec![0u8; session_length as usize];
    cursor.read_exact(&mut session_hash)?;
    let mut file = File::create("session.data")?;
    file.write_all(&session_hash);

    let proxy = &find_proxy(proxies.clone(), session_hash.as_slice());

    if let Some(to_remove) = proxy {
        remove_proxy_send.send(to_remove.clone()).await?;
    }

    let stream: std::os::unix::net::UnixStream;

    let mut log = match proxy.clone() {
        Some(it) => {
            stream = std::os::unix::net::UnixStream::connect(it.logger_socket)?;
            Log {
                stream: Some(&stream),
            }
        }
        None => Log { stream: None },
    };

    let name = parse_user_name(data.clone()).unwrap();
    println!("name: {}", &name);
    println!("proxies size: {}", &proxies.len());

    let base64_data = base64::encode(data);
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);

    let mut payload = HashMap::new();
    payload.insert("type", "sign".to_string());
    payload.insert("data", base64_data);

    match proxy {
        Some(a) => {
            println!("host: {}", a.host);
            payload.insert("hostName", a.host.clone());
        }
        _ => (),
    }
    payload.insert("relayId", relay_id.clone());

    let key = read_sync_key()?;
    let phone_id = read_sync_phone_id()?;

    let str = encrypt(&payload, key.clone())?;

    let mut map = HashMap::new();
    map.insert("message", str);
    map.insert("userId", phone_id);

    let client = reqwest::Client::new();

    log.println(
        "creekey ⏳ Waiting for phone authorization ..."
            .truecolor(239, 1, 154)
            .to_string(),
    );

    let mut resp = client
        .post("https://ssh-proto.s.opencreek.tech/messaging/ring")
        .json(&map)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let mut str = resp.text().await?;
        panic!("got {}: {}", status, str)
    }

    let typ = 14u8;

    let phone_response: MessageRelayResponse = poll_for_message(relay_id).await?;

    println!("Decrypting message...");

    let data: PhoneSignResponse = decrypt(phone_response.message, key)?;

    if !data.accepted {
        println!("Request was denied!");
        return Ok(proxy.clone());
    }

    log.println("creekey 🏁 Accepted request".green().to_string());

    let signature_bytes = base64::decode(data.signature.unwrap())?;
    println!("responding to socket with authorization");

    let mut msg_payload = vec![];
    std::io::Write::write(&mut msg_payload, &[typ])?;
    byteorder::WriteBytesExt::write_u32::<BigEndian>(
        &mut msg_payload,
        signature_bytes.len() as u32,
    )?;
    std::io::Write::write_all(&mut msg_payload, &signature_bytes)?;

    println!("{:X?}", msg_payload);

    tokio::io::AsyncWriteExt::write_i32(socket, msg_payload.len() as i32).await?;
    tokio::io::AsyncWriteExt::write_all(socket, &msg_payload).await?;

    Ok(proxy.clone())
}
