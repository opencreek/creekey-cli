use crate::communication::{
    decrypt, poll_for_message, send_to_phone, MessageRelayResponse, PollError,
};
use crate::ssh_agent::{read_sync_key, read_sync_phone_id, PhoneSignResponse, SshProxy};

use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};

use futures::channel::mpsc::UnboundedSender;
use futures::SinkExt;

use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{Cursor, Read};

use crate::output::Log;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::{sleep, Duration};
use thrussh_keys::key::parse_public_key;
use ring_compat::signature::Verifier;
use ring_compat::signature::ecdsa::p256::NistP256;
use ring_compat::generic_array::GenericArray;
use ecdsa::elliptic_curve::FieldBytes;

fn parse_user_name(data: Vec<u8>) -> Result<String> {
    let mut cursor = Cursor::new(data);

    let length1 = cursor.read_i32::<BigEndian>()?;
    let mut tmp = vec![0u8; length1 as usize];
    cursor.read_exact(&mut tmp)?;
    cursor.read_u8()?;

    let length_name = cursor.read_i32::<BigEndian>()?;
    println!("{:X?}", length_name);
    let mut name = vec![0u8; length_name as usize];
    cursor.read_exact(&mut name)?;

    println!("{:X?}", name);

    Ok(String::from_utf8(name)?)
}

fn parse_key_data(data: Vec<u8>) -> Result<(String, Vec<u8>)> {
    let mut cursor = Cursor::new(data);

    let length1 = cursor.read_i32::<BigEndian>()?;
    let mut key_algo = vec![0u8; length1 as usize];
    cursor.read_exact(&mut key_algo)?;

    if key_algo == b"ecdsa-sha2-nistp256" {
        let length = cursor.read_i32::<BigEndian>()?;
        let mut data = vec![0u8; length as usize];
        cursor.read_exact(&mut data)?;
    }

    let name_length = cursor.read_i32::<BigEndian>()?;
    let mut key_data = vec![0u8; name_length as usize];
    cursor.read_exact(&mut key_data)?;

    Ok((String::from_utf8(key_algo)?, key_data))
}
fn parse_ecdsa_sig(data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {

    let mut cursor = Cursor::new(data);

    let r_length = cursor.read_i32::<BigEndian>()?;
    let mut r = vec![0u8; r_length as usize];
    cursor.read_exact(&mut r)?;

    let t_length = cursor.read_i32::<BigEndian>()?;
    let mut t  = vec![0u8; t_length as usize];
    cursor.read_exact(&mut t)?;

    Ok((r, t))
}

pub fn find_proxy(proxies: Vec<SshProxy>, session_hash: &[u8]) -> Option<SshProxy> {
    eprintln!("------- finding proxy!");
    let ret = proxies.iter().find(|it| {
        if let Ok(pk) = parse_public_key(&it.key) {
            eprintln!("Could parse pk!");
            let ret = pk.verify_detached(session_hash, &it.signature);
            eprintln!("verification: {}", ret);

            ret
        } else {
            if let (algo, key_data) = parse_key_data(it.key.clone()).unwrap() {
                if algo == "ecdsa-sha2-nistp256" {
                    let mat = ring_compat::signature::ecdsa::VerifyingKey::<NistP256>::new(&key_data);
                    if let Ok(pk) = mat {
                        eprintln!("Could parse ecdsa pk!");

                        if let Ok((r, s)) = parse_ecdsa_sig(it.signature.clone()) {
                            let r_gen = GenericArray::clone_from_slice(&r);
                            let s_gen = GenericArray::clone_from_slice(&s);
                            let sig_res = ring_compat::signature::ecdsa::Signature::<NistP256>::from_scalars(r_gen, s_gen);

                            if let Ok(sig) = sig_res{
                                match pk.verify(session_hash, &sig) {
                                    Ok(_) => true,
                                    Err(_) => false
                                }
                            } else {
                                eprintln!("Could not parse sig for ecdsa: {}", sig_res.unwrap_err());
                                eprintln!("signature data: {} len; {:X?}", it.signature.len(), it.signature);
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        eprintln!("Could not parse verifying key for ecdsa: {}", mat.unwrap_err());
                        eprintln!("key data: {} len; {:X?}", it.key.len(), it.key);
                        false
                    }
                } else {
                    eprintln!("Not ecdsa sig!");
                    false
                }
            } else {
                eprintln!("Could not parse key data");
                false
            }
        }
    });

    match ret {
        Some(r) => Some(r.clone()),
        None => None,
    }
}

pub async fn respond_with_failure(socket: &mut UnixStream) -> Result<()> {
    socket.write_i32(1).await?;
    socket.write_u8(5u8).await?;
    socket.flush().await?;

    Ok(())
}

pub async fn sign_request(
    socket: &mut UnixStream,
    _key_blob: Vec<u8>,
    data: Vec<u8>,
    _flags: u32,
    proxies: Vec<SshProxy>,
    mut remove_proxy_send: UnboundedSender<SshProxy>,
) -> Result<()> {
    let clone = data.clone();
    let mut cursor = Cursor::new(clone);
    let session_length = cursor.read_i32::<BigEndian>()?;
    let mut session_hash = vec![0u8; session_length as usize];
    cursor.read_exact(&mut session_hash)?;

    let proxy = &find_proxy(proxies.clone(), session_hash.as_slice());

    if let Some(to_remove) = proxy {
        remove_proxy_send.send(to_remove.clone()).await?;
    }

    let stream: std::os::unix::net::UnixStream;

    let mut log = match proxy.clone() {
        Some(it) => {
            stream = std::os::unix::net::UnixStream::connect(it.logger_socket)?;
            Log::from_stream(&stream)
        }
        None => Log::NONE,
    };

    let name = parse_user_name(data.clone()).unwrap();

    let base64_data = base64::encode(data);
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);

    let mut payload = HashMap::new();
    payload.insert("type", "sign".to_string());
    payload.insert("data", base64_data);
    payload.insert("userName", name);

    match proxy {
        Some(a) => {
            println!("host: {}", a.host);
            payload.insert("hostName", a.host.clone());
        }
        _ => (),
    }
    payload.insert("relayId", relay_id.clone());

    let key = match read_sync_key() {
        Ok(k) => k,
        Err(e) => {
            log.handle_read_error("secret key", e)?;
            sleep(Duration::from_millis(10)).await;
            respond_with_failure(socket).await?;
            return Ok(());
        }
    };

    let phone_id = match read_sync_phone_id() {
        Ok(k) => k,
        Err(e) => {
            log.handle_read_error("phone id", e)?;
            sleep(Duration::from_millis(10)).await;
            respond_with_failure(socket).await?;
            return Ok(());
        }
    };

    log.waiting_on("Waiting for phone authorization ...")?;

    match send_to_phone(key.clone(), payload, phone_id).await {
        Ok(_) => {}
        Err(e) => {
            log.error(format!("Got Error while sending request: {}", e).as_str())?;
            sleep(Duration::from_millis(10)).await;
            respond_with_failure(socket).await?;
            return Ok(());
        }
    }

    let typ = 14u8;

    let polling_response: Result<MessageRelayResponse, PollError> =
        poll_for_message(relay_id).await;

    let phone_response = match polling_response {
        Ok(t) => t,
        Err(e) => {
            match e {
                PollError::Timeout => {
                    // there is an X emoji at the start of the string
                    log.fail("Timed out")?;
                }
                _ => {}
            }
            sleep(Duration::from_millis(10)).await;
            respond_with_failure(socket).await?;
            return Ok(());
        }
    };

    println!("Decrypting message...");

    let data: PhoneSignResponse = decrypt(phone_response.message, key)?;

    if !data.accepted {
        log.fail("Request was denied")?;
        respond_with_failure(socket).await?;
        return Ok(());
    }

    log.success("Accepted request")?;

    let signature_bytes = base64::decode(data.signature.unwrap())?;
    println!("responding to socket with authorization");

    let mut msg_payload = vec![];
    std::io::Write::write(&mut msg_payload, &[typ])?;
    byteorder::WriteBytesExt::write_u32::<BigEndian>(
        &mut msg_payload,
        signature_bytes.len() as u32,
    )?;
    std::io::Write::write_all(&mut msg_payload, &signature_bytes)?;

    tokio::io::AsyncWriteExt::write_i32(socket, msg_payload.len() as i32).await?;
    tokio::io::AsyncWriteExt::write_all(socket, &msg_payload).await?;

    Ok(())
}
