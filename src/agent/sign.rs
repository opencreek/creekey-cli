use crate::communication::PollError;
use crate::ssh_agent::{PhoneSignResponse, SshProxy};

use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};

use futures::channel::mpsc::UnboundedSender;
use futures::SinkExt;

use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;

use std::io::{Cursor, Read};

use crate::output::Log;

use anyhow::anyhow;

use ring_compat::generic_array::GenericArray;
use ring_compat::signature::ecdsa::p256::NistP256;
use ring_compat::signature::ecdsa::p384::NistP384;
use ring_compat::signature::Verifier;

use crate::keychain::{get_phone_id, get_secret_key};
use crate::sign_on_phone::{sign_on_phone, SignError};
use thrussh_keys::key::{parse_public_key, PublicKey};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::time::{sleep, Duration};

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

fn parse_first_string(cursor: &mut Cursor<Vec<u8>>) -> Result<Vec<u8>> {
    let first_size = cursor.read_i32::<BigEndian>()?;
    let mut buffer_first = vec![0u8; first_size as usize];
    cursor.read_exact(&mut buffer_first)?;
    return Ok(buffer_first);
}

fn parse_second_string(cursor: &mut Cursor<Vec<u8>>) -> Result<Vec<u8>> {
    let first_size = cursor.read_i32::<BigEndian>()?;
    let mut buffer_first = vec![0u8; first_size as usize];
    cursor.read_exact(&mut buffer_first)?;

    let ret_length = cursor.read_i32::<BigEndian>()?;
    let mut ret = vec![0u8; ret_length as usize];
    cursor.read_exact(&mut ret)?;

    return Ok(ret);
}

fn parse_ecdsa_sig(data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cursor = Cursor::new(data);
    let sig = parse_second_string(&mut cursor)?;

    let mut cursor = Cursor::new(sig);

    let r_length = cursor.read_i32::<BigEndian>()?;
    let mut r = vec![0u8; r_length as usize];
    cursor.read_exact(&mut r)?;
    if r.len() % 2 != 0 {
        r.remove(0);
    }

    let t_length = cursor.read_i32::<BigEndian>()?;
    let mut s = vec![0u8; t_length as usize];
    cursor.read_exact(&mut s)?;

    if s.len() % 2 != 0 {
        s.remove(0);
    }
    Ok((r, s))
}

fn parse_rsa_sig(data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cursor = Cursor::new(data);

    let name_length = cursor.read_i32::<BigEndian>()?;
    let name = vec![0u8; name_length as usize];

    let sig_length = cursor.read_i32::<BigEndian>()?;
    let mut sig = vec![0u8; sig_length as usize];
    cursor.read_exact(&mut sig)?;

    Ok((name, sig))
}

pub fn verify_ecdsa_signature(it: &SshProxy, session_hash: &[u8]) -> Result<bool> {
    let (algo, key_data) = parse_key_data(it.key.clone())?;

    if algo == "ecdsa-sha2-nistp256" {
        let pk = ring_compat::signature::ecdsa::VerifyingKey::<NistP256>::new(&key_data)
            .map_err(|_| anyhow!("Could not parse pk"))?;
        let (r, s) = parse_ecdsa_sig(it.signature.clone())?;

        let r_gen = GenericArray::clone_from_slice(&r);
        let s_gen = GenericArray::clone_from_slice(&s);
        let sig = ring_compat::signature::ecdsa::Signature::<NistP256>::from_scalars(r_gen, s_gen)
            .map_err(|_| anyhow!("could not get signature"))?;

        Ok(match pk.verify(session_hash, &sig) {
            Ok(_) => true,
            Err(_) => false,
        })
    } else if algo == "ecdsa-sha-2-nistp384" {
        let pk = ring_compat::signature::ecdsa::VerifyingKey::<NistP384>::new(&key_data)
            .map_err(|_| anyhow!("could not parse pk"))?;
        let (r, s) = parse_ecdsa_sig(it.signature.clone())?;

        let r_gen = GenericArray::clone_from_slice(&r);
        let s_gen = GenericArray::clone_from_slice(&s);
        let sig = ring_compat::signature::ecdsa::Signature::<NistP384>::from_scalars(r_gen, s_gen)
            .map_err(|_| anyhow!("could not get signature"))?;

        Ok(match pk.verify(session_hash, &sig) {
            Ok(_) => true,
            Err(_) => false,
        })
    } else {
        Ok(false)
    }
}

pub fn verify_ecdsa_signature_detached(proxy: &SshProxy, session_hash: &[u8]) -> bool {
    match verify_ecdsa_signature(proxy, session_hash) {
        Ok(b) => b,
        Err(e) => {
            eprint!("error while ecdsa verification: {}", e);
            false
        }
    }
}

pub fn check_signature(it: &SshProxy, session_hash: &[u8]) -> Result<bool> {
    let mut cursor = Cursor::new(it.signature.clone());

    let sig_name = parse_first_string(&mut cursor).unwrap();
    let sig_data = parse_first_string(&mut cursor).unwrap();

    let (algo, _key_data) = parse_key_data(it.key.clone()).unwrap();

    if algo == "ssh-ed25519" {
        let pk = parse_public_key(&it.key)?;
        let ret = pk.verify_detached(session_hash, &sig_data);
        return Ok(ret);
    } else if algo.starts_with("ssh-rsa") {
        let pk = PublicKey::parse(&sig_name, &it.key)?;

        let ret = pk.verify_detached(session_hash, &sig_data);

        return Ok(ret);
    } else if algo.starts_with("ecdsa") {
        return Ok(verify_ecdsa_signature_detached(it, session_hash));
    }
    return Err(anyhow!("not suppoorted algo"));
}

pub fn find_proxy(proxies: Vec<SshProxy>, session_hash: &[u8]) -> Option<SshProxy> {
    let ret = proxies
        .iter()
        .find(|it| match check_signature(it, session_hash) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error while verification: {}", e);
                false
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

    let key = match get_secret_key() {
        Ok(k) => k,
        Err(e) => {
            log.handle_keychain_error("secret key", e)?;
            sleep(Duration::from_millis(10)).await;
            respond_with_failure(socket).await?;
            return Ok(());
        }
    };

    let phone_id = match get_phone_id() {
        Ok(k) => k,
        Err(e) => {
            log.handle_keychain_error("phone id", e)?;
            sleep(Duration::from_millis(10)).await;
            respond_with_failure(socket).await?;
            return Ok(());
        }
    };

    log.waiting_on("Waiting for phone authorization ...")?;

    let phone_response: PhoneSignResponse =
        match sign_on_phone(payload, phone_id, relay_id, key.clone()).await {
            Ok(res) => res,
            Err(e) => {
                match e {
                    SignError::PollError(PollError::Timeout) => {
                        log.fail("Timed out")?;
                    }
                    _ => {
                        log.fail(
                            format!("Encountered Error while waiting for signature: {}", e)
                                .as_str(),
                        )?;
                    }
                }
                sleep(Duration::from_millis(10)).await;
                respond_with_failure(socket).await?;
                return Ok(());
            }
        };

    if !phone_response.accepted {
        log.fail("Request was denied")?;
        respond_with_failure(socket).await?;
        return Ok(());
    }

    log.success("Accepted request")?;

    let signature_bytes = base64::decode(phone_response.signature.unwrap())?;
    println!("responding to socket with authorization");

    let typ = 14u8;
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

#[test]
fn check_rsa_signature_working() {
    let proxy = SshProxy {
        host: "test".to_string(),
        logger_socket: "test".to_string(),
        key: vec![
            0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 1, 35, 0, 0, 1, 1, 0, 171, 96,
            59, 133, 17, 166, 118, 121, 189, 181, 64, 219, 59, 210, 3, 75, 0, 74, 233, 54, 208,
            107, 227, 215, 96, 240, 143, 203, 170, 219, 78, 180, 237, 195, 179, 199, 145, 199, 10,
            174, 154, 116, 201, 88, 105, 228, 119, 68, 33, 194, 171, 234, 146, 229, 84, 48, 95, 56,
            181, 253, 65, 75, 50, 8, 229, 116, 195, 55, 227, 32, 147, 101, 24, 70, 44, 118, 82,
            201, 139, 49, 225, 110, 125, 166, 82, 59, 210, 0, 116, 42, 100, 68, 216, 63, 205, 94,
            23, 50, 208, 54, 115, 199, 183, 129, 21, 85, 72, 123, 85, 240, 196, 73, 79, 56, 41,
            236, 230, 15, 148, 37, 90, 149, 203, 154, 245, 55, 215, 252, 140, 127, 228, 158, 243,
            24, 71, 78, 242, 146, 9, 146, 5, 34, 101, 176, 160, 110, 166, 109, 74, 22, 127, 217,
            243, 164, 138, 26, 74, 48, 126, 193, 234, 170, 81, 73, 169, 105, 166, 172, 93, 86, 165,
            239, 98, 126, 81, 125, 129, 251, 100, 79, 91, 116, 92, 79, 71, 142, 205, 8, 42, 148,
            146, 247, 68, 170, 211, 38, 247, 108, 140, 77, 201, 16, 11, 198, 171, 121, 70, 29, 38,
            87, 203, 111, 6, 222, 201, 46, 107, 100, 166, 86, 47, 240, 227, 32, 132, 234, 6, 206,
            14, 169, 211, 90, 88, 59, 251, 0, 186, 211, 140, 157, 25, 112, 60, 84, 152, 146, 229,
            170, 120, 220, 149, 226, 80, 81, 64, 105,
        ],
        signature: vec![
            0, 0, 0, 12, 114, 115, 97, 45, 115, 104, 97, 50, 45, 53, 49, 50, 0, 0, 1, 0, 27, 61,
            102, 135, 160, 192, 232, 125, 112, 222, 157, 208, 52, 67, 207, 58, 212, 30, 201, 216,
            108, 151, 88, 179, 70, 30, 208, 3, 188, 243, 18, 33, 139, 40, 238, 229, 135, 242, 228,
            95, 119, 124, 68, 87, 157, 141, 193, 218, 40, 158, 220, 114, 253, 246, 156, 1, 170, 96,
            31, 6, 4, 224, 244, 52, 115, 94, 56, 167, 247, 238, 119, 135, 234, 187, 168, 125, 199,
            255, 42, 104, 37, 90, 117, 75, 175, 148, 44, 76, 198, 31, 21, 7, 108, 19, 221, 88, 79,
            153, 185, 9, 64, 162, 151, 232, 143, 172, 186, 142, 112, 162, 140, 216, 34, 180, 46,
            165, 245, 112, 168, 15, 41, 202, 9, 1, 138, 20, 216, 43, 114, 112, 65, 96, 67, 143,
            229, 156, 182, 254, 161, 98, 46, 86, 118, 38, 244, 17, 10, 103, 14, 129, 20, 45, 232,
            25, 58, 196, 101, 157, 31, 197, 57, 186, 173, 129, 191, 198, 92, 228, 82, 205, 14, 193,
            118, 129, 125, 154, 230, 158, 144, 27, 8, 99, 249, 85, 155, 219, 218, 151, 89, 126,
            165, 158, 152, 200, 140, 28, 44, 114, 144, 97, 34, 226, 113, 160, 30, 86, 26, 78, 252,
            206, 84, 209, 198, 213, 6, 124, 165, 68, 177, 137, 126, 99, 180, 244, 82, 133, 227,
            189, 70, 191, 71, 25, 172, 9, 236, 220, 132, 147, 156, 37, 139, 23, 239, 252, 227, 139,
            202, 57, 147, 181, 97, 112, 54, 209, 114, 58,
        ],
        saved_at: 0,
    };

    let session = vec![
        10, 19, 223, 75, 135, 189, 210, 187, 217, 206, 12, 91, 18, 204, 244, 155, 159, 210, 106,
        33, 102, 151, 135, 48, 169, 43, 127, 81, 220, 219, 52, 145,
    ];
    let verification = check_signature(&proxy, &session).unwrap();

    assert!(verification, "RSA signature could not be verified!");
}

#[test]
fn check_ed25519_signature_working() {
    let proxy = SshProxy {
        host: "test".to_string(),
        logger_socket: "test".to_string(),
        key: vec![
            0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 33, 201,
            154, 174, 86, 203, 185, 200, 175, 191, 40, 175, 236, 49, 28, 245, 199, 11, 104, 11,
            150, 77, 34, 81, 110, 246, 145, 94, 115, 112, 104, 113,
        ],
        signature: vec![
            0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 64, 117, 71, 6,
            206, 128, 138, 218, 225, 70, 34, 180, 215, 116, 120, 115, 107, 30, 37, 58, 173, 89,
            220, 229, 136, 80, 24, 209, 179, 15, 159, 208, 194, 67, 47, 196, 199, 175, 187, 187,
            180, 15, 59, 32, 172, 115, 183, 230, 23, 79, 139, 15, 252, 169, 130, 51, 169, 183, 185,
            212, 104, 182, 237, 189, 9,
        ],
        saved_at: 0,
    };

    let session = vec![
        24, 242, 186, 56, 104, 113, 146, 43, 222, 110, 179, 216, 169, 8, 116, 175, 185, 93, 110,
        237, 237, 243, 146, 250, 146, 64, 31, 105, 138, 254, 154, 60,
    ];
    let verification = check_signature(&proxy, &session).unwrap();

    assert!(verification, "ed25519 signature could not be verified!");
}

#[test]
fn check_ecdsa_signature_working() {
    let proxy = SshProxy {
        host: "test".to_string(),
        logger_socket: "test".to_string(),
        key: vec![
            0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112,
            50, 53, 54, 0, 0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 162, 37,
            235, 138, 225, 135, 57, 69, 158, 209, 229, 224, 49, 37, 248, 146, 204, 162, 225, 28,
            77, 171, 213, 87, 58, 188, 204, 200, 89, 5, 232, 28, 43, 17, 9, 140, 231, 229, 51, 222,
            16, 37, 116, 41, 139, 55, 192, 34, 155, 114, 213, 228, 226, 222, 158, 170, 205, 87, 29,
            191, 11, 142, 204, 83,
        ],
        signature: vec![
            0, 0, 0, 19, 101, 99, 100, 115, 97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112,
            50, 53, 54, 0, 0, 0, 73, 0, 0, 0, 32, 116, 182, 38, 181, 12, 17, 54, 250, 48, 219, 156,
            207, 58, 212, 254, 209, 242, 145, 149, 88, 196, 4, 198, 72, 152, 187, 93, 188, 36, 112,
            15, 200, 0, 0, 0, 33, 0, 181, 252, 72, 249, 244, 101, 200, 35, 74, 175, 42, 9, 103,
            250, 236, 239, 101, 54, 241, 193, 125, 9, 91, 146, 100, 28, 103, 202, 128, 233, 39,
            144,
        ],
        saved_at: 0,
    };

    let session = vec![
        47, 126, 102, 179, 30, 190, 26, 131, 107, 199, 178, 128, 180, 98, 136, 115, 178, 211, 175,
        56, 156, 169, 208, 255, 196, 45, 197, 34, 12, 40, 40, 191,
    ];
    let verification = check_signature(&proxy, &session).unwrap();

    assert!(verification, "ed25519 signature could not be verified!");
}
