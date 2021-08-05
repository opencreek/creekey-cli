mod pairing;
mod communication;

use std;
use reqwest;
use std::collections::HashMap;
use sodiumoxide::crypto::secretbox;
use std::fs;
use std::fs::File;
use std::os::unix::net::{UnixListener, UnixStream};
use std::io::Read;
use std::io::Write;
use std::io::Cursor;
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use byteorder::ReadBytesExt;
use communication::encrypt;
use anyhow::Result;
use crate::communication::{poll_for_message, decrypt};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use sodiumoxide::randombytes::randombytes;

#[derive(Debug)]
enum SSHAgentPacket {
    RequestIdentities,
    // key_blob, data, flags
    SignRequest(Vec<u8>, Vec<u8>, u32),
}

fn cleanup_socket() {
    let _ = std::fs::remove_file("/tmp/test-socket").unwrap_or(());
}

fn generate_key() {
    let mut path = dirs::home_dir().unwrap();
    path.push(".config");
    path.push("oca");
    path.push("key");

    if path.exists() {
        return
    }

    let key = secretbox::gen_key();

    let str = base64::encode(key);

    let mut file = File::create(path).unwrap();
    file.write_all(str.as_bytes()).unwrap();
}

fn read_sync_key() -> secretbox::Key {
    let mut path = dirs::home_dir().unwrap();
    path.push(".config");
    path.push("oca");
    path.push("key");

    let key_str = fs::read_to_string(path).expect("couldn't read key");

    return match base64::decode(key_str) {
        Ok(k) => secretbox::Key::from_slice(&k).unwrap(),
        Err(e) => panic!("couldn't decode key file: {}", e),
    };
}

fn read_key_blob() -> Vec<u8> {
    let mut path = dirs::home_dir().unwrap();
    path.push(".ssh");
    path.push("id_oca.pub");

    let contents = fs::read_to_string(path).expect("couldn't read id.pub");
    let mut iter = contents.split_whitespace();
    iter.next();
    let key_str = match iter.next() {
        Some(s) => s,
        None => panic!("couldn't read id.pub: wrong format?")
    };

    println!("{}", key_str);
    return match base64::decode(key_str) {
        Ok(k) => k,
        Err(e) => panic!("couldn't decode id_oca.pub: {}", e),
    };
}

fn parse_packet(packet: &Vec<u8>) -> SSHAgentPacket {
    println!("{:X?}", packet);
    let mut cursor = Cursor::new(packet);

    let typ = cursor.read_u8().unwrap();
    if typ == 11 {
        return SSHAgentPacket::RequestIdentities;
    }

    if typ == 13 {
        let key_blob_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut key_blob = vec![0u8; key_blob_length as usize];
        cursor.read_exact(&mut key_blob).unwrap();

        let data_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut data = vec![0u8; data_length as usize];
        cursor.read_exact(&mut data).unwrap();

        let flags = cursor.read_u32::<BigEndian>().unwrap();

        return SSHAgentPacket::SignRequest(key_blob, data, flags);
    }

    panic!("unknown packet")
}


#[derive(Serialize, Deserialize, Debug)]
struct PhoneSignResponse {
    signature: String,
    accepted: bool,
}

fn sign_request(mut socket: UnixStream, key_blob: Vec<u8>, data: Vec<u8>, flags: u32) -> Result<()> {
    println!("{:X?}", key_blob);
    println!("{:X?}", data);
    println!("{:X?}", flags);

    let base64_data = base64::encode(data);
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);

    let mut payload = HashMap::new();
    payload.insert("type", "sign");
    payload.insert("data", &base64_data);
    payload.insert("relayId", &relay_id);

    let key = read_sync_key();
    let str = encrypt(&payload, key.clone())?;

    let mut map = HashMap::new();
    map.insert("message", str);

    let client = reqwest::blocking::Client::new();

    println!("Waiting for phone authorization...");

    let mut resp = client.
        post("https://ssh-proto.s.opencreek.tech/messaging/relay/1")
        .json(&map)
        .send()
        .unwrap();

    let mut str = String::new();
    resp.read_to_string(&mut str).unwrap();

    if !resp.status().is_success() {
        panic!("got {}: {}", resp.status(), str)
    }

    let typ = 14u8;

    let phone_response = poll_for_message(relay_id)?;

    println!("Waiting for phone authorization...");

    println!("message is {}", phone_response.message);
    let data: PhoneSignResponse = decrypt(phone_response.message, key)?;

    if !data.accepted {
        println!("Request was denied!");
        panic!("No authorization given")
    }

    let signature_bytes = base64::decode(data.signature)?;

    let mut msg_payload = vec![];
    msg_payload.write(&[typ])?;
    msg_payload.write_u32::<BigEndian>(signature_bytes.len() as u32)?;
    msg_payload.write_all(&signature_bytes)?;

    println!("{:X?}", msg_payload);

    socket.write_u32::<BigEndian>(msg_payload.len() as u32)?;
    socket.write_all(&msg_payload)?;

    Ok(())
}

fn give_identities(mut socket: UnixStream) {
    println!("giving identities");
    
    let typ = 12u8;

    let nkeys = 1u32;

    let key_blob = read_key_blob();

    println!("{:X?}", key_blob);
    println!("{}", key_blob.len());

    let mut msg_payload = vec![];
    msg_payload.write(&[typ]).unwrap();
    msg_payload.write_u32::<BigEndian>(nkeys).unwrap();

    msg_payload.write_u32::<BigEndian>(key_blob.len() as u32).unwrap();
    msg_payload.write_all(&key_blob).unwrap();

    let comment = "comment";
    let comment_bytes = comment.as_bytes();
    let comment_bytes_length = comment_bytes.len();
    msg_payload.write_u32::<BigEndian>(comment_bytes_length as u32).unwrap();
    msg_payload.write_all(comment_bytes).unwrap();

    let length = msg_payload.len() as u32;

    println!("writing: ");
    println!("length: {}", length);
    println!("{:X?}", msg_payload);

    socket.write_u32::<BigEndian>(length).unwrap();
    socket.write_all(&msg_payload).unwrap();

    println!("finished");

    read_and_handle_packet(socket);
}

fn read_and_handle_packet(mut socket: UnixStream) {
    let length_bytes = socket.read_u32::<BigEndian>().unwrap();

    let mut msg = vec![0u8; length_bytes as usize];
    socket.read_exact(&mut msg).unwrap();

    let packet = parse_packet(&msg);

    match packet {
        SSHAgentPacket::RequestIdentities => 
            give_identities(socket),
        SSHAgentPacket::SignRequest(key_blob, data, flags) => {
            sign_request(socket, key_blob, data, flags).unwrap();
        },
    };
}

fn main() {
    ctrlc::set_handler(move || {
        cleanup_socket();
        std::process::exit(0);
    }).expect("couldn't set ctrlc handler");

    cleanup_socket();
    generate_key();

    let listener = match UnixListener::bind("/tmp/test-socket") {
        Ok(listener) => listener,
        Err(e) => panic!("{}", e),
    };

    println!("Waiting...");

    for stream in listener.incoming() {
        match stream {
            Ok(socket) => {
                read_and_handle_packet(socket);
            },
            Err(err) => panic!("{}", err)
        }
    }
}

