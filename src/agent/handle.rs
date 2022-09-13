use crate::agent::identities::give_identities;
use crate::agent::sign::sign_request;
use crate::ssh_agent::SshProxy;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use futures::channel::mpsc::UnboundedSender;
use futures::SinkExt;
use std::convert::TryInto;
use std::io::Write;
use std::io::{Cursor, Read};

use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UnixStream;

#[derive(Debug)]
pub enum SSHAgentPacket {
    RequestIdentities,
    // key_blob, data, flags
    SignRequest(Vec<u8>, Vec<u8>, u32),
    // hostname, socket_path, signature, key
    HostName(String, String, Vec<u8>, Vec<u8>),
    // extension type, extension data
    ExtensionRequest(String, Vec<u8>),
    Unkown(u8),
}

pub fn parse_packet(packet: &Vec<u8>, _socket: &mut UnixStream) -> SSHAgentPacket {
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

    if typ == 27 {
        let extension_type_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut extension_type_data = vec![0u8; extension_type_length as usize];
        cursor.read_exact(&mut extension_type_data).unwrap();
        let extension_type = String::from_utf8(extension_type_data).unwrap();

        let extension_data_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut extension_data = vec![0u8; extension_data_length as usize];
        cursor.read_exact(&mut extension_data).unwrap();

        return SSHAgentPacket::ExtensionRequest(extension_type, extension_data);
    }

    if typ == 254 {
        let data_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut data = vec![0u8; data_length as usize];
        cursor.read_exact(&mut data).unwrap();

        let socket_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut socket_path = vec![0u8; socket_length as usize];
        cursor.read_exact(&mut socket_path).unwrap();
        let logger_socket = String::from_utf8(socket_path.clone()).unwrap();

        let signature_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut signature = vec![0u8; signature_length as usize];
        cursor.read_exact(&mut signature).unwrap();

        let key_length = cursor.read_u32::<BigEndian>().unwrap();
        let mut key = vec![0u8; key_length as usize];
        cursor.read_exact(&mut key).unwrap();

        return SSHAgentPacket::HostName(
            String::from_utf8(data).unwrap(),
            logger_socket,
            signature,
            key,
        );
    }

    return SSHAgentPacket::Unkown(typ);
}

async fn reply_general_failure(socket: &mut UnixStream) -> Result<()> {
    let typ = 5u8;
    let mut msg_payload = vec![];
    msg_payload.write(&[typ])?;
    let length = msg_payload.len() as u32;

    tokio::io::AsyncWriteExt::write_u32(socket, length).await?;
    tokio::io::AsyncWriteExt::write_all(socket, &msg_payload).await?;

    Ok(())
}

pub async fn read_and_handle_packet(
    socket: &mut UnixStream,
    proxies: Vec<SshProxy>,
    mut new_proxy_send: UnboundedSender<SshProxy>,
    remove_proxy_send: UnboundedSender<SshProxy>,
) -> Result<()> {
    loop {
        socket.readable().await?;
        let mut length_bytes_vec = [0u8; 4];
        let bytes_read = socket.try_read(&mut length_bytes_vec).unwrap_or(0);
        if bytes_read != 4 {
            // yes this will loop, but the readable call will fail if the socket goes away
            continue;
        }
        let length_bytes = u32::from_be_bytes(length_bytes_vec);

        let mut msg = vec![0u8; length_bytes as usize];
        tokio::io::AsyncReadExt::read_exact(socket, &mut msg).await?;

        let packet = parse_packet(&msg, socket);

        match packet {
            SSHAgentPacket::RequestIdentities => {
                give_identities(socket, proxies.clone()).await?;
            }
            SSHAgentPacket::SignRequest(key_blob, data, flags) => {
                let _proxy = sign_request(
                    socket,
                    key_blob,
                    data,
                    flags,
                    proxies.clone(),
                    remove_proxy_send.clone(),
                )
                .await?;
            }
            SSHAgentPacket::HostName(name, logger, signature, key) => {
                new_proxy_send
                    .send(SshProxy {
                        host: name,
                        logger_socket: logger,
                        signature,
                        key,
                        saved_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u64,
                    })
                    .await?;
            }
            SSHAgentPacket::ExtensionRequest(extension_type, _) => {
                println!("Received extension request: {}", extension_type);
                reply_general_failure(socket).await?;
            }
            SSHAgentPacket::Unkown(unknown_type) => {
                println!(
                    "Received unknown/unsupported message type: {}",
                    unknown_type
                );
                reply_general_failure(socket).await?;
            }
        }
    }
}
