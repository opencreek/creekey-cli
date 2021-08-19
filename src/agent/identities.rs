use crate::ssh_agent::{read_key_blob, SshProxy};
use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};

use crate::output::Log;
use colored::Color;
use std::io::Write;
use tokio::net::UnixStream;

pub async fn give_identities(socket: &mut UnixStream, proxies: Vec<SshProxy>) -> Result<()> {
    println!("giving identities");

    let typ = 12u8;

    let nkeys = 1u32;

    let key_blob = match read_key_blob() {
        Ok(k) => k,
        Err(e) => {
            for proxy in proxies {
                if let Ok(stream) = std::os::unix::net::UnixStream::connect(&proxy.logger_socket) {
                    let log = Log::from_stream(&stream);
                    log.println("🚨 Could not find ssh key. did you pair yet?", Color::Red)?;
                }
            }
            return Ok(());
        }
    };

    println!("{:X?}", key_blob);
    println!("{}", key_blob.len());

    let mut msg_payload = vec![];
    msg_payload.write(&[typ])?;
    msg_payload.write_u32::<BigEndian>(nkeys)?;

    msg_payload.write_u32::<BigEndian>(key_blob.len() as u32)?;
    msg_payload.write_all(&key_blob)?;

    let comment = "comment";
    let comment_bytes = comment.as_bytes();
    let comment_bytes_length = comment_bytes.len();
    msg_payload.write_u32::<BigEndian>(comment_bytes_length as u32)?;
    msg_payload.write_all(comment_bytes)?;

    let length = msg_payload.len() as u32;

    println!("writing: ");
    println!("length: {}", length);
    println!("{:X?}", msg_payload);

    tokio::io::AsyncWriteExt::write_u32(socket, length).await?;
    tokio::io::AsyncWriteExt::write_all(socket, &msg_payload).await?;

    println!("finished");

    Ok(())
}
