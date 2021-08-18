use crate::agent::identities::give_identities;
use crate::communication::{decrypt, encrypt, poll_for_message, MessageRelayResponse};
use crate::constants::{get_phone_id_path, get_secret_key_path, get_ssh_key_path};
use crate::me::print_ssh_key;
use crate::pairing::pair;
use crate::setup_ssh::setup_ssh;
use crate::test_sign::test_sign;
use anyhow::Result;
use anyhow::{anyhow, Context};
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use colored::*;
use daemonize::Daemonize;
use futures::channel::mpsc::{self, channel, unbounded, Sender};
use futures::executor::block_on;
use futures::future::Fuse;
use futures::{Future, StreamExt};
use reqwest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::{PublicKey, Signature};
use sodiumoxide::randombytes::randombytes;
use std;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::Read;
use std::io::{Cursor, Write};
use std::path::Path;
use std::sync::mpsc::TryRecvError;
use std::sync::{Arc, Mutex};
use std::thread;
use std::{env, fs};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::select;
use tokio::task;

use crate::agent::handle::read_and_handle_packet;
use futures::future::select_all;
use std::marker::PhantomPinned;
use std::ops::Deref;
use std::pin::Pin;
use tokio::pin;

async fn get_logger_stream(existing: Option<Result<UnixStream>>) -> Result<UnixStream> {
    return match existing {
        Some(Ok(mut t)) => {
            println!("re testing existing stream");
            match t.write_u8(255).await {
                Ok(_) => Ok(t),
                Err(_) => {
                    println!("re getting logger stream");
                    Ok(UnixStream::connect("/tmp/ck-logger.sock").await?)
                    // get_logger_stream(None).await
                }
            }
        }
        _ => {
            println!("creating new stream");
            Ok(UnixStream::connect("/tmp/ck-logger.sock").await?)
        }
    };
}

fn start_logger_thread() -> Result<std::sync::mpsc::Sender<String>> {
    let (tx, rx) = std::sync::mpsc::channel::<String>();

    //todo lol
    thread::spawn(move || {
        block_on(async {
            let mut stream = get_logger_stream(None).await;

            loop {
                match rx.try_recv() {
                    Ok(str) => {
                        stream = get_logger_stream(Some(stream)).await;
                        println!("{}", str);
                        match stream {
                            Ok(ref mut s) => {
                                s.write_all(str.as_str().as_bytes());
                                s.write_all("\n".as_bytes());
                            }
                            _ => (),
                        }
                    }
                    Err(TryRecvError::Disconnected) => {
                        break;
                    }
                    Err(TryRecvError::Empty) => {}
                }
            }
        })
    });

    Ok(tx)
}

fn cleanup_socket() {
    let _ = std::fs::remove_file("/tmp/ck-ssh-agent.sock").unwrap_or(());
}

fn generate_key() -> Result<()> {
    let path = get_secret_key_path()?;

    if path.exists() {
        return Ok(());
    }

    let key = secretbox::gen_key();

    let str = base64::encode(key);

    let mut file = File::create(path)?;
    file.write_all(str.as_bytes())?;
    Ok(())
}

pub fn read_sync_key() -> Result<secretbox::Key> {
    let path = get_secret_key_path()?;

    let key_str =
        fs::read_to_string(path).map_err(|_| anyhow!("Could not read key! Did you `pair` yet?"))?;

    let decoded = base64::decode(key_str)?;
    Ok(secretbox::Key::from_slice(&decoded).unwrap())
}

pub fn read_sync_phone_id() -> Result<String> {
    let path = get_phone_id_path()?;

    let key_str = fs::read_to_string(path)?;
    let trimmed = key_str.trim().to_string();

    Ok(trimmed)
}

pub fn read_ssh_key() -> Result<String> {
    let path = get_ssh_key_path()?;

    if !path.exists() {
        anyhow!("Public Key could not be read. Did you `pair` yet?");
    }

    Ok(fs::read_to_string(path)?)
}

pub fn read_key_blob() -> Result<Vec<u8>> {
    let contents = read_ssh_key()?;
    let mut iter = contents.split_whitespace();
    iter.next().context("Wrong key format");
    let key_str = match iter.next() {
        Some(s) => s,
        None => panic!("couldn't read id.pub: wrong format?"),
    };

    Ok(base64::decode(key_str)?)
}

#[derive(Clone, Debug)]
pub struct SshProxy {
    pub host: String,
    pub logger_socket: String,
    pub signature: Vec<u8>,
    pub key: Vec<u8>,
}

impl SshProxy {
    pub fn println(&mut self, line: String) {
        println!("{}", line);
        // self.logger.write_all(line.as_bytes());
        // self.logger.write_all("\n".as_bytes());
    }
}

//
// fn println(on: &mut Option<&SshProxy>, line: String) {
//     match on {
//         Some(a) => {
//             a.println(line)
//         },
//         _ => ()
//     }
// }
#[derive(Serialize, Deserialize, Debug)]
pub struct PhoneSignResponse {
    pub signature: Option<String>,
    pub accepted: bool,
}

// #[derive(Debug)]
// struct SigningContext<'a> {
//     host_name: Option<String>,
//     logger: Option<&'a UnixStream>,
// }
//
// impl SigningContext<'_> {
//     fn println(&mut self, line: String) {
//         println!("{}", line);
//         match &mut self.logger {
//             Some(stream) => {
//                 stream.write_all(line.as_bytes());
//                 stream.write_all("\n".as_bytes());
//             }
//             None => (),
//         }
//     }
// }

pub async fn start_agent() -> Result<()> {
    let daemonize = Daemonize::new().pid_file("/tmp/ck-agent.pid");

    // daemonize.start()?;

    proctitle::set_title("creekey-agent");
    ctrlc::set_handler(move || {
        cleanup_socket();
        std::process::exit(0);
    })
    .expect("couldn't set ctrlc handler");

    cleanup_socket();
    generate_key();

    let listener = match UnixListener::bind("/tmp/ck-ssh-agent.sock") {
        Ok(listener) => listener,
        Err(e) => panic!("{}", e),
    };

    println!("Waiting...");

    let mut proxies: Arc<Mutex<Vec<SshProxy>>> = Arc::new(Mutex::new(Vec::new()));

    let (new_proxy_send, mut new_proxy_receive) = unbounded::<SshProxy>();
    let (remove_proxy_send, mut remove_proxy_receive) = unbounded::<SshProxy>();

    loop {
        select! {
            Some(proxy) = new_proxy_receive.next() => {
                eprintln!("Got host!");
                let mutex = proxies.clone();
                let mut vec = mutex.lock().unwrap();
                vec.push(proxy);
            }
            Some(to_remove) = remove_proxy_receive.next() => {
                eprintln!("remove proxy");
                let mutex = proxies.clone();
                let mut vec = mutex.lock().unwrap();
                let position = vec.iter().position(|x| {x.signature == to_remove.signature});
                if let Some(pos) = position {
                    vec.remove(pos);
                }
            }
            x = listener.accept() => {
                eprintln!("New socket connection");
                let mutex = proxies.clone();
                let vec = mutex.lock().unwrap().clone();
                let remove_proxy_send = remove_proxy_send.clone();
                let new_proxy_send = new_proxy_send.clone();
                let task = task::spawn(async move {
                    let socket = &mut x.unwrap().0;
                    read_and_handle_packet(socket, vec, new_proxy_send, remove_proxy_send).await;
                    eprintln!("Done with connection");

                    ()
                });
            },
        }
    }
}
