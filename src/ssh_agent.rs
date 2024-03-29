use crate::constants::get_ssh_key_path;

use anyhow::Context;
use anyhow::Result;

use daemonize::Daemonize;
use futures::channel::mpsc::unbounded;

use futures::{SinkExt, StreamExt};

use serde::{Deserialize, Serialize};

use std;

use std::fs;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::net::UnixListener;
use tokio::select;
use tokio::task;

use crate::agent::handle::read_and_handle_packet;
use crate::output::{check_color_tty, Log};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Duration;

fn cleanup_socket() {
    let _ = std::fs::remove_file("/tmp/ck-ssh-agent.sock").unwrap_or(());
}

#[derive(Error, Debug, Clone)]
pub enum ReadError {
    #[error("File is missing")]
    FileIsMissing,

    #[error("could not get path")]
    CouldNotGetPath,

    #[error("Error Parsing Key")]
    KeyParseError,
}

pub fn read_ssh_key() -> Result<String, ReadError> {
    let path = get_ssh_key_path().map_err(|_| ReadError::CouldNotGetPath)?;

    if !path.exists() {
        return Err(ReadError::FileIsMissing);
    }

    Ok(fs::read_to_string(path).map_err(|_| ReadError::KeyParseError)?)
}

pub fn read_key_blob() -> Result<Vec<u8>, ReadError> {
    let contents = read_ssh_key()?;
    let mut iter = contents.split_whitespace();
    iter.next()
        .context("")
        .map_err(|_| ReadError::KeyParseError)?;
    let key_str = match iter.next() {
        Some(s) => s,
        None => panic!("couldn't read id.pub: wrong format?"),
    };

    Ok(base64::decode(key_str).map_err(|_| ReadError::KeyParseError)?)
}

#[derive(Clone, Debug)]
pub struct SshProxy {
    pub host: String,
    pub logger_socket: String,
    pub signature: Vec<u8>,
    pub key: Vec<u8>,
    pub saved_at: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PhoneSignResponse {
    pub signature: Option<String>,
    pub accepted: bool,
    #[serde(rename = "autoAcceptToken")]
    pub auto_accept_token: Option<String>,

    #[serde(rename = "autoAcceptExpiresAt")]
    pub auto_accept_expires_at: Option<String>,
}

pub async fn start_agent(should_daemonize: bool) -> Result<()> {
    check_color_tty();

    if should_daemonize {
        let daemonize = Daemonize::new().pid_file("/tmp/ck-agent.pid");
        Log::NONE.waiting_on("Starting deamon...")?;
        daemonize.start()?;
    }

    proctitle::set_title("creekey-agent");
    ctrlc::set_handler(move || {
        cleanup_socket();
        std::process::exit(0);
    })
    .expect("couldn't set ctrlc handler");

    cleanup_socket();

    let listener = match UnixListener::bind("/tmp/ck-ssh-agent.sock") {
        Ok(listener) => listener,
        Err(e) => panic!("{}", e),
    };

    println!("Waiting...");

    let proxies: Arc<Mutex<Vec<SshProxy>>> = Arc::new(Mutex::new(Vec::new()));

    let (new_proxy_send, mut new_proxy_receive) = unbounded::<SshProxy>();
    let (remove_proxy_send, mut remove_proxy_receive) = unbounded::<SshProxy>();
    let mut interval = tokio::time::interval(Duration::from_secs(60));

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
                let _task = task::spawn(async move {
                    let socket = &mut x.unwrap().0;
                    let ret = read_and_handle_packet(socket, vec, new_proxy_send, remove_proxy_send).await;
                    match ret {
                        Err(e) => eprintln!("error while handling packet: {}", e),
                        _ => {}
                    }
                    eprintln!("Done with connection");

                    ()
                });
            }
            _x = interval.tick() => {
                let mutex = proxies.clone();
                let vec = mutex.lock().unwrap();
                let mut remove_proxy_send = remove_proxy_send.clone();
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

                for proxy in vec.iter() {
                    if now - proxy.saved_at > 5 * 60 {
                        remove_proxy_send.send(proxy.clone()).await?;
                    }
                }

                ()
            }
        }
    }
}
