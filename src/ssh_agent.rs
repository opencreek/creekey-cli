use crate::constants::{get_phone_id_path, get_secret_key_path, get_ssh_key_path};

use anyhow::Result;
use anyhow::{anyhow, Context};

use daemonize::Daemonize;
use futures::channel::mpsc::unbounded;

use futures::StreamExt;

use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::secretbox;

use std;

use std::fs;
use std::sync::{Arc, Mutex};
use tokio::net::UnixListener;
use tokio::select;
use tokio::task;

use crate::agent::handle::read_and_handle_packet;
use crate::output::check_color_tty;

fn cleanup_socket() {
    let _ = std::fs::remove_file("/tmp/ck-ssh-agent.sock").unwrap_or(());
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
    iter.next().context("Wrong key format")?;
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
#[derive(Serialize, Deserialize, Debug)]
pub struct PhoneSignResponse {
    pub signature: Option<String>,
    pub accepted: bool,
}

pub async fn start_agent() -> Result<()> {
    let _daemonize = Daemonize::new().pid_file("/tmp/ck-agent.pid");

    check_color_tty();
    // daemonize.start()?;

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
                        Err(e) => eprintln!("{}", e),
                        _ => {}
                    }
                    eprintln!("Done with connection");

                    ()
                });
            },
        }
    }
}
