use anyhow::Context;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use clap::ArgMatches;
use colored::Colorize;
use os_pipe::{dup_stderr, dup_stdin, dup_stdout};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::sign::ed25519::Signature;
use sodiumoxide::crypto::sign::PublicKey;
use ssh_parser::SshPacket;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Stderr, Write};
use std::net::{Shutdown, TcpStream};
use std::ops::Shl;
use std::os;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

fn start_logger_proxy() -> Result<String> {
    let random = base64::encode_config(sodiumoxide::randombytes::randombytes(8), base64::URL_SAFE);
    let name = format!("/tmp/ck-logger-{}.sock", random);

    let listener = match UnixListener::bind(name.clone()) {
        Ok(listener) => listener,
        Err(e) => panic!("{}", e),
    };
    let mut serr = dup_stderr()?;

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut socket) => {
                    loop {
                        let byte = socket.read_u8().unwrap();
                        if byte != 255 {
                            // filter out checking byte
                            serr.write_u8(byte);
                        }
                    }
                }
                Err(err) => panic!("{}", err),
            }
        }
    });

    Ok(name)
}

fn is_agent_running() -> Result<bool> {
    for prc in procfs::process::all_processes()? {
        if prc.stat.comm == "creekey-agent" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn send_info_packet(host: &str, socket_path: &str, signature: &[u8], key: &[u8]) -> Result<()> {
    let mut stream = UnixStream::connect("/tmp/ck-ssh-agent.sock")?;

    stream.write_u32::<BigEndian>(
        (1 + 4 + host.len() + 4 + socket_path.len() + 4 + signature.len() + 4 + key.len())
            .try_into()?,
    );
    stream.write_u8(254);

    stream.write_u32::<BigEndian>(host.len().try_into()?);
    stream.write_all(host.as_bytes())?;

    stream.write_u32::<BigEndian>(socket_path.len().try_into()?);
    stream.write_all(socket_path.as_bytes())?;

    stream.write_u32::<BigEndian>(signature.len().try_into()?);
    stream.write_all(signature)?;

    stream.write_u32::<BigEndian>(key.len().try_into()?);
    stream.write_all(key)?;

    stream.flush();

    stream.shutdown(Shutdown::Both)?;

    Ok(())
}

pub fn start_ssh_proxy(matches: &ArgMatches) -> Result<()> {
    // let signature_data = std::fs::read("signature.data")?;
    // let signature = Signature::new(signature_data.as_slice().try_into()?);
    // let session_data = std::fs::read("session.data")?;
    // let key_data = std::fs::read("server-key.pub")?;
    //
    // eprintln!("keydata: {:X?}", key_data);
    // eprintln!("session: {:X?}", session_data);
    // eprintln!("signature: {:X?}", signature_data);
    //
    // let pub_key = &PublicKey::from_slice(key_data.as_slice()).context("no key")?;
    // let verified =
    //     sodiumoxide::crypto::sign::verify_detached(&signature, session_data.as_slice(), pub_key);
    // eprintln!("verification: {}", verified);

    if !is_agent_running()? {
        eprintln!("{}", "Starting Daemon...".red().to_string());
        let self_arg = &std::env::args().collect::<Vec<String>>()[0];
        eprintln!("{}", self_arg);

        let child = Command::new("nohup")
            .arg(self_arg)
            .arg("agent")
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        thread::sleep(Duration::from_millis(1000))
    }
    let socket_path = start_logger_proxy()?;

    let host = matches.value_of("host").unwrap();
    let port = matches.value_of("port").unwrap();

    let host_name = String::new() + host + ":" + port;


    let mut stream = TcpStream::connect(host_name.clone())?;
    let mut in_stream = stream.try_clone()?;
    let mut out_stream = stream.try_clone()?;

    let in_thread = std::thread::spawn(move || {
        let mut sout = dup_stdout().unwrap();
        loop {
            // let byte = in_stream.read_u8().unwrap();
            // sout.write_u8(byte);

            let mut data = [0u8; 0x10000usize];
            let host_name = host_name.clone();
            let socket = socket_path.clone();
            let length = in_stream.read(&mut data).unwrap();
            let (received, _) = data.split_at(length);
            if received.len() > 0 {
                let result = ssh_parser::parse_ssh_packet(received);
                match result {
                    Ok((_, parsed_data)) => {
                        let (packet, _) = parsed_data;
                        match packet {
                            SshPacket::DiffieHellmanReply(init) => {
                                let mut hasher = Sha256::new();
                                let mut cursor = Cursor::new(init.pubkey_and_cert);

                                let first_size = cursor.read_i32::<BigEndian>().unwrap();
                                let mut buffer_first = vec![0u8; first_size as usize];
                                cursor.read_exact(&mut buffer_first).unwrap();

                                let key_length = cursor.read_i32::<BigEndian>().unwrap();
                                let mut key = vec![0u8; key_length as usize];
                                cursor.read_exact(&mut key).unwrap();

                                let mut cursor_sig = Cursor::new(init.signature);

                                let first_size_2 = cursor_sig.read_i32::<BigEndian>().unwrap();
                                let mut buffer_first_2 = vec![0u8; first_size_2 as usize];
                                cursor_sig.read_exact(&mut buffer_first_2).unwrap();

                                let signature_size = cursor_sig.read_i32::<BigEndian>().unwrap();
                                let mut signature = vec![0u8; signature_size as usize];
                                cursor_sig.read_exact(&mut signature).unwrap();

                                hasher.update(init.signature);
                                let hash = hasher.finalize();
                                send_info_packet(
                                    &host_name,
                                    &socket,
                                    signature.as_slice(),
                                    key.as_slice(),
                                )
                                .unwrap();
                                // thread::sleep(Duration::from_millis(300))
                            }
                            _ => {}
                        }
                    }
                    Err(_) => {}
                }
                sout.write_all(received).unwrap();
            }
        }
    });

    let out_thread = std::thread::spawn(move || {
        let mut sin = dup_stdin().unwrap();
        loop {
            // let mut byte = sin.read_u8().unwrap();
            // out_stream.write_u8(byte);
            let mut data = [0u8; 0x10000usize];
            let length = sin.read(&mut data).unwrap();
            let (received, _) = data.split_at(length);
            if received.len() > 0 {
                out_stream.write_all(received).unwrap();
            }
        }
    });

    out_thread.join().unwrap();
    in_thread.join().unwrap();
    Ok(())
}
