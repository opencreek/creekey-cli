use anyhow::{Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use clap::ArgMatches;
use os_pipe::{dup_stderr, dup_stdin, dup_stdout};

use ssh_parser::SshPacket;
use std::convert::TryInto;

use std::io::{Cursor, Read, Write};
use std::net::{Shutdown, TcpStream};

use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};

use crate::output::Log;
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
                        let res = socket.read_u8();
                        if let Ok(byte) = res {
                            if byte != 255 {
                                // filter out checking byte
                                serr.write_u8(byte).unwrap();
                            }
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
    match UnixStream::connect("/tmp/ck-ssh-agent.sock") {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn send_info_packet(host: &str, socket_path: &str, signature: &[u8], key: &[u8]) -> Result<()> {
    let mut stream = UnixStream::connect("/tmp/ck-ssh-agent.sock")?;

    stream.write_u32::<BigEndian>(
        (1 + 4 + host.len() + 4 + socket_path.len() + 4 + signature.len() + 4 + key.len())
            .try_into()?,
    )?;
    stream.write_u8(254)?;

    stream.write_u32::<BigEndian>(host.len().try_into()?)?;
    stream.write_all(host.as_bytes())?;

    stream.write_u32::<BigEndian>(socket_path.len().try_into()?)?;
    stream.write_all(socket_path.as_bytes())?;

    stream.write_u32::<BigEndian>(signature.len().try_into()?)?;
    stream.write_all(signature)?;

    stream.write_u32::<BigEndian>(key.len().try_into()?)?;
    stream.write_all(key)?;

    stream.flush()?;

    stream.shutdown(Shutdown::Both)?;

    Ok(())
}

fn check_running_ssh_agent() -> Result<()> {
    if !is_agent_running()? {
        Log::NONE.waiting_on("Starting Daemon...")?;
        let self_arg = &std::env::args().collect::<Vec<String>>()[0];

        let _child = Command::new(self_arg)
            .arg("agent")
            .arg("-d")
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        while !is_agent_running()? {
            thread::sleep(Duration::from_millis(10))
        }
    }
    Ok(())
}

pub fn start_ssh_proxy(matches: &ArgMatches) -> Result<()> {
    let socket_path = start_logger_proxy()?;

    check_running_ssh_agent()?;

    let host = matches
        .value_of("host")
        .context("No host given for proxy. usage:\ncreekey proxy <host> <port>\n See 'crekey setupssh' for more instructions")?;

    let port = matches
        .value_of("port")
        .context("No port given for proxy. usage:\ncreekey proxy <host> <port>\n See 'crekey setupssh' for more instructions")?;

    let host_name = String::new() + host + ":" + port;

    let stream = TcpStream::connect(host_name.clone())?;
    let mut in_stream = stream.try_clone()?;
    let mut out_stream = stream.try_clone()?;

    let in_thread = std::thread::spawn(move || {
        let mut sout = dup_stdout().unwrap();
        loop {
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
                                send_info_packet(
                                    &host_name,
                                    &socket,
                                    init.signature,
                                    init.pubkey_and_cert,
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
