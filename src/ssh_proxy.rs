use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use clap::ArgMatches;
use os_pipe::{dup_stderr, dup_stdin, dup_stdout};

use ssh_parser::SshPacket;
use std::convert::TryInto;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};

use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};

use crate::constants::{agent_socket_path, logger_socket_path};
use crate::output::Log;
use crate::setup_ssh::{auto_migrate_ssh_config, SshConfigState};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(5);

fn start_logger_proxy() -> Result<String> {
    let random = base64::encode_config(sodiumoxide::randombytes::randombytes(8), base64::URL_SAFE);
    let name = logger_socket_path(&random);

    let listener = match UnixListener::bind(name.clone()) {
        Ok(listener) => listener,
        Err(e) => panic!("{}", e),
    };
    let mut serr = dup_stderr().ok();

    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut socket) => {
                    loop {
                        let res = socket.read_u8();
                        if let Ok(byte) = res {
                            if byte != 255 {
                                // filter out checking byte
                                if let Some(ref mut s) = serr {
                                    let _ = s.write_u8(byte);
                                }
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
    match UnixStream::connect(agent_socket_path()) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn send_info_packet(host: &str, socket_path: &str, signature: &[u8], key: &[u8]) -> Result<()> {
    let mut stream = UnixStream::connect(agent_socket_path())?;

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
    if is_agent_running()? {
        return Ok(());
    }

    Log::NONE.waiting_on("Starting Daemon...")?;
    let self_arg = &std::env::args().collect::<Vec<String>>()[0];

    let mut child = Command::new(self_arg)
        .arg("agent")
        .arg("-d")
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to spawn creekey agent")?;

    let started_at = Instant::now();
    loop {
        if is_agent_running()? {
            return Ok(());
        }

        if let Some(status) = child.try_wait()? {
            // The `daemonize` crate forks the actual daemon and exits the
            // intermediate process with success — that's normal. Only a
            // non-success exit means the daemon failed to start.
            if !status.success() {
                return Err(anyhow!(
                    "creekey agent failed to start (exit {}). \
                     If a stale socket from another user exists at {}, remove it manually and try again.",
                    status,
                    agent_socket_path(),
                ));
            }
        }

        if started_at.elapsed() >= DAEMON_START_TIMEOUT {
            return Err(anyhow!(
                "Timed out after {:?} waiting for the creekey agent to bind {}. \
                 Check whether a stale socket from another user is blocking it.",
                DAEMON_START_TIMEOUT,
                agent_socket_path(),
            ));
        }

        thread::sleep(Duration::from_millis(10));
    }
}

pub fn start_ssh_proxy(matches: &ArgMatches) -> Result<()> {
    let socket_path = start_logger_proxy()?;

    match auto_migrate_ssh_config() {
        Ok(SshConfigState::Upgraded { from }) => {
            let _ = Log::NONE.info(&format!(
                "Migrated ~/.ssh/config from creekey config {} to the current format. \
                 The next ssh invocation will pick up the new agent socket path.",
                from
            ));
        }
        Ok(_) => {}
        Err(e) => {
            let _ = Log::NONE.info(&format!(
                "Could not check ~/.ssh/config for outdated creekey config: {}",
                e
            ));
        }
    }

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
