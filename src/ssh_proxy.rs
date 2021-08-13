use clap::ArgMatches;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryInto;
use os_pipe::{dup_stdout, dup_stdin, dup_stderr};
use std::thread;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::net::{TcpStream, Shutdown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::io::{BufReader, BufRead, Write, Read};


fn cleanup_socket() {
    let _ = std::fs::remove_file("/tmp/ck-logger.sock").unwrap_or(());
}

fn logger(rx: Receiver<()>) -> Result<()> {
    ctrlc::set_handler(move || {
        cleanup_socket();
        std::process::exit(0);
    }).expect("couldn't set ctrlc handler");

    cleanup_socket();

    let listener = match UnixListener::bind("/tmp/ck-logger.sock") {
        Ok(listener) => listener,
        Err(e) => panic!("{}", e),
    };
    let mut serr = dup_stderr()?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                loop {
                    match rx.try_recv() {
                        Ok(_) | Err(TryRecvError::Disconnected) => {
                            break;
                        }
                        Err(TryRecvError::Empty) => {}
                    }
                    let byte = socket.read_u8().unwrap();
                    if byte != 255 { // filter out checking byte
                        serr.write_u8(byte);
                    }
                }
            }
            Err(err) => panic!("{}", err)
        }
    }
    Ok(())
}

pub fn start_ssh_proxy(matches: &ArgMatches) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || { logger(rx) });

    let host = matches.value_of("host").unwrap();
    let port = matches.value_of("port").unwrap();
    eprintln!("host: {}, port: {}", host, port);

    let mut stream = UnixStream::connect("/tmp/ck-ssh-agent.sock")?;
    let mut str = String::new() + host + ":" + port;

    stream.write_u32::<BigEndian>((1 + 4 + str.len()).try_into()?);
    stream.write_u8(254);
    stream.write_u32::<BigEndian>(str.len().try_into()?);
    stream.write_all(str.as_bytes())?;
    stream.flush();
    stream.shutdown(Shutdown::Both)?;
    eprintln!("Starting proxy");
    // thread::sleep(Duration::from_millis(1000));

    let mut stream = TcpStream::connect(str)?;
    let mut in_stream = stream.try_clone()?;
    let mut out_stream = stream.try_clone()?;


    let in_thread = std::thread::spawn(move || {
        let mut sout = dup_stdout().unwrap();
        loop {
            let byte = in_stream.read_u8().unwrap();
            sout.write_u8(byte);
        }
    });

    let out_thread = std::thread::spawn(move || {
        let mut sin = dup_stdin().unwrap();
        loop {
            let byte = sin.read_u8().unwrap();
            // eprintln!("from stdin: {}", byte);
            out_stream.write_u8(byte);
        }
    });

    out_thread.join().unwrap();
    in_thread.join().unwrap();
    eprintln!("done quitting!");
    tx.send(());
    Ok(())
}
