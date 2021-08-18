mod agent;
mod communication;
mod constants;
mod me;
mod pairing;
mod setup_ssh;
mod sign_on_phone;
mod ssh_agent;
mod ssh_proxy;
mod test_sign;
mod unpair;

use crate::me::print_ssh_key;
use crate::pairing::pair;
use crate::setup_ssh::setup_ssh;
use crate::ssh_agent::start_agent;
use crate::ssh_proxy::start_ssh_proxy;
use crate::test_sign::test_sign;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use clap::{clap_app, ArgMatches};
use futures::executor::block_on;
use os_pipe::{dup_stdin, dup_stdout, pipe};
use std::convert::TryInto;
use std::fs::File;
use std::io;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = clap_app!(creekey =>
        (version: "0.1.0")
        (author: "Opencreek Technogoly UG - opencreek.tech")
        (about: "Secures your private keys on your phone")
        (@subcommand test =>
            (about: "Tests the SSH setup")
        )
        (@subcommand pair =>
            (about: "Pair with a phone")
        )
        (@subcommand me =>
            (about: "Prints the Public SSH key")
            (@arg copy: -c --copy "Copys the SSH key to the clipboard")
        )
        (@subcommand setupssh =>
            (about: "Setups ssh automaticaly")
        )
        (@subcommand agent =>
            (about: "Runs the agent")
        )
        (@subcommand proxy =>
            (about: "The ssh proxy")
            (@arg host: "The host to connect to")
            (@arg port: "The port to connect to")
        )
    )
    .get_matches();

    return match matches.subcommand() {
        ("pair", _) => pair(),
        ("test", _) => test_sign(),
        ("setupssh", _) => setup_ssh(),
        ("me", Some(matches)) => print_ssh_key(matches.is_present("copy")),
        ("agent", _) => start_agent().await,
        ("proxy", Some(matches)) => start_ssh_proxy(matches),
        _ => unreachable!(),
    };
}
