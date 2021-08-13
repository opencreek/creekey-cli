mod pairing;
mod communication;
mod test_sign;
mod sign_on_phone;
mod constants;
mod setup_ssh;
mod ssh_agent;
mod me;
mod unpair;
mod ssh_proxy;

use anyhow::Result;
use crate::pairing::pair;
use crate::test_sign::test_sign;
use crate::setup_ssh::setup_ssh;
use crate::me::print_ssh_key;
use crate::ssh_agent::start_agent;
use clap::{clap_app, ArgMatches};
use std::net::{TcpStream, Shutdown};
use std::io;
use std::io::{BufReader, BufRead, Write, Read};
use std::sync::Arc;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::fs::File;
use os_pipe::{pipe, dup_stdin, dup_stdout};
use std::convert::TryInto;
use std::time::Duration;
use std::thread;
use crate::ssh_proxy::start_ssh_proxy;

fn main() -> Result<()> {
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
    ).get_matches();

    return match matches.subcommand() {
        ("pair", _) => {
            pair()
        }
        ("test", _) => {
            test_sign()
        }
        ("setupssh", _) => {
            setup_ssh()
        }
        ("me", Some(matches)) => {
            print_ssh_key(matches.is_present("copy"))
        }
        ("agent", _) => start_agent(),
        ("proxy", Some(matches)) => start_ssh_proxy(matches),
        _ => unreachable!(),
    };
}

