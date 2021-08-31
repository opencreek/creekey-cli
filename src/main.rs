use std::panic;

use anyhow::Result;
use clap::{clap_app, AppSettings};

use crate::me::print_ssh_key;
use crate::output::Log;
use crate::pairing::pair;
use crate::setup_git::setup_git;
use crate::setup_ssh::setup_ssh;
use crate::ssh_agent::start_agent;
use crate::ssh_proxy::start_ssh_proxy;
use crate::test_git::test_git;
use crate::test_sign::test_sign;
use crate::unpair::unpair;

#[allow(dead_code)] // because we have multiple entry points.
mod agent;
mod communication;
mod constants;
mod keychain;
mod me;
mod output;
mod pairing;
mod setup_git;
mod setup_ssh;
mod sign_on_phone;
mod ssh_agent;
mod ssh_proxy;
mod test_git;
mod test_sign;
mod unpair;

#[tokio::main]
async fn main() -> Result<()> {
    let mut app = clap_app!(creekey =>
        (version: "0.1.0")
        (author: "Opencreek Technogoly UG - opencreek.tech")
        (about: "Secures your private keys on your phone")
        (@subcommand pair =>
            (about: "Pair with a phone")
            (@arg small: -s --small "Prints a smaller more condensed version")
        )
        (@subcommand testssh =>
            (about: "Tests the SSH setup")
        )
        (@subcommand testgit =>
            (about: "test command ")
        )
        (@subcommand unpair =>
            (about: "unpairs this phone")
        )
        (@subcommand me =>
            (about: "Prints the Public SSH key")
            (@arg copy: -c --copy "Copys the SSH key to the clipboard")
            (@arg raw: -r --raw "Only outputs the key")
            (@arg gpg: --gpg "Shows/copy the gpg key")
        )
        (@subcommand setupssh =>
            (about: "Setups ssh")
            (@arg force: -f --force "Forces automatic setup")
        )
        (@subcommand setupgit =>
            (about: "Setups git codesiging")
            (@arg force: -f --force "Forces automatic setup")
        )
        (@subcommand agent =>
            (setting: AppSettings::Hidden)
            (about: "Runs the agent")
            (@arg daemonize: -d --daemonize "Runs the agent as a daemon")
        )
        (@subcommand proxy =>
            (setting: AppSettings::Hidden)
            (about: "The ssh proxy")
            (@arg host: "The host to connect to")
            (@arg port: "The port to connect to")
        )
    );
    app = app.clone().setting(AppSettings::ColorAlways);
    app = app.clone().setting(AppSettings::ColoredHelp);
    let matches = app.clone().get_matches();

    panic::set_hook(Box::new(|e| {
        Log::NONE
            .panic(format!("Panicked with error: {}", e).as_str())
            .unwrap();
    }));

    let ret = match matches.subcommand() {
        ("pair", Some(matches)) => pair(matches.is_present("small")).await,
        ("unpair", _) => unpair().await,
        ("testgit", _) => test_git().await,
        ("testssh", _) => test_sign().await,
        ("setupssh", Some(matches)) => setup_ssh(matches.is_present("force")),
        ("setupgit", Some(matches)) => setup_git(matches.is_present("force")),
        ("me", Some(matches)) => {
            print_ssh_key(matches.is_present("copy"), matches.is_present("raw"), matches.is_present("gpg"))
        }
        ("agent", _) => start_agent(matches.is_present("daemonize")).await,
        ("proxy", Some(matches)) => start_ssh_proxy(matches),
        _ => {
            app.print_help()?;
            Ok(())
        }
    };

    match ret {
        Ok(_) => Ok(()),
        Err(e) => {
            Log::NONE.panic(format!("Panicked with error: {}", e).as_str())?;
            Ok(())
        }
    }
}
