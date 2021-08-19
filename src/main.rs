mod agent;
mod communication;
mod constants;
mod me;
mod output;
mod pairing;
mod setup_ssh;
mod sign_on_phone;
mod ssh_agent;
mod ssh_proxy;
mod test_sign;
mod unpair;

use crate::me::print_ssh_key;
use crate::output::Log;
use crate::pairing::pair;
use crate::setup_ssh::setup_ssh;
use crate::ssh_agent::start_agent;
use crate::ssh_proxy::start_ssh_proxy;
use crate::test_sign::test_sign;
use crate::unpair::unpair;
use anyhow::Result;

use clap::{clap_app, AppSettings};
use colored::Color;
use std::panic;

#[tokio::main]
async fn main() -> Result<()> {
    let mut app = clap_app!(creekey =>
        (version: "0.1.0")
        (author: "Opencreek Technogoly UG - opencreek.tech")
        (about: "Secures your private keys on your phone")
        (@subcommand test =>
            (about: "Tests the SSH setup")
        )
        (@subcommand pair =>
            (about: "Pair with a phone")
        )
        (@subcommand testgpg =>
            (about: "test command ")
        )
        (@subcommand unpair =>
            (about: "unpairs this phone")
        )
        (@subcommand me =>
            (about: "Prints the Public SSH key")
            (@arg copy: -c --copy "Copys the SSH key to the clipboard")
            (@arg raw: -r --raw "Only outputs the key")
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
    );
    app = app.clone().setting(AppSettings::ColorAlways);
    app = app.clone().setting(AppSettings::ColoredHelp);
    let matches = app.clone().get_matches();

    panic::set_hook(Box::new(|e| {
        Log::NONE.println(
            format!("🚨🚨🚨 Panicked with error: {}", e).as_str(),
            Color::Red,
        );
    }));

    let ret = match matches.subcommand() {
        ("pair", _) => pair().await,
        ("unpair", _) => unpair().await,
        // ("testgpg", _) => sign_git_commit().await,
        ("test", _) => test_sign().await,
        ("setupssh", _) => setup_ssh(),
        ("me", Some(matches)) => {
            print_ssh_key(matches.is_present("copy"), matches.is_present("raw"))
        }
        ("agent", _) => start_agent().await,
        ("proxy", Some(matches)) => start_ssh_proxy(matches),
        _ => {
            app.print_help()?;
            Ok(())
        }
    };

    match ret {
        Ok(_) => Ok(()),
        Err(e) => {
            Log::NONE.println(
                format!("🚨🚨🚨 Panicked with error: {}", e).as_str(),
                Color::Red,
            );
            Ok(())
        }
    }
}
