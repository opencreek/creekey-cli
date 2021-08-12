mod pairing;
mod communication;
mod test_sign;
mod sign_on_phone;
mod constants;
mod setup_ssh;
mod ssh_agent;
mod me;
mod unpair;

use anyhow::Result;
use crate::pairing::pair;
use crate::test_sign::test_sign;
use crate::setup_ssh::setup_ssh;
use crate::me::print_ssh_key;
use crate::ssh_agent::start_agent;
use clap::clap_app;

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
    ).get_matches();

    return match matches.subcommand() {
        ("pair", _) => {
            pair()
        }
        ("test", _) => {
            test_sign()
        }
        ("setup-ssh", _) => {
            setup_ssh()
        }
        ("me", Some(matches)) => {
            print_ssh_key(matches.is_present("copy"))
        }
        ("", None) => start_agent(),
        _ => unreachable!(),
    };
}

