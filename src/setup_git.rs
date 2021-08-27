use crate::keychain::get_gpg_from_keychain;
use crate::output::Log;
use anyhow::{Context, Result};
use colored::Color;
use std::io::{stdin, Read, Write};
use std::process::{Command, Stdio};

const ENABLE_SIGN_CMD: &str = "git config --global commit.gpgsign true";
//TODO this is probably different !!
const SET_GPG_SIGNER_CMD: &str = "git config --global gpg.program /usr/bin/creekey-gpg-sign";

fn handle_command_error(code: Option<i32>, error_message: String, log: &Log) {
    if code == Some(127) {
        log.error(
            "It looks like you do not have a gpg agent setup. Don't worry, we don't need one.",
        );
        log.error("If you even decide to install one, simply run this setup again, to have the creekey public key imported");
    } else {
        log.error("Got error while running gpg import:");
        log.error(&format!("\n{}", error_message));
        log.error("If you don't need the key in your pgp agent, don't worry. You can simply ignore this message.");
        log.error("If you ever decide otherwise, simply run this setup again, to have the creekey public key imported");
    }
}

pub fn add_pub_key_to_pgp(log: Log) -> Result<()> {
    let key = get_gpg_from_keychain()?;

    let mut gpg = match Command::new("gpg")
        .arg("--import")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            handle_command_error(e.raw_os_error(), format!("{}", e), &log);
            return Ok(());
        }
    };

    let stdin = gpg.stdin.take();

    if let Some(mut stdin) = stdin {
        stdin.write_all(key.as_bytes());
    }

    match gpg.wait() {
        Ok(res) => {
            if !res.success() {
                let stdout = gpg.stdout.take();
                let mut stdout_string = String::new();
                stdout.unwrap().read_to_string(&mut stdout_string);
                handle_command_error(res.code(), stdout_string, &log);
            }
        }
        Err(e) => {
            handle_command_error(e.raw_os_error(), format!("{}", e), &log);
        }
    }

    Ok(())
}

pub fn setup_git(force: bool) -> Result<()> {
    let log = Log::NONE;

    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(".ssh");
    path.push("config");

    if !force {
        log.print(
            "❓",
            "You want creekey to auto-configure your git setup? [y/n] ",
            Color::Cyan,
        )?;
    }

    let mut input = String::new();
    if force {
        input = "y".to_string();
    } else {
        stdin().read_line(&mut input)?;
    }

    if input.starts_with("y") {
        log.waiting_on("Configuring git...")?;

        Command::new("git")
            .args(&["config", "--global", "commit.gpgsign", "true"])
            .output()?;
        //TODO this is probably different !!
        Command::new("git")
            .args(&[
                "config",
                "--global",
                "gpg.program",
                "/usr/bin/creekey-gpg-sign",
            ])
            .output()?;

        log.success("Succesfully Configured git!")?;
        add_pub_key_to_pgp(log)?;

        return Ok(());
    }

    log.info("You need to tell your git system, to use the creekey gpg agent.")?;
    log.info("For that run:")?;
    eprintln!("\t{}", ENABLE_SIGN_CMD);
    eprintln!("\t{}", SET_GPG_SIGNER_CMD);

    add_pub_key_to_pgp(log)?;

    Ok(())
}
