
use anyhow::{Result, Context};
use colored::Color;
use std::io::stdin;
use std::process::Command;
use crate::output::Log;

const ENABLE_SIGN_CMD: &str = "git config --global commit.gpgsign true";
//TODO this is probably different !!
const SET_GPG_SIGNER_CMD : &str = "git config --global gpg.program /usr/bin/creekey-gpg-sign";

pub fn setup_git(force: bool) -> Result<()> {
    let log = Log::NONE;

    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(".ssh");
    path.push("config");

    if !force {
        log.print("❓", "You want creekey to auto-configure your git setup? [y/n] ", Color::Cyan)?;
    }

    let mut input = String::new();
    if force {
        input = "y".to_string();
    } else {
        stdin().read_line(&mut input)?;
    }


    if input.starts_with("y") {
        log.waiting_on("Configuring git...")?;

        Command::new("git").args(&["config", "--global", "commit.gpgsign", "true"]).output()?;
        //TODO this is probably different !!
        Command::new("git").args(&["config", "--global", "gpg.programm", "/usr/bin/creekey-gpg-sign"]).output()?;

        log.success("Succesfully Configured git!")?;
        return Ok(())
    }

    log.info("You need to tell your git system, to use the creekey gpg agent.")?;
    log.info("For that run:")?;
    eprintln!("\t{}", ENABLE_SIGN_CMD);
    eprintln!("\t{}", SET_GPG_SIGNER_CMD);

    Ok(())
}
