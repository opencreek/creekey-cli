use crate::output::Log;
use anyhow::{Context, Result};
use colored::Color;
use std::fs::OpenOptions;
use std::io::{stdin, Read, Write};

const SSH_CONF: &str = "# creekey config v1\nHost *\n\tIdentityAgent /tmp/ck-ssh-agent.sock\n\tProxyCommand creekey proxy %h %p\n# /creekey config";

pub fn setup_ssh(force: bool) -> Result<()> {
    let log = Log::NONE;

    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(".ssh");
    path.push("config");

    if !force {
        log.print(
            "❓",
            "You want creekey to auto-configure your ssh setup? [y/n] ",
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
        log.waiting_on("Configuring ssh...")?;

        let mut file = OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .write(true)
            .open(path.clone())?;

        let mut str: String = String::new();
        file.read_to_string(&mut str)?;

        if str.contains("creekey config v1") {
            log.success("Config seems to already be there.")?;
            log.info("If you have problems: manally open the '~/.ssh/config' file and remove the creekey section. then run 'creekey setupssh' again.")?;
            return Ok(());
        }
        file.write_all(SSH_CONF.as_bytes())?;
        log.success("Succesfully Configured SSH!")?;
        return Ok(());
    }

    log.info("You need to tell your ssh system, to use the creekey agent and proxy.")?;
    log.info("Simply copy the following snippet into your '~/.ssh/config' file:")?;
    eprintln!("{}", SSH_CONF);

    Ok(())
}
