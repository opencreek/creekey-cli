use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

pub fn setup_ssh() -> Result<()> {
    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(".ssh");
    path.push("config");

    let mut file = OpenOptions::new()
        .read(true)
        .create(true)
        .append(true)
        .write(true)
        .open(path.clone())?;

    let mut str: String = String::new();
    file.read_to_string(&mut str);

    if str.contains("creekey") {
        return Ok(());
    }
    file.write_all(b"# creekey config\nHost *\n\tIdentityAgent /tmp/ck-ssh-agent.sock")?;

    Ok(())
}
