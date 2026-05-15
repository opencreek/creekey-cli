use crate::constants::agent_socket_path;
use crate::output::Log;
use anyhow::{Context, Result};
use colored::Color;
use std::fs;
use std::io::stdin;
use std::path::PathBuf;

const CURRENT_VERSION: &str = "v2";
const START_PREFIX: &str = "# creekey config ";
const END_MARKER: &str = "# /creekey config";

#[derive(Debug)]
pub enum SshConfigState {
    NoCreekeyBlock,
    AlreadyCurrent,
    Upgraded { from: String },
}

fn ssh_config_path() -> Result<PathBuf> {
    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(".ssh");
    path.push("config");
    Ok(path)
}

fn render_conf() -> String {
    format!(
        "{}{}\nHost *\n\tIdentityAgent {}\n\tProxyCommand creekey proxy %h %p\n{}",
        START_PREFIX,
        CURRENT_VERSION,
        agent_socket_path(),
        END_MARKER,
    )
}

fn strip_existing_block(contents: &str) -> Option<(String, String)> {
    let start = contents.find(START_PREFIX)?;
    let after_start = &contents[start + START_PREFIX.len()..];
    let version_end = after_start.find('\n').unwrap_or(after_start.len());
    let version = after_start[..version_end].trim().to_string();

    let end_rel = contents[start..].find(END_MARKER)?;
    let mut end = start + end_rel + END_MARKER.len();
    if contents.as_bytes().get(end) == Some(&b'\n') {
        end += 1;
    }

    let mut stripped = String::with_capacity(contents.len());
    stripped.push_str(&contents[..start]);
    stripped.push_str(&contents[end..]);
    Some((stripped, version))
}

fn append_conf(mut base: String, conf: &str) -> String {
    if !base.is_empty() && !base.ends_with('\n') {
        base.push('\n');
    }
    base.push_str(conf);
    if !base.ends_with('\n') {
        base.push('\n');
    }
    base
}

/// Rewrites `~/.ssh/config` if it contains an outdated creekey block.
/// Does *not* add a new block when none exists — that's `setup_ssh`'s job.
pub fn auto_migrate_ssh_config() -> Result<SshConfigState> {
    let path = ssh_config_path()?;

    let existing = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SshConfigState::NoCreekeyBlock);
        }
        Err(e) => return Err(e.into()),
    };

    let (stripped, version) = match strip_existing_block(&existing) {
        Some(t) => t,
        None => return Ok(SshConfigState::NoCreekeyBlock),
    };

    if version == CURRENT_VERSION {
        return Ok(SshConfigState::AlreadyCurrent);
    }

    let new_contents = append_conf(stripped, &render_conf());
    fs::write(&path, new_contents)?;
    Ok(SshConfigState::Upgraded { from: version })
}

pub fn setup_ssh(force: bool) -> Result<()> {
    let log = Log::NONE;

    let path = ssh_config_path()?;

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

    let conf = render_conf();

    if input.starts_with("y") {
        log.waiting_on("Configuring ssh...")?;

        let existing = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e.into()),
        };

        let (stripped, replaced_version) = match strip_existing_block(&existing) {
            Some((stripped, version)) => (stripped, Some(version)),
            None => (existing, None),
        };

        if replaced_version.as_deref() == Some(CURRENT_VERSION) {
            log.success("Config is already up to date.")?;
            return Ok(());
        }

        let new_contents = append_conf(stripped, &conf);
        fs::write(&path, new_contents)?;

        match replaced_version {
            Some(old) => {
                log.success(&format!(
                    "Upgraded SSH config from {} to {}.",
                    old, CURRENT_VERSION
                ))?;
            }
            None => {
                log.success("Succesfully Configured SSH!")?;
            }
        }
        return Ok(());
    }

    log.info("You need to tell your ssh system, to use the creekey agent and proxy.")?;
    log.info("Simply copy the following snippet into your '~/.ssh/config' file:")?;
    eprintln!("{}", conf);

    Ok(())
}
