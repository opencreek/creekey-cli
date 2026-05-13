use anyhow::{Context, Result};
use std::path::PathBuf;

static CONFIG_FOLDER: &'static str = ".config/creekey";
static SSH_KEY_PATH: &'static str = ".ssh/id_creekey.pub";

pub fn get_config_folder() -> Result<PathBuf> {
    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(CONFIG_FOLDER);
    Ok(path)
}

pub fn get_ssh_key_path() -> Result<PathBuf> {
    let mut path = dirs::home_dir().context("could not find home dir")?;
    path.push(SSH_KEY_PATH);
    Ok(path)
}

pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn per_user_runtime_dir() -> Option<PathBuf> {
    if let Some(dir) = dirs::runtime_dir() {
        return Some(dir);
    }
    if cfg!(target_os = "macos") {
        if let Some(tmpdir) = std::env::var_os("TMPDIR") {
            return Some(PathBuf::from(tmpdir));
        }
    }
    None
}

fn runtime_path(base: &str, ext: &str) -> String {
    match per_user_runtime_dir() {
        Some(mut path) => {
            path.push(format!("{}.{}", base, ext));
            path.to_string_lossy().into_owned()
        }
        None => format!("/tmp/{}-{}.{}", base, current_uid(), ext),
    }
}

pub fn agent_socket_path() -> String {
    runtime_path("ck-ssh-agent", "sock")
}

pub fn agent_pid_path() -> String {
    runtime_path("ck-agent", "pid")
}

pub fn logger_socket_path(random: &str) -> String {
    runtime_path(&format!("ck-logger-{}", random), "sock")
}
