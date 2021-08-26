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
