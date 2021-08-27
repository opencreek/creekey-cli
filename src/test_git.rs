use crate::output::Log;
use anyhow::Result;
use sodiumoxide::randombytes::randombytes;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{env, fs};

pub fn get_tmp_dir() -> Result<PathBuf> {
    let mut tmp_dir = env::temp_dir();
    let random = base64::encode_config(randombytes(8), base64::URL_SAFE);
    tmp_dir.push(format!("creekey-{}", random));

    fs::create_dir(tmp_dir.clone())?;

    Ok(tmp_dir)
}

pub async fn test_git() -> Result<()> {
    let log = Log::NONE;
    let tmp_dir = get_tmp_dir()?;

    std::env::set_current_dir(tmp_dir.clone())?;

    log.waiting_on("Creating git repository...");
    let mut init = Command::new("git")
        .arg("init")
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .spawn()?;
    init.wait()?;

    log.waiting_on("Creating Test commit. You should get a phone notification shortly!\n");

    let mut commit = Command::new("git")
        .arg("commit")
        .arg("-m")
        .arg("Testing codesigning with creekey")
        .arg("--allow-empty")
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .spawn()?;
    commit.wait()?;

    let mut count = Command::new("git")
        .arg("rev-list")
        .arg("--all")
        .arg("--count")
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()?;
    count.wait()?;

    let mut count_str = String::new();
    let mut stdout = count.stdout.take().unwrap();
    stdout.read_to_string(&mut count_str)?;
    count_str = count_str.replace("\n", "");

    if count_str != "1" {
        log.fail("The commit could not be made.")?;
        log.fail("Could not verify if signature is working.")?;
        fs::remove_dir_all(tmp_dir)?;
        return Ok(());
    }

    let mut git_log = Command::new("git")
        .arg("log")
        .arg("-n")
        .arg("1")
        .arg("--format=%G?")
        .stdout(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()?;
    git_log.wait()?;

    let mut signature_valid = String::new();
    let mut stdout = git_log.stdout.take().unwrap();
    stdout.read_to_string(&mut signature_valid)?;
    signature_valid = signature_valid.replace("\n", "");

    match signature_valid.as_str() {
        "N" => {
            log.fail("No signature detected.")?;
            log.fail("That either means yo do nat have gpg installed (which is ok, we don't need that to actually sign anything)")?;
            log.fail("Or it means that it's not setup yet, in which case:")?;
            log.user_todo("Run 'creekey setupgit' if you haven't already.")?;
        }
        "E" => {
            log.fail("Could not verify signature.")?;
            log.fail("This can either mean that no gpg is installed or that your public key is not set up in the gpg agent.")?;
            log.user_todo("If you have your gpg agent setup run 'creekey setupgit' again.")?;
        }
        "B" => {
            log.fail("Got a bad signature.")?;
        }
        "Y" => {
            log.fail("The GPG key is expired, but otherwise working fine.")?;
        }
        "R" => {
            log.fail("The GPG key is revoked, but otherwise working fine.")?;
        }
        "U" | "G" => {
            log.success("Successfully validated the signature!")?;
            log.success("You're all set!")?;
        }
        rest => {
            log.error(&format!("Got unknown response from git: ->{:x?}<-", rest))?;
        }
    };

    fs::remove_dir_all(tmp_dir)?;

    Ok(())
}
