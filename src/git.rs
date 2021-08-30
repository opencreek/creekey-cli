mod agent;
mod communication;
mod constants;
mod keychain;
#[allow(dead_code)] // because we have multiple entry points.
mod output;
mod sign_on_phone;
mod ssh_agent;

use crate::communication::PollError;
use crate::keychain::{get_phone_id, get_secret_key};
use crate::output::{check_color_tty, Log};
use crate::sign_on_phone::{sign_on_phone, SignError};
use anyhow::Result;

use pgp::armor::BlockType;

use anyhow::anyhow;
use clap::{App, AppSettings, Arg};
use serde::{Deserialize, Serialize};
use sodiumoxide::randombytes::randombytes;
use std::collections::BTreeMap;
use std::env;
use std::fs;

use std::io::{stdin, stdout, Read, Write};
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize, Debug)]
struct GgpRequest {
    data: String,
    #[serde(rename = "type")]
    message_type: String,
    #[serde(rename = "relayId")]
    relay_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GgpResponse {
    signature: Option<String>,
    accepted: bool,
}

struct ArmourSource {
    content: Vec<u8>,
}

impl pgp::ser::Serialize for ArmourSource {
    fn to_writer<W: std::io::Write>(&self, w: &mut W) -> Result<(), pgp::errors::Error> {
        w.write_all(&self.content)?;
        Ok(())
    }
}

impl ArmourSource {
    pub fn new(content: Vec<u8>) -> Self {
        ArmourSource { content }
    }
}

pub async fn sign_git_commit(armour_output: bool) -> Result<()> {
    let path = match env::var("GPG_TTY") {
        Ok(it) => it,
        Err(_) => {
            let mut tty = Command::new("tty")
                .stdout(Stdio::piped())
                .stdin(Stdio::null())
                .spawn()?;

            tty.wait()?;

            let mut string = String::new();
            let mut stdout = tty.stdout.take().unwrap();
            stdout.read_to_string(&mut string)?;
            string
        }
    };

    check_color_tty();

    let file = match fs::OpenOptions::new().write(true).open(path) {
        Ok(it) => it,
        Err(_) => {
            Log::NONE.error("Could not get tty to write to!")?;
            return Err(anyhow!("Could not get tty to writeto"));
        }
    };
    let mut log = Log::from_file(&file);
    let mut buffer = String::new();

    stdin().read_to_string(&mut buffer)?;

    let base64_data = base64::encode(&buffer);

    log.waiting_on("Waiting on Phone Authorization...")?;

    let phone_id = match get_phone_id() {
        Ok(id) => id,
        Err(e) => {
            log.handle_keychain_error("phone id", e)?;
            return Ok(());
        }
    };
    let key = match get_secret_key() {
        Ok(id) => id,
        Err(e) => {
            log.handle_keychain_error("phone id", e)?;
            return Ok(());
        }
    };

    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);
    let request = GgpRequest {
        data: base64_data,
        message_type: "gpg".to_string(),
        relay_id: relay_id.clone(),
    };

    let response: GgpResponse = match sign_on_phone(request, phone_id, relay_id, key).await {
        Ok(t) => t,
        Err(e) => {
            match e {
                SignError::PollError(poll_err) => {
                    if let PollError::Timeout = poll_err {
                        // There is an emoji at the beginning of that string!
                        log.fail("Timed Out")?;
                    }
                }
                _ => {}
            }
            return Ok(());
        }
    };

    if !response.accepted {
        eprintln!("Not accepted!");
        log.fail("Not Accepted")?;
        return Ok(());
    }
    log.success("Accepted")?;

    if let Some(data_base64) = response.signature {
        let out = base64::decode(data_base64)?;

        if armour_output {
            let mut header: BTreeMap<String, String> = BTreeMap::new();
            header.insert("Comment".to_string(), "Signed with creekey.io".to_string());

            let mut res = Vec::with_capacity(out.len() * 2);
            let source = ArmourSource::new(out);
            pgp::armor::write(&source, BlockType::Signature, &mut res, Some(&header))?;

            let str = String::from_utf8(res.clone()).unwrap();
            print!("{}", str);
            eprintln!("\n[GNUPG:] SIG_CREATED ")
        } else {
            // raw output to stdout i guess
            stdout().write_all(&out)?;
        }
    }

    Ok(())
}

fn forward_to_pgp() -> Result<()> {
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    let mut child = match Command::new("gpg")
        .args(args)
        .stdout(Stdio::inherit())
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };

    child.wait().unwrap();

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _path = env::var("GPG_TTY")?;
    check_color_tty();

    let app = App::new("creekey git sign")
        .version("0.1.0")
        .author("Opencreek Technogoly UG - opencreek.tech")
        .about("Git signing with creekey.io")
        .setting(AppSettings::AllowExternalSubcommands)
        .arg(
            Arg::with_name("status-fd")
                .long("status-fd")
                .takes_value(true)
                .help("idk lol"),
        )
        .arg(
            Arg::with_name("sign")
                .short("s")
                .long("sign")
                .help("makes a signature"),
        )
        .arg(
            Arg::with_name("detach-sign")
                .short("b")
                .long("detach-sign")
                .help("makes a detached signature"),
        )
        .arg(
            Arg::with_name("local-user")
                .short("u")
                .long("socal-user")
                .takes_value(true)
                .help("encrypt for USER-ID (todo)"),
        )
        .arg(
            Arg::with_name("armor")
                .short("a")
                .long("armor")
                .help("prints armor ascii output"),
        );
    let matches = app.get_matches_safe();

    match matches {
        Ok(matches) => {
            if matches.is_present("sign") || matches.is_present("detach-sign") {
                sign_git_commit(matches.is_present("armor")).await?;
            } else {
                forward_to_pgp()?;
            }
        }
        _ => {
            forward_to_pgp()?;
        }
    }
    Ok(())
}
