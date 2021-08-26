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

use serde::{Deserialize, Serialize};
use sodiumoxide::randombytes::randombytes;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{stdin, Read, Write};

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

pub async fn sign_git_commit() -> Result<()> {
    let path = env::var("GPG_TTY")?;
    check_color_tty();

    let file = fs::OpenOptions::new().write(true).open(path)?;
    let log = Log::from_file(&file);
    let mut buffer = String::new();

    stdin().read_to_string(&mut buffer)?;

    let base64_data = base64::encode(&buffer);

    let phone_id = get_phone_id().unwrap();
    let relay_id = base64::encode_config(randombytes(32), base64::URL_SAFE);
    let key = get_secret_key()?;
    let request = GgpRequest {
        data: base64_data,
        message_type: "gpg".to_string(),
        relay_id: relay_id.clone(),
    };

    log.waiting_on("Waiting on Phone Authorization...")?;
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
    log.success(&format!("{:X?}", response))?;

    if let Some(data_base64) = response.signature {
        let out = base64::decode(data_base64)?;
        let mut header: BTreeMap<String, String> = BTreeMap::new();
        header.insert("Comment".to_string(), "Signed with creekey.io".to_string());
        log.success(&format!("data: {:X?}", out))?;

        let mut res = Vec::with_capacity(out.len() * 2);
        let source = ArmourSource::new(out);
        pgp::armor::write(&source, BlockType::Signature, &mut res, Some(&header))?;

        let str = String::from_utf8(res.clone()).unwrap();
        print!("{}", str);
        log.info(&format!("\n{}", str));
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    sign_git_commit().await?;
    Ok(())
}
