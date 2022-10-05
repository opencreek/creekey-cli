use crate::keychain::get_gpg_from_keychain;
use crate::output::Log;
use crate::ssh_agent::read_ssh_key;
use anyhow::{anyhow, Result};
use clipboard::{ClipboardContext, ClipboardProvider};

pub fn print_ssh_key(copy_to_clipboard: bool, raw: bool, gpg: bool) -> Result<()> {
    let log = Log::NONE;
    let key = read_ssh_key()?;
    let gpg_key = get_gpg_from_keychain()?;

    if !raw {
        if copy_to_clipboard {
            let mut ctx: ClipboardContext = ClipboardProvider::new()
                .map_err(|_err| anyhow!("Could not create ClipboardProvider"))?;
            let key_to_copy = if gpg { gpg_key.clone() } else { key.clone() };

            ctx.set_contents(key_to_copy.clone()).map_err(|err| {
                println!("{}", err);
                log.error("Could not set clipboard").unwrap();
                anyhow!("error setting clipboard")
            })?;
            log.success("Copied to clipboard")?;
        } else {
            log.user_todo("You can use '--copy' to automatically copy the key to your clipboard")?;
        }
        println!();
    }

    if !raw || !gpg {
        println!("{}", key);
    }

    if !raw {
        println!();
        log.info("gpg key:\n")?;
    }
    if !raw || gpg {
        println!("{}", gpg_key);
    }

    if !raw {
        println!();

        log.user_todo("Copy the public key above to wherever you are using")?;
    }

    Ok(())
}
