use crate::output::Log;
use crate::ssh_agent::read_ssh_key;
use anyhow::{anyhow, Result};
use clipboard::{ClipboardContext, ClipboardProvider};
use colored::Color;

pub fn print_ssh_key(copy_to_clipboard: bool, raw: bool) -> Result<()> {
    let log = Log::NONE;
    let key = read_ssh_key()?;
    if !raw {
        if copy_to_clipboard {
            let mut ctx: ClipboardContext = ClipboardProvider::new()
                .map_err(|_err| anyhow!("Could not create ClipboardProvider"))?;
            ctx.set_contents(key.clone()).map_err(|err| {
                println!("{}", err);
                log.println("🚨 Could not set clipboard", Color::Red);
                anyhow!("error setting clipboard")
            })?;
            log.println("🚨 Copied to clipboard", Color::Green);
        } else {
            log.println(
                " You can use '--copy' to automatically copy the key to your clipboard",
                Color::White,
            )?;
        }
        println!();
    }

    println!("{}", key);

    if !raw {
        println!();

        log.println(
            "➡️ Copy the public key above to wherever you are using",
            Color::Blue,
        );
    }

    Ok(())
}
