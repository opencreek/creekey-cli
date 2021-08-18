use crate::ssh_agent::read_ssh_key;
use anyhow::{anyhow, Result};
use clipboard::{ClipboardContext, ClipboardProvider};

pub fn print_ssh_key(copy_to_clipboard: bool) -> Result<()> {
    let key = read_ssh_key()?;
    if copy_to_clipboard {
        let mut ctx: ClipboardContext = ClipboardProvider::new()
            .map_err(|err| anyhow!("Could not create ClipboardProvider"))?;
        ctx.set_contents(key.clone()).map_err(|err| {
            println!("{}", err);
            anyhow!("error setting clipboard")
        })?;
        println!("copied to clipboard")
    }
    println!("{}", key);

    Ok(())
}
