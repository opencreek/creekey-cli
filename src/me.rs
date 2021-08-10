use crate::read_ssh_key;
use anyhow::Result;

pub fn print_ssh_key() -> Result<()>{
    let key = read_ssh_key()?;
    println!("{}", key);

    Ok(())
}
