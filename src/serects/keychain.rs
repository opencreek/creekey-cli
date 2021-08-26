use keyring::Keyring;
use thiserror::Error;

const service: &str = "creekey";


#[derive(Error, Debug, Clone)]
pub enum KeyChainError {
    #[error("File is missing")]
    Missing,

    #[error("could not get path")]
    CouldNotGetPath,

    #[error("Error Parsing Key")]
    KeyParseError,
}


fn get_secret_key()-> Result<String, KeyChainError> {
    let keyring = Keyring::new(&service, "secret-key");

    match keyring.get_password() {
        Ok(k) => Ok(k),
        Err(e) =>  Ok("TODO".to_string()),
    }
}
