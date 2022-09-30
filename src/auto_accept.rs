use crate::keychain::{get_auto_accept_expires_at, get_auto_accept_token, KeyChainError};
use crate::output::Log;
use chrono::{DateTime, Utc};
use std::env;

pub fn get_auto_accept(request_type: String, request_id: String) -> Option<String> {
    let auto_accept_expires_at =
        match get_auto_accept_expires_at(request_type.clone(), request_id.clone()) {
            Ok(it) => Some(it),
            Err(error) => match error {
                KeyChainError::Missing => None,
                e => {
                    Log::NONE.handle_keychain_error("auto accept", e).ok()?;
                    None
                }
            },
        };

    match auto_accept_expires_at {
        None => None,
        Some(expires_at) => {
            let date = DateTime::parse_from_rfc3339(expires_at.as_str()).ok()?;
            if date > Utc::now() {
                match get_auto_accept_token(request_type, request_id) {
                    Ok(token) => Some(token),
                    Err(_) => None,
                }
            } else {
                None
            }
        }
    }
}
