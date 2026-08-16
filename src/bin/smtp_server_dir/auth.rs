//! Vérification de credentials SMTP AUTH + handlers AUTH LOGIN/PLAIN.
//! Extrait de smtp_server.rs (refactor architecte + cycle 6).
#![allow(dead_code)]

use std::env;
use std::sync::Arc;

use base64::{engine::general_purpose, Engine as _};
use constant_time_eq::constant_time_eq;
use log::debug;
use tokio::io::AsyncBufReadExt;

use simple_smtp_server::logic::Logic;
use simple_smtp_server::session::SessionManager;

use super::{write_response, StreamType};

pub(crate) fn check_credentials(username: &[u8], password: &[u8]) -> bool {
    let expected_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let expected_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

    let username_match = constant_time_eq(username, expected_username.as_bytes());
    let password_match = constant_time_eq(password, expected_password.as_bytes());

    debug!("Username match: {}", username_match);
    debug!("Password match: {}", password_match);

    username_match && password_match
}

// Handle AUTH LOGIN command
pub(crate) async fn handle_auth_login(
    stream: &mut StreamType,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<String> {
    write_response(stream, "334 VXNlcm5hbWU6\r\n").await?; // Base64 pour "Username:"
    let mut username = String::new();
    stream.read_line(&mut username).await?;
    let username = username.trim_end().as_bytes().to_vec();
    debug!("Received username: {}", String::from_utf8_lossy(&username));

    write_response(stream, "334 UGFzc3dvcmQ6\r\n").await?; // Base64 for "Password:"
    let mut password = String::new();
    stream.read_line(&mut password).await?;
    let password = password.trim_end().as_bytes().to_vec();
    debug!("Received password: {}", String::from_utf8_lossy(&password));

    let username = String::from_utf8_lossy(&username).to_string();
    let password = String::from_utf8_lossy(&password).to_string();

    match logic.authenticate_user(&username, &password).await {
        Ok(Some(user)) => {
            let session_id = session_manager.create_session(&username);
            session_manager.set_mailbox(&session_id, &user.mailbox);
            Ok(format!(
                "235 Authentication successful, session ID: {}\r\n",
                session_id
            ))
        }
        Ok(None) => Ok("535 Authentication failed\r\n".to_string()),
        Err(_) => Ok("535 Authentication failed\r\n".to_string()),
    }
}

// Handle AUTH PLAIN command
pub(crate) async fn handle_auth_plain(
    command: &str,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<String> {
    let auth_data = command.split_whitespace().nth(2).unwrap_or("");
    let decoded = general_purpose::STANDARD.decode(auth_data).unwrap();
    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();

    if parts.len() != 3 {
        return Ok("501 Malformed AUTH PLAIN\r\n".to_string());
    }

    let username = parts[1];
    let password = parts[2];

    if check_credentials(username, password) {
        let username_str = String::from_utf8_lossy(username).to_string();
        let session_id = session_manager.create_session(&username_str);
        session_manager.set_mailbox(&session_id, "inbox");
        Ok(format!(
            "235 Authentication successful, session ID: {}\r\n",
            session_id
        ))
    } else {
        Ok("535 Authentication failed\r\n".to_string())
    }
}
