// Split from smtp_server.rs — handlers de commandes SMTP (HELO/QUIT/RSET/STARTTLS/AUTH/…)
use std::sync::Arc;
use base64::{engine::general_purpose, Engine as _};
use log::debug;
use tokio::io::AsyncWriteExt;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::session::SessionManager;

use super::{
    CustomEmail, StreamType,
    env_bool, extract_email_content,
    auth_helpers::check_credentials,
};

fn handle_helo(is_tls: bool, require_starttls: bool) -> String {
    let mut caps = vec!["250-mail.misfits.ai Hello".to_string()];
    if !is_tls {
        caps.push("250-STARTTLS".to_string());
    }
    if is_tls || !require_starttls {
        caps.push("250-AUTH LOGIN PLAIN".to_string());
    }
    caps.push("250 OK".to_string());
    format!("{}\r\n", caps.join("\r\n"))
}

// Réponse QUIT — extrait le contenu si un message est en cours, puis "221 Bye".
fn handle_quit(email: &CustomEmail) -> String {
    if !email.email.from.is_empty() && !email.email.to.is_empty() {
        match extract_email_content(&email.email.body) {
            Ok(content) => println!("Extracted email content: {}", content),
            Err(e) => eprintln!("Error extracting email content: {}", e),
        }
    }
    "221 Bye\r\n".to_string()
}

// Réponse RSET — reset le buffer d'email en cours.
fn handle_rset(email: &mut CustomEmail) -> String {
    *email = CustomEmail {
        email: Email::new("", "", "", "", ""),
        raw_content: String::new(),
        dkim_signature: None,
    };
    "250 OK\r\n".to_string()
}

// Réponse STARTTLS — 220 si on est encore en Plain, 454 si déjà en TLS.
fn handle_starttls(stream: &StreamType) -> String {
    match stream {
        StreamType::Plain(_) => "220 Ready to start TLS\r\n".to_string(),
        StreamType::Tls(_) => "454 TLS not available due to temporary reason\r\n".to_string(),
    }
}

// Garde-fou "530 Must issue a STARTTLS command first" sur les verbes qui l'exigent.
fn require_tls_or_530(require_starttls: bool, is_tls: bool) -> Option<String> {
    if require_starttls && !is_tls {
        Some("530 Must issue a STARTTLS command first\r\n".to_string())
    } else {
        None
    }
}

// Process SMTP commands — dispatch vers les handlers dédiés par verbe.
pub(crate) async fn process_command(
    command: &str,
    email: &mut CustomEmail,
    stream: &mut StreamType,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<String> {
    let trimmed = command.trim();
    let upper = trimmed.to_ascii_uppercase();
    println!("In process_command with: {}", upper.as_str());

    let require_starttls = env_bool("SMTP_REQUIRE_STARTTLS", true);
    let is_tls = stream.is_tls();

    match upper.as_str() {
        s if s.starts_with("HELO") || s.starts_with("EHLO") => {
            Ok(handle_helo(is_tls, require_starttls))
        }
        s if s.starts_with("AUTH LOGIN") => {
            if let Some(err) = require_tls_or_530(require_starttls, is_tls) {
                return Ok(err);
            }
            handle_auth_login(stream, logic.clone(), session_manager.clone()).await
        }
        s if s.starts_with("AUTH PLAIN") => {
            if let Some(err) = require_tls_or_530(require_starttls, is_tls) {
                return Ok(err);
            }
            handle_auth_plain(trimmed, session_manager.clone()).await
        }
        s if s.starts_with("MAIL FROM:") => {
            email.email.from = trimmed[10..].trim().to_string();
            Ok("250 OK\r\n".to_string())
        }
        s if s.starts_with("RCPT TO:") => {
            email.email.to = trimmed[8..].trim().to_string();
            Ok("250 OK\r\n".to_string())
        }
        s if s.starts_with("SUBJECT:") => {
            email.email.subject = s[8..].trim().to_string();
            Ok("250 OK\r\n".to_string())
        }
        "DATA" => Ok("354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string()),
        "." => Ok("250 OK\r\n".to_string()),
        "QUIT" => Ok(handle_quit(email)),
        "RSET" => Ok(handle_rset(email)),
        "NOOP" => Ok("250 OK\r\n".to_string()),
        s if s.starts_with("VRFY") => Ok(
            "252 Cannot VRFY user, but will accept message and attempt delivery\r\n".to_string(),
        ),
        s if s.starts_with("AUTH") => Ok(match require_tls_or_530(require_starttls, is_tls) {
            Some(err) => err,
            None => "235 Authentication successful\r\n".to_string(),
        }),
        s if s.starts_with("STARTTLS") => Ok(handle_starttls(stream)),
        _ => Ok("500 Syntax error, command unrecognized\r\n".to_string()),
    }
}

// Handle AUTH LOGIN command
async fn handle_auth_login(
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
async fn handle_auth_plain(
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
        // FE + API use lowercase folder ids (issue #167)
        session_manager.set_mailbox(&session_id, "inbox");
        Ok(format!(
            "235 Authentication successful, session ID: {}\r\n",
            session_id
        ))
    } else {
        Ok("535 Authentication failed\r\n".to_string())
    }
}

// Write a response to the client
pub(crate) async fn write_response(stream: &mut StreamType, response: &str) -> std::io::Result<()> {
    match stream {
        StreamType::Tls(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
        StreamType::Plain(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
    }
}
