//! Handlers de commandes SMTP (HELO/QUIT/RSET/STARTTLS/dispatcher).
//! Extrait de smtp_server.rs (refactor cycle 6).
#![allow(dead_code)]

use std::sync::Arc;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::session::SessionManager;

use super::{
    env_bool, handle_auth_login, handle_auth_plain, extract_email_content, CustomEmail, StreamType,
};

// Réponse EHLO/HELO — construit la liste de capabilities selon l'état TLS.
pub(crate) fn handle_helo(is_tls: bool, require_starttls: bool) -> String {
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

// Réponse QUIT.
pub(crate) fn handle_quit(email: &CustomEmail) -> String {
    if !email.email.from.is_empty() && !email.email.to.is_empty() {
        match extract_email_content(&email.email.body) {
            Ok(content) => println!("Extracted email content: {}", content),
            Err(e) => eprintln!("Error extracting email content: {}", e),
        }
    }
    "221 Bye\r\n".to_string()
}

// Réponse RSET — reset le buffer d'email en cours.
pub(crate) fn handle_rset(email: &mut CustomEmail) -> String {
    *email = CustomEmail {
        email: Email::new("", "", "", "", ""),
        raw_content: String::new(),
        dkim_signature: None,
    };
    "250 OK\r\n".to_string()
}

// Réponse STARTTLS.
pub(crate) fn handle_starttls(stream: &StreamType) -> String {
    match stream {
        StreamType::Plain(_) => "220 Ready to start TLS\r\n".to_string(),
        StreamType::Tls(_) => "454 TLS not available due to temporary reason\r\n".to_string(),
    }
}

// Garde-fou "530 Must issue a STARTTLS command first".
pub(crate) fn require_tls_or_530(require_starttls: bool, is_tls: bool) -> Option<String> {
    if require_starttls && !is_tls {
        Some("530 Must issue a STARTTLS command first\r\n".to_string())
    } else {
        None
    }
}

fn classify_data_bdat_and_basic_responses(
    upper: &str,
    is_tls: bool,
    require_starttls: bool,
) -> Option<&'static str> {
    match upper {
        "DATA" => Some("354 Start mail input; end with <CRLF>.<CRLF>\r\n"),
        "." => Some("250 OK\r\n"),
        "NOOP" => Some("250 OK\r\n"),
        s if s.starts_with("BDAT") => Some("502 Command not implemented\r\n"),
        s if s.starts_with("VRFY") => {
            Some("252 Cannot VRFY user, but will accept message and attempt delivery\r\n")
        }
        s if s.starts_with("AUTH") => {
            if require_starttls && !is_tls {
                Some("530 Must issue a STARTTLS command first\r\n")
            } else {
                Some("235 Authentication successful\r\n")
            }
        }
        s if s.starts_with("STARTTLS") => {
            if is_tls {
                Some("454 TLS not available due to temporary reason\r\n")
            } else {
                Some("220 Ready to start TLS\r\n")
            }
        }
        _ => None,
    }
}

// Dispatch SMTP commands.
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

    if !upper.starts_with("AUTH LOGIN") && !upper.starts_with("AUTH PLAIN") {
        if let Some(resp) = classify_data_bdat_and_basic_responses(
            upper.as_str(),
            is_tls,
            require_starttls,
        ) {
            return Ok(resp.to_string());
        }
    }

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
        "QUIT" => Ok(handle_quit(email)),
        "RSET" => Ok(handle_rset(email)),
        _ => Ok("500 Syntax error, command unrecognized\r\n".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::classify_data_bdat_and_basic_responses;

    #[test]
    fn data_bdat_edge_coverage_cases() {
        let cases = [
            ("DATA", false, true, Some("354")),
            (" data ", false, true, Some("354")),
            ("DATA\r\n", false, true, Some("354")),
            ("DATA EXTRA", false, true, None),
            ("BDAT", false, true, Some("502")),
            ("BDAT 0 LAST", false, true, Some("502")),
            ("BDAT 10", false, true, Some("502")),
            ("bdat 999999 LAST", false, true, Some("502")),
            (".", false, true, Some("250")),
            ("NOOP", false, true, Some("250")),
            ("VRFY root", false, true, Some("252")),
            ("AUTH PLAIN", false, true, Some("530")),
            ("AUTH PLAIN", true, true, Some("235")),
            ("AUTH XOAUTH2", false, false, Some("235")),
            ("STARTTLS", false, true, Some("220")),
            ("STARTTLS", true, true, Some("454")),
        ];

        for (raw, is_tls, require_starttls, expected) in cases {
            let upper = raw.trim().to_ascii_uppercase();
            let got = classify_data_bdat_and_basic_responses(&upper, is_tls, require_starttls);
            match expected {
                Some(prefix) => {
                    let resp = got.expect("expected response");
                    assert!(
                        resp.starts_with(prefix),
                        "raw={raw:?} resp={resp:?} expected_prefix={prefix}"
                    );
                }
                None => assert!(got.is_none(), "raw={raw:?} expected None, got={got:?}"),
            }
        }
    }
}
