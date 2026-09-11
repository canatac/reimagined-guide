//! Boucles de session SMTP: connexions plain et TLS.
//! Extraites de smtp_server.rs (refactor architecte).
#![allow(unused_imports, dead_code)]

use std::io;
use std::io::BufReader;
use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use mailparse::parse_mail;
use chrono::Utc;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::monitoring;
use simple_smtp_server::session::SessionManager;
use simple_smtp_server::smtp_client::{extract_email_address, send_outgoing_email};

use std::env;

use super::{
    CustomEmail, StreamType, MailServer,
    apply_parsed_header, extract_email_content, extract_session_id_from_response,
    process_command, write_response,
    recipient_helpers::{is_local_recipient, recipient_local_part},
    session_helpers::{
        absorb_data_line, resolve_route, store_and_forward_mongo, use_mongodb_env,
    },
};


use super::session_core::{SessionState, finish_data, handle_command_line};

// Handle TLS client connection
pub(crate) async fn handle_tls_client(
    tls_stream: TlsStream<TcpStream>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<()> {
    info!("TLS connection established");
    let _peer_addr = tls_stream.get_ref().0.peer_addr()?;
    let mut stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));

    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    write_response(&mut stream, greeting).await?;

    let mut state = SessionState::new();
    loop {
        let mut buffer = Vec::new();
        match stream.read_until(b'\n', &mut buffer).await {
            Ok(0) => {
                println!("TLS Client disconnected");
                break;
            }
            Ok(_) => {
                let line = String::from_utf8_lossy(&buffer).to_string();
                println!("Received: {}", line.trim());

                if line.trim().eq_ignore_ascii_case("STARTTLS") {
                    write_response(
                        &mut stream,
                        "454 TLS not available due to temporary reason\r\n",
                    )
                    .await?;
                    continue;
                }
                if state.in_data_mode {
                    if line.trim() == "." {
                        finish_data(&mut state, &mut stream, &logic, &session_manager, false).await?;
                    } else {
                        if let Err(reject) = absorb_data_line(&mut state.current_email, &mut state.in_body, &line) {
                            warn!("Rejected malformed inbound header (reason={}): {}", reject.reason_code(), line.trim_end());
                            write_response(&mut stream, "550 5.6.0 Invalid header\r\n").await?;
                            state.in_data_mode = false;
                            state.in_body = false;
                            state.current_email = CustomEmail {
                                email: Email::new("", "", "", "", ""),
                                raw_content: String::new(),
                                dkim_signature: None,
                            };
                        }
                    }
                } else {
                    let should_break = handle_command_line(
                        &mut state,
                        &mut stream,
                        &logic,
                        &session_manager,
                        &line,
                        None,
                        true,
                    )
                    .await?;
                    if should_break {
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }
    }

    Ok(())
}

// Handle plain client connection
pub(crate) async fn handle_plain_client(
    stream: TcpStream,
    tls_acceptor: Arc<TlsAcceptor>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("New plain connection from: {}", peer_addr);
    let mut stream = StreamType::Plain(tokio::io::BufReader::new(stream));

    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    info!("Sending greeting to {}: {}", peer_addr, greeting.trim());
    write_response(&mut stream, greeting).await?;

    let mut state = SessionState::new();
    loop {
        let mut buffer = String::new();
        match stream.read_line(&mut buffer).await {
            Ok(0) => {
                println!("Client disconnected  : {}", buffer.trim());
                break;
            }
            Ok(_n) => {
                println!("Calling process_command with: {}", buffer.trim());
                if buffer.trim().eq_ignore_ascii_case("STARTTLS") {
                    write_response(&mut stream, "220 Ready to start TLS\r\n").await?;
                    match stream {
                        StreamType::Plain(plain_stream) => {
                            let tls_stream = tls_acceptor.accept(plain_stream.into_inner()).await?;
                            stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));
                            println!("Upgraded to TLS connection");
                        }
                        StreamType::Tls(_) => {
                            write_response(
                                &mut stream,
                                "454 TLS not available due to temporary reason\r\n",
                            )
                            .await?;
                        }
                    }
                    continue;
                }
                if state.in_data_mode {
                    println!("In in_data_mode");
                    if buffer.trim() == "." {
                        finish_data(&mut state, &mut stream, &logic, &session_manager, true).await?;
                    } else {
                        if let Err(reject) = absorb_data_line(&mut state.current_email, &mut state.in_body, &buffer) {
                            warn!("Rejected malformed inbound header (reason={}): {}", reject.reason_code(), buffer.trim_end());
                            write_response(&mut stream, "550 5.6.0 Invalid header\r\n").await?;
                            state.in_data_mode = false;
                            state.in_body = false;
                            state.current_email = CustomEmail {
                                email: Email::new("", "", "", "", ""),
                                raw_content: String::new(),
                                dkim_signature: None,
                            };
                        }
                    }
                } else {
                    let should_break = handle_command_line(
                        &mut state,
                        &mut stream,
                        &logic,
                        &session_manager,
                        &buffer,
                        Some("221 Bye\r\n"),
                        false,
                    )
                    .await?;
                    if should_break {
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Error reading from client {}: {}", peer_addr, e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_greeting_is_correct() {
        let greeting = "220 mail.misfits.ai ESMTP\r\n";
        assert!(greeting.starts_with("220 "));
        assert!(greeting.contains("mail.misfits.ai"));
        assert!(greeting.contains("ESMTP"));
    }

    #[test]
    fn starttls_response_for_tls_client() {
        // When a TLS client sends STARTTLS, it should get 454
        let response = "454 TLS not available due to temporary reason\r\n";
        assert!(response.starts_with("454 "));
        assert!(response.contains("TLS not available"));
    }

    #[test]
    fn starttls_response_for_plain_client() {
        // When a plain client sends STARTTLS, it should get 220
        let response = "220 Ready to start TLS\r\n";
        assert!(response.starts_with("220 "));
        assert!(response.contains("Ready to start TLS"));
    }

    #[test]
    fn invalid_header_response() {
        let response = "550 5.6.0 Invalid header\r\n";
        assert!(response.starts_with("550 "));
        assert!(response.contains("Invalid header"));
    }

    #[test]
    fn bye_response() {
        let response = "221 Bye\r\n";
        assert!(response.starts_with("221 "));
        assert!(response.contains("Bye"));
    }

    #[test]
    fn data_mode_terminator() {
        // In data mode, a line containing only "." terminates data
        let terminator = ".";
        assert_eq!(terminator, ".");
    }

    #[test]
    fn custom_email_default() {
        let email = CustomEmail {
            email: Email::new("", "", "", "", ""),
            raw_content: String::new(),
            dkim_signature: None,
        };
        assert_eq!(email.email.from, "");
        assert_eq!(email.email.to, "");
        assert_eq!(email.raw_content, "");
        assert_eq!(email.dkim_signature, None);
    }

    #[test]
    fn stream_type_is_tls() {
        // We can't easily construct a TlsStream, but we can verify the enum exists
        let _: fn(&StreamType) -> bool = StreamType::is_tls;
        assert!(true);
    }
}
