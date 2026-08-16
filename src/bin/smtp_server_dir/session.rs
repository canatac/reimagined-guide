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

// État commun d'une session en cours.
struct SessionState {
    in_data_mode: bool,
    in_body: bool,
    authenticated_session_id: Option<String>,
    current_email: CustomEmail,
    mail_server: Arc<MailServer>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            in_data_mode: false,
            in_body: false,
            authenticated_session_id: None,
            current_email: CustomEmail {
                email: Email::new("", "", "", "", ""),
                raw_content: String::new(),
                dkim_signature: None,
            },
            mail_server: Arc::new(MailServer::new("./emails")),
        }
    }
}

/// Fin de la commande DATA : persiste (MongoDB ou local) et écrit la réponse.
async fn finish_data(
    state: &mut SessionState,
    stream: &mut StreamType,
    logic: &Arc<Logic>,
    session_manager: &Arc<SessionManager>,
    local_forward: bool,
) -> std::io::Result<()> {
    state.in_data_mode = false;
    if use_mongodb_env() {
        store_and_forward_mongo(
            stream,
            logic,
            session_manager,
            state.authenticated_session_id.as_ref(),
            &state.current_email,
        )
        .await?;
    } else if local_forward {
        // Store locally + attempt forward (plain path historique)
        state.mail_server.store_email(&state.current_email).await?;
        match send_outgoing_email(&state.current_email.email).await {
            Ok(_) => {
                write_response(stream, "250 OK\r\n").await?;
            }
            Err(e) => {
                error!("Failed to forward email: {}", e);
                write_response(
                    stream,
                    "451 4.4.0 Temporary forwarding failure\r\n",
                )
                .await?;
            }
        }
    } else {
        // Store locally (TLS path historique — pas de forward auto)
        if let Err(e) = state.mail_server.store_email(&state.current_email).await {
            eprintln!("Failed to store email locally: {}", e);
            write_response(stream, "451 Local error in processing\r\n").await?;
        } else {
            println!("Email stored successfully locally");
            write_response(stream, "250 OK\r\n").await?;
        }
    }
    Ok(())
}

/// Traite une commande SMTP hors DATA. Retourne true si QUIT (loop must break).
async fn handle_command_line(
    state: &mut SessionState,
    stream: &mut StreamType,
    logic: &Arc<Logic>,
    session_manager: &Arc<SessionManager>,
    line: &str,
    quit_response: Option<&str>,
    log_extracted_body: bool,
) -> std::io::Result<bool> {
    let response = process_command(
        line,
        &mut state.current_email,
        stream,
        logic.clone(),
        session_manager.clone(),
    )
    .await?;
    println!("Response: {}", response);
    if line.trim().to_ascii_uppercase().starts_with("AUTH ") && response.starts_with("235") {
        state.authenticated_session_id = extract_session_id_from_response(&response);
    }
    write_response(stream, &response).await?;

    if line.trim().eq_ignore_ascii_case("DATA") {
        state.in_data_mode = true;
    } else if line.trim().eq_ignore_ascii_case("QUIT") {
        if log_extracted_body {
            if let Ok(content) = extract_email_content(&state.current_email.email.body) {
                println!("Extracted email content: {}", content);
            } else {
                eprintln!("Error extracting email content");
            }
        }
        if let Some(bye) = quit_response {
            write_response(stream, bye).await?;
        }
        return Ok(true);
    }
    Ok(false)
}

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
    write_response(&mut stream, &greeting).await?;

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
                        absorb_data_line(&mut state.current_email, &mut state.in_body, &line);
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
    write_response(&mut stream, &greeting).await?;

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
                        absorb_data_line(&mut state.current_email, &mut state.in_body, &buffer);
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
