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
};

// Handle TLS client connection
pub(crate) async fn handle_tls_client(
    tls_stream: TlsStream<TcpStream>,
    logic: Arc<Logic>,
    session_manager: Arc<SessionManager>,
) -> std::io::Result<()> {
    info!("TLS connection established");
    let peer_addr = tls_stream.get_ref().0.peer_addr()?;

    let mut stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));

    // Send initial greeting
    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    write_response(&mut stream, &greeting).await?;

    let mut in_data_mode: bool = false;
    let mut in_body = false; // Indicateur pour savoir si nous sommes dans le corps de l'email
    let mut authenticated_session_id: Option<String> = None;

    let mut current_email = CustomEmail {
        email: Email::new("", "", "", "", ""),
        raw_content: String::new(),
        dkim_signature: None,
    };

    let mail_server = Arc::new(MailServer::new("./emails"));
    loop {
        let mut buffer = Vec::new();
        match stream.read_until(b'\n', &mut buffer).await {
            Ok(0) => {
                println!("TLS Client disconnected");
                break;
            }
            Ok(_) => {
                // Convertir en String, en ignorant les caractères non-UTF8
                let line = String::from_utf8_lossy(&buffer);
                println!("Received: {}", line.trim());

                if line.trim().eq_ignore_ascii_case("STARTTLS") {
                    write_response(
                        &mut stream,
                        "454 TLS not available due to temporary reason\r\n",
                    )
                    .await?;
                    continue;
                }
                if in_data_mode {
                    if line.trim() == "." {
                        in_data_mode = false;
                        // Convert to logic's Email struct
                        let email_to_store = Email {
                            id: current_email.email.id.clone(),
                            from: current_email.email.from.clone(),
                            to: current_email.email.to.clone(),
                            subject: current_email.email.subject.clone(),
                            body: current_email.email.body.clone(),
                            headers: current_email.email.headers.clone(),
                            flags: current_email.email.flags.clone(),
                            sequence_number: current_email.email.sequence_number,
                            uid: current_email.email.uid,
                            internal_date: current_email.email.internal_date,
                            dkim_signature: current_email.dkim_signature.clone(),
                        };
                        // Check storage preference
                        let use_mongodb = env::var("USE_MONGODB")
                            .unwrap_or_else(|_| "false".to_string())
                            == "true";

                        if use_mongodb {
                            // Store the email in MongoDB
                            let resolved_route = if let Some(session_id) = authenticated_session_id.as_ref() {
                                let username = session_manager.get_username(session_id);
                                let mailbox = session_manager.get_mailbox(session_id);
                                username.zip(mailbox)
                            } else {
                                recipient_local_part(&email_to_store.to)
                                    .map(|user| (user, "inbox".to_string()))
                            };

                            if let Some((user, mbox)) = resolved_route {
                                if let Err(e) = logic.store_email(&user, &mbox, &email_to_store).await {
                                    eprintln!("Failed to store email in MongoDB: {}", e);
                                    write_response(&mut stream, "554 Transaction failed\r\n")
                                        .await?;
                                } else {
                                    println!("Email stored successfully in MongoDB for {user}/{mbox}");
                                    let _ = logic
                                        .log_mail_event(
                                            "received",
                                            &user,
                                            &email_to_store.id,
                                            &email_to_store.subject,
                                            &email_to_store.from,
                                            &email_to_store.to,
                                        )
                                        .await;
                                    if is_local_recipient(&email_to_store.to) {
                                        write_response(&mut stream, "250 OK\r\n").await?;
                                    } else {
                                        match send_outgoing_email(&email_to_store).await {
                                            Ok(_) => {
                                                write_response(&mut stream, "250 OK\r\n").await?;
                                            }
                                            Err(e) => {
                                                error!("Failed to forward authenticated email: {}", e);
                                                write_response(
                                                    &mut stream,
                                                    "451 4.4.0 Temporary forwarding failure\r\n",
                                                )
                                                .await?;
                                            }
                                        }
                                    }
                                }
                            } else {
                                eprintln!(
                                    "No routeable mailbox for recipient {}; refusing",
                                    email_to_store.to
                                );
                                write_response(&mut stream, "550 5.1.1 User unknown\r\n").await?;
                            }
                        } else {
                            // Store locally
                            if let Err(e) = mail_server.store_email(&current_email).await {
                                eprintln!("Failed to store email locally: {}", e);
                                write_response(&mut stream, "451 Local error in processing\r\n")
                                    .await?;
                            } else {
                                println!("Email stored successfully locally");
                                write_response(&mut stream, "250 OK\r\n").await?;
                            }
                        }
                    } else {
                        if !in_body {
                            if line.trim().is_empty() {
                                in_body = true; // Ligne vide détectée, commencez à capturer le corps
                            } else {
                                // Traitez les en-têtes
                                let trimmed_line = line.trim_end_matches(|c| c == '\r' || c == '\n');
                                if !trimmed_line.is_empty() {
                                    apply_parsed_header(&mut current_email, trimmed_line);
                                }
                            }
                        } else {
                            // Ajoutez la ligne au corps de l'email
                            current_email.email.body.push_str(&line);
                        }
                    }
                } else {
                    let response = process_command(
                        &line,
                        &mut current_email,
                        &mut stream,
                        logic.clone(),
                        session_manager.clone(),
                    )
                    .await?;
                    println!("Response: {}", response);
                    if line.trim().to_ascii_uppercase().starts_with("AUTH ") && response.starts_with("235") {
                        authenticated_session_id = extract_session_id_from_response(&response);
                    }
                    write_response(&mut stream, &response).await?;

                    if line.trim().eq_ignore_ascii_case("DATA") {
                        in_data_mode = true;
                    } else if line.trim().eq_ignore_ascii_case("QUIT") {
                        if let Ok(content) = extract_email_content(&current_email.email.body) {
                            println!("Extracted email content: {}", content);
                        } else {
                            eprintln!("Error extracting email content");
                        }
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

    // Send initial greeting
    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    info!("Sending greeting to {}: {}", peer_addr, greeting.trim());
    write_response(&mut stream, &greeting).await?;

    let mut in_data_mode = false;
    let mut in_body = false; // Indicateur pour savoir si nous sommes dans le corps de l'email
    let mut authenticated_session_id: Option<String> = None;

    let mut current_email = CustomEmail {
        email: Email::new("", "", "", "", ""),
        raw_content: String::new(),
        dkim_signature: None,
    };

    let mail_server = Arc::new(MailServer::new("./emails"));

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
                    // Upgrade to TLS
                    match stream {
                        StreamType::Plain(plain_stream) => {
                            let tls_stream = tls_acceptor.accept(plain_stream.into_inner()).await?;
                            stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));
                            println!("Upgraded to TLS connection");
                        }
                        StreamType::Tls(_) => {
                            // Already TLS, shouldn't happen but handle it anyway
                            write_response(
                                &mut stream,
                                "454 TLS not available due to temporary reason\r\n",
                            )
                            .await?;
                        }
                    }
                    continue;
                }
                if in_data_mode {
                    println!("In in_data_mode");
                    if buffer.trim() == "." {
                        in_data_mode = false;
                        let use_mongodb = env::var("USE_MONGODB")
                            .unwrap_or_else(|_| "false".to_string())
                            == "true";
                        if use_mongodb {
                            // Store in MongoDB
                            let resolved_route = if let Some(session_id) = authenticated_session_id.as_ref() {
                                let username = session_manager.get_username(session_id);
                                let mailbox = session_manager.get_mailbox(session_id);
                                username.zip(mailbox)
                            } else {
                                recipient_local_part(&current_email.email.to)
                                    .map(|user| (user, "inbox".to_string()))
                            };

                            if let Some((user, mbox)) = resolved_route {
                                let email_to_store = Email {
                                    id: current_email.email.id.clone(),
                                    from: current_email.email.from.clone(),
                                    to: current_email.email.to.clone(),
                                    subject: current_email.email.subject.clone(),
                                    body: current_email.email.body.clone(),
                                    headers: current_email.email.headers.clone(),
                                    flags: current_email.email.flags.clone(),
                                    sequence_number: current_email.email.sequence_number,
                                    uid: current_email.email.uid,
                                    internal_date: current_email.email.internal_date,
                                    dkim_signature: current_email.dkim_signature.clone(),
                                };
                                if let Err(e) = logic.store_email(&user, &mbox, &email_to_store).await {
                                    eprintln!("Failed to store email in MongoDB: {}", e);
                                    write_response(&mut stream, "554 Transaction failed\r\n")
                                        .await?;
                                } else {
                                    println!("Email stored successfully in MongoDB for {user}/{mbox}");
                                    let _ = logic
                                        .log_mail_event(
                                            "received",
                                            &user,
                                            &email_to_store.id,
                                            &email_to_store.subject,
                                            &email_to_store.from,
                                            &email_to_store.to,
                                        )
                                        .await;
                                    if is_local_recipient(&email_to_store.to) {
                                        write_response(&mut stream, "250 OK\r\n").await?;
                                    } else {
                                        match send_outgoing_email(&email_to_store).await {
                                            Ok(_) => {
                                                write_response(&mut stream, "250 OK\r\n").await?;
                                            }
                                            Err(e) => {
                                                error!("Failed to forward authenticated email: {}", e);
                                                write_response(
                                                    &mut stream,
                                                    "451 4.4.0 Temporary forwarding failure\r\n",
                                                )
                                                .await?;
                                            }
                                        }
                                    }
                                }
                            } else {
                                eprintln!(
                                    "No routeable mailbox for recipient {}; refusing",
                                    current_email.email.to
                                );
                                write_response(&mut stream, "550 5.1.1 User unknown\r\n").await?;
                            }
                        } else {
                            // Store locally + attempt forward
                            mail_server.store_email(&current_email).await?;
                            match send_outgoing_email(&current_email.email).await {
                                Ok(_) => {
                                    write_response(&mut stream, "250 OK\r\n").await?;
                                }
                                Err(e) => {
                                    error!("Failed to forward email: {}", e);
                                    write_response(
                                        &mut stream,
                                        "451 4.4.0 Temporary forwarding failure\r\n",
                                    )
                                    .await?;
                                }
                            }
                        }
                    } else {
                        if !in_body {
                            if buffer.trim().is_empty() {
                                in_body = true; // Ligne vide détectée, commencez à capturer le corps
                            } else {
                                // Traitez les en-têtes
                                let trimmed_buffer = buffer.trim_end_matches(|c| c == '\r' || c == '\n');
                                if !trimmed_buffer.is_empty() {
                                    apply_parsed_header(&mut current_email, trimmed_buffer);
                                }
                            }
                        } else {
                            // Ajoutez la ligne au corps de l'email
                            current_email.email.body.push_str(&buffer);
                        }
                    }
                } else {
                    let response = process_command(
                        &buffer,
                        &mut current_email,
                        &mut stream,
                        logic.clone(),
                        session_manager.clone(),
                    )
                    .await?;
                    println!("Response: {}", response);
                    if buffer.trim().to_ascii_uppercase().starts_with("AUTH ")
                        && response.starts_with("235")
                    {
                        authenticated_session_id = extract_session_id_from_response(&response);
                    }
                    write_response(&mut stream, &response).await?;

                    if buffer.trim().eq_ignore_ascii_case("DATA") {
                        in_data_mode = true;
                    } else if buffer.trim().eq_ignore_ascii_case("QUIT") {
                        write_response(&mut stream, "221 Bye\r\n").await?;
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

