/*
SMTP Server Implementation

This file contains the main SMTP server implementation for a custom email handling system.

Key features:
- Supports both plain (SMTP) and TLS (SMTPS) connections
- Implements basic SMTP commands (HELO/EHLO, MAIL FROM, RCPT TO, DATA, QUIT, etc.)
- Handles STARTTLS for upgrading plain connections to TLS
- Supports basic authentication (AUTH LOGIN and AUTH PLAIN)
- Stores received emails in a local directory

Known Issues:
- **DATA command handling**: The server closes the connection unexpectedly after receiving email data.
  This is a known bug and should be fixed in a future update.

Usage:
To run the SMTP server, use the following command from the project root:
    cargo run --bin smtp_server

The server listens on two ports:
1. TLS port (default: 8465) for secure connections
2. Plain port (default: 8025) for non-secure connections and STARTTLS

Environment variables (set in .env file):
- SMTP_TLS_ADDR: Address for TLS connections (default: "0.0.0.0:8465")
- SMTP_PLAIN_ADDR: Address for plain connections (default: "0.0.0.0:8025")
- SMTP_REQUIRE_STARTTLS: Require STARTTLS before AUTH on plain SMTP port (default: true)
- CERT_PATH: Path to SSL certificate file
- KEY_PATH: Path to SSL private key file
- SMTP_USERNAME: Username for SMTP authentication
- SMTP_PASSWORD: Password for SMTP authentication

Note: This server is intended for development and testing purposes.
For production use, additional security measures and optimizations should be implemented.
*/

use dotenv::dotenv;

use base64::{engine::general_purpose, Engine as _};

use std::io::BufReader;
use std::io::{Error as IoError, ErrorKind};

use chrono::Utc;
use log::{debug, error, info, warn};
use rustls::ServerConfig;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_rustls::TlsAcceptor;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use constant_time_eq::constant_time_eq;
use mailparse::parse_mail;
use rustls_pemfile::{certs, private_key};
use std::env;
use std::error::Error;
use std::fmt;
use tokio_rustls::server::TlsStream;

use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::monitoring;
use simple_smtp_server::session::SessionManager;
use simple_smtp_server::smtp_client::{extract_email_address, send_outgoing_email};

// Custom error type for the main function
#[derive(Debug)]
struct MainError(String);

// Implement Display trait for MainError
impl fmt::Display for MainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implement Error trait for MainError
impl Error for MainError {}

// Implement conversion from std::io::Error to MainError
impl From<std::io::Error> for MainError {
    fn from(err: std::io::Error) -> Self {
        MainError(err.to_string())
    }
}

// Enum to represent different types of streams (TLS or Plain)
#[derive(Debug)]
enum StreamType {
    Tls(tokio::io::BufReader<TlsStream<TcpStream>>),
    Plain(tokio::io::BufReader<TcpStream>),
}

// Implement AsyncRead trait for StreamType
impl AsyncRead for StreamType {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamType::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            StreamType::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

// Implement AsyncBufRead trait for StreamType
impl AsyncBufRead for StreamType {
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&[u8]>> {
        match self.get_mut() {
            StreamType::Tls(s) => std::pin::Pin::new(s).poll_fill_buf(cx),
            StreamType::Plain(s) => std::pin::Pin::new(s).poll_fill_buf(cx),
        }
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        match self.get_mut() {
            StreamType::Tls(s) => std::pin::Pin::new(s).consume(amt),
            StreamType::Plain(s) => std::pin::Pin::new(s).consume(amt),
        }
    }
}

impl StreamType {
    fn is_tls(&self) -> bool {
        matches!(self, StreamType::Tls(_))
    }
}

#[path = "smtp_server_dir/recipient.rs"]
mod recipient_helpers;
#[path = "smtp_server_dir/tls.rs"]
mod tls_helpers;
#[path = "smtp_server_dir/auth.rs"]
mod auth_helpers;
use recipient_helpers::{recipient_domain, is_local_recipient, recipient_local_part};
use tls_helpers::{load_certs, load_key};
use auth_helpers::check_credentials;

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(raw) => {
            let v = raw.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
                || (!matches!(v.as_str(), "0" | "false" | "no" | "off") && default)
        }
        Err(_) => default,
    }
}

fn extract_session_id_from_response(response: &str) -> Option<String> {
    let marker = "session ID:";
    let idx = response.find(marker)?;
    let sid = response[idx + marker.len()..]
        .trim()
        .trim_end_matches('\r')
        .trim_end_matches('\n')
        .to_string();
    if sid.is_empty() {
        None
    } else {
        Some(sid)
    }
}

fn parse_header_line(raw_line: &str) -> Option<(String, String)> {
    let (name, value) = raw_line.split_once(':')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.trim().to_string()))
}

fn parse_message_id_header(value: &str) -> Option<String> {
    let value = value
        .trim_matches(|c| c == '<' || c == '>')
        .trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn apply_parsed_header(current_email: &mut CustomEmail, raw_line: &str) {
    if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
        if let Some((last_name, last_value)) = current_email.email.headers.last_mut() {
            let continuation = raw_line.trim();
            if !continuation.is_empty() {
                if !last_value.is_empty() {
                    last_value.push(' ');
                }
                last_value.push_str(continuation);

                if last_name.eq_ignore_ascii_case("DKIM-Signature") {
                    current_email.dkim_signature = Some(last_value.clone());
                } else if last_name.eq_ignore_ascii_case("Subject") {
                    current_email.email.subject = last_value.clone();
                } else if last_name.eq_ignore_ascii_case("Message-ID") {
                    if let Some(mid) = parse_message_id_header(last_value) {
                        current_email.email.id = mid;
                    }
                }
            }
        }
        return;
    }

    if let Some((name, value)) = parse_header_line(raw_line) {
        current_email
            .email
            .headers
            .push((name.clone(), value.clone()));

        if name.eq_ignore_ascii_case("DKIM-Signature") {
            current_email.dkim_signature = Some(value.clone());
        } else if name.eq_ignore_ascii_case("From") {
            let canonical = format!("From: {}", value);
            current_email.email.from =
                extract_email_address(&canonical, "From:").unwrap_or_default();
        } else if name.eq_ignore_ascii_case("To") {
            let canonical = format!("To: {}", value);
            current_email.email.to = extract_email_address(&canonical, "To:").unwrap_or_default();
        } else if name.eq_ignore_ascii_case("Subject") {
            current_email.email.subject = value;
        } else if name.eq_ignore_ascii_case("Message-ID") {
            if let Some(mid) = parse_message_id_header(&value) {
                current_email.email.id = mid;
            }
        }
    }
}

// Struct to represent the mail server
struct MailServer {
    mail_dir: String,
}

impl MailServer {
    // Create a new MailServer instance
    fn new(mail_dir: &str) -> Self {
        fs::create_dir_all(mail_dir).unwrap();
        MailServer {
            mail_dir: mail_dir.to_string(),
        }
    }

    // Store an email in the mail directory
    async fn store_email(&self, email: &CustomEmail) -> std::io::Result<()> {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S");
        let filename = format!("{}-{}.eml", timestamp, email.email.to.replace("@", "_at_"));
        let path = Path::new(&self.mail_dir).join(filename);

        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(format!("From: {}\r\n", email.email.from).as_bytes())
            .await?;
        file.write_all(format!("To: {}\r\n", email.email.to).as_bytes())
            .await?;
        file.write_all(format!("Subject: {}\r\n\r\n", email.email.subject).as_bytes())
            .await?;
        file.write_all(email.email.body.as_bytes()).await?;

        Ok(())
    }
}

// Handle TLS client connection
async fn handle_tls_client(
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
async fn handle_plain_client(
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

// Réponse EHLO/HELO — construit la liste de capabilities selon l'état TLS.
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
async fn process_command(
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
async fn write_response(stream: &mut StreamType, response: &str) -> std::io::Result<()> {
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

// Load SSL certificates
// (moved to tls_helpers.rs)

// Main function
#[tokio::main]
async fn main() -> Result<(), MainError> {
    // Load environment variables from .env file
    dotenv().ok();

    // rustls 0.23 requires an explicit process-level CryptoProvider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Initialize logger
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Get server addresses from environment variables or use defaults
    let tls_addr = env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string());
    let plain_addr = env::var("SMTP_PLAIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8025".to_string());

    // Get SSL certificate and key paths
    let cert_path: PathBuf =
        PathBuf::from(env::var("CERT_PATH").unwrap_or_else(|_| "localhost.crt".to_string()));
    let key_path: PathBuf =
        PathBuf::from(env::var("KEY_PATH").unwrap_or_else(|_| "localhost.key".to_string()));

    // Load SSL certificates and key
    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;

    // Create TLS configuration
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    config.alpn_protocols = vec![b"smtp".to_vec()];

    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(config)));

    // Bind TCP listeners for TLS and plain connections
    let tls_listener = TcpListener::bind(tls_addr.clone()).await?;
    let plain_listener = TcpListener::bind(plain_addr.clone()).await?;

    // Log server start information
    info!("TLS Server listening on {}", tls_addr);
    info!("Plain Server listening on {}", plain_addr);

    // MongoDB is optional (filesystem storage is the default for staging).
    // Client creation is lazy; a dummy URI is enough when USE_MONGODB=false.
    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";
    let client_uri = if use_mongodb {
        let cluster_url = env::var("MONGODB_CLUSTER_URL").expect("MONGODB_CLUSTER_URL must be set");
        let mongodb_username = env::var("MONGODB_USERNAME").expect("MONGODB_USERNAME must be set");
        let mongodb_password = env::var("MONGODB_PASSWORD").expect("MONGODB_PASSWORD must be set");
        let mongodb_app_name =
            env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());
        if cluster_url.starts_with("mongodb://") || cluster_url.starts_with("mongodb+srv://") {
            // Full URI from 1Password — use directly
            let base = cluster_url.trim_end_matches('&').trim_end_matches('?');
            let sep = if base.contains('?') { "&" } else { "?" };
            format!("{}{}appName={}&serverSelectionTimeoutMS=5000", base, sep, mongodb_app_name)
        } else if cluster_url.contains(".mongodb.net") {
            format!(
                "mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000",
                mongodb_username, mongodb_password, cluster_url, mongodb_app_name
            )
        } else {
            format!(
                "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
                mongodb_username, mongodb_password, cluster_url, mongodb_app_name
            )
        }
    } else {
        info!("USE_MONGODB=false — using local filesystem email storage");
        "mongodb://127.0.0.1:27017".to_string()
    };

    let client = Arc::new(mongodb::Client::with_uri_str(&client_uri).await.unwrap());
    // Warm-up: force DNS resolution + TLS + MongoDB handshake at startup
    // so the first user authentication is not delayed by 10-30s.
    if use_mongodb {
        if let Err(e) = client
            .database("admin")
            .run_command(mongodb::bson::doc! {"ping": 1})
            .await
        {
            warn!("MongoDB warm-up ping failed (non-fatal): {}", e);
        } else {
            info!("MongoDB connection ready.");
        }
    }
    let logic = Arc::new(Logic::new(client.clone()));
    let session_manager = Arc::new(SessionManager::new());

    if monitoring::monitoring_enabled() {
        monitoring::init_bus();
        monitoring::storage::start_persistence_task(client.clone());
        let monitor_idx_client = client.clone();
        tokio::spawn(async move {
            monitoring::storage::ensure_indexes(&monitor_idx_client).await;
        });
        info!("SMTP monitoring bus initialized in smtp_server");
    }

    loop {
        tokio::select! {
            // Handle incoming TLS connections
            result = tls_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New TLS client connected from {}", peer_addr);
                    let acceptor = tls_acceptor.clone();
                    let logic_clone = logic.clone(); // Clone the Arc before moving into the closure
                    let session_manager_clone = session_manager.clone(); // Clone the Arc before moving into the closure
                    tokio::spawn(async move {
                        let tls_stream = acceptor.accept(stream).await.unwrap();
                        if let Err(e) = handle_tls_client(tls_stream, logic_clone, session_manager_clone).await {
                            error!("Error handling plain client {}: {}", peer_addr, e);
                        } else {
                            info!("Plain client session completed successfully");
                        }
                    });
                }
            }

            // Handle incoming plain connections
            result = plain_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New plain client connected from {}", peer_addr);
                    let acceptor = tls_acceptor.clone();
                    let logic_clone = logic.clone(); // Clone the Arc before moving into the closure
                    let session_manager_clone = session_manager.clone(); // Clone the Arc before moving into the closure
                    tokio::spawn(async move {
                        if let Err(e) = handle_plain_client(stream, acceptor, logic_clone, session_manager_clone).await {
                            error!("Error handling plain client {}: {}", peer_addr, e);
                        } else {
                            info!("Plain client session completed successfully");
                        }
                    });
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(())
}

struct CustomEmail {
    email: Email,
    raw_content: String,
    dkim_signature: Option<String>,
}

// Function to extract email content
fn extract_email_content(email_content: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = parse_mail(email_content.as_bytes())?;

    // Try to get the plain text part first
    if let Some(plain_text) = parsed
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/plain")
    {
        return Ok(plain_text.get_body()?.trim().to_string());
    }

    // If no plain text, try to get the HTML part and strip HTML tags
    if let Some(html) = parsed
        .subparts
        .iter()
        .find(|part| part.ctype.mimetype == "text/html")
    {
        let html_content = html.get_body()?;
        // This is a very basic HTML stripping, you might want to use a proper HTML parser
        return Ok(html_content
            .replace(|c: char| c == '<' || c == '>', "")
            .trim()
            .to_string());
    }

    // If no multipart, just return the body
    Ok(parsed.get_body()?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_email_content_plain_text() {
        let email_content = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a plain text email.";
        let result = extract_email_content(email_content).unwrap();
        assert_eq!(result, "This is a plain text email.");
    }

    #[test]
    fn test_extract_email_content_html() {
        let email_content = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body>This is an <b>HTML</b> email.</body></html>";
        let result = extract_email_content(email_content).unwrap();
        assert_eq!(
            result,
            "<html><body>This is an <b>HTML</b> email.</body></html>"
        );
    }

    #[test]
    fn test_extract_email_content_no_body() {
        let email_content =
            "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n";
        let result = extract_email_content(email_content).unwrap();
        assert_eq!(result, "");
    }
}
