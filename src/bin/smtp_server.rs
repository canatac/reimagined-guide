/*
SMTP Server Implementation

This file contains the main SMTP server implementation for a custom email handling system.

Key features:
- Supports both plain (SMTP) and TLS (SMTPS) connections
- Implements basic SMTP commands (HELO/EHLO, MAIL FROM, RCPT TO, DATA, QUIT, etc.)
- Handles STARTTLS for upgrading plain connections to TLS
- Supports basic authentication (AUTH LOGIN and AUTH PLAIN)
- Stores received emails in a local directory

Usage:
To run the SMTP server, use the following command from the project root:
    cargo run --bin smtp_server

The server listens on two ports:
1. TLS port (default: 8465) for secure connections
2. Plain port (default: 8025) for non-secure connections and STARTTLS

Environment variables (set in .env file):
- SMTP_TLS_ADDR: Address for TLS connections (default: "0.0.0.0:8465")
- SMTP_PLAIN_ADDR: Address for plain connections (default: "0.0.0.0:8025")
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

use std::sync::Arc;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use chrono::Utc;
use log::{info, error, debug};
use rustls::ServerConfig;

use tokio_rustls::TlsAcceptor;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncBufRead, AsyncRead}; 
use tokio::net::{TcpStream,TcpListener};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use tokio_rustls::server::TlsStream;
use rustls_pemfile::{certs, private_key};
use std::env;
use mailparse::parse_mail;
use std::error::Error;
use std::fmt;
use constant_time_eq::constant_time_eq;

use simple_smtp_server::send_outgoing_email;
use simple_smtp_server::extract_email_address;

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
    fn poll_fill_buf(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<&[u8]>> {
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

// Struct to represent an email
#[derive(Clone)]
struct Email {
    from: String,
    to: String,
    subject: String,
    body: String,
    dkim_signature: Option<String>,
    headers: Vec<String>,
    raw_content: String,
}

// Function to extract email content
fn extract_email_content(email_content: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parsed = parse_mail(email_content.as_bytes())?;
    
    // Try to get the plain text part first
    if let Some(plain_text) = parsed.subparts.iter().find(|part| part.ctype.mimetype == "text/plain") {
        return Ok(plain_text.get_body()?.trim().to_string());
    }
    
    // If no plain text, try to get the HTML part and strip HTML tags
    if let Some(html) = parsed.subparts.iter().find(|part| part.ctype.mimetype == "text/html") {
        let html_content = html.get_body()?;
        // This is a very basic HTML stripping, you might want to use a proper HTML parser
        return Ok(html_content.replace(|c: char| c == '<' || c == '>', "").trim().to_string());
    }
    
    // If no multipart, just return the body
    Ok(parsed.get_body()?.trim().to_string())
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
    async fn store_email(&self, email: &Email) -> std::io::Result<()> {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S");
        let filename = format!("{}-{}.eml", timestamp, email.to.replace("@", "_at_"));
        let path = Path::new(&self.mail_dir).join(filename);
        
        let mut file = tokio::fs::File::create(path).await?;
        file.write_all(format!("From: {}\r\n", email.from).as_bytes()).await?;
        file.write_all(format!("To: {}\r\n", email.to).as_bytes()).await?;
        file.write_all(format!("Subject: {}\r\n\r\n", email.subject).as_bytes()).await?;
        file.write_all(email.body.as_bytes()).await?;
        
        Ok(())
    }

    async fn forward_email(&self, email: &Email) -> std::io::Result<()> {
        let mut email_content = String::new();

        // Add DKIM-Signature if present
        if let Some(dkim_sig) = &email.dkim_signature {
            email_content.push_str(dkim_sig);
            email_content.push_str("\r\n");
        }

        // Add other headers
        for header in &email.headers {
            if !header.starts_with("DKIM-Signature:") &&
               !header.starts_with("From:") &&
               !header.starts_with("To:") &&
               !header.starts_with("Subject:") {
                email_content.push_str(header);
                email_content.push_str("\r\n");
            }
        }
        // Add From, To, and Subject headers
        email_content.push_str(&format!("From: {}\r\n", email.from.trim()));
        email_content.push_str(&format!("To: {}\r\n", email.to.trim()));
        email_content.push_str(&format!("Subject: {}\r\n", email.subject.trim()));

        // Add an empty line to separate headers from body
        email_content.push_str("\r\n");

        // Add the email body
        email_content.push_str(&email.body);

        println!("Forwarding email: {}", email_content);
        send_outgoing_email(&email_content).await

    }
}

// Handle TLS client connection
async fn handle_tls_client(tls_stream: TlsStream<TcpStream>) -> std::io::Result<()> {
    info!("TLS connection established");

    let mut stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));

    // Send initial greeting
    let greeting = "220 SMTPS Server Ready\r\n";
    write_response(&mut stream, &greeting).await?;

    let mut in_data_mode: bool = false;

    let mut current_email = Email {
        from: String::new(),
        to: String::new(),
        subject: String::new(),
        body: String::new(),
        dkim_signature: None,
        headers: Vec::new(),
        raw_content: String::new()
    };

    let mail_server = Arc::new(MailServer::new("./emails"));
    loop {
        let mut buffer = String::new();
        match stream.read_line(&mut buffer).await {
            Ok(0) => {
                println!("TLS Client disconnected  : {}", buffer.trim());
                break;
            }
            Ok(_n) => {                
                println!("Calling process_command with: {}", buffer.trim());
                if buffer.trim().eq_ignore_ascii_case("STARTTLS") {
                    // Client requested STARTTLS on an already-TLS connection
                    write_response(&mut stream, "454 TLS not available due to temporary reason\r\n").await?;
                    continue;
                }
                if in_data_mode {
                    if buffer.trim() == "." {
                        in_data_mode = false;
                        mail_server.store_email(&current_email).await?;
                        match send_outgoing_email(&current_email.raw_content).await {
                            Ok(_) => {
                                write_response(&mut stream, "250 OK\r\n").await?;
                            }
                            Err(e) => {
                                error!("Failed to forward email: {}", e);
                                write_response(&mut stream, "554 Transaction failed\r\n").await?;
                            }
                        }
                        /*
                        match mail_server.forward_email(&current_email).await {
                            Ok(_) => {
                                write_response(&mut stream, "250 OK\r\n").await?;
                            }
                            Err(e) => {
                                error!("Failed to forward email: {}", e);
                                write_response(&mut stream, "554 Transaction failed\r\n").await?;
                            }
                        } */                       
                    } else {
                        // Collect the stream content without alteration
                        if current_email.raw_content.is_empty() {
                            current_email.raw_content = buffer;
                            let trimmed_buffer = current_email.raw_content.trim();
                            if !trimmed_buffer.is_empty() {
                                let line = trimmed_buffer.to_string();
                                current_email.headers.push(line.clone());
                                if trimmed_buffer.starts_with("DKIM-Signature:") {
                                    current_email.dkim_signature = Some(line);
                                } else if trimmed_buffer.starts_with("From:") {
                                    current_email.from = extract_email_address(trimmed_buffer, "From:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("To:") {
                                    current_email.to = extract_email_address(trimmed_buffer, "To:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("Subject:") {
                                    current_email.subject = trimmed_buffer.trim_start_matches("Subject:").trim().to_string();
                                }
                            }
                        } else {
                            let trimmed_buffer = buffer.trim();
                            if !trimmed_buffer.is_empty() {
                                let line = trimmed_buffer.to_string();
                                current_email.headers.push(line.clone());
                                if trimmed_buffer.starts_with("DKIM-Signature:") {
                                    current_email.dkim_signature = Some(line);
                                } else if trimmed_buffer.starts_with("From:") {
                                    current_email.from = extract_email_address(trimmed_buffer, "From:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("To:") {
                                    current_email.to = extract_email_address(trimmed_buffer, "To:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("Subject:") {
                                    current_email.subject = trimmed_buffer.trim_start_matches("Subject:").trim().to_string();
                                }
                            }
                            current_email.raw_content.push_str(&buffer);
                        }
                    }
                } else {
                    let response = process_command(&buffer, &mut current_email, &mut stream).await?;
                    println!("Response: {}", response);
                    write_response(&mut stream, &response).await?;

                    if buffer.trim() == "DATA" {
                        in_data_mode = true;
                    } else if buffer.trim() == "QUIT" {
                        if let Ok(content) = extract_email_content(&current_email.body) {
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
async fn handle_plain_client(stream: TcpStream, tls_acceptor: Arc<TlsAcceptor>) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("New plain connection from: {}", peer_addr);
    let mut stream = StreamType::Plain(tokio::io::BufReader::new(stream));
    
    // Send initial greeting
    let greeting = "220 mail.misfits.ai ESMTP\r\n";
    info!("Sending greeting to {}: {}", peer_addr, greeting.trim());
    write_response(&mut stream, &greeting).await?;

    let mut in_data_mode = false;

    let mut current_email = Email {
        from: String::new(),
        to: String::new(),
        subject: String::new(),
        body: String::new(),
        headers: Vec::new(),
        dkim_signature: None,
        raw_content: String::new()
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
                            write_response(&mut stream, "454 TLS not available due to temporary reason\r\n").await?;
                        }
                    }
                    continue;
                }
                if in_data_mode {
                    if buffer.trim() == "." {
                        in_data_mode = false;
                        mail_server.store_email(&current_email).await?;
                        match send_outgoing_email(&current_email.raw_content).await {
                            Ok(_) => {
                                write_response(&mut stream, "250 OK\r\n").await?;
                            }
                            Err(e) => {
                                error!("Failed to forward email: {}", e);
                                write_response(&mut stream, "554 Transaction failed\r\n").await?;
                            }
                        }
                        /*
                        match mail_server.forward_email(&current_email).await {
                            Ok(_) => {
                                write_response(&mut stream, "250 OK\r\n").await?;
                            }
                            Err(e) => {
                                error!("Failed to forward email: {}", e);
                                write_response(&mut stream, "554 Transaction failed\r\n").await?;
                            }
                        }
                         */
                        
                    } else {
                        if current_email.raw_content.is_empty() {
                            current_email.raw_content = buffer;
                            let trimmed_buffer = current_email.raw_content.trim();
                            if !trimmed_buffer.is_empty() {
                                let line = trimmed_buffer.to_string();
                                current_email.headers.push(line.clone());
                                if trimmed_buffer.starts_with("DKIM-Signature:") {
                                    current_email.dkim_signature = Some(line);
                                } else if trimmed_buffer.starts_with("From:") {
                                    current_email.from = extract_email_address(trimmed_buffer, "From:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("To:") {
                                    current_email.to = extract_email_address(trimmed_buffer, "To:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("Subject:") {
                                    current_email.subject = trimmed_buffer.trim_start_matches("Subject:").trim().to_string();
                                }
                            }
                        } else {
                            let trimmed_buffer = buffer.trim();
                            if !trimmed_buffer.is_empty() {
                                let line = trimmed_buffer.to_string();
                                current_email.headers.push(line.clone());
                                if trimmed_buffer.starts_with("DKIM-Signature:") {
                                    current_email.dkim_signature = Some(line);
                                } else if trimmed_buffer.starts_with("From:") {
                                    current_email.from = extract_email_address(trimmed_buffer, "From:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("To:") {
                                    current_email.to = extract_email_address(trimmed_buffer, "To:").unwrap_or_default();
                                } else if trimmed_buffer.starts_with("Subject:") {
                                    current_email.subject = trimmed_buffer.trim_start_matches("Subject:").trim().to_string();
                                }
                            }
                            current_email.raw_content.push_str(&buffer);
                        }
                    }
                } else {
                    let response = process_command(&buffer, &mut current_email, &mut stream).await?;
                    println!("Response: {}", response);
                    write_response(&mut stream, &response).await?;
                    
                    if buffer.trim() == "DATA" {
                        in_data_mode = true;
                    } else if buffer.trim() == "QUIT" {
                    
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

// Process SMTP commands
async fn process_command(command: &str, email: &mut Email, stream: &mut StreamType) -> std::io::Result<String> {
    // Implement your SMTP command processing logic here
    // This is a basic example and should be expanded based on your needs

    println!("In process_command with: {}", command.trim().to_uppercase().as_str());

    match command.trim().to_uppercase().as_str() {
        s if s.starts_with("HELO") || s.starts_with("EHLO") => {
            Ok("250-mail.misfits.ai Hello\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n".to_string())
        } 
        s if s.starts_with("AUTH LOGIN") => {
            handle_auth_login(stream).await
        } 
        s if s.starts_with("AUTH PLAIN") => {
            handle_auth_plain(command).await
        } 
        s if s.starts_with("MAIL FROM:") => {
            email.from = s.trim_start_matches("MAIL FROM:").trim().to_string();
            Ok("250 OK\r\n".to_string())
        } 
        s if s.starts_with("RCPT TO:") => {
            email.to = s.trim_start_matches("RCPT TO:").trim().to_string();
            Ok("250 OK\r\n".to_string())
        } 
        s if s.starts_with("SUBJECT:") => {
            email.subject = s[8..].trim().to_string();
            Ok("250 OK\r\n".to_string())
        } 
        "DATA" => {
            Ok("354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string())
        } 
        "." => {
            Ok("250 OK\r\n".to_string())
        } 
        "QUIT" => {
            if !email.from.is_empty() && !email.to.is_empty() {
                match extract_email_content(&email.body) {
                    Ok(content) => {
                        println!("Extracted email content: {}", content);
                    },
                    Err(e) => eprintln!("Error extracting email content: {}", e),
                }
            }
            Ok("221 Bye\r\n".to_string())
        } 
        "RSET" => {
            *email = Email {
                from: String::new(),
                to: String::new(),
                subject: String::new(),
                body: String::new(),
                headers: Vec::new(),
                dkim_signature: None,
                raw_content: String::new()
            };
             // Reset the email using new() instead of default()
            Ok("250 OK\r\n".to_string())
        } 
        "NOOP" => {
            Ok("250 OK\r\n".to_string())
        } 
        s if s.starts_with("VRFY") => {
            // In a real implementation, you'd verify the email address here
            Ok("252 Cannot VRFY user, but will accept message and attempt delivery\r\n".to_string())
        } 
        s if s.starts_with("AUTH") => {
            // In a real implementation, you'd handle authentication here
            Ok("235 Authentication successful\r\n".to_string())
        } 
        s if s.starts_with("STARTTLS") => {
            match stream {
                StreamType::Plain(_) => Ok("220 Ready to start TLS\r\n".to_string()),
                StreamType::Tls(_) => Ok("454 TLS not available due to temporary reason\r\n".to_string()),
            }
        } 
        _ => {
            Ok("500 Syntax error, command unrecognized\r\n".to_string())
        }
    }    
    
}

// Handle AUTH LOGIN command
async fn handle_auth_login(stream: &mut StreamType) -> std::io::Result<String> {
    write_response(stream, "334 VXNlcm5hbWU6\r\n").await?; // Base64 for "Username:"
    let mut username = String::new();
    stream.read_line(&mut username).await?;
    let username = username.trim_end().as_bytes().to_vec();
    debug!("Received username: {}", String::from_utf8_lossy(&username));

    write_response(stream, "334 UGFzc3dvcmQ6\r\n").await?; // Base64 for "Password:"
    let mut password = String::new();
    stream.read_line(&mut password).await?;
    let password = password.trim_end().as_bytes().to_vec();
    debug!("Received password: {}", String::from_utf8_lossy(&password));

    if check_credentials(&username, &password) {
        Ok("235 Authentication successful\r\n".to_string())
    } else {
        Ok("535 Authentication failed\r\n".to_string())
    }
}

// Handle AUTH PLAIN command
async fn handle_auth_plain(command: &str) -> std::io::Result<String> {
    let auth_data = command.split_whitespace().nth(2).unwrap_or("");
    let decoded = general_purpose::STANDARD.decode(auth_data).unwrap();
    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
    
    if parts.len() != 3 {
        return Ok("501 Malformed AUTH PLAIN\r\n".to_string());
    }

    let username = parts[1];
    let password = parts[2];

    if check_credentials(username, password) {
        Ok("235 Authentication successful\r\n".to_string())
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
fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

// Load SSL private key
fn load_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    Ok(private_key(&mut BufReader::new(File::open(path)?))
        .unwrap()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no private key found".to_string(),
        ))?)
}

// Check user credentials
fn check_credentials(username: &[u8], password: &[u8]) -> bool {
    // Implement your authentication logic here
    // For example:
    let expected_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let expected_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    
    let username_match = constant_time_eq(username, expected_username.as_bytes());
    let password_match = constant_time_eq(password, expected_password.as_bytes());

    debug!("Username match: {}", username_match);
    debug!("Password match: {}", password_match);

    username_match && password_match
}

// Main function
#[tokio::main]
async fn main() -> Result<(), MainError> {
    // Load environment variables from .env file
    dotenv().ok();

    // Initialize logger
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // Get server addresses from environment variables or use defaults
    let tls_addr = env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string());
    let plain_addr = env::var("SMTP_PLAIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8025".to_string());

    // Get SSL certificate and key paths
    let cert_path: PathBuf = PathBuf::from(env::var("CERT_PATH").unwrap_or_else(|_| "localhost.crt".to_string()));
    let key_path: PathBuf = PathBuf::from(env::var("KEY_PATH").unwrap_or_else(|_| "localhost.key".to_string()));

    // Load SSL certificates and key
    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;

    // Create TLS configuration
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| IoError::new(ErrorKind::InvalidInput, err))?;
    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(config)));

    // Bind TCP listeners for TLS and plain connections
    let tls_listener = TcpListener::bind(tls_addr.clone()).await?;
    let plain_listener = TcpListener::bind(plain_addr.clone()).await?;
    
    // Log server start information
    info!("TLS Server listening on {}", tls_addr);
    info!("Plain Server listening on {}", plain_addr);

    info!("Testing TLS configuration...");
    tokio::spawn(async move {
        match tokio::net::TcpStream::connect(tls_addr.clone()).await {
            Ok(_) => info!("Successfully connected to TLS port"),
            Err(e) => error!("Failed to connect to TLS port: {}", e),
        }
    });

    loop {

        tokio::select! {
            // Handle incoming TLS connections
            result = tls_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New TLS client connected from {}", peer_addr);
                    let acceptor = tls_acceptor.clone();
                    let tls_stream = acceptor.accept(stream).await?;
                    tokio::spawn(async move {
                        if let Err(e) = handle_tls_client(tls_stream).await {
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
                    tokio::spawn(async move {
                        if let Err(e) = handle_plain_client(stream, acceptor).await {
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

    }
