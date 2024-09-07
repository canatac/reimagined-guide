use dotenv::dotenv;

use base64::{engine::general_purpose, Engine as _};

use std::io::{BufReader, Write};
use std::sync::Arc;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use chrono::Utc;
use log::{info, error};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncBufRead, AsyncRead, AsyncReadExt}; 
use tokio::net::{TcpStream,TcpListener};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;
use rustls_pemfile::{certs, private_key};
use std::env;
use mailparse::parse_mail;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct MainError(String);

impl fmt::Display for MainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for MainError {}

impl From<std::io::Error> for MainError {
    fn from(err: std::io::Error) -> Self {
        MainError(err.to_string())
    }
}


#[derive(Debug)]
enum StreamType {
    Tls(tokio::io::BufReader<TlsStream<TcpStream>>),
    Plain(tokio::io::BufReader<TcpStream>),
}
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
#[derive(Clone)]
struct Email {
    from: String,
    to: String,
    subject: String,
    body: String,
    headers: Vec<(String, String)>,
}

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
struct MailServer {
    mail_dir: String,
}

impl MailServer {
    fn new(mail_dir: &str) -> Self {
        fs::create_dir_all(mail_dir).unwrap();
        MailServer {
            mail_dir: mail_dir.to_string(),
        }
    }

    fn store_email(&self, email: &Email) -> std::io::Result<()> {
        let timestamp = Utc::now().format("%Y%m%d%H%M%S");
        let filename = format!("{}-{}.eml", timestamp, email.to.replace("@", "_at_"));
        let path = Path::new(&self.mail_dir).join(filename);
        
        let mut file = File::create(path)?;
        writeln!(file, "From: {}", email.from)?;
        writeln!(file, "To: {}", email.to)?;
        writeln!(file, "Subject: {}", email.subject)?;
        writeln!(file)?;
        write!(file, "{}", email.body)?;
        // Extract and log the actual content
        
        Ok(())
    }

}

async fn handle_client(tls_stream: TlsStream<TcpStream>) -> std::io::Result<()> {
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
        headers: Vec::new(),
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

                if in_data_mode {
                    if buffer.trim() == "." {
                        in_data_mode = false;
                        mail_server.store_email(&current_email)?;
                        
                        write_response(&mut stream, "250 OK\r\n").await?;
                        
                    } else {
                            current_email.body.push_str(&buffer);                 
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

async fn handle_plain_client(stream: TcpStream, tls_acceptor: Arc<TlsAcceptor>) -> std::io::Result<()> {
    let mut stream = StreamType::Plain(tokio::io::BufReader::new(stream));
    
    // Send initial greeting
    let greeting = "220 SMTP Server Ready\r\n";
    write_response(&mut stream, &greeting).await?;

    let mut in_data_mode = false;
    let mut is_outgoing = false;

    let mut current_email = Email {
        from: String::new(),
        to: String::new(),
        subject: String::new(),
        body: String::new(),
        headers: Vec::new(),
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
                          
                        write_response(&mut stream, "250 OK\r\n").await?;
                    } else {
                            current_email.body.push_str(&buffer);                 
                    }
                } else {
                    let response = process_command(&buffer, &mut current_email, &mut stream).await?;
                    println!("Response: {}", response);
                    write_response(&mut stream, &response).await?;
                    
                    if buffer.trim() == "DATA" {
                        in_data_mode = true;
                    } else if buffer.trim() == "QUIT" {
                        // Send reply email before closing the connection
                    
                    write_response(&mut stream, "221 Bye\r\n").await?;
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
            //email.from = command[10..].trim().to_string();
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
            Ok("220 TLS ready\r\n".to_string())
        } 
        _ => {
            Ok("500 Syntax error, command unrecognized\r\n".to_string())
        }
    }    
    
}

async fn handle_auth_login(stream: &mut StreamType) -> std::io::Result<String> {
    write_response(stream, "334 VXNlcm5hbWU6\r\n").await?; // Base64 for "Username:"
    let mut username = String::new();
    stream.read_line(&mut username).await?;
    let username = general_purpose::STANDARD.decode(username.trim_end()).unwrap();

    write_response(stream, "334 UGFzc3dvcmQ6\r\n").await?; // Base64 for "Password:"
    let mut password = String::new();
    stream.read_line(&mut password).await?;
    let password = general_purpose::STANDARD.decode(password.trim_end()).unwrap();

    if check_credentials(&username, &password) {
        Ok("235 Authentication successful\r\n".to_string())
    } else {
        Ok("535 Authentication failed\r\n".to_string())
    }
}

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

fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

fn load_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    Ok(private_key(&mut BufReader::new(File::open(path)?))
        .unwrap()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no private key found".to_string(),
        ))?)
}
fn check_credentials(username: &[u8], password: &[u8]) -> bool {
    // Implement your authentication logic here
    // For example:
    let expected_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let expected_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    
    username == expected_username.as_bytes() && password == expected_password.as_bytes()}

#[tokio::main]
async fn main() -> Result<(), MainError> {

    dotenv().ok();

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let tls_addr = env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string());
    let plain_addr = env::var("SMTP_PLAIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8025".to_string());

    let cert_path: PathBuf = PathBuf::from(env::var("CERT_PATH").unwrap_or_else(|_| "localhost.crt".to_string()));
    let key_path: PathBuf = PathBuf::from(env::var("KEY_PATH").unwrap_or_else(|_| "localhost.key".to_string()));

    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;
    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let tls_listener = TcpListener::bind(tls_addr.clone()).await?;
    let plain_listener = TcpListener::bind(plain_addr.clone()).await?;
    
    info!("TLS Server listening on {}", tls_addr);
    info!("Plain Server listening on {}", plain_addr);    

    loop {
        tokio::select! {
            result = tls_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New TLS client connected from {}", peer_addr);
        
                    let acceptor = tls_acceptor.clone();
            
                    tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        println!("TLS connection established with {}", peer_addr);
            
                                        if let Err(e) = handle_client(tls_stream).await {
                                            error!("Error handling client {}: {}", peer_addr, e);
                                        } else {
                                            info!("Client session completed successfully");
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Error during TLS connection: {}", e);
                                    }
                                }
                    });
                }
            }
            result = plain_listener.accept() => {
                if let Ok((stream, peer_addr)) = result {
                    info!("New plain client connected from {}", peer_addr);
                    let acceptor = tls_acceptor.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_plain_client(stream, acceptor.into()).await {
                            error!("Error handling plain client {}: {}", peer_addr, e);
                        } else {
                            info!("Plain client session completed successfully");
                        }
                    });
                }
            }   
        }
    }
}
