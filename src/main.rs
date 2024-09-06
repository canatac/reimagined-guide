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
use mailparse::{parse_mail};
use lettre::message::{header::ContentType, Mailbox, MessageBuilder};
use lettre::{SmtpTransport, Transport};
use lettre::Address;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use std::net::IpAddr;
use std::io::{Error as IoError, ErrorKind};

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
        match extract_email_content(&email.body) {
            Ok(content) => {
                println!("Extracted email content: {}", content);
                
                // Send a reply email
                let reply_subject = "Re: ".to_string() + &email.subject;
                let reply_body = "Thank you for joining me! Please subscribe first before talking with me!";
                
                match send_reply_email(&email.from, &reply_subject, reply_body) {
                    Ok(_) => println!("Reply sent successfully"),
                    Err(e) => eprintln!("Error sending reply: {}", e),
                }
            },
            Err(e) => eprintln!("Error extracting email content: {}", e),
        }
        Ok(())
    }

}

fn send_reply_email(to: &str, subject: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let address = Address::new(smtp_username, "misfits.ai")?;

    println!("Sending email from: {} to: {}", address.to_string(), to);

    let email = MessageBuilder::new()
        .from(Mailbox::new(Some("AI Assistant".to_string()), address))
        .to(to.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())?;

        let mailer = SmtpTransport::builder_dangerous("127.0.0.1")
        .port(2525)
        .build();

    mailer.send(&email)?;

    Ok(())
}



async fn send_outgoing_email(email: &Email) -> std::io::Result<()> {
    // Parse the recipient's domain
    //let recipient_domain = email.to.split('@').nth(1).ok_or("Invalid recipient email")?;
    let recipient_domain = email.to.split('@').nth(1)
    .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid recipient email"))?;
    // Create a new resolver
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Lookup MX records
    let mx_lookup = resolver.mx_lookup(recipient_domain).await?;
    let mx_records: Vec<_> = mx_lookup.iter().collect();

    if mx_records.is_empty() {
        return Err(IoError::new(ErrorKind::Other, "No MX records found"))
    }

    // Connect to the first MX server
    let mut stream = TcpStream::connect(format!("{}:25", mx_records[0].exchange())).await?;

    // SMTP conversation
    async fn expect_code(stream: &mut TcpStream, expected: &str) -> std::io::Result<()> {
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        if !response.starts_with(expected) {
            return Err(IoError::new(ErrorKind::Other, format!("Unexpected response: {}", response)));
        }
        Ok(())
    }

    expect_code(&mut stream, "220").await?;
    stream.write_all(b"HELO misfits.ai\r\n").await?;
    expect_code(&mut stream, "250").await?;

    stream.write_all(format!("MAIL FROM:<{}>\r\n", email.from).as_bytes()).await?;
    expect_code(&mut stream, "250").await?;

    stream.write_all(format!("RCPT TO:<{}>\r\n", email.to).as_bytes()).await?;
    expect_code(&mut stream, "250").await?;

    stream.write_all(b"DATA\r\n").await?;
    expect_code(&mut stream, "354").await?;

    // Send headers
    for (key, value) in &email.headers {
        stream.write_all(format!("{}: {}\r\n", key, value).as_bytes()).await?;
    }
    stream.write_all(format!("Subject: {}\r\n", email.subject).as_bytes()).await?;
    stream.write_all(format!("From: {}\r\n", email.from).as_bytes()).await?;
    stream.write_all(format!("To: {}\r\n", email.to).as_bytes()).await?;
    stream.write_all(b"\r\n").await?;

    // Send body
    stream.write_all(email.body.as_bytes()).await?;

    stream.write_all(b"\r\n.\r\n").await?;
    expect_code(&mut stream, "250").await?;

    stream.write_all(b"QUIT\r\n").await?;
    expect_code(&mut stream, "221").await?;

    Ok(())
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
                        current_email = Email {
                            from: String::new(),
                            to: String::new(),
                            subject: String::new(),
                            body: String::new(),
                            headers: Vec::new(),
                        };
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

fn is_outgoing_email(mail_from: &str) -> bool {
    // Implement logic to determine if this is an outgoing email
    // For example, check if the MAIL FROM address is from your domain
    mail_from.contains("@misfits.ai")
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
                        if is_outgoing {
                            // Handle outgoing email
                            println!("Sending outgoing email: From: {}, To: {}, Subject: {}", current_email.from, current_email.to, current_email.subject);
                            match send_outgoing_email(&current_email).await {
                                Ok(_) => {
                                    println!("Email sent successfully");
                                    write_response(&mut stream, "250 OK\r\n").await?
                                },
                                Err(e) => {
                                    eprintln!("Error sending email: {}", e);
                                    write_response(&mut stream, "554 Transaction failed\r\n").await?
                                }
                            }                        } else {
                            // Handle incoming email
                            mail_server.store_email(&current_email)?;
                        }                        current_email = Email {
                            from: String::new(),
                            to: String::new(),
                            subject: String::new(),
                            body: String::new(),
                            headers: Vec::new(),
                        };
                        write_response(&mut stream, "250 OK\r\n").await?;
                    } else {
                            current_email.body.push_str(&buffer);                 
                    }
                } else {
                    let response = process_command(&buffer, &mut current_email, &mut stream).await?;
                    println!("Response: {}", response);
                    write_response(&mut stream, &response).await?;
                    if buffer.trim().starts_with("MAIL FROM:") {
                        // Determine if this is an outgoing email based on the MAIL FROM address
                        is_outgoing = is_outgoing_email(&buffer);
                    }
                    if buffer.trim() == "DATA" {
                        in_data_mode = true;
                    } else if buffer.trim() == "QUIT" {
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    dotenv().ok();

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // construct a subscriber that prints formatted traces to stdout
// Start configuring a `fmt` subscriber
let subscriber = tracing_subscriber::fmt()
    // Use a more compact, abbreviated log format
    .compact()
    // Display source code file paths
    .with_file(true)
    // Display source code line numbers
    .with_line_number(true)
    // Display the thread ID an event was recorded on
    .with_thread_ids(true)
    // Don't display the event's target (module path)
    .with_target(false)
    // Build the subscriber
    .finish();    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber)?;

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
            //let (stream, peer_addr) = listener.accept().await?;
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
                                        eprintln!("Erreur lors de la connexion TLS: {}", e);
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
