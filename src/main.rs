use std::io::{Write, BufReader};
use std::sync::Arc;
use std::fs::{self, File};
use std::path::Path;
use chrono::Utc;
use log::{info, error};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpStream,TcpListener};

use tokio_rustls::server::TlsStream;
use rustls_pemfile::pkcs8_private_keys;
use rustls_pemfile::certs;

enum StreamType {
    Plain(tokio::io::BufReader<TcpStream>),
    Tls(tokio::io::BufReader<TlsStream<TcpStream>>),
}

#[derive(Clone)]
struct Email {
    from: String,
    to: String,
    subject: String,
    body: String,
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
        
        Ok(())
    }

    fn send_email(&self, email: &Email) -> std::io::Result<()> {
        // In a real implementation, you'd connect to the recipient's SMTP server here
        // For now, we'll just print the email details
        println!("Sending email:");
        println!("From: {}", email.from);
        println!("To: {}", email.to);
        println!("Subject: {}", email.subject);
        println!("Body: {}", email.body);
        
        // Store the sent email
        self.store_email(email)
    }
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    tls_acceptor: TlsAcceptor,
    mail_server: Arc<MailServer>) -> std::io::Result<()>  {
    
    let mut stream = StreamType::Plain(tokio::io::BufReader::new(stream));
    write_response(&mut stream, "220 Blop Simple Server\r\n").await?;

    let mut in_data_mode = false;
    let mut current_email = Email {
        from: String::new(),
        to: String::new(),
        subject: String::new(),
        body: String::new(),
    };

    loop {
        let mut buffer = String::new();
        //buffer.clear();
        match read_line(&mut stream, &mut buffer).await {
                Ok(0) => {
                    println!("Client closed the connection");
                    break;
                }
                Ok(_) => {
                    println!("Read bytes: {}",buffer.trim());
                    if buffer.trim().eq_ignore_ascii_case("STARTTLS") && !is_tls(&stream) {
                        //stream = upgrade_to_tls(stream, tls_acceptor.clone()).await?;
                        // Inform the client that the TLS negotiation has succeeded
                        //write_response(&mut stream, "220 TLS negotiation succeeded\r\n").await?;
                        //continue;

                        match upgrade_to_tls(stream, tls_acceptor.clone()).await {
                            Ok(upgraded_stream) => {
                                stream = upgraded_stream;
                                println!("TLS upgrade successful");
                                write_response(&mut stream, "220 TLS negotiation succeeded\r\n").await?;
                            }
                            Err(e) => {
                                eprintln!("TLS upgrade failed: {}", e);
                                return Err(e);
                            }
                        }
                        continue;
                    }
                    if in_data_mode {
                        if buffer.trim() == "." {
                            in_data_mode = false;
                            mail_server.store_email(&current_email)?;
                            mail_server.send_email(&current_email)?;
                            current_email = Email {
                                from: String::new(),
                                to: String::new(),
                                subject: String::new(),
                                body: String::new(),
                            };
                            write_response(&mut stream, "250 OK\r\n").await?;
                        } else {
                                current_email.body.push_str(&buffer);                 
                        }
                    } else {
                        let response = process_command(&buffer, &mut current_email).await?;
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
                    eprintln!("Error reading from stream: {}", e);
                    break;
                }
        }
    }
    println!("Client session completed successfully");
    Ok(())
}

async fn read_line(stream: &mut StreamType, buffer: &mut String) -> std::io::Result<usize> {
    match stream {
        StreamType::Plain(ref mut s) => s.read_line(buffer).await,
        StreamType::Tls(ref mut s) => s.read_line(buffer).await,
    }
}

async fn write_response(stream: &mut StreamType, response: &str) -> std::io::Result<()> {
    match stream {
        StreamType::Plain(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
        StreamType::Tls(ref mut s) => {
            s.write_all(response.as_bytes()).await?;
            s.flush().await
        }
    }
}

fn is_tls(stream: &StreamType) -> bool {
    matches!(stream, StreamType::Tls(_))
}

async fn upgrade_to_tls(
    stream: StreamType,
    tls_acceptor: TlsAcceptor
) -> std::io::Result<StreamType> {
    match stream {
        StreamType::Plain(plain_stream) => {
            info!("Initiating TLS upgrade...");
            let inner_stream = plain_stream.into_inner();
            info!("Starting TLS handshake...");
            //let tls_stream = tls_acceptor.accept(plain_stream.into_inner()).await?;
            match tokio::time::timeout(std::time::Duration::from_secs(120), tls_acceptor.accept(inner_stream)).await {
                Ok(Ok(tls_stream)) => {
                    info!("TLS upgrade completed successfully");
                    Ok(StreamType::Tls(tokio::io::BufReader::new(tls_stream)))
                },
                Ok(Err(e)) => {
                    error!("TLS acceptance error: {:?}", e);
                    Err(std::io::Error::new(std::io::ErrorKind::Other, e))
                },
                Err(_) => {
                    error!("TLS handshake timed out");
                    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out"))
                }
            }

            //Ok(StreamType::Tls(tokio::io::BufReader::new(tls_stream)))
        }
        StreamType::Tls(_) => Ok(stream), // Already TLS
    }
}

async fn process_command(command: &str, email: &mut Email ) -> std::io::Result<String> {
    let command = command.trim();
    
    if command.starts_with("HELO") || command.starts_with("EHLO") {
        Ok("250-mail.misfits.ai\r\n250-STARTTLS\r\n250 OK\r\n".to_string())
    } else if command.starts_with("MAIL FROM:") {
        email.from = command[10..].trim().to_string();
        Ok("250 OK\r\n".to_string())
    } else if command.starts_with("RCPT TO:") {
        email.to = command[8..].trim().to_string();
        Ok("250 OK\r\n".to_string())
    } else if command.starts_with("SUBJECT:") {
        email.subject = command[8..].trim().to_string();
        Ok("250 OK\r\n".to_string())
    } else if command == "DATA" {
        Ok("354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string())
    } else if command == "." {
        Ok("250 OK\r\n".to_string())
    } else if command == "QUIT" {
        Ok("221 Bye\r\n".to_string())
    } else {
        Ok("500 Syntax error, command unrecognized\r\n".to_string())
    }
}

fn load_certs(path: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    println!("Attempting to load certificate from: {}", path);

    let cert_file = File::open(path).expect("Failed to open cert file");
    let mut reader = BufReader::new(cert_file);
    //certs(&mut reader).unwrap().into_iter().map(rustls::Certificate).collect()
    let certs = certs(&mut reader)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cert"))?;
    println!("Loaded {} certificates", certs.len());
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

fn load_private_key(path: &str) -> std::io::Result<rustls::PrivateKey>  {
    println!("Attempting to load private key from: {}", path);

    let key_file = File::open(path)?;
    let mut reader = BufReader::new(key_file);
    let keys = pkcs8_private_keys(&mut reader)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key"))?;
    println!("Loaded {} private keys", keys.len());
    Ok(rustls::PrivateKey(keys[0].clone()))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {

    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let addr = "0.0.0.0:587";
    let cert_path = "/home/canatac/temp_certs/fullchain.pem";
    let key_path = "/home/canatac/temp_certs/privkey.pem";

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(addr).await?;
    info!("Server listening on {}", addr);

    while let Ok((stream, peer_addr)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let mail_server = Arc::new(MailServer::new("./emails")); // Assuming you have a MailServer struct

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, acceptor, mail_server).await {
                error!("Error handling client {}: {}", peer_addr, e);
            }
        });
    }

    Ok(())
}