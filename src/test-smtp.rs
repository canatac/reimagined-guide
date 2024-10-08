use std::io::{BufReader, Write};
use std::sync::Arc;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use chrono::Utc;
use log::{info, error};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncBufRead, AsyncRead}; 
use tokio::net::{TcpStream,TcpListener};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;
use rustls_pemfile::{certs, private_key};

#[derive(Debug)]
enum StreamType {
    Plain(tokio::io::BufReader<TcpStream>),
    Tls(tokio::io::BufReader<TlsStream<TcpStream>>),
}
impl AsyncRead for StreamType {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamType::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            StreamType::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}
impl AsyncBufRead for StreamType {
    fn poll_fill_buf(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<&[u8]>> {
        match self.get_mut() {
            StreamType::Plain(s) => std::pin::Pin::new(s).poll_fill_buf(cx),
            StreamType::Tls(s) => std::pin::Pin::new(s).poll_fill_buf(cx),
        }
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        match self.get_mut() {
            StreamType::Plain(s) => std::pin::Pin::new(s).consume(amt),
            StreamType::Tls(s) => std::pin::Pin::new(s).consume(amt),
        }
    }
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

async fn handle_client(mut tls_stream: TlsStream<TcpStream>) -> std::io::Result<()> {
    let mut stream = StreamType::Tls(tokio::io::BufReader::new(tls_stream));
    
    // Send initial greeting
    let greeting = "220 SMTP Server Ready\r\n";
    write_response(&mut stream, &greeting).await?;

    let mut in_data_mode = false;

    let mut current_email = Email {
        from: String::new(),
        to: String::new(),
        subject: String::new(),
        body: String::new(),
    };

    let mail_server = Arc::new(MailServer::new("./emails"));
    loop {
        let mut buffer = String::new();
        match stream.read_line(&mut buffer).await {
            Ok(0) => {
                println!("Client disconnected  : {}", buffer.trim());
                break;
            }
            Ok(n) => {                
                println!("Calling process_command with: {}", buffer.trim());

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
                eprintln!("Error reading from client: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn process_command(command: &str, email: &mut Email) -> std::io::Result<String> {
    // Implement your SMTP command processing logic here
    // This is a basic example and should be expanded based on your needs

    println!("In process_command with: {}", command.trim().to_uppercase().as_str());

    if command.starts_with("HELO") || command.starts_with("EHLO") {
        Ok("250-mail.misfits.ai\r\n250-STARTTLS\r\n250 OK\r\n".to_string())
    } else if command.starts_with("MAIL FROM:") {
        //email.from = command[10..].trim().to_string();
        email.from = command.trim_start_matches("MAIL FROM:").trim().to_string();
        Ok("250 OK\r\n".to_string())
    } else if command.starts_with("RCPT TO:") {
        email.to = command.trim_start_matches("RCPT TO:").trim().to_string();
        Ok("250 OK\r\n".to_string())

      //  email.to = command[8..].trim().to_string();
       // Ok("250 OK\r\n".to_string())
    } else if command.starts_with("SUBJECT:") {
        email.subject = command[8..].trim().to_string();
        Ok("250 OK\r\n".to_string())
    } else if command == "DATA" {
        Ok("354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string())
    } else if command == "." {
        Ok("250 OK\r\n".to_string())
    } else if command == "QUIT" {
        Ok("221 Bye\r\n".to_string())
    } else if command == "RSET" {
        email.subject = String::new();
        email.from = String::new();
        email.to = String::new();
        email.subject = String::new();
        email.body = String::new();
         // Reset the email using new() instead of default()
        Ok("250 OK\r\n".to_string())
    } else if command == "NOOP" {
        Ok("250 OK\r\n".to_string())
    } else if command.starts_with("VRFY") {
        // In a real implementation, you'd verify the email address here
        Ok("252 Cannot VRFY user, but will accept message and attempt delivery\r\n".to_string())
    } else if command.starts_with("AUTH") {
        // In a real implementation, you'd handle authentication here
        Ok("235 Authentication successful\r\n".to_string())
    } 
    else {
        Ok("500 Syntax error, command unrecognized\r\n".to_string())
    }
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


/*
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

*/

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

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

    let addr = "0.0.0.0:465";
    let cert_path:PathBuf = PathBuf::from("localhost.crt");
    let key_path:PathBuf = PathBuf::from("localhost.key");


    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(addr).await?;
    info!("Server listening on {}", addr);



    loop {
        let (stream, peer_addr) = listener.accept().await?;
        
        info!("New client connected from {}", peer_addr);
    
        

        let acceptor = acceptor.clone();
    /*
        tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, acceptor, mail_server).await {
                        error!("Error handling client {}: {}", peer_addr, e);
                    }else{
                        info!("Client session completed successfully");
                    
            }
        });
      */

        tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(mut tls_stream) => {
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
