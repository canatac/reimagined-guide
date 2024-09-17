/*
This is an SMTP client implementation.

To run this client, use the following command from the project root:

cargo run --bin client -- [OPTIONS]

OPTIONS:
    -f, --from <FROM>        Sets the sender email address
    -t, --to <TO>            Sets the recipient email address
    -s, --subject <SUBJECT>  Sets the email subject
    -b, --body <BODY>        Sets the email body

Example usage:
cargo run --bin client -- \
    --from "sender@example.com" \
    --to "recipient@example.com" \
    --subject "Test Email" \
    --body "This is a test email sent from the Rust SMTP client."

Make sure you have set the necessary environment variables in your .env file:
    SMTP_USERNAME: Your SMTP username
    SMTP_PASSWORD: Your SMTP password
    FULLCHAIN_PATH: Path to your SSL certificate chain file

The client will attempt to connect to the SMTP server, send the email, and report the result.
*/

use std::io::{Error as IoError, ErrorKind};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use clap::{App, Arg};
use tokio_rustls::TlsConnector;
use tokio::time::timeout;
use std::time::Duration;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use rustls::pki_types::{ServerName,CertificateDer};

use std::convert::TryFrom;
use std::fs::File;
use std::io::BufReader;
use rustls_native_certs::load_native_certs;
use webpki_roots::TLS_SERVER_ROOTS;
use std::env;
use dotenv::dotenv;
const SMTP_PORTS: [u16; 3] = [587, 465, 25];
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);


#[derive(Clone)]
pub struct Email {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

enum StreamType {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

async fn test_smtp_port(host: &str, port: u16) -> bool {
    match timeout(CONNECTION_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn find_smtp_port(host: &str) -> Option<u16> {
    for &port in &SMTP_PORTS {
        if test_smtp_port(host, port).await {
            return Some(port);
        }
    }
    None
}

async fn expect_code<T: AsyncReadExt + Unpin>(stream: &mut T, expected: &str) -> std::io::Result<()> {
    let mut response = [0; 1024];
    let n = stream.read(&mut response).await?;
    let response = String::from_utf8_lossy(&response[..n]);
    if !response.starts_with(expected) {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Unexpected response: {}", response)));
    }
    Ok(())
}
pub async fn send_outgoing_email(email_content: &str) -> std::io::Result<()> {
    println!("Sending email: {}", email_content);
    let recipient_email = extract_email_address(email_content, "To:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid recipient email"))?;
    let recipient_domain = recipient_email.split('@').nth(1)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid recipient email"))?;
    
    println!("Resolving MX records for domain: {}", recipient_domain);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let mx_lookup = resolver.mx_lookup(recipient_domain).await
        .map_err(|e| IoError::new(ErrorKind::Other, format!("MX lookup failed: {}", e)))?;
    let mx_records: Vec<_> = mx_lookup.iter().collect();

    if mx_records.is_empty() {
        return Err(IoError::new(ErrorKind::Other, "No MX records found"))
    }
    println!("Found {} MX records. Using: {}", mx_records.len(), mx_records[0].exchange());

    let smtp_server = mx_records[0].exchange().to_ascii().trim_end_matches('.').to_string();
    let smtp_port = find_smtp_port(&smtp_server).await
        .ok_or_else(|| IoError::new(ErrorKind::Other, "No open SMTP ports found"))?;

    println!("Connecting to {}:{}", smtp_server, smtp_port);
    let mut stream = TcpStream::connect((smtp_server.as_str(), smtp_port)).await?;

    println!("Connected successfully");

    expect_code(&mut stream, "220").await?;
    stream.write_all(b"EHLO misfits.ai\r\n").await?;
    expect_code(&mut stream, "250").await?;

    let mut stream_type =  if smtp_port != 465 {  // 465 is already SSL/TLS
        let smtp_server_clone = smtp_server.clone();
        stream.write_all(b"STARTTLS\r\n").await?;
        expect_code(&mut stream, "220").await?;

        let mut root_store = RootCertStore::empty();
        
        // Load native root certificates
        for cert in load_native_certs().map_err(|e| IoError::new(ErrorKind::Other, e))? {
            root_store.add_parsable_certificates([CertificateDer::from(cert.0)]);
        }

        // Add your misfits.ai certificate
        let fullchain_path = env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set");
        let mut fullchain_file = BufReader::new(File::open(fullchain_path)?);
        let certs = rustls_pemfile::certs(&mut fullchain_file);
        for cert in certs {
            root_store.add_parsable_certificates(cert);
        }
        
        // Optionally add webpki roots as well
        root_store.add_parsable_certificates(TLS_SERVER_ROOTS.iter().map(|ta| ta.subject.to_vec().into()));

        let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(smtp_server_clone)
            .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid server name"))?;
        
        let tls_stream = connector.connect(server_name, stream).await?;

        StreamType::Tls(tls_stream)
    } else {
        StreamType::Plain(stream)
    };
    match &mut stream_type {
        StreamType::Plain(ref mut s) => {
            s.write_all(b"EHLO misfits.ai\r\n").await?;
            expect_code(s, "250").await?;
        }
        StreamType::Tls(ref mut s) => {
            s.write_all(b"EHLO misfits.ai\r\n").await?;
            expect_code(s, "250").await?;
        }
    }
    // Use the appropriate stream for the rest of the communication
    send_email_content(&mut stream_type, email_content).await?;

    Ok(())
}

// Update this function to accept a string instead of an Email struct
async fn send_email_content(stream: &mut StreamType, email_content: &str) -> std::io::Result<()> {
    let from_address = extract_email_address(email_content, "From:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid From address"))?;
    let to_address = extract_email_address(email_content, "To:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid To address"))?;

    match stream {
        StreamType::Plain(ref mut s) => send_email_content_inner(s, &from_address, &to_address, email_content).await,
        StreamType::Tls(ref mut s) => send_email_content_inner(s, &from_address, &to_address, email_content).await,
    }
}

// Helper function to extract email address from headers

fn extract_email_address(content: &str, header: &str) -> Option<String> {
    content.lines()
        .find(|line| line.starts_with(header))
        .and_then(|line| line.split(':').nth(1))
        .map(|addr| addr.trim().trim_matches(|c| c == '<' || c == '>').to_string())
}
async fn send_email_content_inner<T: AsyncWriteExt + AsyncReadExt + Unpin>(
    stream: &mut T, 
    from: &str, 
    to: &str, 
    email_content: &str
) -> std::io::Result<()> {
    stream.write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes()).await?;
    expect_code(stream, "250").await?;

    stream.write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes()).await?;
    expect_code(stream, "250").await?;

    stream.write_all(b"DATA\r\n").await?;
    expect_code(stream, "354").await?;

    // Send the entire email content
    stream.write_all(email_content.as_bytes()).await?;

    // Ensure the email content ends with \r\n.\r\n
    if !email_content.ends_with("\r\n.\r\n") {
        stream.write_all(b"\r\n.\r\n").await?;
    }

    expect_code(stream, "250").await?;

    stream.write_all(b"QUIT\r\n").await?;
    expect_code(stream, "221").await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    dotenv().ok();

    let matches = App::new("Email Sender")
        .version("1.0")
        .author("Your Name")
        .about("Sends emails via SMTP")
        .arg(Arg::with_name("from")
            .short('f')
            .long("from")
            .value_name("FROM")
            .help("Sets the sender email address")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("to")
            .short('t')
            .long("to")
            .value_name("TO")
            .help("Sets the recipient email address")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("subject")
            .short('s')
            .long("subject")
            .value_name("SUBJECT")
            .help("Sets the email subject")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("body")
            .short('b')
            .long("body")
            .value_name("BODY")
            .help("Sets the email body")
            .required(true)
            .takes_value(true))
        .get_matches();

    let from = matches.value_of("from").unwrap();
    let to = matches.value_of("to").unwrap();
    let subject = matches.value_of("subject").unwrap();
    let body = matches.value_of("body").unwrap();

    // Create the email content
    let email_content = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
        from, to, subject, body
    );


    match send_outgoing_email(&email_content).await {
        Ok(_) => println!("Email sent successfully"),
        Err(e) => eprintln!("Error sending email: {}", e),
    }

    Ok(())
}