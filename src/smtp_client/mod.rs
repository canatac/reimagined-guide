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

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use chrono::Utc;
use std::io::{Error as IoError, ErrorKind};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

use rustls_native_certs::load_native_certs;
use std::convert::TryFrom;
use std::env;
use std::fs::File;
use std::io::BufReader;
use uuid::Uuid;
use webpki_roots::TLS_SERVER_ROOTS;
pub(crate) const SMTP_PORTS: [u16; 3] = [25, 587, 465];
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
use crate::entities::Email;

enum StreamType {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}


// Sous-modules extraits pour clean code (refactor architecte).
mod body_utils;
mod discovery;
use body_utils::compose_smtp_payload;
use discovery::{find_smtp_port, expect_code, ehlo_hostname};

pub async fn send_outgoing_email(email: &Email) -> std::io::Result<()> {
    if let Ok(relay_host) = env::var("SMTP_RELAY_HOST") {
        return send_via_relay(email, &relay_host).await;
    }
    send_via_mx(email).await
}

async fn send_via_relay(email: &Email, relay_host: &str) -> std::io::Result<()> {
    use base64::{engine::general_purpose, Engine as _};

    let relay_port: u16 = env::var("SMTP_RELAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(587);
    let relay_user = env::var("SMTP_RELAY_USER").unwrap_or_default();
    let relay_pass = env::var("SMTP_RELAY_PASSWORD").unwrap_or_default();

    let email_content = compose_smtp_payload(email);

    let ehlo_hostname = ehlo_hostname();

    let mut stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((relay_host, relay_port)),
    )
    .await
    .map_err(|_| IoError::new(ErrorKind::TimedOut, "Relay connection timed out"))?
    .map_err(|e| IoError::new(e.kind(), format!("Relay connect failed: {}", e)))?;

    expect_code(&mut stream, "220").await?;
    stream.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
    expect_code(&mut stream, "250").await?;

    // STARTTLS on port 587; skip on 465 (implicit TLS not yet supported for relay)
    let mut stream_type = if relay_port != 465 {
        stream.write_all(b"STARTTLS\r\n").await?;
        expect_code(&mut stream, "220").await?;

        let mut root_store = RootCertStore::empty();
        for cert in load_native_certs().certs {
            root_store.add_parsable_certificates([cert]);
        }
        root_store.add_parsable_certificates(
            TLS_SERVER_ROOTS.iter().map(|ta| ta.subject.to_vec().into()),
        );
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(relay_host.to_string())
            .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid relay hostname"))?;
        let tls_stream = connector.connect(server_name, stream).await?;
        let mut s = tls_stream;
        s.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
        expect_code(&mut s, "250").await?;
        StreamType::Tls(s)
    } else {
        StreamType::Plain(stream)
    };

    // AUTH PLAIN: base64("\0user\0password")
    if !relay_user.is_empty() {
        let cred = general_purpose::STANDARD
            .encode(format!("\0{}\0{}", relay_user, relay_pass));
        let auth_cmd = format!("AUTH PLAIN {}\r\n", cred);
        match &mut stream_type {
            StreamType::Plain(ref mut s) => { s.write_all(auth_cmd.as_bytes()).await?; expect_code(s, "235").await?; }
            StreamType::Tls(ref mut s)   => { s.write_all(auth_cmd.as_bytes()).await?; expect_code(s, "235").await?; }
        }
    }

    send_email_content(&mut stream_type, &email_content).await
}

async fn send_via_mx(email: &Email) -> std::io::Result<()> {
    let t_total = Instant::now();
    let mon = crate::monitoring::monitoring_enabled();

    // Extract or synthesise a stable message_id for correlation.
    let message_id = email
        .headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == "message-id")
        .map(|(_, v)| v.trim_matches(|c| c == '<' || c == '>').to_string())
        .unwrap_or_else(|| email.id.clone());

    // One UUID per send attempt — links all events for this delivery.
    let correlation_id = Uuid::new_v4().to_string();

    if mon {
        let mut ev = crate::monitoring::SmtpEvent::new(
            &message_id,
            crate::monitoring::SmtpEventType::Accepted,
            &email.from,
            &email.to,
        );
        ev.correlation_id = correlation_id.clone();
        crate::monitoring::emit(ev);
    }

    println!("Sending email: {}", email.body);

    let email_content = compose_smtp_payload(email);

    let recipient_email = extract_email_address(&email_content, "To:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid recipient email"))?;
    let recipient_domain = recipient_email
        .split('@')
        .nth(1)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid recipient email"))?;

    println!("Resolving MX records for domain: {}", recipient_domain);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // --- DNS lookup ---
    let t_dns = Instant::now();
    let mx_lookup = resolver.mx_lookup(recipient_domain).await.map_err(|e| {
        if mon {
            let mut ev = crate::monitoring::SmtpEvent::new(
                &message_id,
                crate::monitoring::SmtpEventType::Bounced,
                &email.from,
                &email.to,
            );
            ev.correlation_id = correlation_id.clone();
            ev.dns_ms = Some(t_dns.elapsed().as_millis() as u64);
            ev.total_ms = Some(t_total.elapsed().as_millis() as u64);
            ev.status = crate::monitoring::SmtpStatus::Failed;
            ev.bounce_type = Some(crate::monitoring::BounceType::Soft);
            ev.bounce_reason = Some(format!("MX lookup failed: {}", e));
            crate::monitoring::emit(ev);
        }
        IoError::new(ErrorKind::Other, format!("MX lookup failed: {}", e))
    })?;
    let dns_ms = t_dns.elapsed().as_millis() as u64;

    let mx_records: Vec<_> = mx_lookup.iter().collect();
    if mx_records.is_empty() {
        if mon {
            let mut ev = crate::monitoring::SmtpEvent::new(
                &message_id,
                crate::monitoring::SmtpEventType::Bounced,
                &email.from,
                &email.to,
            );
            ev.correlation_id = correlation_id.clone();
            ev.dns_ms = Some(dns_ms);
            ev.status = crate::monitoring::SmtpStatus::Failed;
            ev.bounce_type = Some(crate::monitoring::BounceType::Soft);
            ev.bounce_reason = Some("No MX records found".into());
            crate::monitoring::emit(ev);
        }
        return Err(IoError::new(ErrorKind::Other, "No MX records found"));
    }

    if mon {
        let mut ev = crate::monitoring::SmtpEvent::new(
            &message_id,
            crate::monitoring::SmtpEventType::DnsLookup,
            &email.from,
            &email.to,
        );
        ev.correlation_id = correlation_id.clone();
        ev.dns_ms = Some(dns_ms);
        crate::monitoring::emit(ev);
    }

    println!(
        "Found {} MX records. Using: {}",
        mx_records.len(),
        mx_records[0].exchange()
    );

    let smtp_server = mx_records[0]
        .exchange()
        .to_ascii()
        .trim_end_matches('.')
        .to_string();

    let smtp_port = match find_smtp_port(&smtp_server).await {
        Some(port) => {
            if mon {
                let mut ev = crate::monitoring::SmtpEvent::new(
                    &message_id,
                    crate::monitoring::SmtpEventType::MxSelected,
                    &email.from,
                    &email.to,
                );
                ev.correlation_id = correlation_id.clone();
                ev.mx_host = Some(smtp_server.clone());
                ev.remote_port = Some(port);
                crate::monitoring::emit(ev);
            }
            port
        }
        None => {
            if mon {
                let mut ev = crate::monitoring::SmtpEvent::new(
                    &message_id,
                    crate::monitoring::SmtpEventType::Bounced,
                    &email.from,
                    &email.to,
                );
                ev.correlation_id = correlation_id.clone();
                ev.mx_host = Some(smtp_server.clone());
                ev.dns_ms = Some(dns_ms);
                ev.total_ms = Some(t_total.elapsed().as_millis() as u64);
                ev.status = crate::monitoring::SmtpStatus::Failed;
                ev.bounce_type = Some(crate::monitoring::BounceType::Soft);
                ev.bounce_reason = Some("No open SMTP ports found".into());
                crate::monitoring::emit(ev);
            }
            return Err(IoError::new(ErrorKind::Other, "No open SMTP ports found"));
        }
    };

    // --- TCP connect ---
    println!("Connecting to {}:{}", smtp_server, smtp_port);
    let t_connect = Instant::now();
    let mut stream = TcpStream::connect((smtp_server.as_str(), smtp_port)).await?;
    let remote_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let connect_ms = t_connect.elapsed().as_millis() as u64;

    // GeoIP enrichment runs in background to avoid blocking the SMTP pipeline.
    if mon {
        let ip = remote_ip.clone();
        let mid = message_id.clone();
        let cid = correlation_id.clone();
        let from = email.from.clone();
        let to = email.to.clone();
        let mx = smtp_server.clone();
        let port = smtp_port;
        tokio::spawn(async move {
            let geo = crate::monitoring::enrichment::enrich_ip(&ip).await;
            let mut ev = crate::monitoring::SmtpEvent::new(
                &mid,
                crate::monitoring::SmtpEventType::SmtpConnect,
                &from,
                &to,
            );
            ev.correlation_id = cid;
            ev.mx_host = Some(mx);
            ev.remote_port = Some(port);
            ev.connect_ms = Some(connect_ms);
            ev = ev.with_geo(geo);
            ev.compute_risk_score();
            crate::monitoring::emit(ev);
        });
    }

    println!("Connected successfully");

    // Wrap all pre-send SMTP steps so errors still emit a Bounced monitoring event.
    let handshake_result: std::io::Result<(StreamType, u64, String)> = async {
        expect_code(&mut stream, "220").await?;
        let ehlo_hostname = ehlo_hostname();
        stream.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
        expect_code(&mut stream, "250").await?;

        // --- STARTTLS / TLS handshake ---
        let t_tls = Instant::now();
        let mut stream_type = if smtp_port != 465 {
            let smtp_server_clone = smtp_server.clone();
            stream.write_all(b"STARTTLS\r\n").await?;
            expect_code(&mut stream, "220").await?;

            let mut root_store = RootCertStore::empty();
            for cert in load_native_certs().certs {
                root_store.add_parsable_certificates([cert]);
            }
            root_store.add_parsable_certificates(
                TLS_SERVER_ROOTS.iter().map(|ta| ta.subject.to_vec().into()),
            );
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));
            let server_name = ServerName::try_from(smtp_server_clone)
                .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid server name"))?;
            let tls_stream = connector.connect(server_name, stream).await?;
            let mut s = tls_stream;
            s.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
            expect_code(&mut s, "250").await?;
            StreamType::Tls(s)
        } else {
            StreamType::Plain(stream)
        };
        let tls_ms = t_tls.elapsed().as_millis() as u64;

        if smtp_port == 465 {
            match &mut stream_type {
                StreamType::Plain(ref mut s) => {
                    s.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
                    expect_code(s, "250").await?;
                }
                StreamType::Tls(_) => {}
            }
        }

        Ok((stream_type, tls_ms, ehlo_hostname))
    }.await;

    let (mut stream_type, tls_ms, _ehlo_hostname) = match handshake_result {
        Ok(v) => v,
        Err(e) => {
            if mon {
                let mut ev = crate::monitoring::SmtpEvent::new(
                    &message_id,
                    crate::monitoring::SmtpEventType::Bounced,
                    &email.from,
                    &email.to,
                );
                ev.correlation_id = correlation_id.clone();
                ev.mx_host = Some(smtp_server.clone());
                ev.remote_ip = Some(remote_ip.clone());
                ev.total_ms = Some(t_total.elapsed().as_millis() as u64);
                ev.status = crate::monitoring::SmtpStatus::Failed;
                ev.bounce_type = Some(crate::monitoring::BounceType::Soft);
                ev.bounce_reason = Some(format!("TLS/SMTP handshake failed: {}", e));
                crate::monitoring::emit(ev);
            }
            return Err(e);
        }
    };

    if mon {
        let mut ev = crate::monitoring::SmtpEvent::new(
            &message_id,
            crate::monitoring::SmtpEventType::TlsOk,
            &email.from,
            &email.to,
        );
        ev.correlation_id = correlation_id.clone();
        ev.mx_host = Some(smtp_server.clone());
        ev.remote_ip = Some(remote_ip.clone());
        ev.tls_ms = Some(tls_ms);
        crate::monitoring::emit(ev);
    }

    let result = send_email_content(&mut stream_type, &email_content).await;
    let total_ms = t_total.elapsed().as_millis() as u64;

    if mon {
        match &result {
            Ok(_) => {
                let mut ev = crate::monitoring::SmtpEvent::new(
                    &message_id,
                    crate::monitoring::SmtpEventType::Delivered,
                    &email.from,
                    &email.to,
                );
                ev.correlation_id = correlation_id.clone();
                ev.mx_host = Some(smtp_server.clone());
                ev.remote_ip = Some(remote_ip.clone());
                ev.dns_ms = Some(dns_ms);
                ev.connect_ms = Some(connect_ms);
                ev.tls_ms = Some(tls_ms);
                ev.total_ms = Some(total_ms);
                ev.smtp_code = Some(250);
                ev.smtp_reply = Some("250 OK".into());
                ev.status = crate::monitoring::SmtpStatus::Delivered;
                ev.compute_risk_score();
                crate::monitoring::emit(ev);
            }
            Err(e) => {
                let err_msg = e.to_string();
                let smtp_code = crate::monitoring::parse_smtp_code(&err_msg);
                let bounce_type = match smtp_code {
                    Some(c) if c >= 550 => crate::monitoring::BounceType::Hard,
                    Some(421) | Some(450) => crate::monitoring::BounceType::Soft,
                    _ => crate::monitoring::BounceType::Soft,
                };
                let mut ev = crate::monitoring::SmtpEvent::new(
                    &message_id,
                    crate::monitoring::SmtpEventType::Bounced,
                    &email.from,
                    &email.to,
                );
                ev.correlation_id = correlation_id;
                ev.mx_host = Some(smtp_server.clone());
                ev.remote_ip = Some(remote_ip.clone());
                ev.total_ms = Some(total_ms);
                ev.smtp_code = smtp_code;
                ev.smtp_reply = Some(err_msg.clone());
                ev.status = crate::monitoring::SmtpStatus::Bounced;
                ev.bounce_type = Some(bounce_type);
                ev.bounce_reason = Some(err_msg);
                ev.compute_risk_score();
                crate::monitoring::emit(ev);
            }
        }
    }

    result
}

// Update this function to accept a string instead of an Email struct
async fn send_email_content(stream: &mut StreamType, email_content: &str) -> std::io::Result<()> {
    let from_address = extract_email_address(email_content, "From:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid From address"))?;
    let to_address = extract_email_address(email_content, "To:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid To address"))?;

    match stream {
        StreamType::Plain(ref mut s) => {
            send_email_content_inner(s, &from_address, &to_address, email_content).await
        }
        StreamType::Tls(ref mut s) => {
            send_email_content_inner(s, &from_address, &to_address, email_content).await
        }
    }
}

// Helper function to extract email address from headers

pub fn extract_email_address(content: &str, header: &str) -> Option<String> {
    let line = content.lines().find(|line| line.starts_with(header))?;
    let value = line.splitn(2, ':').nth(1)?.trim();
    // Handle "Display Name <email@example.com>" format
    if let (Some(start), Some(end)) = (value.rfind('<'), value.rfind('>')) {
        if start < end {
            return Some(value[start + 1..end].trim().to_string());
        }
    }
    Some(value.to_string())
}
async fn send_email_content_inner<T: AsyncWriteExt + AsyncReadExt + Unpin>(
    stream: &mut T,
    from: &str,
    to: &str,
    email_content: &str,
) -> std::io::Result<()> {
    println!("Sending MAIL FROM: <{}>", from);
    stream
        .write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes())
        .await?;
    expect_code(stream, "250").await?;

    println!("Sending RCPT TO: <{}>", to);
    stream
        .write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes())
        .await?;
    expect_code(stream, "250").await?;

    println!("Sending DATA command");
    stream.write_all(b"DATA\r\n").await?;
    expect_code(stream, "354").await?;
    // Send the entire email content without alteration
    println!(
        "++++++++++++++++++++++++++++Sending unaltered email content: {}",
        email_content
    );
    stream.write_all(email_content.as_bytes()).await?;

    // Ensure the email content ends with \r\n.\r\n
    if !email_content.ends_with("\r\n.\r\n") {
        println!("Adding final .");
        stream.write_all(b"\r\n.\r\n").await?;
    }

    expect_code(stream, "250").await?;

    println!("Sending QUIT command");
    stream.write_all(b"QUIT\r\n").await?;
    expect_code(stream, "221").await?;

    return Ok(());
}

