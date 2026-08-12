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
const SMTP_PORTS: [u16; 3] = [25, 587, 465];
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
use crate::entities::Email;
use std::collections::HashMap;

enum StreamType {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

fn normalize_crlf(input: &str) -> String {
    input
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

fn strip_tags_simple(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn body_looks_like_html(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("<html")
        || lower.contains("<body")
        || lower.contains("<p")
        || lower.contains("<div")
        || lower.contains("<br")
        || lower.contains("<table")
        || lower.contains("<span")
        || lower.contains("</")
}

fn ensure_html_document(raw: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("<html") {
        return trimmed.to_string();
    }
    format!("<!DOCTYPE html><html><body>{}</body></html>", trimmed)
}

fn upsert_content_type(headers: &mut Vec<(String, String)>, value: String) {
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        *existing = value;
    } else {
        headers.push(("Content-Type".to_string(), value));
    }
}

fn compose_smtp_payload(email: &Email) -> String {
    let mut headers = email.headers.clone();
    let body = email.body.trim();

    let has_multipart = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("multipart/")
    });

    let payload_body = if has_multipart {
        body.to_string()
    } else if body_looks_like_html(body) {
        let html = normalize_crlf(&ensure_html_document(body));
        let mut plain = strip_tags_simple(&html);
        if plain.trim().is_empty() {
            plain = body.to_string();
        }
        plain = normalize_crlf(plain.trim());

        let boundary = format!("misfits-alt-{}", Uuid::new_v4().simple());
        upsert_content_type(
            &mut headers,
            format!("multipart/alternative; boundary=\"{}\"", boundary),
        );

        format!(
            "--{b}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{plain}\r\n--{b}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{html}\r\n--{b}--\r\n",
            b = boundary,
            plain = plain,
            html = html,
        )
    } else {
        upsert_content_type(&mut headers, "text/plain; charset=utf-8".to_string());
        normalize_crlf(body)
    };

    let mut email_content = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n",
        email.from, email.to, email.subject
    );
    for (key, value) in &headers {
        email_content.push_str(&format!("{}: {}\r\n", key, value));
    }
    email_content.push_str(&format!("\r\n{}", payload_body));
    email_content
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

async fn expect_code<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    expected: &str,
) -> std::io::Result<()> {
    let mut response = [0; 1024];
    let mut acc = String::new();

    for _ in 0..16 {
        let n = stream.read(&mut response).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Connection closed while waiting for SMTP {}", expected),
            ));
        }

        let chunk = String::from_utf8_lossy(&response[..n]);
        acc.push_str(&chunk);
        println!("Received response: {}", chunk);

        for line in acc.split("\r\n").filter(|l| !l.is_empty()) {
            if line.len() < 4 {
                continue;
            }
            let prefix = &line[..3];
            let sep = line.as_bytes()[3] as char;
            let is_code = prefix.chars().all(|c| c.is_ascii_digit());
            if !is_code {
                continue;
            }

            if prefix == expected && sep == ' ' {
                return Ok(());
            }

            if sep == ' ' && prefix != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unexpected response: {}", acc),
                ));
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("Timed out waiting for SMTP {} response: {}", expected, acc),
    ))
}
fn ehlo_hostname() -> String {
    if let Ok(value) = env::var("SMTP_HOSTNAME") {
        let v = value.trim().trim_end_matches('.');
        if !v.is_empty() {
            return v.to_string();
        }
    }

    if let Ok(value) = env::var("DOMAIN_NAME") {
        let d = value.trim().trim_end_matches('.');
        if !d.is_empty() {
            if d.eq_ignore_ascii_case("misfits.ai") {
                return "mail.misfits.ai".to_string();
            }
            if d.starts_with("mail.") {
                return d.to_string();
            }
            return format!("mail.{}", d);
        }
    }

    "mail.misfits.ai".to_string()
}

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

fn _parse_email_content(content: &str) -> (HashMap<String, String>, String) {
    let mut headers: HashMap<String, String> = HashMap::new();
    let mut lines = content.lines().peekable();
    let mut body = String::new();
    let mut in_body = false;

    while let Some(line) = lines.next() {
        if in_body {
            body.push_str(line);
            body.push_str("\r\n");
        } else if line.is_empty() {
            in_body = true;
        } else {
            // New header or continuation
            if let Some(index) = line.find(':') {
                let (key, mut value) = line.split_at(index);
                let header_name = key.trim().to_string();
                value = value[1..].trim();

                if header_name == "DKIM-Signature" {
                    let mut full_signature = value.to_string();
                    let mut b_tag_content = String::new();

                    while let Some(next_line) = lines.next() {
                        let trimmed = next_line.trim();
                        if trimmed.is_empty() {
                            break;
                        }
                        if trimmed.starts_with("b=") {
                            b_tag_content.push_str(&trimmed[2..]); // Start capturing from after "b="
                            while !b_tag_content.ends_with('=') {
                                if let Some(next_b_line) = lines.next() {
                                    b_tag_content.push_str(next_b_line.trim());
                                } else {
                                    break; // End of input
                                }
                            }
                            // Add the captured b tag content to full_signature
                            full_signature.push_str("b=");
                            full_signature.push_str(&b_tag_content);
                            break; // We've captured the entire b tag, so we can stop
                        } else {
                            full_signature.push(' ');
                            full_signature.push_str(trimmed);
                        }
                    }
                    println!("Full DKIM-Signature: {}", full_signature);
                    let processed_signature = _process_dkim_signature(&full_signature);
                    eprintln!("Processed DKIM-Signature: {}", processed_signature);
                    headers.insert(header_name, processed_signature);
                } else {
                    // Handle other headers
                    let mut full_value = value.to_string();
                    while let Some(next_line) = lines.peek() {
                        if next_line.starts_with(char::is_whitespace) {
                            full_value.push(' ');
                            full_value.push_str(next_line.trim());
                            lines.next(); // consume the peeked line
                        } else {
                            break;
                        }
                    }
                    headers.insert(header_name.clone(), full_value.clone());
                    eprintln!("Inserted header '{}': {}", header_name, full_value);
                }
            }
        }
    }

    // Process specific headers
    if let Some(from) = headers.get_mut("From") {
        let formatted = _format_email_address(from);
        *from = formatted.clone();
        eprintln!("Formatted 'From' header: {}", formatted);
    }
    if let Some(to) = headers.get_mut("To") {
        let formatted = _format_email_address(to);
        *to = formatted.clone();
        eprintln!("Formatted 'To' header: {}", formatted);
    }
    for (key, value) in &headers {
        eprintln!("Header '{}': {}", key, value);
    }

    (headers, body)
}

fn _process_dkim_signature(signature: &str) -> String {
    // RFC 6376
    let dkim_tags = [
        "v", "a", "b", "bh", "c", "d", "h", "i", "l", "q", "s", "t", "x", "z",
    ];

    let parts: Vec<&str> = signature.split(';').collect();
    let processed_parts: Vec<String> = parts
        .iter()
        .take_while(|&&part| {
            let trimmed = part.trim();
            dkim_tags.iter().any(|&tag| {
                trimmed.starts_with(tag) && trimmed[tag.len()..].trim_start().starts_with('=')
            })
        })
        .map(|&part| {
            let trimmed = part.trim();
            if trimmed.starts_with("b=") {
                // Remove line breaks in 'b' tag value as per DKIM spec
                let b_value = trimmed.splitn(2, '=').nth(1).unwrap_or("");
                format!(
                    "b={}",
                    b_value
                        .lines()
                        .map(|line| line.trim())
                        .collect::<Vec<_>>()
                        .join("")
                )
            } else {
                trimmed.to_string()
            }
        })
        .collect();

    processed_parts.join("; ")
}

fn _format_email_address(addr: &str) -> String {
    if !addr.contains('<') && !addr.contains('>') {
        format!("<{}>", addr.trim())
    } else {
        addr.to_string()
    }
}

fn _validate_email_content(content: &str) -> Result<(), String> {
    let lines: Vec<&str> = content.lines().collect();
    if !lines[0].starts_with("From: <") || !lines[0].ends_with(">") {
        return Err("Invalid From header".to_string());
    }
    if !lines[1].starts_with("To: <") || !lines[1].ends_with(">") {
        return Err("Invalid To header".to_string());
    }
    if !lines[2].starts_with("Subject: ") {
        return Err("Invalid Subject header".to_string());
    }
    if lines[3] != "" {
        return Err("Missing blank line after headers".to_string());
    }
    Ok(())
}
