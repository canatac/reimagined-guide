//! Découverte de port SMTP + helpers protocole (expect_code, ehlo_hostname).
//! Extraits de mod.rs (refactor architecte).

use std::env;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{SMTP_PORTS, CONNECTION_TIMEOUT};

pub(crate) async fn test_smtp_port(host: &str, port: u16) -> bool {
    match timeout(CONNECTION_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

pub(crate) async fn find_smtp_port(host: &str) -> Option<u16> {
    for &port in &SMTP_PORTS {
        if test_smtp_port(host, port).await {
            return Some(port);
        }
    }
    None
}

pub(crate) async fn expect_code<T: AsyncReadExt + Unpin>(
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
pub(crate) fn ehlo_hostname() -> String {
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

