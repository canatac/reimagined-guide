//! Découverte de port SMTP + helpers protocole (expect_code, ehlo_hostname).
//! Extraits de mod.rs (refactor architecte).

use std::env;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{smtp_timeout_budget, SMTP_PORTS};

pub(crate) async fn test_smtp_port(host: &str, port: u16) -> bool {
    matches!(
        timeout(CONNECTION_TIMEOUT, TcpStream::connect((host, port))).await,
        Ok(Ok(_))
    )
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
    let budget = smtp_timeout_budget();
    expect_code_for_phase(stream, expected, "smtp_response", budget.data_ms).await
}

pub(crate) async fn expect_code_for_phase<T: AsyncReadExt + Unpin>(
    stream: &mut T,
    expected: &str,
    phase: &str,
    timeout_ms: u64,
) -> std::io::Result<()> {
    let mut response = [0; 1024];
    let mut acc = String::new();

    for _ in 0..16 {
        let n = timeout(Duration::from_millis(timeout_ms), stream.read(&mut response))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("SMTP phase timeout [{}]: waited {}ms for code {}", phase, timeout_ms, expected),
                )
            })??;
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
                return Err(std::io::Error::other(format!(
                    "Unexpected response: {}",
                    acc
                )));
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("SMTP phase timeout [{}]: waiting code {} response after {}ms: {}", phase, expected, timeout_ms, acc),
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

