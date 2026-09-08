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

use rustls::pki_types::ServerName;
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
use webpki_roots::TLS_SERVER_ROOTS;
pub(crate) const SMTP_PORTS: [u16; 3] = [25, 587, 465];
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy)]
pub(crate) struct SmtpTimeoutBudget {
    pub dns_ms: u64,
    pub port_probe_ms: u64,
    pub connect_ms: u64,
    pub banner_ms: u64,
    pub ehlo_ms: u64,
    pub starttls_ms: u64,
    pub tls_handshake_ms: u64,
    pub mail_from_ms: u64,
    pub rcpt_to_ms: u64,
    pub data_ms: u64,
    pub body_ms: u64,
    pub quit_ms: u64,
    pub auth_ms: u64,
}

fn timeout_env_ms(key: &str, default_ms: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default_ms)
}

pub(crate) fn smtp_timeout_budget() -> SmtpTimeoutBudget {
    SmtpTimeoutBudget {
        dns_ms: timeout_env_ms("SMTP_TIMEOUT_DNS_MS", 3000),
        port_probe_ms: timeout_env_ms("SMTP_TIMEOUT_PORT_PROBE_MS", CONNECTION_TIMEOUT.as_millis() as u64),
        connect_ms: timeout_env_ms("SMTP_TIMEOUT_CONNECT_MS", 10000),
        banner_ms: timeout_env_ms("SMTP_TIMEOUT_BANNER_MS", 5000),
        ehlo_ms: timeout_env_ms("SMTP_TIMEOUT_EHLO_MS", 5000),
        starttls_ms: timeout_env_ms("SMTP_TIMEOUT_STARTTLS_MS", 5000),
        tls_handshake_ms: timeout_env_ms("SMTP_TIMEOUT_TLS_HANDSHAKE_MS", 10000),
        mail_from_ms: timeout_env_ms("SMTP_TIMEOUT_MAIL_FROM_MS", 5000),
        rcpt_to_ms: timeout_env_ms("SMTP_TIMEOUT_RCPT_TO_MS", 7000),
        data_ms: timeout_env_ms("SMTP_TIMEOUT_DATA_MS", 10000),
        body_ms: timeout_env_ms("SMTP_TIMEOUT_BODY_MS", 20000),
        quit_ms: timeout_env_ms("SMTP_TIMEOUT_QUIT_MS", 3000),
        auth_ms: timeout_env_ms("SMTP_TIMEOUT_AUTH_MS", 7000),
    }
}

#[cfg(test)]
mod timeout_budget_tests {
    use super::*;

    #[test]
    fn timeout_budget_defaults_are_positive() {
        let b = smtp_timeout_budget();
        assert!(b.dns_ms > 0);
        assert!(b.connect_ms > 0);
        assert!(b.tls_handshake_ms > 0);
    }

    #[test]
    fn timeout_budget_reads_env_override() {
        std::env::set_var("SMTP_TIMEOUT_CONNECT_MS", "4242");
        let b = smtp_timeout_budget();
        assert_eq!(b.connect_ms, 4242);
        std::env::remove_var("SMTP_TIMEOUT_CONNECT_MS");
    }
}

use crate::entities::Email;

#[allow(clippy::large_enum_variant)]
enum StreamType {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

// Sous-modules extraits pour clean code (refactor architecte).
mod body_utils;
mod discovery;
mod relay;
mod mx;
mod session;

use body_utils::compose_smtp_payload;
use discovery::{find_smtp_port, expect_code_for_phase, ehlo_hostname};
use relay::send_via_relay;
use mx::send_via_mx;
use session::send_email_content;
pub use session::extract_email_address;

pub async fn send_outgoing_email(email: &Email) -> std::io::Result<()> {
    if let Ok(relay_host) = env::var("SMTP_RELAY_HOST") {
        return send_via_relay(email, &relay_host).await;
    }
    send_via_mx(email).await
}
