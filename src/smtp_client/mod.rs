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
mod relay;
mod mx;
mod session;

use body_utils::compose_smtp_payload;
use discovery::{find_smtp_port, expect_code, ehlo_hostname};
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
