//! SMTP connection pool for relay reuse.
//!
//! Keeps authenticated TLS connections alive after a send so that
//! sequential emails to the same relay host skip TCP+TLS handshake + AUTH.

use std::collections::{HashMap, VecDeque};
use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use super::{
    expect_code_for_phase, smtp_timeout_budget, ehlo_hostname, StreamType,
    send_email_content, compose_smtp_payload,
};
use crate::entities::Email;

/// Maximum number of idle connections kept per relay host.
pub fn max_idle() -> usize {
    env::var("SMTP_POOL_MAX_IDLE")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|v: &usize| *v > 0)
        .unwrap_or(4)
}

/// Maximum total (idle + in-use) connections per relay host.
pub fn max_active() -> usize {
    env::var("SMTP_POOL_MAX_ACTIVE")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|v: &usize| *v > 0)
        .unwrap_or(8)
}

/// How long an idle connection stays in the pool before being dropped.
pub fn idle_timeout() -> Duration {
    Duration::from_secs(
        env::var("SMTP_POOL_IDLE_TIMEOUT_S")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .filter(|v: &u64| *v > 0)
            .unwrap_or(60),
    )
}

/// A pooled, authenticated SMTP connection.
struct PooledConnection {
    stream: StreamType,
    last_used: Instant,
}

impl PooledConnection {
    fn is_expired(&self) -> bool {
        self.last_used.elapsed() > idle_timeout()
    }
}

/// Per-host pool state.
struct HostPool {
    idle: VecDeque<PooledConnection>,
    active_count: usize,
}

impl HostPool {
    fn new() -> Self {
        Self {
            idle: VecDeque::new(),
            active_count: 0,
        }
    }

    fn total(&self) -> usize {
        self.idle.len() + self.active_count
    }
}

/// Global connection pool keyed by `host:port`.
type PoolMap = Arc<Mutex<HashMap<String, HostPool>>>;

lazy_static::lazy_static! {
    static ref POOL: PoolMap = Arc::new(Mutex::new(HashMap::new()));
}

pub fn relay_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

/// Send an email via the relay, using a pooled connection when available.
pub async fn send_via_relay_pooled(email: &Email, relay_host: &str) -> std::io::Result<()> {
    let relay_port: u16 = env::var("SMTP_RELAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(587);

    let key = relay_key(relay_host, relay_port);

    // Try to acquire an idle connection.
    let pooled: Option<PooledConnection> = {
        let mut pools = POOL.lock().await;
        let pool = pools.entry(key.clone()).or_insert_with(HostPool::new);
        pool.active_count += 1;
        while let Some(mut conn) = pool.idle.pop_front() {
            if conn.is_expired() {
                continue;
            }
            conn.last_used = Instant::now();
            return send_with_pooled(email, conn.stream, key).await;
        }
        None
    };

    if pooled.is_none() {
        // No idle connection — check capacity before creating new.
        {
            let pools = POOL.lock().await;
            if let Some(pool) = pools.get(&key) {
                if pool.total() >= max_active() {
                    let mut pools = POOL.lock().await;
                    if let Some(p) = pools.get_mut(&key) {
                        p.active_count -= 1;
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("SMTP pool exhausted for {} (max {})", key, max_active()),
                    ));
                }
            }
        }

        // Establish new connection.
        let stream = establish_relay_connection(relay_host, relay_port).await?;
        send_with_existing(email, stream, key).await
    } else {
        unreachable!()
    }
}

async fn send_with_pooled(
    email: &Email,
    mut stream: StreamType,
    key: String,
) -> std::io::Result<()> {
    // RSET to reuse the connection (reset SMTP session state).
    let rset_ok = match &mut stream {
        StreamType::Plain(s) => {
            s.write_all(b"RSET\r\n").await.ok();
            expect_code_for_phase(s, "250", "pool_rset", 3000).await.ok().is_some()
        }
        StreamType::Tls(s) => {
            s.write_all(b"RSET\r\n").await.ok();
            expect_code_for_phase(s, "250", "pool_rset", 3000).await.ok().is_some()
        }
    };

    if !rset_ok {
        // Connection is stale — establish new one.
        let mut pools = POOL.lock().await;
        if let Some(p) = pools.get_mut(&key) {
            p.active_count -= 1;
        }
        let stream = establish_relay_connection_from_key(&key).await?;
        return send_with_existing(email, stream, key).await;
    }

    let budget = smtp_timeout_budget();
    let email_content = compose_smtp_payload(email);
    let result = send_email_content(&mut stream, &email_content, &budget).await;

    return_connection_to_pool(&key, stream, result.is_ok()).await;
    result
}

async fn send_with_existing(
    email: &Email,
    mut stream: StreamType,
    key: String,
) -> std::io::Result<()> {
    let budget = smtp_timeout_budget();
    let email_content = compose_smtp_payload(email);
    let result = send_email_content(&mut stream, &email_content, &budget).await;

    return_connection_to_pool(&key, stream, result.is_ok()).await;
    result
}

async fn return_connection_to_pool(key: &str, stream: StreamType, success: bool) {
    let mut pools = POOL.lock().await;
    let pool = pools.entry(key.to_string()).or_insert_with(HostPool::new);
    pool.active_count -= 1;
    if success && pool.idle.len() < max_idle() {
        pool.idle.push_back(PooledConnection {
            stream,
            last_used: Instant::now(),
        });
    }
    // else: drop connection (it will close naturally)
}

async fn establish_relay_connection_from_key(key: &str) -> std::io::Result<StreamType> {
    let parts: Vec<&str> = key.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid relay key: {}", key),
        ));
    }
    let port: u16 = parts[0].parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid port in relay key")
    })?;
    let host = parts[1];
    establish_relay_connection(host, port).await
}

/// Establish a fresh authenticated TLS connection to the relay.
async fn establish_relay_connection(
    relay_host: &str,
    relay_port: u16,
) -> std::io::Result<StreamType> {
    use base64::{engine::general_purpose, Engine as _};
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use rustls_native_certs::load_native_certs;
    use std::convert::TryFrom;
    use std::io::{Error as IoError, ErrorKind};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::sync::Arc;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;
    use webpki_roots::TLS_SERVER_ROOTS;

    let budget = smtp_timeout_budget();
    let relay_user = env::var("SMTP_RELAY_USER").unwrap_or_default();
    let relay_pass = env::var("SMTP_RELAY_PASSWORD").unwrap_or_default();
    let ehlo_hostname = ehlo_hostname();

    let mut stream = timeout(
        Duration::from_millis(budget.connect_ms),
        TcpStream::connect((relay_host, relay_port)),
    )
    .await
    .map_err(|_| IoError::new(ErrorKind::TimedOut, "Relay connection timed out"))?
    .map_err(|e| IoError::new(e.kind(), format!("Relay connect failed: {}", e)))?;

    expect_code_for_phase(&mut stream, "220", "relay_banner", budget.banner_ms).await?;
    stream
        .write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes())
        .await?;
    expect_code_for_phase(&mut stream, "250", "relay_ehlo", budget.ehlo_ms).await?;

    let mut stream_type = if relay_port != 465 {
        stream.write_all(b"STARTTLS\r\n").await?;
        expect_code_for_phase(&mut stream, "220", "relay_starttls_ack", budget.starttls_ms)
            .await?;

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
        let tls_stream = timeout(
            Duration::from_millis(budget.tls_handshake_ms),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| {
            IoError::new(
                ErrorKind::TimedOut,
                format!(
                    "SMTP phase timeout [relay_tls_handshake]: {}ms",
                    budget.tls_handshake_ms
                ),
            )
        })??;
        let mut s = tls_stream;
        s.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes())
            .await?;
        expect_code_for_phase(&mut s, "250", "relay_tls_ehlo", budget.ehlo_ms).await?;
        StreamType::Tls(s)
    } else {
        StreamType::Plain(stream)
    };

    if !relay_user.is_empty() {
        let cred = general_purpose::STANDARD.encode(format!("\0{}\0{}", relay_user, relay_pass));
        let auth_cmd = format!("AUTH PLAIN {}\r\n", cred);
        match &mut stream_type {
            StreamType::Plain(s) => {
                s.write_all(auth_cmd.as_bytes()).await?;
                expect_code_for_phase(s, "235", "relay_auth", budget.auth_ms).await?;
            }
            StreamType::Tls(s) => {
                s.write_all(auth_cmd.as_bytes()).await?;
                expect_code_for_phase(s, "235", "relay_auth", budget.auth_ms).await?;
            }
        }
    }

    Ok(stream_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_key_format() {
        assert_eq!(relay_key("smtp.example.com", 587), "smtp.example.com:587");
        assert_eq!(relay_key("mail.relay.io", 465), "mail.relay.io:465");
    }

    #[test]
    fn max_idle_default() {
        assert_eq!(max_idle(), 4);
    }

    #[test]
    fn max_active_default() {
        assert_eq!(max_active(), 8);
    }

    #[test]
    fn idle_timeout_default() {
        assert_eq!(idle_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn host_pool_new_is_empty() {
        let pool = HostPool::new();
        assert_eq!(pool.total(), 0);
        assert!(pool.idle.is_empty());
    }

    #[test]
    fn host_pool_total_counts() {
        let mut pool = HostPool::new();
        pool.active_count = 3;
        assert_eq!(pool.total(), 3);
    }
}
