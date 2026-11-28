//! MTA-STS and the delivery to an MX on port 25 (#856).
//!
//! An integration test: the unit tests of the lib do not compile on master.

use simple_smtp_server::smtp_client::{mta_sts_port_check, mx_handshake_for_tests, MtaStsResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn a_policy_requiring_tls_allows_the_delivery_on_port_25() {
    // RFC 8461: the delivery to an MX is on port 25 with STARTTLS.
    assert!(mta_sts_port_check(&MtaStsResult::TlsRequired, 25, "example.com").is_ok());
    assert!(mta_sts_port_check(&MtaStsResult::TlsRequired, 587, "example.com").is_ok());
}

#[test]
fn without_a_policy_every_port_is_allowed() {
    assert!(mta_sts_port_check(&MtaStsResult::NoPolicy, 25, "example.com").is_ok());
    assert!(mta_sts_port_check(&MtaStsResult::NoPolicy, 465, "example.com").is_ok());
}

#[test]
fn a_policy_requiring_tls_refuses_a_port_left_in_clear() {
    // The handshake never encrypts port 465 (no implicit TLS).
    let err = mta_sts_port_check(&MtaStsResult::TlsRequired, 465, "example.com").unwrap_err();
    assert!(err.contains("requires TLS"), "{}", err);
}

/// A fake MX that refuses STARTTLS; returns the commands it received.
async fn mx_refusing_starttls() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        sock.write_all(b"220 fake mx\r\n").await.unwrap();
        loop {
            let n = match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let line = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            let answer: &[u8] = if line.starts_with("EHLO") {
                b"250 fake mx\r\n"
            } else if line.starts_with("STARTTLS") {
                b"454 4.7.0 TLS not available\r\n"
            } else {
                b"250 ok\r\n"
            };
            received.push(line);
            if sock.write_all(answer).await.is_err() {
                break;
            }
        }
        received
    });
    (port, server)
}

#[tokio::test]
async fn the_delivery_on_port_25_never_falls_back_to_clear() {
    // Allowing port 25 under MTA-STS is safe only because the handshake
    // fails when STARTTLS is refused, before any MAIL FROM.
    let (port, server) = mx_refusing_starttls().await;
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let result = mx_handshake_for_tests(stream, "localhost", 25).await;
    assert!(result.is_err(), "a refused STARTTLS must fail the delivery");
    let received = server.await.unwrap();
    assert!(
        received.iter().any(|c| c.starts_with("STARTTLS")),
        "{:?}",
        received
    );
    assert!(
        !received.iter().any(|c| c.starts_with("MAIL FROM")),
        "{:?}",
        received
    );
}
