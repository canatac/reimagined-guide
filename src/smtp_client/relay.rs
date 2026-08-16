use super::*;

pub(super) async fn send_via_relay(email: &Email, relay_host: &str) -> std::io::Result<()> {
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
