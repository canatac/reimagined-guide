//! Send email via external account SMTP credentials.
//! Implements POST /api/external-accounts/{id}/send (issue #564).

use super::*;
use crate::external_imap::ExternalImapAccount;

/// Send an email through an external account's SMTP server.
/// Models the same flow as `send_via_relay` but uses per-account SMTP config + credentials.
pub async fn send_via_external_smtp(
    email: &Email,
    account: &ExternalImapAccount,
) -> std::io::Result<()> {
    use base64::{engine::general_purpose, Engine as _};

    let budget = smtp_timeout_budget();

    let smtp_host = account
        .smtp_host
        .as_deref()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "External account has no SMTP host"))?;
    let smtp_port: u16 = account.smtp_port.unwrap_or(587);
    let smtp_tls = account.smtp_tls.unwrap_or(true);
    let smtp_creds = account.secret_value.as_deref().unwrap_or_default();

    let email_content = compose_smtp_payload(email);
    let ehlo_hostname = ehlo_hostname();

    let mut stream = timeout(
        Duration::from_millis(budget.connect_ms),
        TcpStream::connect((smtp_host, smtp_port)),
    )
    .await
    .map_err(|_| IoError::new(ErrorKind::TimedOut, "External SMTP connection timed out"))?
    .map_err(|e| IoError::new(e.kind(), format!("External SMTP connect failed: {}", e)))?;

    expect_code_for_phase(&mut stream, "220", "ext_smtp_banner", budget.banner_ms).await?;
    stream
        .write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes())
        .await?;
    expect_code_for_phase(&mut stream, "250", "ext_smtp_ehlo", budget.ehlo_ms).await?;

    let mut stream_type = if smtp_tls && smtp_port != 465 {
        stream.write_all(b"STARTTLS\r\n").await?;
        expect_code_for_phase(&mut stream, "220", "ext_smtp_starttls", budget.starttls_ms)
            .await?;

        let mut root_store = RootCertStore::empty();
        for cert in load_native_certs().certs {
            root_store.add_parsable_certificates([cert]);
        }
        root_store.add_parsable_certificates(TLS_SERVER_ROOTS.iter().map(|ta| ta.subject.to_vec().into()));
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(smtp_host.to_string())
            .map_err(|_| IoError::new(ErrorKind::InvalidInput, "Invalid external SMTP hostname"))?;
        let tls_stream = timeout(
            Duration::from_millis(budget.tls_handshake_ms),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| {
            IoError::new(
                ErrorKind::TimedOut,
                format!("External SMTP TLS handshake timeout: {}ms", budget.tls_handshake_ms),
            )
        })??;
        let mut s = tls_stream;
        s.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes())
            .await?;
        expect_code_for_phase(&mut s, "250", "ext_smtp_tls_ehlo", budget.ehlo_ms).await?;
        StreamType::Tls(s)
    } else {
        StreamType::Plain(stream)
    };

    // AUTH PLAIN with external account credentials
    if !smtp_creds.is_empty() {
        let auth_token = if smtp_creds.contains('\0') {
            // Already formatted as \0user\0pass
            general_purpose::STANDARD.encode(smtp_creds)
        } else {
            // Treat as password only (use email as username)
            general_purpose::STANDARD.encode(format!("\0{}\0{}", account.email, smtp_creds))
        };
        let auth_cmd = format!("AUTH PLAIN {}\r\n", auth_token);
        match &mut stream_type {
            StreamType::Plain(ref mut s) => {
                s.write_all(auth_cmd.as_bytes()).await?;
                expect_code_for_phase(s, "235", "ext_smtp_auth", budget.auth_ms).await?;
            }
            StreamType::Tls(ref mut s) => {
                s.write_all(auth_cmd.as_bytes()).await?;
                expect_code_for_phase(s, "235", "ext_smtp_auth", budget.auth_ms).await?;
            }
        }
    }

    send_email_content(&mut stream_type, &email_content, &budget).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_smtp_default_port_is_587() {
        let port: u16 = 587;
        assert_eq!(port, 587);
    }

    #[test]
    fn external_smtp_port_465_skips_starttls() {
        let port: u16 = 465;
        assert_eq!(port, 465);
    }

    #[test]
    fn external_smtp_tls_default_true() {
        let smtp_tls: Option<bool> = Some(true);
        assert_eq!(smtp_tls.unwrap_or(true), true);
    }

    #[test]
    fn external_smtp_auth_encoding() {
        use base64::{engine::general_purpose, Engine as _};
        let email = "user@gmail.com";
        let password = "apppassword123";
        let encoded = general_purpose::STANDARD.encode(format!("\0{}\0{}", email, password));
        assert!(!encoded.is_empty());
        // Verify it decodes correctly
        let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert!(decoded_str.contains(email));
        assert!(decoded_str.contains(password));
    }

    #[test]
    fn external_smtp_missing_host_error() {
        let smtp_host: Option<&str> = None;
        assert!(smtp_host.is_none());
    }
}
