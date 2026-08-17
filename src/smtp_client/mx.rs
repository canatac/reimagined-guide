use super::*;

#[path = "mx_events.rs"]
mod events;
use events::{SendContext, spawn_connect_event, emit_final_event};

/// Résolution DNS + sélection du premier MX record et du port SMTP ouvert.
async fn resolve_mx_target(
    domain: &str,
    ctx: &SendContext,
    t_total: Instant,
) -> std::io::Result<(String, u16, u64)> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let t_dns = Instant::now();
    let mx_lookup = resolver.mx_lookup(domain).await.map_err(|e| {
        let dns_ms = t_dns.elapsed().as_millis() as u64;
        ctx.emit_bounce_soft(
            format!("MX lookup failed: {}", e),
            None,
            None,
            Some(t_total.elapsed().as_millis() as u64),
            Some(dns_ms),
        );
        IoError::new(ErrorKind::Other, format!("MX lookup failed: {}", e))
    })?;
    let dns_ms = t_dns.elapsed().as_millis() as u64;

    let mx_records: Vec<_> = mx_lookup.iter().collect();
    if mx_records.is_empty() {
        ctx.emit_bounce_soft("No MX records found".into(), None, None, None, Some(dns_ms));
        return Err(IoError::new(ErrorKind::Other, "No MX records found"));
    }

    if ctx.mon {
        let mut ev = ctx.emit(crate::monitoring::SmtpEventType::DnsLookup);
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
            if ctx.mon {
                let mut ev = ctx.emit(crate::monitoring::SmtpEventType::MxSelected);
                ev.mx_host = Some(smtp_server.clone());
                ev.remote_port = Some(port);
                crate::monitoring::emit(ev);
            }
            port
        }
        None => {
            ctx.emit_bounce_soft(
                "No open SMTP ports found".into(),
                Some(smtp_server.clone()),
                None,
                Some(t_total.elapsed().as_millis() as u64),
                Some(dns_ms),
            );
            return Err(IoError::new(ErrorKind::Other, "No open SMTP ports found"));
        }
    };

    Ok((smtp_server, smtp_port, dns_ms))
}

/// EHLO + STARTTLS + second EHLO chiffré. Retourne le stream prêt pour MAIL FROM.
async fn perform_smtp_handshake(
    mut stream: TcpStream,
    smtp_server: String,
    smtp_port: u16,
) -> std::io::Result<(StreamType, u64)> {
    expect_code(&mut stream, "220").await?;
    let ehlo_hostname = ehlo_hostname();
    stream.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
    expect_code(&mut stream, "250").await?;

    let t_tls = Instant::now();
    let mut stream_type = if smtp_port != 465 {
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
        let server_name = ServerName::try_from(smtp_server)
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
        if let StreamType::Plain(ref mut s) = &mut stream_type {
            s.write_all(format!("EHLO {}\r\n", ehlo_hostname).as_bytes()).await?;
            expect_code(s, "250").await?;
        }
    }

    Ok((stream_type, tls_ms))
}

pub(super) async fn send_via_mx(email: &Email) -> std::io::Result<()> {
    let t_total = Instant::now();
    let ctx = SendContext::from_email(email);

    if ctx.mon {
        crate::monitoring::emit(ctx.emit(crate::monitoring::SmtpEventType::Accepted));
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
    let (smtp_server, smtp_port, dns_ms) = resolve_mx_target(recipient_domain, &ctx, t_total).await?;

    println!("Connecting to {}:{}", smtp_server, smtp_port);
    let t_connect = Instant::now();
    let stream = TcpStream::connect((smtp_server.as_str(), smtp_port)).await?;
    let remote_ip = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let connect_ms = t_connect.elapsed().as_millis() as u64;

    spawn_connect_event(&ctx, remote_ip.clone(), smtp_server.clone(), smtp_port, connect_ms);
    println!("Connected successfully");

    let (mut stream_type, tls_ms) = match perform_smtp_handshake(stream, smtp_server.clone(), smtp_port).await {
        Ok(v) => v,
        Err(e) => {
            ctx.emit_bounce_soft(
                format!("TLS/SMTP handshake failed: {}", e),
                Some(smtp_server.clone()),
                Some(remote_ip.clone()),
                Some(t_total.elapsed().as_millis() as u64),
                Some(dns_ms),
            );
            return Err(e);
        }
    };

    if ctx.mon {
        let mut ev = ctx.emit(crate::monitoring::SmtpEventType::TlsOk);
        ev.mx_host = Some(smtp_server.clone());
        ev.remote_ip = Some(remote_ip.clone());
        ev.tls_ms = Some(tls_ms);
        crate::monitoring::emit(ev);
    }

    let result = send_email_content(&mut stream_type, &email_content).await;
    let total_ms = t_total.elapsed().as_millis() as u64;

    emit_final_event(&ctx, &result, &smtp_server, &remote_ip, dns_ms, connect_ms, tls_ms, total_ms);
    result
}
