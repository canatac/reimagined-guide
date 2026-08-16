use super::*;

/// Contexte partagé pour l'émission d'événements de monitoring pendant l'envoi.
struct SendContext {
    message_id: String,
    correlation_id: String,
    from: String,
    to: String,
    mon: bool,
}

impl SendContext {
    fn from_email(email: &Email) -> Self {
        let message_id = email
            .headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == "message-id")
            .map(|(_, v)| v.trim_matches(|c| c == '<' || c == '>').to_string())
            .unwrap_or_else(|| email.id.clone());
        Self {
            message_id,
            correlation_id: Uuid::new_v4().to_string(),
            from: email.from.clone(),
            to: email.to.clone(),
            mon: crate::monitoring::monitoring_enabled(),
        }
    }

    fn emit(&self, ev_type: crate::monitoring::SmtpEventType) -> crate::monitoring::SmtpEvent {
        let mut ev = crate::monitoring::SmtpEvent::new(&self.message_id, ev_type, &self.from, &self.to);
        ev.correlation_id = self.correlation_id.clone();
        ev
    }

    fn emit_bounce_soft(&self, reason: String, mx_host: Option<String>, remote_ip: Option<String>, total_ms: Option<u64>, dns_ms: Option<u64>) {
        if !self.mon {
            return;
        }
        let mut ev = self.emit(crate::monitoring::SmtpEventType::Bounced);
        ev.mx_host = mx_host;
        ev.remote_ip = remote_ip;
        ev.total_ms = total_ms;
        ev.dns_ms = dns_ms;
        ev.status = crate::monitoring::SmtpStatus::Failed;
        ev.bounce_type = Some(crate::monitoring::BounceType::Soft);
        ev.bounce_reason = Some(reason);
        crate::monitoring::emit(ev);
    }
}

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

/// Enrichissement GeoIP + émission asynchrone de l'événement SmtpConnect.
fn spawn_connect_event(ctx: &SendContext, remote_ip: String, mx: String, port: u16, connect_ms: u64) {
    if !ctx.mon {
        return;
    }
    let mid = ctx.message_id.clone();
    let cid = ctx.correlation_id.clone();
    let from = ctx.from.clone();
    let to = ctx.to.clone();
    tokio::spawn(async move {
        let geo = crate::monitoring::enrichment::enrich_ip(&remote_ip).await;
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

/// Émet l'événement Delivered ou Bounced selon le résultat de la transaction SMTP.
fn emit_final_event(
    ctx: &SendContext,
    result: &std::io::Result<()>,
    smtp_server: &str,
    remote_ip: &str,
    dns_ms: u64,
    connect_ms: u64,
    tls_ms: u64,
    total_ms: u64,
) {
    if !ctx.mon {
        return;
    }
    match result {
        Ok(_) => {
            let mut ev = ctx.emit(crate::monitoring::SmtpEventType::Delivered);
            ev.mx_host = Some(smtp_server.to_string());
            ev.remote_ip = Some(remote_ip.to_string());
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
            let mut ev = ctx.emit(crate::monitoring::SmtpEventType::Bounced);
            ev.mx_host = Some(smtp_server.to_string());
            ev.remote_ip = Some(remote_ip.to_string());
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
