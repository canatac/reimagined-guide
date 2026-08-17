//! Contexte d'envoi + émission d'événements de monitoring pour `mx.rs`.
//! Extrait de `mx.rs` (cycle 39) pour maintenir chaque fichier sous le seuil LOC.

use super::*;
use crate::entities::Email;

/// Contexte partagé pour l'émission d'événements de monitoring pendant l'envoi.
pub(super) struct SendContext {
    pub(super) message_id: String,
    pub(super) correlation_id: String,
    pub(super) from: String,
    pub(super) to: String,
    pub(super) mon: bool,
}

impl SendContext {
    pub(super) fn from_email(email: &Email) -> Self {
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

    pub(super) fn emit(&self, ev_type: crate::monitoring::SmtpEventType) -> crate::monitoring::SmtpEvent {
        let mut ev = crate::monitoring::SmtpEvent::new(&self.message_id, ev_type, &self.from, &self.to);
        ev.correlation_id = self.correlation_id.clone();
        ev
    }

    pub(super) fn emit_bounce_soft(
        &self,
        reason: String,
        mx_host: Option<String>,
        remote_ip: Option<String>,
        total_ms: Option<u64>,
        dns_ms: Option<u64>,
    ) {
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

/// Enrichissement GeoIP + émission asynchrone de l'événement SmtpConnect.
pub(super) fn spawn_connect_event(ctx: &SendContext, remote_ip: String, mx: String, port: u16, connect_ms: u64) {
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

/// Émet l'événement Delivered ou Bounced selon le résultat de la transaction SMTP.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_final_event(
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
