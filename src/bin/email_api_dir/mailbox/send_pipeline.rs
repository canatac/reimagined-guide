// Sprint 8: split from mailbox_handlers.rs
#![allow(unused_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Refactor Sprint : la God Function `api_send` a été découpée en helpers
// pub(crate) ci-dessous. `api_send` orchestre désormais uniquement le pipeline.
// Comportement HTTP et effets de bord strictement identiques à l'implémentation
// originale (validation, résolution `from`, signature DKIM, mise en file
// d'attente ou envoi immédiat, persistance, émission d'événement SSE).
// ---------------------------------------------------------------------------

pub(crate) struct ValidatedSendRequest {
    pub user_id: String,
    pub from: String,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub mail_body: String,
    pub smtp_body: String,
    pub content_type_header: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

pub(crate) struct DkimOutcome {
    pub dkim_sig: String,
    pub message_id_hdr: String,
    pub already_delivered: bool,
    pub dkim_remote_accepted: bool,
    pub dkim_remote_rejected: bool,
    pub dkim_response: Option<String>,
    pub dkim_mx_host: Option<String>,
    pub dkim_remote_ip: Option<String>,
    pub dkim_remote_port: Option<u16>,
}

/// Valide la requête entrante et construit le corps MIME final.
pub(crate) fn validate_send_request(
    body: &ComposeSendRequest,
    req: &actix_web::HttpRequest,
) -> Result<ValidatedSendRequest, HttpResponse> {
    let user_id = resolve_user_id(req);
    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return Err(HttpResponse::BadRequest().json(serde_json::json!({
            "sent": false,
            "message": "At least one recipient (to) is required",
        })));
    }
    let cc = join_recipients(&body.cc);
    let bcc = join_recipients(&body.bcc);
    let subject = body.subject.clone();
    let mail_body = body.body.clone();
    let attachments = body
        .attachments
        .iter()
        .filter(|a| !a.filename.trim().is_empty() && !a.data_base64.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>();
    let (smtp_body, content_type_header) = match build_body_with_attachments(&mail_body, &attachments) {
        Ok(v) => v,
        Err(e) => {
            return Err(HttpResponse::BadRequest().json(serde_json::json!({
                "sent": false,
                "message": e,
            })))
        }
    };
    let in_reply_to = body
        .in_reply_to
        .as_deref()
        .and_then(canonical_message_id);
    let references = body
        .references
        .iter()
        .filter_map(|r| canonical_message_id(r))
        .collect::<Vec<_>>();

    Ok(ValidatedSendRequest {
        user_id,
        from,
        to,
        cc,
        bcc,
        subject,
        mail_body,
        smtp_body,
        content_type_header,
        in_reply_to,
        references,
    })
}

/// Signe le courriel via le service DKIM partagé et interprète sa réponse.
pub(crate) async fn apply_dkim_signature(
    v: &ValidatedSendRequest,
) -> Result<DkimOutcome, HttpResponse> {
    let email_req = EmailRequest {
        from: v.from.clone(),
        to: v.to.clone(),
        subject: v.subject.clone(),
        body: v.mail_body.clone(),
    };
    let dkim_service: Box<dyn DkimService> = Box::new(RealDkimService);
    match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            let status = dkim_result["status"].as_str().unwrap_or("");
            if status != "success" {
                let msg = dkim_result["message"]
                    .as_str()
                    .or_else(|| dkim_result["error"].as_str())
                    .unwrap_or("DKIM signing failed");
                return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                    "sent": false,
                    "message": format!("Failed to sign email: {}", msg),
                })));
            }

            let sig = dkim_result["dkimSignature"]
                .as_str()
                .or_else(|| dkim_result["dkim_signature"].as_str())
                .unwrap_or("")
                .to_string();
            let mid = dkim_result["messageId"]
                .as_str()
                .or_else(|| dkim_result["message_id"].as_str())
                .unwrap_or("")
                .to_string();

            let accepted_by_remote_mx =
                dkim_result["acceptedByRemoteMx"].as_bool().unwrap_or(false)
                    || dkim_result["accepted"]
                        .as_array()
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
            let rejected_by_remote_mx = dkim_result["rejected"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let upstream_response = dkim_result["response"].as_str().map(|s| s.to_string());
            let upstream_mx_host = dkim_result["smtpHost"].as_str().map(|s| s.to_string());
            let upstream_remote_ip = dkim_result["remoteIp"].as_str().map(|s| s.to_string());
            let upstream_remote_port = dkim_result["smtpPort"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok());

            let internal_hop = is_internal_delivery_hop(
                upstream_mx_host.as_deref(),
                upstream_remote_ip.as_deref(),
                upstream_remote_port,
                Some("dkim-service"),
            );
            let effective_remote_accept = accepted_by_remote_mx && !internal_hop;

            let delivered = sig.is_empty() && accepted_by_remote_mx;
            if sig.is_empty() && !delivered {
                return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                        "sent": false,
                        "message": "DKIM signer returned success without signature and without SMTP handoff proof; refusing unsigned send",
                    })));
            }
            Ok(DkimOutcome {
                dkim_sig: sig,
                message_id_hdr: mid,
                already_delivered: delivered,
                dkim_remote_accepted: effective_remote_accept,
                dkim_remote_rejected: rejected_by_remote_mx,
                dkim_response: upstream_response,
                dkim_mx_host: upstream_mx_host,
                dkim_remote_ip: upstream_remote_ip,
                dkim_remote_port: upstream_remote_port,
            })
        }
        Err(e) => {
            eprintln!("DKIM service error on /api/send: {}", e);
            Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "message": format!("Failed to generate DKIM signature: {}", e),
            })))
        }
    }
}

/// Construit l'objet `Email` final (identifiant, Message-ID, en-têtes).
pub(crate) fn build_email_and_message_id(
    v: &ValidatedSendRequest,
    dkim: &DkimOutcome,
) -> (Email, String, String) {
    let id = Uuid::new_v4().to_string();
    let message_id = if dkim.message_id_hdr.is_empty() {
        format!("<{}@{}>", id, domain_from_env())
    } else if dkim.message_id_hdr.starts_with('<') {
        dkim.message_id_hdr.clone()
    } else {
        format!("<{}>", dkim.message_id_hdr)
    };

    let mut headers = vec![
        ("Message-ID".to_string(), message_id.clone()),
        ("Date".to_string(), Utc::now().to_rfc2822()),
        ("MIME-Version".to_string(), "1.0".to_string()),
        ("Content-Type".to_string(), v.content_type_header.clone()),
    ];
    if !v.cc.is_empty() {
        headers.push(("Cc".to_string(), v.cc.clone()));
    }
    if !v.bcc.is_empty() {
        headers.push(("Bcc".to_string(), v.bcc.clone()));
    }
    if !dkim.dkim_sig.is_empty() {
        headers.push(("DKIM-Signature".to_string(), dkim.dkim_sig.clone()));
    }
    if let Some(in_reply_to) = &v.in_reply_to {
        headers.push(("In-Reply-To".to_string(), in_reply_to.clone()));
    }
    if !v.references.is_empty() {
        headers.push(("References".to_string(), v.references.join(" ")));
    }

    let email = Email {
        id: id.clone(),
        from: v.from.clone(),
        to: v.to.clone(),
        subject: v.subject.clone(),
        body: v.smtp_body.clone(),
        headers,
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: if dkim.dkim_sig.is_empty() {
            None
        } else {
            Some(dkim.dkim_sig.clone())
        },
    };
    (email, id, message_id)
}

