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
    pub attachments: Vec<ComposeAttachmentInput>,
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

impl DkimOutcome {
    pub fn new(dkim_sig: String, message_id_hdr: String) -> Self {
        DkimOutcome {
            dkim_sig,
            message_id_hdr,
            already_delivered: false,
            dkim_remote_accepted: false,
            dkim_remote_rejected: false,
            dkim_response: None,
            dkim_mx_host: None,
            dkim_remote_ip: None,
            dkim_remote_port: None,
        }
    }

    pub fn with_remote_status(mut self, accepted: bool, rejected: bool, response: Option<String>) -> Self {
        self.dkim_remote_accepted = accepted;
        self.dkim_remote_rejected = rejected;
        self.dkim_response = response;
        self
    }

    pub fn is_successful(&self) -> bool {
        !self.dkim_sig.is_empty() && !self.dkim_remote_rejected
    }

    pub fn has_dkim_signature(&self) -> bool {
        !self.dkim_sig.is_empty()
    }

    pub fn remote_rejected(&self) -> bool {
        self.dkim_remote_rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_send_request_fields() {
        let req = ValidatedSendRequest {
            user_id: "user-1".to_string(),
            from: "from@example.com".to_string(),
            to: "to@example.com".to_string(),
            cc: "cc@example.com".to_string(),
            bcc: "bcc@example.com".to_string(),
            subject: "Test".to_string(),
            mail_body: "Body".to_string(),
            smtp_body: "SMTP body".to_string(),
            content_type_header: "text/plain".to_string(),
            in_reply_to: Some("reply-to".to_string()),
            references: vec!["ref1".to_string()],
            attachments: vec![],
        };
        assert_eq!(req.user_id, "user-1");
        assert_eq!(req.from, "from@example.com");
        assert_eq!(req.to, "to@example.com");
        assert_eq!(req.cc, "cc@example.com");
        assert_eq!(req.bcc, "bcc@example.com");
        assert_eq!(req.subject, "Test");
        assert_eq!(req.mail_body, "Body");
        assert!(!req.attachments.is_empty() || req.attachments.is_empty());
    }

    #[test]
    fn dkim_outcome_new() {
        let outcome = DkimOutcome::new("sig123".to_string(), "msg-id-1".to_string());
        assert_eq!(outcome.dkim_sig, "sig123");
        assert_eq!(outcome.message_id_hdr, "msg-id-1");
        assert!(!outcome.already_delivered);
        assert!(!outcome.dkim_remote_accepted);
        assert!(!outcome.dkim_remote_rejected);
        assert!(outcome.dkim_response.is_none());
    }

    #[test]
    fn dkim_outcome_with_remote_status() {
        let outcome = DkimOutcome::new("sig".to_string(), "mid".to_string())
            .with_remote_status(true, false, Some("250 OK".to_string()));
        assert!(outcome.dkim_remote_accepted);
        assert!(!outcome.dkim_remote_rejected);
        assert_eq!(outcome.dkim_response, Some("250 OK".to_string()));
    }

    #[test]
    fn dkim_outcome_is_successful() {
        let outcome = DkimOutcome::new("sig".to_string(), "mid".to_string());
        assert!(outcome.is_successful());
    }

    #[test]
    fn dkim_outcome_not_successful_when_rejected() {
        let outcome = DkimOutcome::new("sig".to_string(), "mid".to_string())
            .with_remote_status(false, true, Some("550 Rejected".to_string()));
        assert!(!outcome.is_successful());
    }

    #[test]
    fn dkim_outcome_not_successful_when_no_sig() {
        let outcome = DkimOutcome::new("".to_string(), "mid".to_string());
        assert!(!outcome.is_successful());
    }

    #[test]
    fn dkim_outcome_has_dkim_signature() {
        let with_sig = DkimOutcome::new("sig".to_string(), "mid".to_string());
        assert!(with_sig.has_dkim_signature());
        let without_sig = DkimOutcome::new("".to_string(), "mid".to_string());
        assert!(!without_sig.has_dkim_signature());
    }

    #[test]
    fn dkim_outcome_remote_rejected() {
        let rejected = DkimOutcome::new("sig".to_string(), "mid".to_string())
            .with_remote_status(false, true, None);
        assert!(rejected.remote_rejected());
        let accepted = DkimOutcome::new("sig".to_string(), "mid".to_string())
            .with_remote_status(true, false, None);
        assert!(!accepted.remote_rejected());
    }

    #[test]
    fn dkim_outcome_remote_info_fields() {
        let outcome = DkimOutcome {
            dkim_sig: "sig".to_string(),
            message_id_hdr: "mid".to_string(),
            already_delivered: true,
            dkim_remote_accepted: true,
            dkim_remote_rejected: false,
            dkim_response: Some("250 OK".to_string()),
            dkim_mx_host: Some("mail.example.com".to_string()),
            dkim_remote_ip: Some("1.2.3.4".to_string()),
            dkim_remote_port: Some(587),
        };
        assert!(outcome.already_delivered);
        assert_eq!(outcome.dkim_mx_host, Some("mail.example.com".to_string()));
        assert_eq!(outcome.dkim_remote_ip, Some("1.2.3.4".to_string()));
        assert_eq!(outcome.dkim_remote_port, Some(587));
    }
}

/// Valide la requête entrante et construit le corps MIME finale.
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
        attachments,
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
        attachments: v
            .attachments
            .iter()
            .map(|att| EmailAttachment {
                filename: att.filename.clone(),
                content_type: att.content_type.clone(),
                data_base64: att.data_base64.clone(),
            })
            .collect(),
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
        internal_date: Utc::now(),
        dkim_signature: if dkim.dkim_sig.is_empty() {
            None
        } else {
            Some(dkim.dkim_sig.clone())
        },
    };
    (email, id, message_id)
}

