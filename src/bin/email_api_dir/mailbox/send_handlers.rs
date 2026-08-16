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

/// Met en file d'attente le message si une fenêtre d'annulation est configurée.
pub(crate) async fn maybe_enqueue_for_undo(
    v: &ValidatedSendRequest,
    dkim: &DkimOutcome,
    email: &Email,
    id: &str,
    message_id: &str,
    mongo: &Arc<mongodb::Client>,
) -> Option<HttpResponse> {
    let undo_window_secs = env::var("SEND_UNDO_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    if undo_window_secs == 0 || dkim.already_delivered {
        return None;
    }
    let send_after = bson::DateTime::from_millis(
        Utc::now().timestamp_millis() + (undo_window_secs as i64 * 1000),
    );
    let queue_doc = doc! {
        "id": id,
        "user_id": &v.user_id,
        "from": &v.from,
        "to": &v.to,
        "cc": &v.cc,
        "bcc": &v.bcc,
        "subject": &v.subject,
        "body": &v.smtp_body,
        "content_type": &v.content_type_header,
        "dkim_signature": email.dkim_signature.as_deref().unwrap_or(""),
        "message_id": message_id,
        "in_reply_to": v.in_reply_to.as_deref().unwrap_or(""),
        "references": &v.references,
        "status": "pending",
        "send_after": send_after,
        "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
    };
    let db = mongo_db_name();
    let sq_coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    Some(match sq_coll.insert_one(queue_doc).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "sent": false,
            "queued": true,
            "id": id,
            "messageId": message_id,
            "deliveryState": "pending",
            "undoWindowSecs": undo_window_secs,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "sent": false, "error": e.to_string()
        })),
    })
}

/// Envoi effectif, persistance « Sent » et émission d'événement SSE.
pub(crate) async fn dispatch_and_finalize(
    v: &ValidatedSendRequest,
    dkim: &DkimOutcome,
    email: &Email,
    id: &str,
    message_id: &str,
    logic: &Arc<Logic>,
    bus: &EventBus,
    mongo: &Arc<mongodb::Client>,
) -> HttpResponse {
    let send_result = if dkim.already_delivered {
        Ok(())
    } else {
        send_outgoing_email(email).await
    };

    match send_result {
        Ok(_) => {
            if dkim.already_delivered && monitoring::monitoring_enabled() {
                let mut ev = monitoring::SmtpEvent::new(
                    &normalize_message_id(message_id),
                    if dkim.dkim_remote_accepted {
                        monitoring::SmtpEventType::Delivered
                    } else {
                        monitoring::SmtpEventType::Queued
                    },
                    &v.from,
                    &v.to,
                );

                ev.status = if dkim.dkim_remote_accepted {
                    monitoring::SmtpStatus::Delivered
                } else if dkim.dkim_remote_rejected {
                    monitoring::SmtpStatus::Bounced
                } else {
                    monitoring::SmtpStatus::Pending
                };

                ev.company = Some("dkim-service".to_string());
                ev.mx_host = dkim.dkim_mx_host.clone();
                ev.remote_ip = dkim.dkim_remote_ip.clone();
                ev.remote_port = dkim.dkim_remote_port;
                ev.smtp_reply = dkim.dkim_response.clone().or_else(|| {
                    Some(
                        if dkim.dkim_remote_accepted {
                            "Upstream SMTP accepted by DKIM service"
                        } else if dkim.dkim_remote_rejected {
                            "Upstream SMTP rejected recipient in DKIM service"
                        } else {
                            "Handoff accepted by DKIM service (remote mailbox receipt not independently verified)"
                        }
                        .to_string(),
                    )
                });
                monitoring::emit(ev);
            }

            if let Err(e) = logic.store_email(&v.user_id, "sent", email).await {
                eprintln!("store sent copy failed: {}", e);
            }
            emit_event(
                bus,
                mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Sent,
                    user_id: v.user_id.clone(),
                    email_id: id.to_string(),
                    subject: v.subject.clone(),
                    from: v.from.clone(),
                    to: v.to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let delivery_state = if dkim.dkim_remote_rejected {
                "failed"
            } else if dkim.dkim_remote_accepted {
                "sent"
            } else if dkim.already_delivered {
                "queued"
            } else {
                "sending"
            };

            HttpResponse::Ok().json(serde_json::json!({
                "sent": true,
                "id": id,
                "messageId": message_id,
                "deliveryState": delivery_state,
            }))
        }
        Err(e) => {
            eprintln!("send_outgoing_email failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "deliveryState": "failed",
                "message": format!("Failed to send email: {}", e),
            }))
        }
    }
}

pub(crate) async fn api_send(
    body: web::Json<ComposeSendRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let validated = match validate_send_request(&body, &req) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let dkim = match apply_dkim_signature(&validated).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let (email, id, message_id) = build_email_and_message_id(&validated, &dkim);

    if let Some(resp) =
        maybe_enqueue_for_undo(&validated, &dkim, &email, &id, &message_id, &mongo).await
    {
        return resp;
    }

    dispatch_and_finalize(
        &validated, &dkim, &email, &id, &message_id, &logic, &bus, &mongo,
    )
    .await
}

// --- Send undo (POST /api/send/undo) ---

pub(crate) async fn api_send_undo(
    body: web::Json<UndoSendRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
    match coll
        .update_one(
            doc! {
                "id": &body.id,
                "user_id": &user_id,
                "status": "pending",
                "send_after": { "$gt": now },
            },
            doc! { "$set": { "status": "cancelled" } },
        )
        .await
    {
        Ok(r) if r.matched_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "cancelled": true, "id": &body.id }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "cancelled": false,
            "reason": "Email not found, already sent, or undo window has passed"
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

// --- Send schedule (POST /api/send/schedule) ---

pub(crate) async fn api_send_schedule(
    body: web::Json<ScheduleSendBody>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one recipient (to) is required"
        }));
    }

    let send_at = match chrono::DateTime::parse_from_rfc3339(&body.send_at) {
        Ok(dt) => dt,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Invalid send_at: use ISO 8601 format" }))
        }
    };
    if send_at.timestamp() <= Utc::now().timestamp() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "send_at must be in the future" }));
    }

    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));
    let cc = join_recipients(&body.cc);
    let bcc = join_recipients(&body.bcc);
    let in_reply_to = body
        .in_reply_to
        .as_deref()
        .and_then(canonical_message_id);
    let references = body
        .references
        .iter()
        .filter_map(|r| canonical_message_id(r))
        .collect::<Vec<_>>();
    let attachments = body
        .attachments
        .iter()
        .filter(|a| !a.filename.trim().is_empty() && !a.data_base64.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>();
    let (smtp_body, content_type_header) = match build_body_with_attachments(&body.body, &attachments) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": e,
            }))
        }
    };

    let id = Uuid::new_v4().to_string();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match coll
        .insert_one(doc! {
            "id": &id,
            "user_id": &user_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &body.subject,
            "body": &smtp_body,
            "content_type": &content_type_header,
            "dkim_signature": "",
            "message_id": format!("<{}@{}>", &id, domain_from_env()),
            "in_reply_to": in_reply_to.as_deref().unwrap_or(""),
            "references": &references,
            "status": "scheduled",
            "send_after": bson::DateTime::from_millis(send_at.timestamp_millis()),
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        })
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "queued": true, "id": id, "sendAt": body.send_at
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

pub(crate) async fn api_send_status(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();

    let email = match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Email not found"
            }))
        }
        Err(e) => {
            eprintln!("api_send_status fetch_email error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch email"
            }));
        }
    };

    let message_id_header = email
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let message_id = normalize_message_id(&message_id_header);
    if message_id.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "id": email.id,
            "message": "No Message-ID found",
            "monitoring": {
                "traceable": false
            }
        }));
    }

    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("smtp_events");

    let events = match coll
        .find(doc! { "message_id": &message_id })
        .sort(doc! { "ts": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| bson::from_document::<monitoring::SmtpEvent>(d).ok())
            .collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("api_send_status query smtp_events error: {}", e);
            vec![]
        }
    };

    let accepted_by_remote_mx = events.iter().any(|e| {
        matches!(e.event_type, monitoring::SmtpEventType::Delivered)
            && matches!(e.status, monitoring::SmtpStatus::Delivered)
            && !is_internal_delivery_hop(
                e.mx_host.as_deref(),
                e.remote_ip.as_deref(),
                e.remote_port,
                e.company.as_deref(),
            )
    });
    let bounced_or_failed = events.iter().any(|e| {
        matches!(
            e.status,
            monitoring::SmtpStatus::Bounced | monitoring::SmtpStatus::Failed
        )
    });
    let saw_internal_handoff = events.iter().any(|e| {
        is_internal_delivery_hop(
            e.mx_host.as_deref(),
            e.remote_ip.as_deref(),
            e.remote_port,
            e.company.as_deref(),
        )
    });
    let handoff_only = !accepted_by_remote_mx && !bounced_or_failed && saw_internal_handoff;

    let latest = events
        .iter()
        .find(|e| {
            matches!(
                e.status,
                monitoring::SmtpStatus::Delivered
                    | monitoring::SmtpStatus::Bounced
                    | monitoring::SmtpStatus::Failed
                    | monitoring::SmtpStatus::Deferred
            )
        })
        .or_else(|| events.first());
    let delivery_state = if accepted_by_remote_mx {
        "sent"
    } else if bounced_or_failed {
        "failed"
    } else if handoff_only {
        "queued"
    } else {
        "sending"
    };

    HttpResponse::Ok().json(serde_json::json!({
        "id": email.id,
        "messageId": message_id,
        "deliveryState": delivery_state,
        "from": email.from,
        "to": email.to,
        "subject": email.subject,
        "monitoring": {
            "traceable": true,
            "events": events.len(),
            "acceptedByRemoteMx": accepted_by_remote_mx,
            "bouncedOrFailed": bounced_or_failed,
            "handoffOnly": handoff_only,
            "latestEventType": latest.map(|e| format!("{:?}", e.event_type)),
            "latestStatus": latest.map(|e| format!("{:?}", e.status)),
            "latestSmtpCode": latest.and_then(|e| e.smtp_code),
            "latestSmtpReply": latest.and_then(|e| e.smtp_reply.clone()),
            "traceEndpoint": format!("/api/monitoring/messages/{}/trace", message_id),
            "note": if accepted_by_remote_mx {
                "Remote MX accepted the message (strong delivery signal)."
            } else if handoff_only {
                "Message handed off to DKIM service; remote mailbox receipt is not independently verified yet."
            } else if bounced_or_failed {
                "SMTP monitoring reports bounce/failure events."
            } else {
                "No conclusive delivery signal yet."
            }
        }
    }))
}

