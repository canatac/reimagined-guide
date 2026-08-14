// Sprint 8: split from mailbox_handlers.rs
#![allow(unused_imports)]
use super::*;

pub(crate) async fn api_send(
    body: web::Json<ComposeSendRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "sent": false,
            "message": "At least one recipient (to) is required",
        }));
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
            return HttpResponse::BadRequest().json(serde_json::json!({
                "sent": false,
                "message": e,
            }))
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

    let email_req = EmailRequest {
        from: from.clone(),
        to: to.clone(),
        subject: subject.clone(),
        body: mail_body.clone(),
    };

    // DKIM sign via shared service (same path as /send-email).
    // Note: studious-octo-rotary-phone exposes POST /generate-dkim and may
    // both sign and deliver via Nodemailer — when no dkimSignature is
    // returned we treat success as "already delivered by dkim-service".
    let dkim_service: Box<dyn DkimService> = Box::new(RealDkimService);
    let (
        dkim_sig,
        message_id_hdr,
        already_delivered,
        dkim_remote_accepted,
        dkim_remote_rejected,
        dkim_response,
        dkim_mx_host,
        dkim_remote_ip,
        dkim_remote_port,
    ) = match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            let status = dkim_result["status"].as_str().unwrap_or("");
            if status != "success" {
                let msg = dkim_result["message"]
                    .as_str()
                    .or_else(|| dkim_result["error"].as_str())
                    .unwrap_or("DKIM signing failed");
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "sent": false,
                    "message": format!("Failed to sign email: {}", msg),
                }));
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

            // Distinguish true remote-MX acceptance from internal relay handoff.
            let internal_hop = is_internal_delivery_hop(
                upstream_mx_host.as_deref(),
                upstream_remote_ip.as_deref(),
                upstream_remote_port,
                Some("dkim-service"),
            );
            let effective_remote_accept = accepted_by_remote_mx && !internal_hop;

            // No DKIM signature means dkim-service likely performed SMTP itself.
            // Accept this path only with explicit SMTP handoff proof (`accepted*`).
            // We still keep `effective_remote_accept` separate so status can tell
            // true remote MX acceptance from internal relay handoff.
            let delivered = sig.is_empty() && accepted_by_remote_mx;
            if sig.is_empty() && !delivered {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                        "sent": false,
                        "message": "DKIM signer returned success without signature and without SMTP handoff proof; refusing unsigned send",
                    }));
            }
            (
                sig,
                mid,
                delivered,
                effective_remote_accept,
                rejected_by_remote_mx,
                upstream_response,
                upstream_mx_host,
                upstream_remote_ip,
                upstream_remote_port,
            )
        }
        Err(e) => {
            eprintln!("DKIM service error on /api/send: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "message": format!("Failed to generate DKIM signature: {}", e),
            }));
        }
    };

    let id = Uuid::new_v4().to_string();
    let message_id = if message_id_hdr.is_empty() {
        format!("<{}@{}>", id, domain_from_env())
    } else if message_id_hdr.starts_with('<') {
        message_id_hdr.clone()
    } else {
        format!("<{}>", message_id_hdr)
    };

    let mut headers = vec![
        ("Message-ID".to_string(), message_id.clone()),
        ("Date".to_string(), Utc::now().to_rfc2822()),
        ("MIME-Version".to_string(), "1.0".to_string()),
        (
            "Content-Type".to_string(),
            content_type_header.clone(),
        ),
    ];
    if !cc.is_empty() {
        headers.push(("Cc".to_string(), cc.clone()));
    }
    if !bcc.is_empty() {
        // Envelope Bcc isn't fully separated yet; record header for stored copy only if present.
        headers.push(("Bcc".to_string(), bcc.clone()));
    }
    if !dkim_sig.is_empty() {
        headers.push(("DKIM-Signature".to_string(), dkim_sig.clone()));
    }
    if let Some(in_reply_to) = &in_reply_to {
        headers.push(("In-Reply-To".to_string(), in_reply_to.clone()));
    }
    if !references.is_empty() {
        headers.push(("References".to_string(), references.join(" ")));
    }

    let email = Email {
        id: id.clone(),
        from: from.clone(),
        to: to.clone(),
        subject: subject.clone(),
        body: smtp_body.clone(),
        headers,
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: if dkim_sig.is_empty() {
            None
        } else {
            Some(dkim_sig)
        },
    };

    // If the DKIM service already delivered the message (success response
    // without a dkim signature), skip direct SMTP relay. This prevents false
    // negatives when relay ports are closed but delivery already happened.

    // Undo window: queue the email instead of sending immediately.
    let undo_window_secs = env::var("SEND_UNDO_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    if undo_window_secs > 0 && !already_delivered {
        let send_after = bson::DateTime::from_millis(
            Utc::now().timestamp_millis() + (undo_window_secs as i64 * 1000),
        );
        let queue_doc = doc! {
            "id": &id,
            "user_id": &user_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &subject,
            "body": &smtp_body,
            "content_type": &content_type_header,
            "dkim_signature": email.dkim_signature.as_deref().unwrap_or(""),
            "message_id": &message_id,
            "in_reply_to": in_reply_to.as_deref().unwrap_or(""),
            "references": &references,
            "status": "pending",
            "send_after": send_after,
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        };
        let db = mongo_db_name();
        let sq_coll = mongo
            .database(&db)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        return match sq_coll.insert_one(queue_doc).await {
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
        };
    }

    let send_result = if already_delivered {
        Ok(())
    } else {
        send_outgoing_email(&email).await
    };

    match send_result {
        Ok(_) => {
            if already_delivered && monitoring::monitoring_enabled() {
                // DKIM service did the SMTP handoff/delivery itself. Persist an
                // explicit monitoring event so trace API/status API can surface
                // whether upstream accepted recipient(s).
                let mut ev = monitoring::SmtpEvent::new(
                    &normalize_message_id(&message_id),
                    if dkim_remote_accepted {
                        monitoring::SmtpEventType::Delivered
                    } else {
                        monitoring::SmtpEventType::Queued
                    },
                    &from,
                    &to,
                );

                ev.status = if dkim_remote_accepted {
                    monitoring::SmtpStatus::Delivered
                } else if dkim_remote_rejected {
                    monitoring::SmtpStatus::Bounced
                } else {
                    monitoring::SmtpStatus::Pending
                };

                ev.company = Some("dkim-service".to_string());
                ev.mx_host = dkim_mx_host;
                ev.remote_ip = dkim_remote_ip;
                ev.remote_port = dkim_remote_port;
                ev.smtp_reply = dkim_response.or_else(|| {
                    Some(
                        if dkim_remote_accepted {
                            "Upstream SMTP accepted by DKIM service"
                        } else if dkim_remote_rejected {
                            "Upstream SMTP rejected recipient in DKIM service"
                        } else {
                            "Handoff accepted by DKIM service (remote mailbox receipt not independently verified)"
                        }
                        .to_string(),
                    )
                });
                monitoring::emit(ev);
            }

            // Store Sent copy for the sender. Local-domain inbox copies come
            // exclusively from SMTP inbound (Nodemailer/dkim or MX self-delivery)
            // to avoid duplicate messages.
            if let Err(e) = logic.store_email(&user_id, "sent", &email).await {
                eprintln!("store sent copy failed: {}", e);
            }
            emit_event(
                &bus,
                &mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Sent,
                    user_id: user_id.clone(),
                    email_id: id.clone(),
                    subject: subject.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let delivery_state = if dkim_remote_rejected {
                "failed"
            } else if dkim_remote_accepted {
                "sent"
            } else if already_delivered {
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

// --- Send queue background worker ---

pub(crate) async fn send_queue_worker(mongo: Arc<mongodb::Client>) {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let coll = mongo
            .database(&db_name)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());

        let cursor = match coll
            .find(doc! {
                "status": { "$in": ["pending", "scheduled"] },
                "send_after": { "$lte": now },
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("send_queue_worker find error: {}", e);
                continue;
            }
        };

        let entries = match cursor.try_collect::<Vec<bson::Document>>().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("send_queue_worker collect error: {}", e);
                continue;
            }
        };

        for entry in entries {
            let id = entry.get_str("id").unwrap_or("").to_string();
            let from = entry.get_str("from").unwrap_or("").to_string();
            let to = entry.get_str("to").unwrap_or("").to_string();
            let subject = entry.get_str("subject").unwrap_or("").to_string();
            let body_text = entry.get_str("body").unwrap_or("").to_string();
            let content_type = entry
                .get_str("content_type")
                .unwrap_or("text/html; charset=utf-8")
                .to_string();
            let cc = entry.get_str("cc").unwrap_or("").to_string();
            let bcc = entry.get_str("bcc").unwrap_or("").to_string();
            let dkim_sig = entry.get_str("dkim_signature").unwrap_or("").to_string();
            let message_id = entry.get_str("message_id").unwrap_or("").to_string();
            let in_reply_to = entry
                .get_str("in_reply_to")
                .ok()
                .and_then(canonical_message_id);
            let references = entry
                .get_array("references")
                .ok()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter_map(canonical_message_id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            // Optimistic lock: claim entry before sending
            let claim = coll
                .update_one(
                    doc! { "id": &id, "status": { "$in": ["pending", "scheduled"] } },
                    doc! { "$set": { "status": "sending" } },
                )
                .await;
            match claim {
                Ok(r) if r.matched_count == 0 => continue,
                Err(e) => {
                    eprintln!("send_queue claim error for {}: {}", id, e);
                    continue;
                }
                _ => {}
            }

            let mut headers = vec![
                (
                    "Message-ID".to_string(),
                    if message_id.is_empty() {
                        format!(
                            "<{}@{}>",
                            id,
                            std::env::var("DOMAIN_NAME")
                                .unwrap_or_else(|_| "misfits.ai".to_string())
                        )
                    } else {
                        message_id
                    },
                ),
                ("Date".to_string(), Utc::now().to_rfc2822()),
                ("MIME-Version".to_string(), "1.0".to_string()),
                (
                    "Content-Type".to_string(),
                    content_type,
                ),
            ];
            if !cc.is_empty() {
                headers.push(("Cc".to_string(), cc));
            }
            if !bcc.is_empty() {
                headers.push(("Bcc".to_string(), bcc));
            }
            if !dkim_sig.is_empty() {
                headers.push(("DKIM-Signature".to_string(), dkim_sig.clone()));
            }
            if let Some(in_reply_to) = &in_reply_to {
                headers.push(("In-Reply-To".to_string(), in_reply_to.clone()));
            }
            if !references.is_empty() {
                headers.push(("References".to_string(), references.join(" ")));
            }

            let email = Email {
                id: id.clone(),
                from,
                to,
                subject,
                body: body_text,
                headers,
                flags: vec![],
                sequence_number: 0,
                uid: 0,
                internal_date: bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                dkim_signature: if dkim_sig.is_empty() {
                    None
                } else {
                    Some(dkim_sig)
                },
            };

            let status = match send_outgoing_email(&email).await {
                Ok(_) => "sent",
                Err(e) => {
                    eprintln!("send_queue_worker send error for {}: {}", id, e);
                    "failed"
                }
            };

            let _ = coll
                .update_one(doc! { "id": &id }, doc! { "$set": { "status": status } })
                .await;
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

