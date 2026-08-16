// Split from send_handlers.rs — endpoints HTTP
#![allow(unused_imports)]
use super::*;
use super::send_pipeline::*;

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

