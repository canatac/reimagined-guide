// Send pipeline finalization: undo queue + dispatch/persist/SSE.
// Extracted from send_pipeline.rs (Sprint 17) to keep files <= 300 LOC.
#![allow(unused_imports)]
use super::*;
use super::send_pipeline::{DkimOutcome, ValidatedSendRequest};

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
                if matches!(ev.status, monitoring::SmtpStatus::Bounced) {
                    let reply = ev.smtp_reply.clone().unwrap_or_else(|| "unknown".to_string());
                    let taxonomy = monitoring::classify_smtp_reject(None, &reply);
                    ev.reject_reason_code = Some(taxonomy.reason_code.to_string());
                    ev.reject_action = Some(taxonomy.action.to_string());
                }
                monitoring::emit(ev);
            }

            // Sent copy persistence is handled by authenticated SMTP submission path
            // in smtp_server to avoid duplicate entries between API and SMTP layers.
            let sent_copy_persisted = true;
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
            let delivery_state = delivery_state_from_dkim(dkim);

            HttpResponse::Ok().json(serde_json::json!({
                "sent": true,
                "id": id,
                "messageId": message_id,
                "deliveryState": delivery_state,
                "storedInSent": sent_copy_persisted,
                "warning": if sent_copy_persisted {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String("Message sent but failed to persist Sent mailbox copy".to_string())
                }
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

/// Pure helper to compute delivery state from DKIM outcome.
fn delivery_state_from_dkim(dkim: &DkimOutcome) -> &'static str {
    if dkim.dkim_remote_rejected {
        "failed"
    } else if dkim.dkim_remote_accepted {
        "sent"
    } else if dkim.already_delivered {
        "queued"
    } else {
        "sending"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dkim_outcome() -> DkimOutcome {
        DkimOutcome {
            dkim_sig: "v=1; a=rsa-sha256; ...".to_string(),
            message_id_hdr: "<generated@example.com>".to_string(),
            already_delivered: false,
            dkim_remote_accepted: true,
            dkim_remote_rejected: false,
            dkim_response: Some("250 OK".to_string()),
            dkim_mx_host: Some("mx.example.com".to_string()),
            dkim_remote_ip: Some("192.0.2.1".to_string()),
            dkim_remote_port: Some(25),
        }
    }

    #[test]
    fn delivery_state_from_dkim_accepted() {
        let dkim = make_dkim_outcome();
        assert_eq!(delivery_state_from_dkim(&dkim), "sent");
    }

    #[test]
    fn delivery_state_from_dkim_rejected() {
        let mut dkim = make_dkim_outcome();
        dkim.dkim_remote_rejected = true;
        assert_eq!(delivery_state_from_dkim(&dkim), "failed");
    }

    #[test]
    fn delivery_state_from_dkim_already_delivered() {
        let mut dkim = make_dkim_outcome();
        dkim.dkim_remote_accepted = false;
        dkim.already_delivered = true;
        assert_eq!(delivery_state_from_dkim(&dkim), "queued");
    }

    #[test]
    fn delivery_state_from_dkim_sending() {
        let mut dkim = make_dkim_outcome();
        dkim.dkim_remote_accepted = false;
        assert_eq!(delivery_state_from_dkim(&dkim), "sending");
    }

    #[test]
    fn delivery_state_from_dkim_rejected_takes_precedence() {
        let mut dkim = make_dkim_outcome();
        dkim.dkim_remote_accepted = true;
        dkim.dkim_remote_rejected = true;
        assert_eq!(delivery_state_from_dkim(&dkim), "failed");
    }
}
