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
                monitoring::emit(ev);
            }

            let sent_copy_persisted = match logic.store_email(&v.user_id, "sent", email).await {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("store sent copy failed: {}", e);
                    false
                }
            };
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
