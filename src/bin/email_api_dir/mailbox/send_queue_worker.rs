#![allow(unused_imports, dead_code)]
use super::super::*;
use super::send_pipeline::*;
use super::send_endpoints::*;

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

