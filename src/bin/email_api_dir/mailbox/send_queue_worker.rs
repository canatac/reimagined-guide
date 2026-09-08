#![allow(unused_imports, dead_code)]
use super::super::*;
use super::send_pipeline::*;
use super::send_endpoints::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// --- Send queue background worker ---

fn retry_policy() -> (u32, u64, u64, u64) {
    let max_attempts = std::env::var("SMTP_RETRY_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(3)
        .max(1);
    let base_ms = std::env::var("SMTP_RETRY_BASE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(500)
        .max(1);
    let max_ms = std::env::var("SMTP_RETRY_MAX_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30_000)
        .max(base_ms);
    let jitter_ms = std::env::var("SMTP_RETRY_JITTER_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(250);
    (max_attempts, base_ms, max_ms, jitter_ms)
}

fn deterministic_jitter_ms(message_id: &str, attempt: u32, jitter_cap_ms: u64) -> u64 {
    if jitter_cap_ms == 0 {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    message_id.hash(&mut hasher);
    attempt.hash(&mut hasher);
    hasher.finish() % (jitter_cap_ms + 1)
}

fn backoff_delay_ms(
    message_id: &str,
    attempt: u32,
    base_ms: u64,
    max_ms: u64,
    jitter_cap_ms: u64,
) -> u64 {
    let exponent = attempt.saturating_sub(1).min(16);
    let exp = base_ms.saturating_mul(1u64 << exponent);
    let jitter = deterministic_jitter_ms(message_id, attempt, jitter_cap_ms);
    exp.saturating_add(jitter).min(max_ms)
}

fn is_retryable_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    match err.kind() {
        ErrorKind::TimedOut
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::NotConnected
        | ErrorKind::WouldBlock
        | ErrorKind::Interrupted => true,
        _ => {
            let msg = err.to_string().to_ascii_lowercase();
            msg.contains("temporary")
                || msg.contains("timed out")
                || msg.contains("timeout")
                || msg.contains("4.2.")
                || msg.contains("4.3.")
                || msg.contains("4.4.")
                || msg.contains("4.5.")
        }
    }
}

pub(crate) async fn send_queue_worker(mongo: Arc<mongodb::Client>) {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let logic = Arc::new(Logic::new(mongo.clone()));
    let (max_attempts, base_ms, max_ms, jitter_ms) = retry_policy();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let coll = mongo
            .database(&db_name)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        let now = Utc::now();

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
            let user_id = entry.get_str("user_id").unwrap_or("admin").to_string();
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
                internal_date: Utc::now(),
                dkim_signature: if dkim_sig.is_empty() {
                    None
                } else {
                    Some(dkim_sig)
                },
            };

            let mut final_status = "failed";
            let mut retry_outcome = "final_fail";
            let mut retry_count: i64 = 0;
            let mut last_error: Option<String> = None;

            for attempt in 1..=max_attempts {
                match send_outgoing_email(&email).await {
                    Ok(_) => {
                        retry_count = i64::from(attempt.saturating_sub(1));
                        final_status = "sent";
                        retry_outcome = if attempt > 1 {
                            "success_after_retry"
                        } else {
                            "sent_first_try"
                        };
                        break;
                    }
                    Err(e) => {
                        let retryable = is_retryable_error(&e);
                        let err_msg = e.to_string();
                        last_error = Some(err_msg.clone());
                        eprintln!(
                            "send_queue_worker send error for {} (attempt {}/{}): {}",
                            id, attempt, max_attempts, err_msg
                        );
                        if !retryable || attempt >= max_attempts {
                            retry_count = i64::from(attempt.saturating_sub(1));
                            break;
                        }
                        let delay_ms = backoff_delay_ms(&id, attempt, base_ms, max_ms, jitter_ms);
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    }
                }
            }

            let _ = coll
                .update_one(
                    doc! { "id": &id },
                    doc! { "$set": {
                        "status": final_status,
                        "retry_count": retry_count,
                        "retry_outcome": retry_outcome,
                        "last_error": last_error,
                        "updated_at": Utc::now(),
                    } },
                )
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{backoff_delay_ms, deterministic_jitter_ms};

    #[test]
    fn backoff_grows_and_is_bounded() {
        let d1 = backoff_delay_ms("m1", 1, 100, 5_000, 0);
        let d2 = backoff_delay_ms("m1", 2, 100, 5_000, 0);
        let d3 = backoff_delay_ms("m1", 3, 100, 5_000, 0);
        assert_eq!(d1, 100);
        assert_eq!(d2, 200);
        assert_eq!(d3, 400);
        let capped = backoff_delay_ms("m1", 20, 100, 5_000, 250);
        assert!(capped <= 5_000);
    }

    #[test]
    fn jitter_is_deterministic_per_message_and_attempt() {
        let a = deterministic_jitter_ms("msg-1", 2, 250);
        let b = deterministic_jitter_ms("msg-1", 2, 250);
        let c = deterministic_jitter_ms("msg-1", 3, 250);
        assert_eq!(a, b);
        assert!(a <= 250);
        assert!(c <= 250);
    }
}

