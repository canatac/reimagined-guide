use super::*;
use chrono::{DateTime, Utc};
use mongodb::bson::Bson;

fn normalize_email_document_for_deser(mut doc: bson::Document) -> bson::Document {
    if let Ok(v) = doc.get_i64("sequence_number") {
        if v >= 0 {
            doc.insert("sequence_number", v as i32);
        }
    }
    if let Ok(v) = doc.get_i64("uid") {
        if v >= 0 {
            doc.insert("uid", v as i32);
        }
    }
    doc
}

pub(super) fn deserialize_email_document(doc: bson::Document) -> Option<Email> {
    let normalized = normalize_email_document_for_deser(doc);

    if let Ok(email) = bson::from_document::<Email>(normalized.clone()) {
        return Some(email);
    }

    // Backward-compat fallback: build Email manually so inbox listing still
    // works when `internal_date`/`headers` BSON shapes drift.
    let internal_date = match normalized.get("internal_date") {
        Some(Bson::DateTime(dt)) => {
            DateTime::<Utc>::from_timestamp_millis(dt.timestamp_millis()).unwrap_or_else(Utc::now)
        }
        Some(Bson::String(s)) => DateTime::parse_from_rfc3339(s)
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        _ => Utc::now(),
    };

    let headers = match normalized.get("headers") {
        Some(Bson::Array(items)) => items
            .iter()
            .filter_map(|it| match it {
                Bson::Array(pair) if pair.len() >= 2 => {
                    let k = pair[0].as_str()?.to_string();
                    let v = pair[1].as_str()?.to_string();
                    Some((k, v))
                }
                Bson::Document(d) => {
                    let k = d
                        .get_str("name")
                        .or_else(|_| d.get_str("key"))
                        .ok()?
                        .to_string();
                    let v = d
                        .get_str("value")
                        .or_else(|_| d.get_str("val"))
                        .ok()?
                        .to_string();
                    Some((k, v))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let flags = match normalized.get("flags") {
        Some(Bson::Array(items)) => items
            .iter()
            .filter_map(|it| it.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };

    let sequence_number = normalized
        .get_i32("sequence_number")
        .ok()
        .map(|v| v as u32)
        .or_else(|| normalized.get_i64("sequence_number").ok().map(|v| v as u32))
        .unwrap_or(0);

    let uid = normalized
        .get_i32("uid")
        .ok()
        .map(|v| v as u32)
        .or_else(|| normalized.get_i64("uid").ok().map(|v| v as u32))
        .unwrap_or(0);

    let email = Email {
        id: normalized.get_str("id").unwrap_or_default().to_string(),
        from: normalized.get_str("from").unwrap_or_default().to_string(),
        to: normalized.get_str("to").unwrap_or_default().to_string(),
        subject: normalized
            .get_str("subject")
            .unwrap_or_default()
            .to_string(),
        body: normalized.get_str("body").unwrap_or_default().to_string(),
        headers,
        flags,
        sequence_number,
        uid,
        internal_date,
        dkim_signature: normalized
            .get_str("dkim_signature")
            .ok()
            .map(str::to_string),
    };

    if !email.id.is_empty() && !email.to.is_empty() {
        return Some(email);
    }

    eprintln!(
        "deserialize_email_document dropped id={} user_id={} mailbox={} (schema mismatch)",
        normalized.get_str("id").unwrap_or("<missing>"),
        normalized.get_str("user_id").unwrap_or("<missing>"),
        normalized.get_str("mailbox").unwrap_or("<missing>")
    );
    None
}
