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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_sequence_number_i64() {
        let mut doc = bson::Document::new();
        doc.insert("sequence_number", 5i64);
        let normalized = normalize_email_document_for_deser(doc);
        assert_eq!(normalized.get_i32("sequence_number").unwrap(), 5);
    }

    #[test]
    fn normalize_sequence_number_negative() {
        let mut doc = bson::Document::new();
        doc.insert("sequence_number", -1i64);
        let normalized = normalize_email_document_for_deser(doc);
        // Negative values should not be converted
        assert!(normalized.get_i64("sequence_number").is_ok());
    }

    #[test]
    fn normalize_uid_i64() {
        let mut doc = bson::Document::new();
        doc.insert("uid", 10i64);
        let normalized = normalize_email_document_for_deser(doc);
        assert_eq!(normalized.get_i32("uid").unwrap(), 10);
    }

    #[test]
    fn normalize_uid_negative() {
        let mut doc = bson::Document::new();
        doc.insert("uid", -5i64);
        let normalized = normalize_email_document_for_deser(doc);
        // Negative values should not be converted
        assert!(normalized.get_i64("uid").is_ok());
    }

    #[test]
    fn normalize_preserves_other_fields() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("sequence_number", 1i64);
        let normalized = normalize_email_document_for_deser(doc);
        assert_eq!(normalized.get_str("id").unwrap(), "email-123");
        assert_eq!(normalized.get_str("from").unwrap(), "sender@example.com");
        assert_eq!(normalized.get_str("to").unwrap(), "recipient@example.com");
    }

    #[test]
    fn deserialize_valid_email() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("subject", "Test Subject");
        doc.insert("body", "Test Body");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("flags", bson::Array::new());
        doc.insert("headers", bson::Array::new());
        doc.insert("sequence_number", 1i32);
        doc.insert("uid", 1i32);

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.id, "email-123");
        assert_eq!(email.from, "sender@example.com");
        assert_eq!(email.to, "recipient@example.com");
        assert_eq!(email.subject, "Test Subject");
        assert_eq!(email.body, "Test Body");
    }

    #[test]
    fn deserialize_missing_id() {
        let mut doc = bson::Document::new();
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));

        let result = deserialize_email_document(doc);
        assert!(result.is_none());
    }

    #[test]
    fn deserialize_missing_to() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));

        let result = deserialize_email_document(doc);
        assert!(result.is_none());
    }

    #[test]
    fn deserialize_with_flags() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("flags", vec!["\\Seen", "\\Flagged"]);

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.flags.len(), 2);
        assert!(email.flags.contains(&"\\Seen".to_string()));
        assert!(email.flags.contains(&"\\Flagged".to_string()));
    }

    #[test]
    fn deserialize_with_headers_array() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("headers", vec![vec!["Content-Type", "text/plain"], vec!["Subject", "Test"]]);

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.headers.len(), 2);
    }

    #[test]
    fn deserialize_with_headers_doc() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));

        let mut header_doc = bson::Document::new();
        header_doc.insert("name", "Content-Type");
        header_doc.insert("value", "text/html");
        doc.insert("headers", vec![header_doc]);

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.headers.len(), 1);
        assert_eq!(email.headers[0].0, "Content-Type");
        assert_eq!(email.headers[0].1, "text/html");
    }

    #[test]
    fn deserialize_with_dkim_signature() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("dkim_signature", "v=1; a=rsa-sha256;");

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.dkim_signature, Some("v=1; a=rsa-sha256;".to_string()));
    }

    #[test]
    fn deserialize_without_dkim_signature() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.dkim_signature, None);
    }

    #[test]
    fn deserialize_internal_date_string() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", "2023-11-14T22:13:20Z");

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
    }

    #[test]
    fn deserialize_internal_date_missing() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
    }

    #[test]
    fn deserialize_sequence_number_i64() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("sequence_number", 42i64);

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.sequence_number, 42);
    }

    #[test]
    fn deserialize_uid_i64() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("uid", 99i64);

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.uid, 99);
    }

    #[test]
    fn deserialize_empty_flags() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("flags", bson::Array::new());

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.flags.len(), 0);
    }

    #[test]
    fn deserialize_empty_headers() {
        let mut doc = bson::Document::new();
        doc.insert("id", "email-123");
        doc.insert("from", "sender@example.com");
        doc.insert("to", "recipient@example.com");
        doc.insert("internal_date", bson::DateTime::from_millis(1700000000000i64));
        doc.insert("headers", bson::Array::new());

        let result = deserialize_email_document(doc);
        assert!(result.is_some());
        let email = result.unwrap();
        assert_eq!(email.headers.len(), 0);
    }
}
