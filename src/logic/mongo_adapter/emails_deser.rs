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
    fn normalize_email_document_for_deser_i64_to_i32() {
        let doc = bson::doc! { "sequence_number": 42i64, "uid": 100i64 };
        let result = normalize_email_document_for_deser(doc);
        assert_eq!(result.get_i32("sequence_number").unwrap(), 42);
        assert_eq!(result.get_i32("uid").unwrap(), 100);
    }

    #[test]
    fn normalize_email_document_for_deser_negative_i64_preserved() {
        let doc = bson::doc! { "sequence_number": -1i64, "uid": -5i64 };
        let result = normalize_email_document_for_deser(doc);
        // Negative values should NOT be converted to i32
        assert!(result.get_i64("sequence_number").is_ok());
        assert!(result.get_i64("uid").is_ok());
    }

    #[test]
    fn deserialize_email_document_full() {
        let doc = bson::doc! {
            "id": "email-1",
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Hello",
            "internal_date": bson::DateTime::from_millis(1700000000000i64),
            "headers": [],
            "flags": [],
            "sequence_number": 5i64,
            "uid": 42i64,
        };
        let email = deserialize_email_document(doc).unwrap();
        assert_eq!(email.id, "email-1");
        assert_eq!(email.from, "a@b.com");
        assert_eq!(email.to, "c@d.com");
        assert_eq!(email.subject, "Test");
        assert_eq!(email.body, "Hello");
        assert_eq!(email.sequence_number, 5);
        assert_eq!(email.uid, 42);
    }

    #[test]
    fn deserialize_email_document_missing_optional_fields() {
        let doc = bson::doc! {
            "id": "email-2",
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Body",
        };
        let email = deserialize_email_document(doc).unwrap();
        assert_eq!(email.id, "email-2");
        assert_eq!(email.sequence_number, 0);
        assert_eq!(email.uid, 0);
        assert!(email.flags.is_empty());
        assert!(email.headers.is_empty());
    }

    #[test]
    fn deserialize_email_document_with_headers_array() {
        let doc = bson::doc! {
            "id": "email-3",
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Body",
            "headers": [
                ["X-Foo", "bar"],
                ["X-Baz", "qux"],
            ],
        };
        let email = deserialize_email_document(doc).unwrap();
        assert_eq!(email.headers.len(), 2);
        assert_eq!(email.headers[0], ("X-Foo".to_string(), "bar".to_string()));
    }

    #[test]
    fn deserialize_email_document_with_flags() {
        let doc = bson::doc! {
            "id": "email-4",
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Body",
            "flags": ["\\Seen", "\\Flagged"],
        };
        let email = deserialize_email_document(doc).unwrap();
        assert_eq!(email.flags, vec!["\\Seen".to_string(), "\\Flagged".to_string()]);
    }

    #[test]
    fn deserialize_email_document_internal_date_string() {
        let doc = bson::doc! {
            "id": "email-5",
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Body",
            "internal_date": "2026-01-01T00:00:00Z",
        };
        let email = deserialize_email_document(doc).unwrap();
        assert_eq!(email.id, "email-5");
    }

    #[test]
    fn deserialize_email_document_missing_id_returns_none() {
        let doc = bson::doc! {
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Body",
        };
        assert!(deserialize_email_document(doc).is_none());
    }

    #[test]
    fn deserialize_email_document_missing_to_returns_none() {
        let doc = bson::doc! {
            "id": "email-6",
            "from": "a@b.com",
            "subject": "Test",
            "body": "Body",
        };
        assert!(deserialize_email_document(doc).is_none());
    }

    #[test]
    fn deserialize_email_document_dkim_signature() {
        let doc = bson::doc! {
            "id": "email-7",
            "from": "a@b.com",
            "to": "c@d.com",
            "subject": "Test",
            "body": "Body",
            "dkim_signature": "v=1; ...",
        };
        let email = deserialize_email_document(doc).unwrap();
        assert_eq!(email.dkim_signature, Some("v=1; ...".to_string()));
    }
}
