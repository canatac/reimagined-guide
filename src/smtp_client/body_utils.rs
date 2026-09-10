//! Utilitaires purs de composition du body/headers d'un email SMTP.
//! Extraits de mod.rs (refactor architecte) pour clean code / testabilité.

use chrono::Utc;
use uuid::Uuid;

use crate::entities::Email;

pub(crate) fn normalize_crlf(input: &str) -> String {
    input
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

pub(crate) fn strip_tags_simple(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn body_looks_like_html(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("<html")
        || lower.contains("<body")
        || lower.contains("<p")
        || lower.contains("<div")
        || lower.contains("<br")
        || lower.contains("<table")
        || lower.contains("<span")
        || lower.contains("</")
}

pub(crate) fn ensure_html_document(raw: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("<html") {
        return trimmed.to_string();
    }
    format!("<!DOCTYPE html><html><body>{}</body></html>", trimmed)
}

pub(crate) fn upsert_content_type(headers: &mut Vec<(String, String)>, value: String) {
    if let Some((_, existing)) = headers
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        *existing = value;
    } else {
        headers.push(("Content-Type".to_string(), value));
    }
}

pub(crate) fn compose_smtp_payload(email: &Email) -> String {
    let mut headers = email.headers.clone();

    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("date")) {
        headers.push(("Date".to_string(), Utc::now().to_rfc2822()));
    }
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("message-id"))
    {
        headers.push((
            "Message-ID".to_string(),
            format!("<{}@misfits.ai>", Uuid::new_v4()),
        ));
    }

    let has_dkim_signature = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("dkim-signature"));

    if has_dkim_signature {
        let mut email_content = String::new();

        let has_from = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("from"));
        let has_to = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("to"));
        let has_subject = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("subject"));

        if !has_from {
            email_content.push_str(&format!("From: {}\r\n", email.from));
        }
        if !has_to {
            email_content.push_str(&format!("To: {}\r\n", email.to));
        }
        if !has_subject {
            email_content.push_str(&format!("Subject: {}\r\n", email.subject));
        }

        for (key, value) in &headers {
            email_content.push_str(&format!("{}: {}\r\n", key, value));
        }

        email_content.push_str("\r\n");
        email_content.push_str(&normalize_crlf(&email.body));
        return email_content;
    }

    headers.retain(|(k, _)| {
        !(k.eq_ignore_ascii_case("from")
            || k.eq_ignore_ascii_case("to")
            || k.eq_ignore_ascii_case("subject"))
    });

    let body = email.body.as_str();

    let has_multipart = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("multipart/")
    });

    let payload_body = if has_multipart {
        normalize_crlf(body)
    } else if body_looks_like_html(body) {
        let html = normalize_crlf(&ensure_html_document(body));
        let mut plain = strip_tags_simple(&html);
        if plain.trim().is_empty() {
            plain = body.to_string();
        }
        plain = normalize_crlf(plain.trim());

        let boundary = format!("misfits-alt-{}", Uuid::new_v4().simple());
        upsert_content_type(
            &mut headers,
            format!("multipart/alternative; boundary=\"{}\"", boundary),
        );

        format!(
            "--{b}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{plain}\r\n--{b}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{html}\r\n--{b}--\r\n",
            b = boundary,
            plain = plain,
            html = html,
        )
    } else {
        upsert_content_type(&mut headers, "text/plain; charset=utf-8".to_string());
        normalize_crlf(body)
    };

    let mut email_content = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\n",
        email.from, email.to, email.subject
    );
    for (key, value) in &headers {
        email_content.push_str(&format!("{}: {}\r\n", key, value));
    }
    email_content.push_str(&format!("\r\n{}", payload_body));
    email_content
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_crlf_converts_lf_to_crlf() {
        assert_eq!(normalize_crlf("line1\nline2"), "line1\r\nline2");
    }

    #[test]
    fn normalize_crlf_converts_cr_to_crlf() {
        assert_eq!(normalize_crlf("line1\rline2"), "line1\r\nline2");
    }

    #[test]
    fn normalize_crlf_preserves_crlf() {
        assert_eq!(normalize_crlf("line1\r\nline2"), "line1\r\nline2");
    }

    #[test]
    fn strip_tags_simple_removes_html_tags() {
        assert_eq!(strip_tags_simple("<p>Hello <b>world</b></p>"), "Hello world");
    }

    #[test]
    fn strip_tags_simple_handles_no_tags() {
        assert_eq!(strip_tags_simple("plain text"), "plain text");
    }

    #[test]
    fn body_looks_like_html_detects_html() {
        assert!(body_looks_like_html("<html><body>Hello</body></html>"));
        assert!(body_looks_like_html("<p>Hello</p>"));
        assert!(body_looks_like_html("<div>content</div>"));
    }

    #[test]
    fn body_looks_like_html_rejects_plain_text() {
        assert!(!body_looks_like_html("Just plain text"));
        assert!(!body_looks_like_html("No tags here"));
    }

    #[test]
    fn ensure_html_document_wraps_plain_text() {
        let result = ensure_html_document("Hello world");
        assert!(result.contains("<html>"));
        assert!(result.contains("</html>"));
        assert!(result.contains("Hello world"));
    }

    #[test]
    fn ensure_html_document_preserves_existing_html() {
        let input = "<html><body>Existing</body></html>";
        assert_eq!(ensure_html_document(input), input);
    }

    #[test]
    fn upsert_content_type_adds_new_header() {
        let mut headers = vec![("From".to_string(), "a@b.com".to_string())];
        upsert_content_type(&mut headers, "text/html; charset=utf-8".to_string());
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].0, "Content-Type");
        assert_eq!(headers[1].1, "text/html; charset=utf-8");
    }

    #[test]
    fn upsert_content_type_updates_existing() {
        let mut headers = vec![
            ("From".to_string(), "a@b.com".to_string()),
            ("Content-Type".to_string(), "text/plain".to_string()),
        ];
        upsert_content_type(&mut headers, "text/html; charset=utf-8".to_string());
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1, "text/html; charset=utf-8");
    }

    #[test]
    fn compose_smtp_payload_plain_text() {
        let email = crate::entities::Email::new(
            "test-id",
            "from@example.com",
            "to@example.com",
            "Subject",
            "Plain text body",
        );
        let payload = compose_smtp_payload(&email);
        assert!(payload.contains("From: from@example.com"));
        assert!(payload.contains("To: to@example.com"));
        assert!(payload.contains("Subject: Subject"));
        assert!(payload.contains("Plain text body"));
        assert!(payload.contains("Content-Type: text/plain"));
    }

    #[test]
    fn compose_smtp_payload_html_body() {
        let email = crate::entities::Email::new(
            "test-id",
            "from@example.com",
            "to@example.com",
            "Subject",
            "<p>HTML body</p>",
        );
        let payload = compose_smtp_payload(&email);
        assert!(payload.contains("Content-Type: text/html"));
        assert!(payload.contains("multipart/alternative"));
        assert!(payload.contains("HTML body"));
    }
}

