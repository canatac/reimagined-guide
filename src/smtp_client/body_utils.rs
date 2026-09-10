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
    fn normalize_crlf_handles_mixed() {
        assert_eq!(normalize_crlf("a\nb\rc\r\nd"), "a\r\nb\r\nc\r\nd");
    }

    #[test]
    fn strip_tags_simple_removes_html() {
        assert_eq!(strip_tags_simple("<p>Hello <b>World</b></p>"), "Hello World");
    }

    #[test]
    fn strip_tags_simple_handles_empty() {
        assert_eq!(strip_tags_simple(""), "");
    }

    #[test]
    fn strip_tags_simple_handles_no_tags() {
        assert_eq!(strip_tags_simple("plain text"), "plain text");
    }

    #[test]
    fn strip_tags_simple_collapses_whitespace() {
        assert_eq!(strip_tags_simple("<p>  hello   world  </p>"), "hello world");
    }

    #[test]
    fn body_looks_like_html_detects_html() {
        assert!(body_looks_like_html("<html><body>Hello</body></html>"));
        assert!(body_looks_like_html("<p>text</p>"));
        assert!(body_looks_like_html("<div>content</div>"));
        assert!(body_looks_like_html("</table>"));
    }

    #[test]
    fn body_looks_like_html_rejects_plain() {
        assert!(!body_looks_like_html("Just plain text"));
        assert!(!body_looks_like_html(""));
    }

    #[test]
    fn ensure_html_document_wraps_plain() {
        let result = ensure_html_document("Hello World");
        assert!(result.contains("<html>"));
        assert!(result.contains("<body>"));
        assert!(result.contains("Hello World"));
    }

    #[test]
    fn ensure_html_document_preserves_html() {
        let input = "<html><body>Hi</body></html>";
        assert_eq!(ensure_html_document(input), input);
    }

    #[test]
    fn upsert_content_type_adds_new() {
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
        upsert_content_type(&mut headers, "text/html".to_string());
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1, "text/html");
    }

    #[test]
    fn upsert_content_type_case_insensitive() {
        let mut headers = vec![("content-type".to_string(), "text/plain".to_string())];
        upsert_content_type(&mut headers, "text/html".to_string());
        assert_eq!(headers[0].1, "text/html");
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
    fn normalize_crlf_unix_to_windows() {
        assert_eq!(normalize_crlf("line1\nline2\n"), "line1\r\nline2\r\n");
    }

    #[test]
    fn normalize_crlf_mac_to_windows() {
        assert_eq!(normalize_crlf("line1\rline2\r"), "line1\r\nline2\r\n");
    }

    #[test]
    fn normalize_crlf_passthrough() {
        assert_eq!(normalize_crlf("line1\r\nline2\r\n"), "line1\r\nline2\r\n");
    }

    #[test]
    fn normalize_crlf_mixed() {
        assert_eq!(normalize_crlf("a\nb\rc\r\nd"), "a\r\nb\r\nc\r\nd\r\n");
    }

    #[test]
    fn strip_tags_simple_html() {
        let html = "<p>Hello <b>world</b>!</p>";
        assert_eq!(strip_tags_simple(html), "Hello world !");
    }

    #[test]
    fn strip_tags_simple_empty() {
        assert_eq!(strip_tags_simple(""), "");
    }

    #[test]
    fn strip_tags_simple_no_tags() {
        assert_eq!(strip_tags_simple("plain text"), "plain text");
    }

    #[test]
    fn strip_tags_simple_nested() {
        let html = "<div><p><span>deep</span></p></div>";
        assert_eq!(strip_tags_simple(html), "deep");
    }

    #[test]
    fn body_looks_like_html_html_tag() {
        assert!(body_looks_like_html("<html><body>hello</body></html>"));
    }

    #[test]
    fn body_looks_like_html_body_tag() {
        assert!(body_looks_like_html("<body>content</body>"));
    }

    #[test]
    fn body_looks_like_html_p_tag() {
        assert!(body_looks_like_html("<p>paragraph</p>"));
    }

    #[test]
    fn body_looks_like_html_div_tag() {
        assert!(body_looks_like_html("<div>block</div>"));
    }

    #[test]
    fn body_looks_like_html_br_tag() {
        assert!(body_looks_like_html("line<br>break"));
    }

    #[test]
    fn body_looks_like_html_table() {
        assert!(body_looks_like_html("<table><tr><td>data</td></tr></table>"));
    }

    #[test]
    fn body_looks_like_html_span() {
        assert!(body_looks_like_html("<span>inline</span>"));
    }

    #[test]
    fn body_looks_like_html_closing_tag() {
        assert!(body_looks_like_html("text</div>"));
    }

    #[test]
    fn body_looks_like_html_plain_text() {
        assert!(!body_looks_like_html("Just plain text."));
    }

    #[test]
    fn body_looks_like_html_angle_brackets_not_tags() {
        assert!(!body_looks_like_html("2 < 3 && 5 > 4"));
    }

    #[test]
    fn ensure_html_document_wraps_plain() {
        let raw = "<p>Hello</p>";
        let html = ensure_html_document(raw);
        assert_eq!(html, "<!DOCTYPE html><html><body><p>Hello</p></body></html>");
    }

    #[test]
    fn ensure_html_document_passthrough_existing() {
        let raw = "<html><body>Already HTML</body></html>";
        let html = ensure_html_document(raw);
        assert_eq!(html, "<html><body>Already HTML</body></html>");
    }

    #[test]
    fn ensure_html_document_trim() {
        let raw = "  <p>trimmed</p>  ";
        let html = ensure_html_document(raw);
        assert_eq!(html, "<!DOCTYPE html><html><body><p>trimmed</p></body></html>");
    }

    #[test]
    fn upsert_content_type_adds_new() {
        let mut headers = vec![];
        upsert_content_type(&mut headers, "text/plain".to_string());
        assert_eq!(headers, vec![("Content-Type".to_string(), "text/plain".to_string())]);
    }

    #[test]
    fn upsert_content_type_updates_existing() {
        let mut headers = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Date".to_string(), "today".to_string()),
        ];
        upsert_content_type(&mut headers, "text/html".to_string());
        assert_eq!(headers[0].1, "text/html");
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn upsert_content_type_case_insensitive() {
        let mut headers = vec![("content-type".to_string(), "old".to_string())];
        upsert_content_type(&mut headers, "new".to_string());
        assert_eq!(headers[0].1, "new");
    }

    #[test]
    fn compose_smtp_payload_plain_email() {
        let email = crate::entities::Email {
            id: "test-1".to_string(),
            from: "sender@example.com".to_string(),
            to: "receiver@example.com".to_string(),
            subject: "Test Subject".to_string(),
            body: "Hello world".to_string(),
            headers: vec![],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let payload = compose_smtp_payload(&email);
        assert!(payload.contains("From: sender@example.com"));
        assert!(payload.contains("To: receiver@example.com"));
        assert!(payload.contains("Subject: Test Subject"));
        assert!(payload.contains("Hello world"));
        assert!(payload.contains("Date:"));
        assert!(payload.contains("Message-ID:"));
    }

    #[test]
    fn compose_smtp_payload_html_email() {
        let email = crate::entities::Email {
            id: "test-2".to_string(),
            from: "a@b.com".to_string(),
            to: "c@d.com".to_string(),
            subject: "HTML Test".to_string(),
            body: "<p>Hello</p>".to_string(),
            headers: vec![],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let payload = compose_smtp_payload(&email);
        assert!(payload.contains("multipart/alternative"));
        assert!(payload.contains("text/plain"));
        assert!(payload.contains("text/html"));
        assert!(payload.contains("Hello"));
    }

    #[test]
    fn compose_smtp_payload_preserves_custom_headers() {
        let email = crate::entities::Email {
            id: "test-3".to_string(),
            from: "a@b.com".to_string(),
            to: "c@d.com".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            headers: vec![("X-Custom".to_string(), "custom-value".to_string())],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let payload = compose_smtp_payload(&email);
        assert!(payload.contains("X-Custom: custom-value"));
    }

    #[test]
    fn compose_smtp_payload_dkim_signature() {
        let email = crate::entities::Email {
            id: "test-4".to_string(),
            from: "a@b.com".to_string(),
            to: "c@d.com".to_string(),
            subject: "DKIM Test".to_string(),
            body: "Body".to_string(),
            headers: vec![("DKIM-Signature".to_string(), "v=1; ...".to_string())],
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let payload = compose_smtp_payload(&email);
        assert!(payload.contains("DKIM-Signature: v=1; ..."));
    }
}

