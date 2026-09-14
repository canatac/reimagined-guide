// MIME body decoding helpers extracted from mime_utils.rs (Sprint 17)
use super::super::*;
use super::mime_utils::strip_tags;

pub(super) fn compact_preview(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn raw_mime_from_email(email: &Email) -> String {
    if email.headers.is_empty() {
        email.body.clone()
    } else {
        let headers = email
            .headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\r\n");
        format!("{}\r\n\r\n{}", headers, email.body)
    }
}

fn walk_mime_parts(part: &mailparse::ParsedMail<'_>, html: &mut Option<String>, text: &mut Option<String>) {
    if part.subparts.is_empty() {
        let mt = part.ctype.mimetype.to_ascii_lowercase();
        if mt == "text/html" && html.is_none() {
            if let Ok(b) = part.get_body() {
                *html = Some(b);
            }
        } else if mt == "text/plain" && text.is_none() {
            if let Ok(b) = part.get_body() {
                *text = Some(b);
            }
        }
        return;
    }

    for sub in &part.subparts {
        walk_mime_parts(sub, html, text);
    }
}

fn decode_parts_from_parsed(parsed: &mailparse::ParsedMail<'_>) -> Option<(String, String, String)> {
    let mut html = None;
    let mut text = None;
    walk_mime_parts(parsed, &mut html, &mut text);

    if let Some(html_body) = html {
        let preview = compact_preview(&strip_tags(&html_body)).chars().take(160).collect();
        return Some((html_body, "html".to_string(), preview));
    }
    if let Some(text_body) = text {
        let preview = compact_preview(&text_body).chars().take(160).collect();
        return Some((text_body, "text".to_string(), preview));
    }

    None
}

pub(super) fn looks_like_raw_multipart_dump(body: &str) -> bool {
    let b = body.trim_start();
    b.starts_with("--") && b.contains("Content-Type:")
}

fn decode_from_synthetic_boundary(body: &str) -> Option<(String, String, String)> {
    let first_line = body.lines().next()?.trim();
    if !first_line.starts_with("--") {
        return None;
    }
    let boundary = first_line
        .trim_start_matches("--")
        .trim_end_matches("--")
        .trim();
    if boundary.is_empty() {
        return None;
    }

    let synthetic = format!(
        "Content-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n{}",
        boundary, body
    );
    let parsed = mailparse::parse_mail(synthetic.as_bytes()).ok()?;
    decode_parts_from_parsed(&parsed)
}

pub(super) fn decoded_mail_body_for_ui(email: &Email) -> (String, String, String) {
    let raw_mime = raw_mime_from_email(email);

    if let Ok(parsed) = mailparse::parse_mail(raw_mime.as_bytes()) {
        if let Some(decoded) = decode_parts_from_parsed(&parsed) {
            return decoded;
        }

        if let Ok(body) = parsed.get_body() {
            if looks_like_raw_multipart_dump(&body) {
                if let Some(decoded) = decode_from_synthetic_boundary(&body) {
                    return decoded;
                }
            }

            let looks_html = body.to_ascii_lowercase().contains("<html")
                || body.contains("</")
                || body.contains("<p");
            if looks_html {
                let preview = compact_preview(&strip_tags(&body)).chars().take(160).collect();
                return (body, "html".to_string(), preview);
            }
            let preview = compact_preview(&body).chars().take(160).collect();
            return (body, "text".to_string(), preview);
        }
    }

    if let Some(decoded) = decode_from_synthetic_boundary(&email.body) {
        return decoded;
    }

    let body_type = if email.body.to_ascii_lowercase().contains("<html")
        || email.body.contains("</")
        || email.body.contains("<p")
    {
        "html"
    } else {
        "text"
    };
    let plain = if body_type == "html" {
        strip_tags(&email.body)
    } else {
        email.body.clone()
    };
    let preview = compact_preview(&plain).chars().take(160).collect();
    (email.body.clone(), body_type.to_string(), preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_preview_collapses_whitespace() {
        assert_eq!(compact_preview("hello   world"), "hello world");
    }

    #[test]
    fn compact_preview_empty() {
        assert_eq!(compact_preview(""), "");
    }

    fn make_email(headers: Vec<(String, String)>, body: String) -> Email {
        Email {
            id: String::new(),
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            body,
            headers,
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        }
    }

    #[test]
    fn raw_mime_from_email_with_headers() {
        let email = make_email(
            vec![("From".to_string(), "a@b.com".to_string())],
            "body".to_string(),
        );
        assert_eq!(raw_mime_from_email(&email), "From: a@b.com\r\n\r\nbody");
    }

    #[test]
    fn raw_mime_from_email_no_headers() {
        let email = make_email(vec![], "body".to_string());
        assert_eq!(raw_mime_from_email(&email), "body");
    }

    #[test]
    fn looks_like_raw_multipart_dump_true() {
        assert!(looks_like_raw_multipart_dump(
            "--boundary\nContent-Type: text/plain"
        ));
    }

    #[test]
    fn looks_like_raw_multipart_dump_false() {
        assert!(!looks_like_raw_multipart_dump("plain text"));
    }

    #[test]
    fn looks_like_raw_multipart_dump_no_content_type() {
        assert!(!looks_like_raw_multipart_dump("--boundary\nhello"));
    }

    #[test]
    fn decoded_mail_body_for_ui_plain_text() {
        let email = make_email(vec![], "Hello World".to_string());
        let (body, body_type, preview) = decoded_mail_body_for_ui(&email);
        assert_eq!(body, "Hello World");
        assert_eq!(body_type, "text");
        assert_eq!(preview, "Hello World");
    }

    #[test]
    fn decoded_mail_body_for_ui_html() {
        let email = make_email(
            vec![],
            "<html><body><p>Hello World</p></body></html>".to_string(),
        );
        let (body, body_type, _) = decoded_mail_body_for_ui(&email);
        assert_eq!(body_type, "html");
        assert!(body.contains("Hello World"));
    }

    #[test]
    fn decoded_mail_body_for_ui_trims_preview() {
        let long_text = "a ".repeat(200);
        let email = make_email(vec![], long_text);
        let (_, _, preview) = decoded_mail_body_for_ui(&email);
        assert!(preview.chars().count() <= 160);
    }
}
