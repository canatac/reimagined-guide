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
