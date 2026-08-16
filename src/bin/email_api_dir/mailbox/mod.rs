// mailbox/mod.rs — split from mailbox_handlers.rs (Sprint 8)
pub mod read_handlers;
pub mod send_handlers;
pub mod send_queue_worker;
pub mod single_handlers;
pub mod drafts_handlers;

pub use read_handlers::*;
pub use send_handlers::*;
pub use send_queue_worker::*;
pub use single_handlers::*;
pub use drafts_handlers::*;


#[derive(Deserialize)]
pub(crate) struct EmailListQuery {
    #[serde(default = "default_folder")]
    folder: String,
    #[serde(default = "default_page")]
    page: u32,
    #[serde(rename = "pageSize", default = "default_page_size")]
    page_size: u32,
}

fn default_folder() -> String {
    "inbox".to_string()
}
fn default_page() -> u32 {
    1
}
fn default_page_size() -> u32 {
    50
}

/// Canonical FE folder id → mailbox names to try in Mongo (SMTP historically used INBOX).
fn folder_to_mailboxes(folder: &str) -> Vec<String> {
    let f = folder.trim().to_ascii_lowercase();
    match f.as_str() {
        "inbox" => vec!["inbox".into(), "INBOX".into()],
        "sent" => vec!["sent".into(), "SENT".into(), "Sent".into()],
        "drafts" => vec!["drafts".into(), "DRAFTS".into(), "Drafts".into()],
        "archive" => vec!["archive".into(), "ARCHIVE".into(), "Archive".into()],
        "trash" => vec!["trash".into(), "TRASH".into(), "Trash".into()],
        "spam" => vec!["spam".into(), "SPAM".into(), "Spam".into(), "Junk".into()],
        other => vec![other.to_string(), other.to_ascii_uppercase()],
    }
}

fn canonical_folder(folder: &str) -> Option<String> {
    let f = folder.trim().to_ascii_lowercase();
    match f.as_str() {
        "inbox" | "sent" | "drafts" | "archive" | "trash" | "spam" => Some(f),
        _ => None,
    }
}

/// Resolve mailbox local-part. Convention: user_id = `admin` (not admin@misfits.ai).
pub(crate) fn resolve_user_id(req: &actix_web::HttpRequest) -> String {
    if let Some(id) = req
        .headers()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return id.to_string();
    }
    if let Some(email) = req
        .headers()
        .get("x-user-email")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return email.split('@').next().unwrap_or(email).to_string();
    }
    env::var("SMTP_USERNAME").unwrap_or_else(|_| "admin".to_string())
}


use super::*;
use base64::Engine as _;

#[derive(Serialize, Deserialize)]
pub(crate) struct EmailAddressDto {
    name: String,
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailDto {
    id: String,
    thread_id: String,
    folder: String,
    from: EmailAddressDto,
    to: Vec<EmailAddressDto>,
    subject: String,
    preview: String,
    body: String,
    body_type: String,
    date: String,
    received_at: String,
    is_read: bool,
    is_starred: bool,
    is_important: bool,
    has_attachments: bool,
    attachments: Vec<serde_json::Value>,
    labels: Vec<String>,
    size: u64,
    message_id: String,
}

pub(crate) fn parse_address(raw: &str) -> EmailAddressDto {
    let raw = raw.trim();
    // "Name <addr@x>" or bare addr. Guard against malformed inputs where
    // '>' appears before '<' (e.g. `">" <admin@misfits.ai`) — naive slicing
    // panics on start > end. Pick the last '<' and the matching '>' after it.
    if let Some(start) = raw.rfind('<') {
        // Only treat as bracketed form when a '>' exists AFTER the '<'.
        if let Some(rel_end) = raw[start + 1..].find('>') {
            let end = start + 1 + rel_end;
            let name = raw[..start].trim().trim_matches('"').trim().to_string();
            let address = raw[start + 1..end].trim().to_string();
            if !address.is_empty() {
                return EmailAddressDto {
                    name: if name.is_empty() {
                        address.split('@').next().unwrap_or("").to_string()
                    } else {
                        name
                    },
                    address,
                };
            }
        }
    }
    // Bare address fallback: strip any stray angle brackets/quotes.
    let cleaned = raw
        .trim_matches(|c| c == '<' || c == '>' || c == '"')
        .trim();
    EmailAddressDto {
        name: cleaned.split('@').next().unwrap_or(cleaned).to_string(),
        address: cleaned.to_string(),
    }
}

pub(crate) fn strip_tags(html: &str) -> String {
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

fn compact_preview(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn raw_mime_from_email(email: &Email) -> String {
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

fn looks_like_raw_multipart_dump(body: &str) -> bool {
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

fn infer_attachment_kind(content_type: &str, filename: &str) -> &'static str {
    let ct = content_type.to_ascii_lowercase();
    let lower_name = filename.to_ascii_lowercase();
    if ct.starts_with("image/") {
        "image"
    } else if ct == "application/pdf" || lower_name.ends_with(".pdf") {
        "pdf"
    } else if ct.contains("word")
        || lower_name.ends_with(".doc")
        || lower_name.ends_with(".docx")
        || lower_name.ends_with(".odt")
    {
        "doc"
    } else if ct.contains("sheet")
        || lower_name.ends_with(".xls")
        || lower_name.ends_with(".xlsx")
        || lower_name.ends_with(".csv")
    {
        "spreadsheet"
    } else if ct.contains("presentation")
        || lower_name.ends_with(".ppt")
        || lower_name.ends_with(".pptx")
    {
        "presentation"
    } else if ct.starts_with("audio/") {
        "audio"
    } else if ct.starts_with("video/") {
        "video"
    } else if ct.contains("zip")
        || ct.contains("gzip")
        || ct.contains("tar")
        || ct.contains("7z")
        || lower_name.ends_with(".zip")
        || lower_name.ends_with(".tar")
        || lower_name.ends_with(".gz")
        || lower_name.ends_with(".7z")
    {
        "archive"
    } else {
        "other"
    }
}

#[derive(Clone)]
struct ExtractedAttachment {
    id: String,
    filename: String,
    content_type: String,
    size: u64,
    kind: String,
    data: Vec<u8>,
}

fn walk_mime_attachments(
    part: &mailparse::ParsedMail<'_>,
    out: &mut Vec<ExtractedAttachment>,
    index: &mut usize,
) {
    if !part.subparts.is_empty() {
        for sub in &part.subparts {
            walk_mime_attachments(sub, out, index);
        }
        return;
    }

    let content_type = part.ctype.mimetype.to_ascii_lowercase();
    let disp = part.get_content_disposition();
    let disp_kind = format!("{:?}", disp.disposition).to_ascii_lowercase();
    let filename = disp
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("attachment-{}", *index + 1));

    let is_attachment = disp_kind == "attachment"
        || disp.params.contains_key("filename")
        || part.ctype.params.contains_key("name")
        || (!content_type.starts_with("text/") && content_type != "application/pgp-signature");

    if !is_attachment {
        return;
    }

    let bytes = part.get_body_raw().unwrap_or_default();
    let kind = infer_attachment_kind(&content_type, &filename).to_string();
    let id = format!("att-{}", *index);
    *index += 1;

    out.push(ExtractedAttachment {
        id,
        filename,
        content_type,
        size: bytes.len() as u64,
        kind,
        data: bytes,
    });
}

fn extract_attachments_for_ui(email: &Email) -> Vec<ExtractedAttachment> {
    let raw_mime = raw_mime_from_email(email);
    if let Ok(parsed) = mailparse::parse_mail(raw_mime.as_bytes()) {
        let mut out = Vec::new();
        let mut idx = 0usize;
        walk_mime_attachments(&parsed, &mut out, &mut idx);
        return out;
    }

    if looks_like_raw_multipart_dump(&email.body) {
        let first_line = match email.body.lines().next() {
            Some(l) => l.trim(),
            None => return Vec::new(),
        };
        let boundary = first_line
            .trim_start_matches("--")
            .trim_end_matches("--")
            .trim();
        if boundary.is_empty() {
            return Vec::new();
        }
        let synthetic = format!(
            "Content-Type: multipart/mixed; boundary=\"{}\"\r\n\r\n{}",
            boundary, email.body
        );
        if let Ok(parsed) = mailparse::parse_mail(synthetic.as_bytes()) {
            let mut out = Vec::new();
            let mut idx = 0usize;
            walk_mime_attachments(&parsed, &mut out, &mut idx);
            return out;
        }
    }

    Vec::new()
}

fn decoded_mail_body_for_ui(email: &Email) -> (String, String, String) {
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

    // Fallback (legacy behavior) when MIME parse fails
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

pub(crate) fn email_to_dto(email: &Email, folder: &str, include_body: bool) -> EmailDto {
    let flags_l: Vec<String> = email.flags.iter().map(|f| f.to_ascii_lowercase()).collect();
    let is_read = flags_l.iter().any(|f| f == "seen" || f == "\\seen");
    let is_starred = flags_l
        .iter()
        .any(|f| f == "flagged" || f == "\\flagged" || f == "starred");
    let (decoded_body, body_type, preview) = decoded_mail_body_for_ui(email);
    let date = {
        let ms = email.internal_date.timestamp_millis();
        chrono::DateTime::from_timestamp_millis(ms)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339())
    };
    // SMTP/Nodemailer inbound often leaves `id` blank and packs DKIM-/Message-ID
    // into weird header tuples ("Message-ID: <...>", "Message-ID: <...>").
    let message_id = email
        .headers
        .iter()
        .find_map(|(k, v)| {
            if k.eq_ignore_ascii_case("message-id") && !v.is_empty() {
                Some(v.clone())
            } else if k.to_ascii_lowercase().starts_with("message-id:") {
                let val = k.splitn(2, ':').nth(1).unwrap_or("").trim();
                if !val.is_empty() {
                    Some(val.to_string())
                } else if !v.is_empty() {
                    Some(v.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if !email.id.is_empty() {
                email.id.clone()
            } else if email.uid > 0 {
                format!("uid-{}", email.uid)
            } else {
                Uuid::new_v4().to_string()
            }
        });
    let id = if email.id.is_empty() {
        message_id
            .trim_matches(|c| c == '<' || c == '>')
            .to_string()
    } else {
        email.id.clone()
    };
    let to_list: Vec<EmailAddressDto> = email
        .to
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_address)
        .collect();
    let attachments = extract_attachments_for_ui(email);
    let attachments_json: Vec<serde_json::Value> = attachments
        .iter()
        .map(|att| {
            serde_json::json!({
                "id": att.id,
                "filename": att.filename,
                "contentType": att.content_type,
                "size": att.size,
                "type": att.kind,
                "downloadUrl": format!("/api/emails/{}/attachments/{}", id, att.id),
            })
        })
        .collect();

    EmailDto {
        id,
        thread_id: message_id.clone(),
        folder: folder.to_ascii_lowercase(),
        from: parse_address(&email.from),
        to: to_list,
        subject: email.subject.clone(),
        preview,
        // List payloads stay lean — detail fetch fills body via GET /api/emails/:id
        body: if include_body {
            decoded_body.clone()
        } else {
            String::new()
        },
        body_type,
        date: date.clone(),
        received_at: date,
        is_read,
        is_starred,
        is_important: false,
        has_attachments: !attachments_json.is_empty(),
        attachments: attachments_json,
        labels: vec![],
        size: email.body.len() as u64,
        message_id,
    }
}

