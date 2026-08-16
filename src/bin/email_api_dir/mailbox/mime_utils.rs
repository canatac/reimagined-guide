// MIME DTO + address parsing helpers (post-Sprint 17 split).
// Body decoding lives in mime_body.rs; attachment extraction in mime_attachments.rs.
use super::super::*;
#[allow(unused_imports)]
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::mime_attachments::extract_attachments_for_ui;
use super::mime_body::decoded_mail_body_for_ui;

#[derive(Serialize, Deserialize)]
pub(crate) struct EmailAddressDto {
    pub name: String,
    pub address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailDto {
    pub id: String,
    pub thread_id: String,
    pub folder: String,
    pub from: EmailAddressDto,
    pub to: Vec<EmailAddressDto>,
    pub subject: String,
    pub preview: String,
    pub body: String,
    pub body_type: String,
    pub date: String,
    pub received_at: String,
    pub is_read: bool,
    pub is_starred: bool,
    pub is_important: bool,
    pub has_attachments: bool,
    pub attachments: Vec<serde_json::Value>,
    pub labels: Vec<String>,
    pub size: u64,
    pub message_id: String,
}

pub(crate) fn parse_address(raw: &str) -> EmailAddressDto {
    let raw = raw.trim();
    if let Some(start) = raw.rfind('<') {
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

// Silence unused import lint for base64 which is used transitively by some subcrates.
#[allow(dead_code)]
fn _touch_base64(s: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}
