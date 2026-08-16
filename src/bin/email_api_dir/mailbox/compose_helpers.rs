// Compose helpers extracted from read_handlers.rs (Sprint 17).
#![allow(unused_imports)]
use super::*;

// --- Send + get-by-id (Phase A3/A4, issues #168/#169) -------------------------

#[derive(Deserialize)]
pub(crate) struct ComposerRecipient {
    #[serde(default)]
    email: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, Clone)]
pub(crate) struct ComposeAttachmentInput {
    #[serde(default)]
    pub(crate) filename: String,
    #[serde(default, rename = "contentType", alias = "content_type")]
    pub(crate) content_type: String,
    #[serde(default)]
    pub(crate) size: Option<u64>,
    #[serde(default, rename = "dataBase64", alias = "data_base64")]
    pub(crate) data_base64: String,
}

#[derive(Deserialize)]
pub(crate) struct ComposeSendRequest {
    #[serde(default)]
    pub(crate) to: Vec<ComposerRecipient>,
    #[serde(default)]
    pub(crate) cc: Vec<ComposerRecipient>,
    #[serde(default)]
    pub(crate) bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    pub(crate) subject: String,
    #[serde(default)]
    pub(crate) body: String,
    #[serde(default)]
    pub(crate) attachments: Vec<ComposeAttachmentInput>,
    /// Some FE clients send flat strings instead of recipient objects.
    #[serde(default)]
    pub(crate) from: Option<String>,
    #[serde(default, rename = "inReplyTo", alias = "in_reply_to")]
    pub(crate) in_reply_to: Option<String>,
    #[serde(default)]
    pub(crate) references: Vec<String>,
}

pub(crate) fn format_recipient(r: &ComposerRecipient) -> Option<String> {
    let email = r.email.trim();
    if email.is_empty() {
        return None;
    }
    match r.name.as_ref().map(|n| n.trim()).filter(|n| !n.is_empty()) {
        Some(name) => Some(format!("{} <{}>", name, email)),
        None => Some(email.to_string()),
    }
}

pub(crate) fn join_recipients(list: &[ComposerRecipient]) -> String {
    list.iter()
        .filter_map(format_recipient)
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn domain_from_env() -> String {
    env::var("DOMAIN_NAME").unwrap_or_else(|_| "misfits.ai".to_string())
}

pub(crate) fn from_address_for_user(user_id: &str) -> String {
    if user_id.contains('@') {
        user_id.to_string()
    } else {
        format!("{}@{}", user_id, domain_from_env())
    }
}

pub(crate) fn normalize_message_id(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

pub(crate) fn canonical_message_id(raw: &str) -> Option<String> {
    let normalized = normalize_message_id(raw);
    if normalized.is_empty() {
        None
    } else {
        Some(format!("<{}>", normalized))
    }
}

fn sanitize_filename(name: &str, fallback_index: usize) -> String {
    let cleaned = name
        .trim()
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect::<String>();
    let cleaned = cleaned.trim_matches('.').trim();
    if cleaned.is_empty() {
        format!("attachment-{}", fallback_index + 1)
    } else {
        cleaned.to_string()
    }
}

fn chunk_base64_lines(encoded: &str) -> String {
    if encoded.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(encoded.len() + (encoded.len() / 76 + 2) * 2);
    let mut i = 0;
    while i < encoded.len() {
        let end = (i + 76).min(encoded.len());
        out.push_str(&encoded[i..end]);
        out.push_str("\r\n");
        i = end;
    }
    out
}

pub(crate) fn build_body_with_attachments(
    body_html: &str,
    attachments: &[ComposeAttachmentInput],
) -> Result<(String, String), String> {
    if attachments.is_empty() {
        return Ok((body_html.to_string(), "text/html; charset=utf-8".to_string()));
    }

    let mut plain = strip_tags(body_html);
    if plain.trim().is_empty() {
        plain = body_html.to_string();
    }
    let plain = plain.trim();

    let mixed_boundary = format!("misfits-mixed-{}", Uuid::new_v4().simple());
    let alt_boundary = format!("misfits-alt-{}", Uuid::new_v4().simple());

    let mut body = String::new();
    body.push_str(&format!("--{}\r\n", mixed_boundary));
    body.push_str(&format!(
        "Content-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n",
        alt_boundary
    ));

    body.push_str(&format!("--{}\r\n", alt_boundary));
    body.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    body.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    body.push_str(&plain.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n"));
    body.push_str("\r\n");

    body.push_str(&format!("--{}\r\n", alt_boundary));
    body.push_str("Content-Type: text/html; charset=utf-8\r\n");
    body.push_str("Content-Transfer-Encoding: 8bit\r\n\r\n");
    body.push_str(&body_html.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n"));
    body.push_str("\r\n");
    body.push_str(&format!("--{}--\r\n", alt_boundary));

    for (idx, att) in attachments.iter().enumerate() {
        if att.data_base64.trim().is_empty() {
            continue;
        }
        let raw = att
            .data_base64
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .map_err(|e| format!("invalid attachment base64 for '{}': {}", att.filename, e))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let safe_name = sanitize_filename(&att.filename, idx);
        let content_type = if att.content_type.trim().is_empty() {
            "application/octet-stream".to_string()
        } else {
            att.content_type.trim().to_string()
        };

        body.push_str(&format!("--{}\r\n", mixed_boundary));
        body.push_str(&format!(
            "Content-Type: {}; name=\"{}\"\r\n",
            content_type, safe_name
        ));
        body.push_str("Content-Transfer-Encoding: base64\r\n");
        body.push_str(&format!(
            "Content-Disposition: attachment; filename=\"{}\"\r\n\r\n",
            safe_name
        ));
        body.push_str(&chunk_base64_lines(&encoded));
    }

    body.push_str(&format!("--{}--\r\n", mixed_boundary));

    Ok((
        body,
        format!("multipart/mixed; boundary=\"{}\"", mixed_boundary),
    ))
}

pub(crate) fn is_private_or_local_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast()
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        Err(_) => false,
    }
}

pub(crate) fn is_internal_delivery_hop(
    mx_host: Option<&str>,
    remote_ip: Option<&str>,
    remote_port: Option<u16>,
    company: Option<&str>,
) -> bool {
    let host_internal = mx_host
        .map(|h| {
            let h = h.to_ascii_lowercase();
            h == "smtp-server" || h.ends_with(".local") || h.ends_with(".internal")
        })
        .unwrap_or(false);

    let ip_internal = remote_ip.map(is_private_or_local_ip).unwrap_or(false);
    let relay_port = matches!(remote_port, Some(8025 | 8465));
    let company_internal = company
        .map(|c| c.eq_ignore_ascii_case("dkim-service"))
        .unwrap_or(false);

    host_internal || ip_internal || (company_internal && relay_port)
}
