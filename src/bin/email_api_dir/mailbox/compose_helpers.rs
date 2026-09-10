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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_recipient_with_name() {
        let r = ComposerRecipient {
            email: "<EMAIL>".into(),
            name: Some("John".into()),
        };
        assert_eq!(format_recipient(&r), Some("John <<EMAIL>>".to_string()));
    }

    #[test]
    fn format_recipient_without_name() {
        let r = ComposerRecipient {
            email: "<EMAIL>".into(),
            name: None,
        };
        assert_eq!(format_recipient(&r), Some("<EMAIL>".to_string()));
    }

    #[test]
    fn format_recipient_empty_email() {
        let r = ComposerRecipient {
            email: "".into(),
            name: Some("John".into()),
        };
        assert_eq!(format_recipient(&r), None);
    }

    #[test]
    fn join_recipients_comma_separated() {
        let list = vec![
            ComposerRecipient { email: "<EMAIL>".into(), name: None },
            ComposerRecipient { email: "<EMAIL>".into(), name: Some("Bob".into()) },
        ];
        assert_eq!(join_recipients(&list), "<EMAIL>, Bob <<EMAIL>>");
    }

    #[test]
    fn from_address_for_user_with_at() {
        assert_eq!(from_address_for_user("admin@misfits.ai"), "admin@misfits.ai");
    }

    #[test]
    fn normalize_message_id_strips_brackets() {
        assert_eq!(normalize_message_id("<msg-123>"), "msg-123");
    }

    #[test]
    fn canonical_message_id_wraps_brackets() {
        assert_eq!(canonical_message_id("msg-123"), Some("<msg-123>".to_string()));
    }

    #[test]
    fn canonical_message_id_empty() {
        assert_eq!(canonical_message_id(""), None);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_recipient_with_name() {
        let r = ComposerRecipient { email: "<EMAIL>".into(), name: Some("John".into()) };
        assert_eq!(format_recipient(&r), Some("John <<EMAIL>>".to_string()));
    }

    #[test]
    fn format_recipient_no_name() {
        let r = ComposerRecipient { email: "<EMAIL>".into(), name: None };
        assert_eq!(format_recipient(&r), Some("<EMAIL>".to_string()));
    }

    #[test]
    fn format_recipient_empty_email() {
        let r = ComposerRecipient { email: "".into(), name: Some("John".into()) };
        assert_eq!(format_recipient(&r), None);
    }

    #[test]
    fn format_recipient_empty_name_becomes_none() {
        let r = ComposerRecipient { email: "<EMAIL>".into(), name: Some("  ".into()) };
        assert_eq!(format_recipient(&r), Some("<EMAIL>".to_string()));
    }

    #[test]
    fn join_recipients_comma_separated() {
        let recipients = vec![
            ComposerRecipient { email: "<EMAIL>".into(), name: Some("A".into()) },
            ComposerRecipient { email: "<EMAIL>".into(), name: None },
        ];
        assert_eq!(join_recipients(&recipients), "A <<EMAIL>>, <EMAIL>");
    }

    #[test]
    fn join_recipients_skips_empty() {
        let recipients = vec![
            ComposerRecipient { email: "".into(), name: Some("A".into()) },
            ComposerRecipient { email: "<EMAIL>".into(), name: None },
        ];
        assert_eq!(join_recipients(&recipients), "<EMAIL>");
    }

    #[test]
    fn domain_from_env_default() {
        std::env::remove_var("DOMAIN_NAME");
        assert_eq!(domain_from_env(), "misfits.ai");
    }

    #[test]
    fn domain_from_env_from_env() {
        std::env::set_var("DOMAIN_NAME", "example.com");
        assert_eq!(domain_from_env(), "example.com");
        std::env::remove_var("DOMAIN_NAME");
    }

    #[test]
    fn from_address_for_user_with_at() {
        assert_eq!(from_address_for_user("<EMAIL>"), "<EMAIL>");
    }

    #[test]
    fn from_address_for_user_without_at() {
        std::env::remove_var("DOMAIN_NAME");
        assert_eq!(from_address_for_user("user"), "<EMAIL>");
    }

    #[test]
    fn normalize_message_id_strips_brackets() {
        assert_eq!(normalize_message_id("<msg-123>"), "msg-123");
    }

    #[test]
    fn normalize_message_id_no_brackets() {
        assert_eq!(normalize_message_id("msg-123"), "msg-123");
    }

    #[test]
    fn canonical_message_id_wraps_brackets() {
        assert_eq!(canonical_message_id("msg-123"), Some("<msg-123>".to_string()));
    }

    #[test]
    fn canonical_message_id_empty() {
        assert_eq!(canonical_message_id(""), None);
    }

    #[test]
    fn sanitize_filename_removes_special_chars() {
        assert_eq!(sanitize_filename("file/name.txt", 0), "file_name.txt");
        assert_eq!(sanitize_filename("file:name.txt", 0), "file_name.txt");
        assert_eq!(sanitize_filename("file*name?.txt", 0), "file_name_.txt");
    }

    #[test]
    fn sanitize_filename_fallback_when_empty() {
        assert_eq!(sanitize_filename("", 0), "attachment-1");
        assert_eq!(sanitize_filename("...", 2), "attachment-3");
    }

    #[test]
    fn is_private_or_local_ip_loopback() {
        assert!(is_private_or_local_ip("127.0.0.1"));
        assert!(is_private_or_local_ip("::1"));
    }

    #[test]
    fn is_private_or_local_ip_private() {
        assert!(is_private_or_local_ip("10.0.0.1"));
        assert!(is_private_or_local_ip("192.168.1.1"));
        assert!(is_private_or_local_ip("172.16.0.1"));
    }

    #[test]
    fn is_private_or_local_ip_public() {
        assert!(!is_private_or_local_ip("8.8.8.8"));
        assert!(!is_private_or_local_ip("1.1.1.1"));
    }

    #[test]
    fn is_private_or_local_ip_invalid() {
        assert!(!is_private_or_local_ip("not-an-ip"));
    }

    #[test]
    fn is_internal_delivery_hop_local_host() {
        assert!(is_internal_delivery_hop(Some("smtp-server"), None, None, None));
        assert!(is_internal_delivery_hop(Some("host.local"), None, None, None));
        assert!(is_internal_delivery_hop(Some("host.internal"), None, None, None));
    }

    #[test]
    fn is_internal_delivery_hop_private_ip() {
        assert!(is_internal_delivery_hop(None, Some("10.0.0.1"), None, None));
    }

    #[test]
    fn is_internal_delivery_hop_company_relay() {
        assert!(is_internal_delivery_hop(None, None, Some(8025), Some("dkim-service")));
        assert!(is_internal_delivery_hop(None, None, Some(8465), Some("dkim-service")));
    }

    #[test]
    fn is_internal_delivery_hop_not_internal() {
        assert!(!is_internal_delivery_hop(Some("mail.google.com"), Some("8.8.8.8"), Some(587), Some("Google")));
    }
}
