// Sprint 8: split from mailbox_handlers.rs
#![allow(unused_imports)]
use super::*;

pub(crate) async fn api_email_attachment_download(
    path: web::Path<(String, String)>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let (email_id, attachment_id) = path.into_inner();

    match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => {
            let attachments = extract_attachments_for_ui(&email);
            if let Some(att) = attachments.into_iter().find(|a| a.id == attachment_id) {
                let safe_name = att.filename.replace('"', "_");
                return HttpResponse::Ok()
                    .insert_header(("Content-Type", att.content_type))
                    .insert_header((
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", safe_name),
                    ))
                    .body(att.data);
            }
            HttpResponse::NotFound().json(serde_json::json!({
                "message": "Attachment not found",
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("api_email_attachment_download fetch_email error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch attachment",
            }))
        }
    }
}

pub(crate) fn email_to_list_dto(email: &Email, folder: &str) -> EmailDto {
    email_to_dto(email, folder, false)
}

pub(crate) fn email_to_detail_dto(email: &Email, folder: &str) -> EmailDto {
    email_to_dto(email, folder, true)
}

pub(crate) async fn api_emails(
    query: web::Query<EmailListQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let folder = query.folder.trim().to_ascii_lowercase();
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    // Over-fetch a single page-sized chunk per mailbox candidate, then merge.
    // Skip huge dumps: limit from Mongo already newest-first.
    let fetch_limit = (page_size as i64)
        .saturating_mul(page as i64)
        .max(page_size as i64);

    let mut collected: Vec<Email> = Vec::new();
    for mailbox in folder_to_mailboxes(&folder) {
        match logic
            .get_emails_page(&user_id, &mailbox, fetch_limit, 0)
            .await
        {
            Ok(mut batch) => {
                collected.append(&mut batch);
            }
            Err(e) => {
                eprintln!("get_emails user={} mailbox={}: {}", user_id, mailbox, e);
            }
        }
    }

    // Newest first (Mongo sort already does this; keep stable merge)
    collected.sort_by(|a, b| b.internal_date.cmp(&a.internal_date));
    // Dedup by id / message-id fallback
    let mut seen = std::collections::HashSet::new();
    collected.retain(|e| {
        let key = if e.id.is_empty() {
            format!(
                "{}|{}|{}",
                e.from,
                e.subject,
                e.internal_date.timestamp_millis()
            )
        } else {
            e.id.clone()
        };
        seen.insert(key)
    });

    let total = collected.len() as u32;
    let start = ((page - 1) * page_size) as usize;
    let page_items: Vec<EmailDto> = collected
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .map(|e| email_to_list_dto(&e, &folder))
        .collect();
    let has_more = start + page_items.len() < total as usize;

    HttpResponse::Ok().json(serde_json::json!({
        "emails": page_items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "hasMore": has_more,
    }))
}

pub(crate) async fn api_tags() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"tags": []}))
}

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
    filename: String,
    #[serde(default, rename = "contentType", alias = "content_type")]
    content_type: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default, rename = "dataBase64", alias = "data_base64")]
    data_base64: String,
}

#[derive(Deserialize)]
pub(crate) struct ComposeSendRequest {
    #[serde(default)]
    to: Vec<ComposerRecipient>,
    #[serde(default)]
    cc: Vec<ComposerRecipient>,
    #[serde(default)]
    bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    attachments: Vec<ComposeAttachmentInput>,
    /// Some FE clients send flat strings instead of recipient objects.
    #[serde(default)]
    from: Option<String>,
    #[serde(default, rename = "inReplyTo", alias = "in_reply_to")]
    in_reply_to: Option<String>,
    #[serde(default)]
    references: Vec<String>,
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

fn build_body_with_attachments(
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

