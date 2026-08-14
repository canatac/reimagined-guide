
#[derive(Deserialize)]
struct EmailListQuery {
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
fn resolve_user_id(req: &actix_web::HttpRequest) -> String {
    if let Some(id) = req
        .headers()
        .get("x-user-id")

// mailbox_handlers.rs — extracted from email_api_dir/main.rs Sprint 2
// Handlers: api_emails, api_send, api_send_undo, api_send_schedule,
//           api_send_status, api_email_action, api_drafts_*, send_queue_worker
// Types: EmailAddressDto, EmailDto, ComposerRecipient, DraftDto

use super::*;

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

pub(crate) fn email_to_dto(email: &Email, folder: &str, include_body: bool) -> EmailDto {
    let flags_l: Vec<String> = email.flags.iter().map(|f| f.to_ascii_lowercase()).collect();
    let is_read = flags_l.iter().any(|f| f == "seen" || f == "\\seen");
    let is_starred = flags_l
        .iter()
        .any(|f| f == "flagged" || f == "\\flagged" || f == "starred");
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
    let preview: String = plain.chars().take(160).collect();
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
            email.body.clone()
        } else {
            String::new()
        },
        body_type: body_type.to_string(),
        date: date.clone(),
        received_at: date,
        is_read,
        is_starred,
        is_important: false,
        has_attachments: false,
        attachments: vec![],
        labels: vec![],
        size: email.body.len() as u64,
        message_id,
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
    /// Some FE clients send flat strings instead of recipient objects.
    #[serde(default)]
    from: Option<String>,
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

pub(crate) async fn api_send(
    body: web::Json<ComposeSendRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "sent": false,
            "message": "At least one recipient (to) is required",
        }));
    }
    let cc = join_recipients(&body.cc);
    let bcc = join_recipients(&body.bcc);
    let subject = body.subject.clone();
    let mail_body = body.body.clone();

    let email_req = EmailRequest {
        from: from.clone(),
        to: to.clone(),
        subject: subject.clone(),
        body: mail_body.clone(),
    };

    // DKIM sign via shared service (same path as /send-email).
    // Note: studious-octo-rotary-phone exposes POST /generate-dkim and may
    // both sign and deliver via Nodemailer — when no dkimSignature is
    // returned we treat success as "already delivered by dkim-service".
    let dkim_service: Box<dyn DkimService> = Box::new(RealDkimService);
    let (
        dkim_sig,
        message_id_hdr,
        already_delivered,
        dkim_remote_accepted,
        dkim_remote_rejected,
        dkim_response,
        dkim_mx_host,
        dkim_remote_ip,
        dkim_remote_port,
    ) = match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            let status = dkim_result["status"].as_str().unwrap_or("");
            if status != "success" {
                let msg = dkim_result["message"]
                    .as_str()
                    .or_else(|| dkim_result["error"].as_str())
                    .unwrap_or("DKIM signing failed");
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "sent": false,
                    "message": format!("Failed to sign email: {}", msg),
                }));
            }

            let sig = dkim_result["dkimSignature"]
                .as_str()
                .or_else(|| dkim_result["dkim_signature"].as_str())
                .unwrap_or("")
                .to_string();
            let mid = dkim_result["messageId"]
                .as_str()
                .or_else(|| dkim_result["message_id"].as_str())
                .unwrap_or("")
                .to_string();

            let accepted_by_remote_mx =
                dkim_result["acceptedByRemoteMx"].as_bool().unwrap_or(false)
                    || dkim_result["accepted"]
                        .as_array()
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
            let rejected_by_remote_mx = dkim_result["rejected"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let upstream_response = dkim_result["response"].as_str().map(|s| s.to_string());
            let upstream_mx_host = dkim_result["smtpHost"].as_str().map(|s| s.to_string());
            let upstream_remote_ip = dkim_result["remoteIp"].as_str().map(|s| s.to_string());
            let upstream_remote_port = dkim_result["smtpPort"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok());

            // Distinguish true remote-MX acceptance from internal relay handoff.
            let internal_hop = is_internal_delivery_hop(
                upstream_mx_host.as_deref(),
                upstream_remote_ip.as_deref(),
                upstream_remote_port,
                Some("dkim-service"),
            );
            let effective_remote_accept = accepted_by_remote_mx && !internal_hop;

            // No DKIM signature means dkim-service likely performed SMTP itself.
            // Accept this path only with explicit SMTP handoff proof (`accepted*`).
            // We still keep `effective_remote_accept` separate so status can tell
            // true remote MX acceptance from internal relay handoff.
            let delivered = sig.is_empty() && accepted_by_remote_mx;
            if sig.is_empty() && !delivered {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                        "sent": false,
                        "message": "DKIM signer returned success without signature and without SMTP handoff proof; refusing unsigned send",
                    }));
            }
            (
                sig,
                mid,
                delivered,
                effective_remote_accept,
                rejected_by_remote_mx,
                upstream_response,
                upstream_mx_host,
                upstream_remote_ip,
                upstream_remote_port,
            )
        }
        Err(e) => {
            eprintln!("DKIM service error on /api/send: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "message": format!("Failed to generate DKIM signature: {}", e),
            }));
        }
    };

    let id = Uuid::new_v4().to_string();
    let message_id = if message_id_hdr.is_empty() {
        format!("<{}@{}>", id, domain_from_env())
    } else if message_id_hdr.starts_with('<') {
        message_id_hdr.clone()
    } else {
        format!("<{}>", message_id_hdr)
    };

    let mut headers = vec![
        ("Message-ID".to_string(), message_id.clone()),
        ("Date".to_string(), Utc::now().to_rfc2822()),
        ("MIME-Version".to_string(), "1.0".to_string()),
        (
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        ),
    ];
    if !cc.is_empty() {
        headers.push(("Cc".to_string(), cc.clone()));
    }
    if !bcc.is_empty() {
        // Envelope Bcc isn't fully separated yet; record header for stored copy only if present.
        headers.push(("Bcc".to_string(), bcc.clone()));
    }
    if !dkim_sig.is_empty() {
        headers.push(("DKIM-Signature".to_string(), dkim_sig.clone()));
    }

    let email = Email {
        id: id.clone(),
        from: from.clone(),
        to: to.clone(),
        subject: subject.clone(),
        body: mail_body.clone(),
        headers,
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: if dkim_sig.is_empty() {
            None
        } else {
            Some(dkim_sig)
        },
    };

    // If the DKIM service already delivered the message (success response
    // without a dkim signature), skip direct SMTP relay. This prevents false
    // negatives when relay ports are closed but delivery already happened.

    // Undo window: queue the email instead of sending immediately.
    let undo_window_secs = env::var("SEND_UNDO_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    if undo_window_secs > 0 && !already_delivered {
        let send_after = bson::DateTime::from_millis(
            Utc::now().timestamp_millis() + (undo_window_secs as i64 * 1000),
        );
        let queue_doc = doc! {
            "id": &id,
            "user_id": &user_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &subject,
            "body": &mail_body,
            "dkim_signature": email.dkim_signature.as_deref().unwrap_or(""),
            "message_id": &message_id,
            "status": "pending",
            "send_after": send_after,
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        };
        let db = mongo_db_name();
        let sq_coll = mongo
            .database(&db)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        return match sq_coll.insert_one(queue_doc).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "sent": false,
                "queued": true,
                "id": id,
                "messageId": message_id,
                "deliveryState": "pending",
                "undoWindowSecs": undo_window_secs,
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false, "error": e.to_string()
            })),
        };
    }

    let send_result = if already_delivered {
        Ok(())
    } else {
        send_outgoing_email(&email).await
    };

    match send_result {
        Ok(_) => {
            if already_delivered && monitoring::monitoring_enabled() {
                // DKIM service did the SMTP handoff/delivery itself. Persist an
                // explicit monitoring event so trace API/status API can surface
                // whether upstream accepted recipient(s).
                let mut ev = monitoring::SmtpEvent::new(
                    &normalize_message_id(&message_id),
                    if dkim_remote_accepted {
                        monitoring::SmtpEventType::Delivered
                    } else {
                        monitoring::SmtpEventType::Queued
                    },
                    &from,
                    &to,
                );

                ev.status = if dkim_remote_accepted {
                    monitoring::SmtpStatus::Delivered
                } else if dkim_remote_rejected {
                    monitoring::SmtpStatus::Bounced
                } else {
                    monitoring::SmtpStatus::Pending
                };

                ev.company = Some("dkim-service".to_string());
                ev.mx_host = dkim_mx_host;
                ev.remote_ip = dkim_remote_ip;
                ev.remote_port = dkim_remote_port;
                ev.smtp_reply = dkim_response.or_else(|| {
                    Some(
                        if dkim_remote_accepted {
                            "Upstream SMTP accepted by DKIM service"
                        } else if dkim_remote_rejected {
                            "Upstream SMTP rejected recipient in DKIM service"
                        } else {
                            "Handoff accepted by DKIM service (remote mailbox receipt not independently verified)"
                        }
                        .to_string(),
                    )
                });
                monitoring::emit(ev);
            }

            // Store Sent copy for the sender. Local-domain inbox copies come
            // exclusively from SMTP inbound (Nodemailer/dkim or MX self-delivery)
            // to avoid duplicate messages.
            if let Err(e) = logic.store_email(&user_id, "sent", &email).await {
                eprintln!("store sent copy failed: {}", e);
            }
            emit_event(
                &bus,
                &mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Sent,
                    user_id: user_id.clone(),
                    email_id: id.clone(),
                    subject: subject.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let delivery_state = if dkim_remote_rejected {
                "failed"
            } else if dkim_remote_accepted {
                "sent"
            } else if already_delivered {
                "queued"
            } else {
                "sending"
            };

            HttpResponse::Ok().json(serde_json::json!({
                "sent": true,
                "id": id,
                "messageId": message_id,
                "deliveryState": delivery_state,
            }))
        }
        Err(e) => {
            eprintln!("send_outgoing_email failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "deliveryState": "failed",
                "message": format!("Failed to send email: {}", e),
            }))
        }
    }
}

// --- Send undo (POST /api/send/undo) ---

pub(crate) async fn api_send_undo(
    body: web::Json<UndoSendRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
    match coll
        .update_one(
            doc! {
                "id": &body.id,
                "user_id": &user_id,
                "status": "pending",
                "send_after": { "$gt": now },
            },
            doc! { "$set": { "status": "cancelled" } },
        )
        .await
    {
        Ok(r) if r.matched_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "cancelled": true, "id": &body.id }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "cancelled": false,
            "reason": "Email not found, already sent, or undo window has passed"
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

// --- Send schedule (POST /api/send/schedule) ---

pub(crate) async fn api_send_schedule(
    body: web::Json<ScheduleSendBody>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one recipient (to) is required"
        }));
    }

    let send_at = match chrono::DateTime::parse_from_rfc3339(&body.send_at) {
        Ok(dt) => dt,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Invalid send_at: use ISO 8601 format" }))
        }
    };
    if send_at.timestamp() <= Utc::now().timestamp() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "send_at must be in the future" }));
    }

    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));
    let cc = join_recipients(&body.cc);
    let bcc = join_recipients(&body.bcc);

    let id = Uuid::new_v4().to_string();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match coll
        .insert_one(doc! {
            "id": &id,
            "user_id": &user_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &body.subject,
            "body": &body.body,
            "dkim_signature": "",
            "message_id": format!("<{}@{}>", &id, domain_from_env()),
            "status": "scheduled",
            "send_after": bson::DateTime::from_millis(send_at.timestamp_millis()),
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        })
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "queued": true, "id": id, "sendAt": body.send_at
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

// --- Send queue background worker ---

pub(crate) async fn send_queue_worker(mongo: Arc<mongodb::Client>) {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let coll = mongo
            .database(&db_name)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());

        let cursor = match coll
            .find(doc! {
                "status": { "$in": ["pending", "scheduled"] },
                "send_after": { "$lte": now },
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("send_queue_worker find error: {}", e);
                continue;
            }
        };

        let entries = match cursor.try_collect::<Vec<bson::Document>>().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("send_queue_worker collect error: {}", e);
                continue;
            }
        };

        for entry in entries {
            let id = entry.get_str("id").unwrap_or("").to_string();
            let from = entry.get_str("from").unwrap_or("").to_string();
            let to = entry.get_str("to").unwrap_or("").to_string();
            let subject = entry.get_str("subject").unwrap_or("").to_string();
            let body_text = entry.get_str("body").unwrap_or("").to_string();
            let cc = entry.get_str("cc").unwrap_or("").to_string();
            let bcc = entry.get_str("bcc").unwrap_or("").to_string();
            let dkim_sig = entry.get_str("dkim_signature").unwrap_or("").to_string();
            let message_id = entry.get_str("message_id").unwrap_or("").to_string();

            // Optimistic lock: claim entry before sending
            let claim = coll
                .update_one(
                    doc! { "id": &id, "status": { "$in": ["pending", "scheduled"] } },
                    doc! { "$set": { "status": "sending" } },
                )
                .await;
            match claim {
                Ok(r) if r.matched_count == 0 => continue,
                Err(e) => {
                    eprintln!("send_queue claim error for {}: {}", id, e);
                    continue;
                }
                _ => {}
            }

            let mut headers = vec![
                (
                    "Message-ID".to_string(),
                    if message_id.is_empty() {
                        format!(
                            "<{}@{}>",
                            id,
                            std::env::var("DOMAIN_NAME")
                                .unwrap_or_else(|_| "misfits.ai".to_string())
                        )
                    } else {
                        message_id
                    },
                ),
                ("Date".to_string(), Utc::now().to_rfc2822()),
                ("MIME-Version".to_string(), "1.0".to_string()),
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
            ];
            if !cc.is_empty() {
                headers.push(("Cc".to_string(), cc));
            }
            if !bcc.is_empty() {
                headers.push(("Bcc".to_string(), bcc));
            }
            if !dkim_sig.is_empty() {
                headers.push(("DKIM-Signature".to_string(), dkim_sig.clone()));
            }

            let email = Email {
                id: id.clone(),
                from,
                to,
                subject,
                body: body_text,
                headers,
                flags: vec![],
                sequence_number: 0,
                uid: 0,
                internal_date: bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                dkim_signature: if dkim_sig.is_empty() {
                    None
                } else {
                    Some(dkim_sig)
                },
            };

            let status = match send_outgoing_email(&email).await {
                Ok(_) => "sent",
                Err(e) => {
                    eprintln!("send_queue_worker send error for {}: {}", id, e);
                    "failed"
                }
            };

            let _ = coll
                .update_one(doc! { "id": &id }, doc! { "$set": { "status": status } })
                .await;
        }
    }
}

pub(crate) async fn api_send_status(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();

    let email = match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Email not found"
            }))
        }
        Err(e) => {
            eprintln!("api_send_status fetch_email error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch email"
            }));
        }
    };

    let message_id_header = email
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let message_id = normalize_message_id(&message_id_header);
    if message_id.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "id": email.id,
            "message": "No Message-ID found",
            "monitoring": {
                "traceable": false
            }
        }));
    }

    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("smtp_events");

    let events = match coll
        .find(doc! { "message_id": &message_id })
        .sort(doc! { "ts": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| bson::from_document::<monitoring::SmtpEvent>(d).ok())
            .collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("api_send_status query smtp_events error: {}", e);
            vec![]
        }
    };

    let accepted_by_remote_mx = events.iter().any(|e| {
        matches!(e.event_type, monitoring::SmtpEventType::Delivered)
            && matches!(e.status, monitoring::SmtpStatus::Delivered)
            && !is_internal_delivery_hop(
                e.mx_host.as_deref(),
                e.remote_ip.as_deref(),
                e.remote_port,
                e.company.as_deref(),
            )
    });
    let bounced_or_failed = events.iter().any(|e| {
        matches!(
            e.status,
            monitoring::SmtpStatus::Bounced | monitoring::SmtpStatus::Failed
        )
    });
    let saw_internal_handoff = events.iter().any(|e| {
        is_internal_delivery_hop(
            e.mx_host.as_deref(),
            e.remote_ip.as_deref(),
            e.remote_port,
            e.company.as_deref(),
        )
    });
    let handoff_only = !accepted_by_remote_mx && !bounced_or_failed && saw_internal_handoff;

    let latest = events
        .iter()
        .find(|e| {
            matches!(
                e.status,
                monitoring::SmtpStatus::Delivered
                    | monitoring::SmtpStatus::Bounced
                    | monitoring::SmtpStatus::Failed
                    | monitoring::SmtpStatus::Deferred
            )
        })
        .or_else(|| events.first());
    let delivery_state = if accepted_by_remote_mx {
        "sent"
    } else if bounced_or_failed {
        "failed"
    } else if handoff_only {
        "queued"
    } else {
        "sending"
    };

    HttpResponse::Ok().json(serde_json::json!({
        "id": email.id,
        "messageId": message_id,
        "deliveryState": delivery_state,
        "from": email.from,
        "to": email.to,
        "subject": email.subject,
        "monitoring": {
            "traceable": true,
            "events": events.len(),
            "acceptedByRemoteMx": accepted_by_remote_mx,
            "bouncedOrFailed": bounced_or_failed,
            "handoffOnly": handoff_only,
            "latestEventType": latest.map(|e| format!("{:?}", e.event_type)),
            "latestStatus": latest.map(|e| format!("{:?}", e.status)),
            "latestSmtpCode": latest.and_then(|e| e.smtp_code),
            "latestSmtpReply": latest.and_then(|e| e.smtp_reply.clone()),
            "traceEndpoint": format!("/api/monitoring/messages/{}/trace", message_id),
            "note": if accepted_by_remote_mx {
                "Remote MX accepted the message (strong delivery signal)."
            } else if handoff_only {
                "Message handed off to DKIM service; remote mailbox receipt is not independently verified yet."
            } else if bounced_or_failed {
                "SMTP monitoring reports bounce/failure events."
            } else {
                "No conclusive delivery signal yet."
            }
        }
    }))
}

pub(crate) async fn api_email_by_id(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();
    match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => {
            emit_event(
                &bus,
                &mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Read,
                    user_id: user_id.clone(),
                    email_id: email.id.clone(),
                    subject: email.subject.clone(),
                    from: email.from.clone(),
                    to: email.to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let dto = email_to_detail_dto(&email, "inbox");
            HttpResponse::Ok().json(dto)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("fetch_email error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch email",
            }))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailActionRequest {
    action: String,
    #[serde(default)]
    target_folder: Option<String>,
}

pub(crate) async fn api_email_action(
    path: web::Path<String>,
    body: web::Json<EmailActionRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();
    let action = body.action.trim().to_ascii_lowercase();

    let result = match action.as_str() {
        "archive" => logic.move_email_to_mailbox(&user_id, &email_id, "archive").await,
        "trash" | "delete" => logic.move_email_to_mailbox(&user_id, &email_id, "trash").await,
        "restore" => logic.move_email_to_mailbox(&user_id, &email_id, "inbox").await,
        "move" => {
            let Some(target) = body
                .target_folder
                .as_ref()
                .and_then(|f| canonical_folder(f))
            else {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "ok": false,
                    "message": "targetFolder must be one of inbox|sent|drafts|archive|trash|spam",
                }));
            };
            logic.move_email_to_mailbox(&user_id, &email_id, &target).await
        }
        "markread" => logic.set_email_read(&user_id, &email_id, true).await,
        "markunread" => logic.set_email_read(&user_id, &email_id, false).await,
        "star" => logic.set_email_starred(&user_id, &email_id, true).await,
        "unstar" => logic.set_email_starred(&user_id, &email_id, false).await,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "message": "Unsupported action. Use move|archive|trash|delete|restore|markRead|markUnread|star|unstar",
            }))
        }
    };

    match result {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "id": email_id,
            "action": body.action,
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "ok": false,
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("api_email_action error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "message": "Failed to apply email action",
            }))
        }
    }
}

pub(crate) async fn api_drafts_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "updatedAt": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => {
            let mut drafts: Vec<serde_json::Value> = Vec::new();
            for mut docu in cursor
                .try_collect::<Vec<bson::Document>>()
                .await
                .unwrap_or_default()
            {
                docu.remove("_id");
                docu.remove("user_id");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu)) {
                    drafts.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({"drafts": drafts}))
        }
        Err(e) => {
            eprintln!("api_drafts_list error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to load drafts",
            }))
        }
    }
}

pub(crate) async fn api_drafts_upsert(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let Some(mut obj) = body.as_object().cloned() else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Invalid draft payload",
        }));
    };

    let draft_id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let now = Utc::now().to_rfc3339();
    obj.insert(
        "id".to_string(),
        serde_json::Value::String(draft_id.clone()),
    );
    obj.insert(
        "updatedAt".to_string(),
        serde_json::Value::String(now.clone()),
    );
    if !obj.contains_key("createdAt") {
        obj.insert(
            "createdAt".to_string(),
            serde_json::Value::String(now.clone()),
        );
    }

    let draft_value = serde_json::Value::Object(obj.clone());
    let mut draft_doc = match bson::to_document(&draft_value) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("api_drafts_upsert serialize error: {}", e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Draft payload is not serializable",
            }));
        }
    };
    draft_doc.insert("user_id", user_id.clone());
    // Avoid Mongo update conflict between $set and $setOnInsert on createdAt.
    draft_doc.remove("createdAt");

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    let created_at = obj
        .get("createdAt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| now.clone());
    let mut set_on_insert = bson::Document::new();
    set_on_insert.insert("createdAt", created_at);

    match coll
        .update_one(
            doc! { "user_id": &user_id, "id": &draft_id },
            doc! {
                "$set": draft_doc,
                "$setOnInsert": set_on_insert,
            },
        )
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(draft_value),
        Err(e) => {
            eprintln!("api_drafts_upsert db error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to save draft",
            }))
        }
    }
}

pub(crate) async fn api_drafts_delete(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let draft_id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    match coll
        .delete_one(doc! { "user_id": &user_id, "id": &draft_id })
        .await
    {
        Ok(r) if r.deleted_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "deleted": true,
            "id": draft_id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "deleted": false,
            "message": "Draft not found",
        })),
        Err(e) => {
            eprintln!("api_drafts_delete error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to delete draft",
            }))
        }
    }
}

