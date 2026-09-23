//! Unified inbox: merges native + external account emails into a single view.
//!
//! Feature: Multi-account aggregation (#571)
//! When `?unified=true` is passed to /api/emails, fetches from native mailboxes
//! AND all external accounts, merge-sorts by date, and tags each email with
//! account metadata.

#![allow(unused_imports)]
use super::super::*;
use simple_smtp_domain::ExternalImapMessage;

/// A unified email entry that can represent either a native or external email.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnifiedEmailDto {
    pub id: String,
    pub folder: String,
    pub from_name: String,
    pub from_address: String,
    pub to_list: Vec<String>,
    pub subject: String,
    pub preview: String,
    pub date: String,
    pub is_read: bool,
    pub is_starred: bool,
    pub has_attachments: bool,
    pub account_id: String,
    pub account_type: String, // "native" | "external"
    pub account_email: String,
    pub source: String, // "native" | "external:<provider>" — explicit source tag for unified inbox
}

/// Convert a native Email to a UnifiedEmailDto.
pub(crate) fn native_to_unified(email: &Email, folder: &str) -> UnifiedEmailDto {
    let flags_l: Vec<String> = email.flags.iter().map(|f| f.to_ascii_lowercase()).collect();
    let is_read = flags_l.iter().any(|f| f == "seen" || f == "\\seen");
    let is_starred = flags_l
        .iter()
        .any(|f| f == "flagged" || f == "\\flagged" || f == "starred");
    let preview = email.subject.chars().take(120).collect();
    let date = {
        let ms = email.internal_date.timestamp_millis();
        chrono::DateTime::from_timestamp_millis(ms)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
    };
    let (from_name, from_address) = parse_name_address(&email.from);
    let to_list: Vec<String> = email
        .to
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let (_, addr) = parse_name_address(s);
            addr
        })
        .collect();

    UnifiedEmailDto {
        id: email.id.clone(),
        folder: folder.to_ascii_lowercase(),
        from_name,
        from_address,
        to_list,
        subject: email.subject.clone(),
        preview,
        date,
        is_read,
        is_starred,
        has_attachments: false, // Native emails use separate attachment fetch
        account_id: "native".to_string(),
        account_type: "native".to_string(),
        account_email: String::new(),
        source: "native".to_string(),
    }
}

/// Convert an ExternalImapMessage to a UnifiedEmailDto.
pub(crate) fn external_to_unified(msg: &ExternalImapMessage, account_email: &str) -> UnifiedEmailDto {
    let flags_l: Vec<String> = msg.flags.iter().map(|f| f.to_ascii_lowercase()).collect();
    let is_read = flags_l.iter().any(|f| f == "\\seen" || f == "seen");
    let is_starred = flags_l
        .iter()
        .any(|f| f == "\\flagged" || f == "flagged" || f == "starred");
    let date = msg
        .internal_date
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let (from_name, from_address) = msg
        .from
        .as_deref()
        .map(parse_name_address)
        .unwrap_or((String::new(), String::new()));
    let to_list: Vec<String> = msg
        .to
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let (_, addr) = parse_name_address(s);
                    addr
                })
                .collect()
        })
        .unwrap_or_default();

    UnifiedEmailDto {
        id: msg.id.clone(),
        folder: "inbox".to_string(), // External emails mapped to inbox role
        from_name,
        from_address,
        to_list,
        subject: msg.subject.clone().unwrap_or_default(),
        preview: msg.body_preview.clone().unwrap_or_default(),
        date,
        is_read,
        is_starred,
        has_attachments: false,
        account_id: msg.account_id.clone(),
        account_type: "external".to_string(),
        account_email: account_email.to_string(),
        source: format!("external:{}", account_email),
    }
}

/// Parse "Name <email>" into (name, address).
fn parse_name_address(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if let Some(start) = raw.rfind('<') {
        if let Some(rel_end) = raw[start + 1..].find('>') {
            let end = start + 1 + rel_end;
            let name = raw[..start].trim().trim_matches('"').trim().to_string();
            let address = raw[start + 1..end].trim().to_string();
            if !address.is_empty() {
                return (name, address);
            }
        }
    }
    (String::new(), raw.to_string())
}

/// Sort unified emails by date descending (newest first).
pub(crate) fn sort_unified_by_date(emails: &mut Vec<UnifiedEmailDto>) {
    emails.sort_by(|a, b| b.date.cmp(&a.date));
}

/// The unified inbox handler: GET /api/emails?unified=true
pub(crate) async fn api_emails_unified(
    query: web::Query<EmailListQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    external: web::Data<Arc<simple_smtp_server::external_imap::ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    // Auth guard
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_user_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let folder = query.folder.trim().to_ascii_lowercase();
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    let fetch_limit = (page_size as i64)
        .saturating_mul(page as i64)
        .max(page_size as i64);

    let mut unified_emails: Vec<UnifiedEmailDto> = Vec::new();

    // 1. Fetch native emails
    for mailbox in folder_to_mailboxes(&folder) {
        match logic
            .get_emails_page(&user_id, &mailbox, fetch_limit, 0)
            .await
        {
            Ok(batch) => {
                for email in batch {
                    unified_emails.push(native_to_unified(&email, &folder));
                }
            }
            Err(e) => {
                eprintln!("unified_inbox native mailbox={}: {}", mailbox, e);
            }
        }
    }

    // 2. Fetch external account emails
    match external.list_accounts(&user_id).await {
        Ok(accounts) => {
            for account in accounts {
                if account.status != "active" {
                    continue;
                }
                let folder_filter = if folder == "inbox" {
                    Some("INBOX")
                } else {
                    Some(folder.as_str())
                };
                match external
                    .list_messages(&user_id, &account.id, folder_filter, 1, page_size as u64)
                    .await
                {
                    Ok(messages) => {
                        for msg in messages {
                            unified_emails.push(external_to_unified(&msg, &account.email));
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "unified_inbox external account_id=<redacted>: {}",
                            e
                        );
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("unified_inbox list_accounts error: {}", e);
        }
    }

    // 3. Sort by date descending
    sort_unified_by_date(&mut unified_emails);

    // 4. Paginate
    let total = unified_emails.len() as u32;
    let start = ((page - 1) * page_size) as usize;
    let page_items: Vec<UnifiedEmailDto> = unified_emails
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();
    let has_more = start + page_items.len() < total as usize;

    HttpResponse::Ok().json(serde_json::json!({
        "emails": page_items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "hasMore": has_more,
        "unified": true,
    }))
}

/// GET /api/unified/folders — list folders from all accounts (native + external)
pub(crate) async fn api_unified_folders(
    req: actix_web::HttpRequest,
    external: web::Data<Arc<simple_smtp_server::external_imap::ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_user_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);

    let mut folders = vec![
        serde_json::json!({"id": "inbox", "name": "Inbox", "accountType": "native", "accountId": "native"}),
        serde_json::json!({"id": "sent", "name": "Sent", "accountType": "native", "accountId": "native"}),
        serde_json::json!({"id": "drafts", "name": "Drafts", "accountType": "native", "accountId": "native"}),
        serde_json::json!({"id": "archive", "name": "Archive", "accountType": "native", "accountId": "native"}),
        serde_json::json!({"id": "trash", "name": "Trash", "accountType": "native", "accountId": "native"}),
        serde_json::json!({"id": "spam", "name": "Spam", "accountType": "native", "accountId": "native"}),
    ];

    // Add external account folders
    match external.list_accounts(&user_id).await {
        Ok(accounts) => {
            for account in accounts {
                if account.status != "active" {
                    continue;
                }
                folders.push(serde_json::json!({
                    "id": format!("external:{}", account.id),
                    "name": format!("{} ({})", account.email, account.provider),
                    "accountType": "external",
                    "accountId": account.id,
                    "email": account.email,
                    "provider": account.provider,
                }));
            }
        }
        Err(e) => {
            eprintln!("api_unified_folders list_accounts error: {}", e);
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "folders": folders }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_address_with_name() {
        let (name, addr) = parse_name_address("John Doe <john@example.com>");
        assert_eq!(name, "John Doe");
        assert_eq!(addr, "john@example.com");
    }

    #[test]
    fn parse_name_address_email_only() {
        let (name, addr) = parse_name_address("john@example.com");
        assert_eq!(name, "");
        assert_eq!(addr, "john@example.com");
    }

    #[test]
    fn parse_name_address_with_quotes() {
        let (name, addr) = parse_name_address("\"Doe, John\" <john@example.com>");
        assert_eq!(name, "Doe, John");
        assert_eq!(addr, "john@example.com");
    }

    #[test]
    fn sort_unified_by_date_newest_first() {
        let mut emails = vec![
            UnifiedEmailDto {
                id: "1".to_string(),
                folder: "inbox".to_string(),
                from_name: "A".to_string(),
                from_address: "a@a.com".to_string(),
                to_list: vec![],
                subject: "Old".to_string(),
                preview: "".to_string(),
                date: "2026-01-01T00:00:00Z".to_string(),
                is_read: false,
                is_starred: false,
                has_attachments: false,
                account_id: "native".to_string(),
                account_type: "native".to_string(),
                account_email: String::new(),
                source: "native".to_string(),
            },
            UnifiedEmailDto {
                id: "2".to_string(),
                folder: "inbox".to_string(),
                from_name: "B".to_string(),
                from_address: "b@b.com".to_string(),
                to_list: vec![],
                subject: "New".to_string(),
                preview: "".to_string(),
                date: "2026-06-01T00:00:00Z".to_string(),
                is_read: false,
                is_starred: false,
                has_attachments: false,
                account_id: "native".to_string(),
                account_type: "native".to_string(),
                account_email: String::new(),
                source: "native".to_string(),
            },
        ];
        sort_unified_by_date(&mut emails);
        assert_eq!(emails[0].subject, "New");
        assert_eq!(emails[1].subject, "Old");
    }

    #[test]
    fn unified_email_dto_serialization() {
        let dto = UnifiedEmailDto {
            id: "test-1".to_string(),
            folder: "inbox".to_string(),
            from_name: "Sender".to_string(),
            from_address: "sender@test.com".to_string(),
            to_list: vec!["recv@test.com".to_string()],
            subject: "Hello".to_string(),
            preview: "Preview text".to_string(),
            date: "2026-09-22T12:00:00Z".to_string(),
            is_read: true,
            is_starred: false,
            has_attachments: false,
            account_id: "acc-123".to_string(),
            account_type: "external".to_string(),
            account_email: "ext@gmail.com".to_string(),
            source: "external:ext@gmail.com".to_string(),
        };
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["id"], "test-1");
        assert_eq!(json["accountType"], "external");
        assert_eq!(json["accountEmail"], "ext@gmail.com");
        assert_eq!(json["source"], "external:ext@gmail.com");
    }

    #[test]
    fn native_email_source_tag_is_native() {
        let email = Email {
            id: "native-1".to_string(),
            from: "sender@test.com".to_string(),
            to: "recv@test.com".to_string(),
            subject: "Native".to_string(),
            body: "body".to_string(),
            headers: vec![],
            flags: vec![],
            sequence_number: 1,
            uid: 1,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };
        let dto = native_to_unified(&email, "inbox");
        assert_eq!(dto.source, "native");
        assert_eq!(dto.account_type, "native");
    }

    #[test]
    fn external_email_source_tag_includes_account_email() {
        let msg = ExternalImapMessage {
            id: "ext-1".to_string(),
            account_id: "acc-456".to_string(),
            folder_id: Some("folder-1".to_string()),
            owner_user_id: "user-1".to_string(),
            remote_uid: Some(42),
            message_id_header: Some("<msg-42@external.com>".to_string()),
            thread_key: None,
            from: Some("<<EMAIL>>".to_string()),
            to: Some("<<EMAIL>>".to_string()),
            subject: Some("External".to_string()),
            sent_at: None,
            flags: vec!["\\Seen".to_string()],
            internal_date: None,
            body_preview: Some("preview".to_string()),
            raw_ref: None,
            dedup_hash: Some("uid:acc-456:42".to_string()),
            deleted: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let dto = external_to_unified(&msg, "<EMAIL>");
        assert_eq!(dto.source, "external:<EMAIL>");
        assert_eq!(dto.account_type, "external");
        assert_eq!(dto.account_email, "<EMAIL>");
        assert!(dto.is_read);
    }
}
