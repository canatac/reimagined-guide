// Folder + user resolution helpers extraits de mailbox/mod.rs
use serde::Deserialize;
use std::env;

#[derive(Deserialize)]
pub(crate) struct EmailListQuery {
    #[serde(default = "default_folder")]
    pub folder: String,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(rename = "pageSize", default = "default_page_size")]
    pub page_size: u32,
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
pub(crate) fn folder_to_mailboxes(folder: &str) -> Vec<String> {
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

pub(crate) fn canonical_folder(folder: &str) -> Option<String> {
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
