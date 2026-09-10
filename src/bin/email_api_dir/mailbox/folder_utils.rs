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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_to_mailboxes_inbox() {
        assert_eq!(folder_to_mailboxes("inbox"), vec!["inbox", "INBOX"]);
    }

    #[test]
    fn folder_to_mailboxes_sent() {
        assert_eq!(folder_to_mailboxes("sent"), vec!["sent", "SENT", "Sent"]);
    }

    #[test]
    fn folder_to_mailboxes_spam() {
        assert_eq!(
            folder_to_mailboxes("spam"),
            vec!["spam", "SPAM", "Spam", "Junk"]
        );
    }

    #[test]
    fn folder_to_mailboxes_unknown() {
        assert_eq!(
            folder_to_mailboxes("custom_folder"),
            vec!["custom_folder", "CUSTOM_FOLDER"]
        );
    }

    #[test]
    fn folder_to_mailboxes_trims_input() {
        assert_eq!(folder_to_mailboxes("  inbox  "), vec!["inbox", "INBOX"]);
    }

    #[test]
    fn folder_to_mailboxes_case_insensitive() {
        assert_eq!(folder_to_mailboxes("INBOX"), vec!["inbox", "INBOX"]);
        assert_eq!(folder_to_mailboxes("Sent"), vec!["sent", "SENT", "Sent"]);
    }

    #[test]
    fn canonical_folder_valid() {
        assert_eq!(canonical_folder("inbox"), Some("inbox".to_string()));
        assert_eq!(canonical_folder("sent"), Some("sent".to_string()));
        assert_eq!(canonical_folder("drafts"), Some("drafts".to_string()));
        assert_eq!(canonical_folder("archive"), Some("archive".to_string()));
        assert_eq!(canonical_folder("trash"), Some("trash".to_string()));
        assert_eq!(canonical_folder("spam"), Some("spam".to_string()));
    }

    #[test]
    fn canonical_folder_invalid() {
        assert_eq!(canonical_folder("custom"), None);
        assert_eq!(canonical_folder(""), None);
        assert_eq!(canonical_folder("unknown"), None);
    }

    #[test]
    fn canonical_folder_trims() {
        assert_eq!(canonical_folder("  inbox  "), Some("inbox".to_string()));
    }

    #[test]
    fn canonical_folder_case_insensitive() {
        assert_eq!(canonical_folder("INBOX"), Some("inbox".to_string()));
        assert_eq!(canonical_folder("Sent"), Some("sent".to_string()));
    }

    #[test]
    fn email_list_query_defaults() {
        assert_eq!(default_folder(), "inbox");
        assert_eq!(default_page(), 1);
        assert_eq!(default_page_size(), 50);
    }
}
