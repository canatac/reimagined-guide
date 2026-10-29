use crate::entities::{
    ExternalImapFolder, ExternalImapMessage, ExternalSyncRun,
};
pub use crate::entities::ExternalImapAccount;

pub mod live_probe;
mod live_probe_helpers;

mod dialog;
mod dialog_helpers;
mod parser;
pub mod periodic_sync;

use futures_util::TryStreamExt;
use mongodb::bson;
use mongodb::bson::doc;
use mongodb::error::Result;
use mongodb::{Client, Collection};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// Re-exports internes utilisés par account_ops / folder_ops / sync_ops / message_ops.
pub(crate) use dialog::imap_fetch_headers_since;
pub(crate) use dialog_helpers::imap_probe;
pub(crate) use parser::{format_imap_date, ImapFetchedHeader};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccountCredentials {
    pub secret_value: Option<String>,
    pub secret_ref: Option<String>,
    // OAuth 2.0 token fields (MW-2026-062)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_token_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalImapServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSmtpServerConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateExternalAccountInput {
    pub provider: String,
    pub email: String,
    pub auth_type: String,
    pub imap: ExternalImapServerConfig,
    pub smtp: Option<ExternalSmtpServerConfig>,
    pub credentials: Option<ExternalAccountCredentials>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateExternalAccountInput {
    pub provider: Option<String>,
    pub email: Option<String>,
    pub auth_type: Option<String>,
    pub status: Option<String>,
    pub imap: Option<ExternalImapServerConfig>,
    pub smtp: Option<ExternalSmtpServerConfig>,
    pub credentials: Option<ExternalAccountCredentials>,
    pub last_error: Option<String>,
    pub last_sync_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalFolderMappingInput {
    pub local_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSyncInput {
    pub mode: String,
    #[serde(default)]
    pub folders: Vec<String>,
    pub since: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalMessageActionInput {
    pub action: String,
    pub target_folder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImapTestResult {
    pub ok: bool,
    pub capabilities: Vec<String>,
    pub greeting: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImapDiscoverResult {
    pub folders: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncExecutionResult {
    pub fetched: u64,
    pub updated: u64,
    pub deleted: u64,
    pub discovered_folders: u64,
}

pub struct ExternalImapService {
    client: Arc<Client>,
}

fn default_true() -> bool {
    true
}

impl ExternalImapService {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    /// Get a reference to the MongoDB client (for OAuth2 token storage, etc.)
    pub fn client(&self) -> Arc<Client> {
        self.client.clone()
    }

    fn db_name() -> String {
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
    }

    fn coll_accounts(&self) -> Collection<ExternalImapAccount> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalImapAccount>("external_imap_accounts")
    }

    fn coll_folders(&self) -> Collection<ExternalImapFolder> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalImapFolder>("external_imap_folders")
    }

    fn coll_messages(&self) -> Collection<ExternalImapMessage> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalImapMessage>("external_imap_messages")
    }

    fn coll_sync_runs(&self) -> Collection<ExternalSyncRun> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalSyncRun>("external_imap_sync_runs")
    }
}

// Helpers Sprint 14

pub(crate) fn redact_account(mut a: ExternalImapAccount) -> ExternalImapAccount {
    a.secret_value = None;
    a.oauth_access_token = None;
    a.oauth_refresh_token = None;
    a
}

pub(crate) fn parse_rfc3339_as_bson(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

pub(crate) fn infer_role(remote_name: &str) -> String {
    let lower = remote_name.to_ascii_lowercase();
    if lower == "inbox" {
        "inbox".to_string()
    } else if lower.contains("sent") {
        "sent".to_string()
    } else if lower.contains("draft") {
        "drafts".to_string()
    } else if lower.contains("trash") || lower.contains("bin") {
        "trash".to_string()
    } else if lower.contains("spam") || lower.contains("junk") {
        "spam".to_string()
    } else if lower.contains("archive") {
        "archive".to_string()
    } else {
        "custom".to_string()
    }
}

mod account_ops;
mod folder_ops;
mod sync_ops;
mod message_ops;
mod imap_client_ops;
pub mod oauth2;

// Re-exports
pub use oauth2::{build_xoauth2_auth_string, is_token_expired, provider_config, refresh_oauth2_token, OAuth2ProviderConfig, OAuth2TokenResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_account_clears_secret_value() {
        let account = ExternalImapAccount {
            id: "acct-1".into(),
            owner_user_id: "user-1".into(),
            provider: "gmail".into(),
            email: "a@gmail.com".into(),
            auth_type: "oauth2".into(),
            secret_ref: Some("ref-1".into()),
            secret_value: Some("super-secret".into()),
            oauth_access_token: Some("token".into()),
            oauth_refresh_token: Some("refresh".into()),
            oauth_token_expires_at: Some(chrono::Utc::now()),
            oauth_scopes: Some(vec!["https://mail.google.com/".into()]),
            imap_host: "imap.gmail.com".into(),
            imap_port: 993,
            imap_tls: true,
            smtp_host: Some("smtp.gmail.com".into()),
            smtp_port: Some(587),
            smtp_tls: Some(true),
            status: "active".into(),
            last_sync_at: None,
            last_error: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let redacted = redact_account(account);
        assert_eq!(redacted.secret_value, None);
        assert_eq!(redacted.secret_ref, Some("ref-1".into()));
        assert_eq!(redacted.email, "a@gmail.com");
        assert_eq!(redacted.oauth_access_token, None);
        assert_eq!(redacted.oauth_refresh_token, None);
    }

    #[test]
    fn parse_rfc3339_as_bson_valid() {
        let result = parse_rfc3339_as_bson("2026-09-10T12:00:00Z");
        assert!(result.is_some());
    }

    #[test]
    fn parse_rfc3339_as_bson_invalid() {
        assert!(parse_rfc3339_as_bson("not-a-date").is_none());
        assert!(parse_rfc3339_as_bson("").is_none());
    }

    #[test]
    fn infer_role_inbox() {
        assert_eq!(infer_role("INBOX"), "inbox");
        assert_eq!(infer_role("Inbox"), "inbox");
    }

    #[test]
    fn infer_role_sent() {
        assert_eq!(infer_role("Sent"), "sent");
        assert_eq!(infer_role("Sent Items"), "sent");
    }

    #[test]
    fn infer_role_drafts() {
        assert_eq!(infer_role("Drafts"), "drafts");
        assert_eq!(infer_role("Draft"), "drafts");
    }

    #[test]
    fn infer_role_trash() {
        assert_eq!(infer_role("Trash"), "trash");
        assert_eq!(infer_role("Bin"), "trash");
    }

    #[test]
    fn infer_role_spam() {
        assert_eq!(infer_role("Spam"), "spam");
        assert_eq!(infer_role("Junk"), "spam");
    }

    #[test]
    fn infer_role_archive() {
        assert_eq!(infer_role("Archive"), "archive");
    }

    #[test]
    fn infer_role_custom() {
        assert_eq!(infer_role("MyFolder"), "custom");
        assert_eq!(infer_role("Work"), "custom");
    }
}
