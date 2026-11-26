use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub mod errors;
pub mod ports;

pub use errors::{DomainError, DomainResult};

/// Custom deserializer for DateTime<Utc> that handles both BSON Date extended JSON format and RFC 3339 strings.
/// BSON Date format: {"$date": "2026-01-01T00:00:00Z"}
/// RFC 3339 format: "2026-01-01T00:00:00Z"
fn deserialize_datetime_utc<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value = Value::deserialize(deserializer)?;
    
    match value {
        Value::String(s) => {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| Error::custom(format!("invalid RFC 3339 date: {}", e)))
        }
        Value::Object(map) => {
            if let Some(date_str) = map.get("$date").and_then(Value::as_str) {
                DateTime::parse_from_rfc3339(date_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(|e| Error::custom(format!("invalid BSON date: {}", e)))
            } else {
                Err(Error::custom("expected $date field in BSON Date object"))
            }
        }
        _ => Err(Error::custom("expected string or BSON Date object"))
    }
}

/// Custom deserializer for Option<DateTime<Utc>> that handles both BSON Date extended JSON format and RFC 3339 strings.
fn deserialize_option_datetime_utc<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value = Value::deserialize(deserializer)?;
    
    match value {
        Value::Null => Ok(None),
        Value::String(s) => {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map(Some)
                .map_err(|e| Error::custom(format!("invalid RFC 3339 date: {}", e)))
        }
        Value::Object(map) => {
            if let Some(date_str) = map.get("$date").and_then(Value::as_str) {
                DateTime::parse_from_rfc3339(date_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map(Some)
                    .map_err(|e| Error::custom(format!("invalid BSON date: {}", e)))
            } else {
                Err(Error::custom("expected $date field in BSON Date object"))
            }
        }
        _ => Err(Error::custom("expected null, string, or BSON Date object"))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalImapAccount {
    pub id: String,
    pub owner_user_id: String,
    pub provider: String,
    pub email: String,
    pub auth_type: String,
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub secret_value: Option<String>,
    // OAuth 2.0 fields (MW-2026-062)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_access_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_option_datetime_utc")]
    pub oauth_token_expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_scopes: Option<Vec<String>>,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_tls: bool,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_tls: Option<bool>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_option_datetime_utc")]
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalImapFolder {
    pub id: String,
    pub account_id: String,
    pub owner_user_id: String,
    pub remote_name: String,
    pub local_role: String,
    pub uid_validity: Option<u64>,
    pub highest_uid: Option<u64>,
    pub highest_modseq: Option<u64>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalImapMessage {
    pub id: String,
    pub account_id: String,
    pub folder_id: Option<String>,
    pub owner_user_id: String,
    pub remote_uid: Option<u64>,
    pub message_id_header: Option<String>,
    pub thread_key: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_option_datetime_utc")]
    pub sent_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_option_datetime_utc")]
    pub internal_date: Option<DateTime<Utc>>,
    pub body_preview: Option<String>,
    pub raw_ref: Option<String>,
    pub dedup_hash: Option<String>,
    pub deleted: bool,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSyncRun {
    pub id: String,
    pub account_id: String,
    pub owner_user_id: String,
    pub mode: String,
    #[serde(default)]
    pub folders: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_option_datetime_utc")]
    pub since: Option<DateTime<Utc>>,
    pub status: String,
    pub stats_fetched: u64,
    pub stats_updated: u64,
    pub stats_deleted: u64,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_option_datetime_utc")]
    pub ended_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEvent {
    pub id: String,
    pub user_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub start: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub end: DateTime<Utc>,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default = "default_color")]
    pub color: String,
    #[serde(default)]
    pub location: String,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub updated_at: DateTime<Utc>,
}

fn default_event_type() -> String {
    "default".to_string()
}

fn default_color() -> String {
    "#3788d8".to_string()
}

impl CalendarEvent {
    pub fn new(user_id: &str, title: &str, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        let now = chrono::Utc::now();
        CalendarEvent {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            title: title.to_string(),
            description: String::new(),
            start,
            end,
            event_type: default_event_type(),
            color: default_color(),
            location: String::new(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Email {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub sequence_number: u32,
    #[serde(default)]
    pub uid: u32,
    #[serde(deserialize_with = "deserialize_datetime_utc")]
    pub internal_date: DateTime<Utc>,
    #[serde(default)]
    pub dkim_signature: Option<String>,
}

impl Email {
    pub fn new(id: &str, from: &str, to: &str, subject: &str, body: &str) -> Self {
        Email {
            id: id.to_string(),
            from: from.to_string(),
            to: to.to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            headers: vec![],
            flags: Vec::new(),
            sequence_number: 0,
            uid: 0,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserActivity {
    pub at: String,
    pub label: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserRecord {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    pub status: String,
    pub two_factor_enabled: bool,
    pub last_login_at: Option<String>,
    pub last_activity_at: Option<String>,
    pub sessions24h: i64,
    pub actions7d: i64,
    pub change_requests30d: i64,
    pub recent_activity: Vec<AdminUserActivity>,
    pub created_at: String,
    pub updated_at: String,
    // PR3 — comptes admin réels. Tous optionnels + defaults pour
    // préserver les documents existants qui n'ont pas ces champs.
    /// bcrypt hash. `None` tant que l'utilisateur n'a pas défini de mot
    /// de passe (invitation en attente ou compte annuaire pur).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
    /// Token d'invitation à usage unique (jeton opaque, uuid v4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    /// RFC3339 — expiration du jeton d'invitation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_expires_at: Option<String>,
    /// RFC3339 — date d'envoi de la dernière invitation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invited_at: Option<String>,
    /// Notes internes libres (max ~1KB, non affichées à l'utilisateur).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStage {
    pub key: String,
    pub label: String,
    pub owner: String,
    pub status: String,
    pub checklist: Vec<String>,
    pub done_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowEvent {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub from_status: String,
    pub to_status: String,
    pub note: Option<String>,
}

fn default_execution_state() -> String {
    "idle".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRequestItem {
    pub id: String,
    pub title: String,
    pub problem: String,
    pub desired_outcome: String,
    pub scope: String,
    pub priority: String,
    pub status: String,
    pub requested_by: String,
    pub linked_repo: String,
    pub created_at: String,
    pub updated_at: String,
    pub taken_in_charge_at: Option<String>,
    pub taken_in_charge_by: Option<String>,
    pub target_release_window: String,
    pub acceptance_criteria: Vec<String>,
    pub workflow: Vec<WorkflowStage>,
    #[serde(default)]
    pub workflow_events: Vec<WorkflowEvent>,
    #[serde(default = "default_execution_state")]
    pub execution_state: String,
    #[serde(default)]
    pub execution_run_id: Option<String>,
    #[serde(default)]
    pub execution_started_at: Option<String>,
    #[serde(default)]
    pub execution_last_heartbeat_at: Option<String>,
    #[serde(default)]
    pub execution_finished_at: Option<String>,
    #[serde(default)]
    pub execution_last_error: Option<String>,
    pub changelog_entry: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicyConfig {
    pub user_id: String,
    pub retention_days: i64, // 0 = never purge, 30/90/365 typical
    pub auto_purge_enabled: bool,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionAuditEntry {
    pub id: String,
    pub at: String,
    pub action: String, // "purge" | "config_update" | "policy_eval"
    pub user_id: String,
    pub retention_days: i64,
    pub emails_purged: i64,
    pub oldest_retained: Option<String>,
    pub note: Option<String>,
}