use mongodb::bson;
use serde::{Deserialize, Serialize};

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
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_tls: bool,
    pub smtp_host: Option<String>,
    pub smtp_port: Option<u16>,
    pub smtp_tls: Option<bool>,
    pub status: String,
    pub last_sync_at: Option<bson::DateTime>,
    pub last_error: Option<String>,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
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
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
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
    pub sent_at: Option<bson::DateTime>,
    #[serde(default)]
    pub flags: Vec<String>,
    pub internal_date: Option<bson::DateTime>,
    pub body_preview: Option<String>,
    pub raw_ref: Option<String>,
    pub dedup_hash: Option<String>,
    pub deleted: bool,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
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
    pub since: Option<bson::DateTime>,
    pub status: String,
    pub stats_fetched: u64,
    pub stats_updated: u64,
    pub stats_deleted: u64,
    pub started_at: bson::DateTime,
    pub ended_at: Option<bson::DateTime>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CalendarEvent {
    pub id: String,
    pub user_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub start: bson::DateTime,
    pub end: bson::DateTime,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default = "default_color")]
    pub color: String,
    #[serde(default)]
    pub location: String,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

fn default_event_type() -> String {
    "default".to_string()
}

fn default_color() -> String {
    "#3788d8".to_string()
}

impl CalendarEvent {
    pub fn new(user_id: &str, title: &str, start: bson::DateTime, end: bson::DateTime) -> Self {
        let now = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
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
    pub internal_date: bson::DateTime,
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
            internal_date: bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis()),
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
