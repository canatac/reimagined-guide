use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod errors;
pub mod ports;

pub use errors::{DomainError, DomainResult};

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
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
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
    pub created_at: DateTime<Utc>,
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
    pub sent_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub flags: Vec<String>,
    pub internal_date: Option<DateTime<Utc>>,
    pub body_preview: Option<String>,
    pub raw_ref: Option<String>,
    pub dedup_hash: Option<String>,
    pub deleted: bool,
    pub created_at: DateTime<Utc>,
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
    pub since: Option<DateTime<Utc>>,
    pub status: String,
    pub stats_fetched: u64,
    pub stats_updated: u64,
    pub stats_deleted: u64,
    pub started_at: DateTime<Utc>,
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
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default = "default_color")]
    pub color: String,
    #[serde(default)]
    pub location: String,
    pub created_at: DateTime<Utc>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn calendar_event_new_sets_defaults() {
        let start = Utc::now();
        let end = Utc::now();
        let ev = CalendarEvent::new("user-1", "standup", start, end);

        assert_eq!(ev.user_id, "user-1");
        assert_eq!(ev.title, "standup");
        assert_eq!(ev.description, "");
        assert_eq!(ev.event_type, "default");
        assert_eq!(ev.color, "#3788d8");
        assert_eq!(ev.location, "");
        assert!(!ev.id.is_empty());
    }

    #[test]
    fn email_new_sets_initial_values() {
        let email = Email::new("id-1", "a@example.com", "b@example.com", "subject", "body");

        assert_eq!(email.id, "id-1");
        assert_eq!(email.from, "a@example.com");
        assert_eq!(email.to, "b@example.com");
        assert_eq!(email.subject, "subject");
        assert_eq!(email.body, "body");
        assert!(email.headers.is_empty());
        assert!(email.flags.is_empty());
        assert_eq!(email.sequence_number, 0);
        assert_eq!(email.uid, 0);
        assert_eq!(email.dkim_signature, None);
    }

    #[test]
    fn serde_defaults_are_applied_on_deserialize() {
        let event = json!({
            "id": "evt-1",
            "userId": "u-1",
            "title": "meeting",
            "start": "2026-01-01T10:00:00Z",
            "end": "2026-01-01T11:00:00Z",
            "createdAt": "2026-01-01T09:00:00Z",
            "updatedAt": "2026-01-01T09:00:00Z"
        });
        let parsed_event: CalendarEvent = serde_json::from_value(event).expect("calendar event parse");
        assert_eq!(parsed_event.description, "");
        assert_eq!(parsed_event.location, "");
        assert_eq!(parsed_event.event_type, "default");
        assert_eq!(parsed_event.color, "#3788d8");

        let cr = json!({
            "id": "cr-1",
            "title": "Improve CI",
            "problem": "soft guards",
            "desiredOutcome": "hard guards",
            "scope": "backend",
            "priority": "P1",
            "status": "open",
            "requestedBy": "root",
            "linkedRepo": "canatac/reimagined-guide",
            "createdAt": "2026-01-01T09:00:00Z",
            "updatedAt": "2026-01-01T09:00:00Z",
            "takenInChargeAt": null,
            "takenInChargeBy": null,
            "targetReleaseWindow": "2026-W01",
            "acceptanceCriteria": [],
            "workflow": [],
            "changelogEntry": null
        });
        let parsed_cr: ChangeRequestItem = serde_json::from_value(cr).expect("change request parse");
        assert_eq!(parsed_cr.execution_state, "idle");
        assert!(parsed_cr.workflow_events.is_empty());
        assert_eq!(parsed_cr.execution_run_id, None);
    }

    #[test]
    fn external_imap_account_roundtrip() {
        let acct = ExternalImapAccount {
            id: "acct-1".into(),
            owner_user_id: "user-1".into(),
            provider: "gmail".into(),
            email: "a@gmail.com".into(),
            auth_type: "oauth2".into(),
            secret_ref: Some("ref-1".into()),
            secret_value: None,
            imap_host: "imap.gmail.com".into(),
            imap_port: 993,
            imap_tls: true,
            smtp_host: Some("smtp.gmail.com".into()),
            smtp_port: Some(587),
            smtp_tls: Some(true),
            status: "active".into(),
            last_sync_at: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_value(&acct).unwrap();
        assert_eq!(json["id"], "acct-1");
        assert_eq!(json["provider"], "gmail");
        assert_eq!(json["imapPort"], 993);
        let parsed: ExternalImapAccount = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.id, "acct-1");
        assert_eq!(parsed.smtp_port, Some(587));
    }

    #[test]
    fn email_roundtrip_with_headers_and_flags() {
        let email = Email {
            id: "e-1".into(),
            from: "a@x.com".into(),
            to: "b@x.com".into(),
            subject: "hi".into(),
            body: "body text".into(),
            headers: vec![("X-Foo".into(), "bar".into())],
            flags: vec!["\\Seen".into()],
            sequence_number: 5,
            uid: 42,
            internal_date: Utc::now(),
            dkim_signature: Some("sig123".into()),
        };
        let json = serde_json::to_value(&email).unwrap();
        assert_eq!(json["from"], "a@x.com");
        assert_eq!(json["uid"], 42);
        let parsed: Email = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.flags, vec![String::from("\\Seen")]);
        assert_eq!(parsed.dkim_signature, Some("sig123".into()));
        assert_eq!(parsed.headers[0], ("X-Foo".into(), "bar".into()));
    }

    #[test]
    fn admin_user_record_defaults_for_optional_fields() {
        let json = json!({
            "id": "u-1",
            "email": "a@b.com",
            "role": "admin",
            "status": "active",
            "twoFactorEnabled": false,
            "sessions24h": 0,
            "actions7d": 0,
            "changeRequests30d": 0,
            "recentActivity": [],
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z"
        });
        let rec: AdminUserRecord = serde_json::from_value(json).unwrap();
        assert_eq!(rec.id, "u-1");
        assert_eq!(rec.display_name, None);
        assert_eq!(rec.password_hash, None);
        assert_eq!(rec.invite_token, None);
        assert_eq!(rec.notes, None);
    }

    #[test]
    fn change_request_item_workflow_roundtrip() {
        let cr = ChangeRequestItem {
            id: "cr-2".into(),
            title: "Add metrics".into(),
            problem: "no visibility".into(),
            desired_outcome: "full metrics".into(),
            scope: "backend".into(),
            priority: "P2".into(),
            status: "open".into(),
            requested_by: "root".into(),
            linked_repo: "canatac/reimagined-guide".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            taken_in_charge_at: None,
            taken_in_charge_by: None,
            target_release_window: "2026-W05".into(),
            acceptance_criteria: vec!["criterion-1".into()],
            workflow: vec![WorkflowStage {
                key: "dev".into(),
                label: "Development".into(),
                owner: "dev-back".into(),
                status: "in_progress".into(),
                checklist: vec!["write tests".into()],
                done_at: None,
            }],
            workflow_events: vec![],
            execution_state: "running".into(),
            execution_run_id: Some("run-1".into()),
            execution_started_at: Some("2026-01-02T00:00:00Z".into()),
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
            changelog_entry: None,
        };
        let json = serde_json::to_value(&cr).unwrap();
        assert_eq!(json["executionState"], "running");
        assert_eq!(json["workflow"][0]["key"], "dev");
        let parsed: ChangeRequestItem = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.execution_state, "running");
        assert_eq!(parsed.workflow.len(), 1);
        assert_eq!(parsed.workflow[0].status, "in_progress");
    }

    #[test]
    fn domain_error_display_messages() {
        assert_eq!(DomainError::NotFound.to_string(), "not found");
        assert_eq!(
            DomainError::Conflict("dup".into()).to_string(),
            "conflict: dup"
        );
        assert_eq!(
            DomainError::Invalid("bad".into()).to_string(),
            "invalid input: bad"
        );
        assert_eq!(
            DomainError::Storage("io".into()).to_string(),
            "storage error: io"
        );
        assert_eq!(
            DomainError::Internal("bug".into()).to_string(),
            "internal error: bug"
        );
    }

    #[test]
    fn domain_result_ok_and_err() {
        let ok: DomainResult<i32> = Ok(42);
        assert_eq!(ok, Ok(42));
        let err: DomainResult<i32> = Err(DomainError::NotFound);
        assert!(err.is_err());
    }
}
