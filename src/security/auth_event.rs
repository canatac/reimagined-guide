//! Auth events emitted on login/SMTP auth outcomes.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub id: String,
    pub ts: String,
    pub kind: AuthEventKind,
    pub user_id: Option<String>,
    pub ip: String,
    pub success: bool,
    pub tenant_id: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventKind {
    SmtpAuth,
    ApiLogin,
    ApiKey,
}

impl AuthEvent {
    pub fn new(kind: AuthEventKind, ip: &str, success: bool) -> Self {
        AuthEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            kind,
            user_id: None,
            ip: ip.to_string(),
            success,
            tenant_id: None,
            user_agent: None,
        }
    }
}

pub async fn log_auth_event(client: &mongodb::Client, event: AuthEvent) {
    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = client
        .database(&db)
        .collection::<mongodb::bson::Document>("auth_events");
    if let Ok(doc) = mongodb::bson::to_document(&event) {
        let _ = coll.insert_one(doc).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_event_new_sets_defaults() {
        let ev = AuthEvent::new(AuthEventKind::SmtpAuth, "192.168.1.1", true);
        assert_eq!(ev.kind, AuthEventKind::SmtpAuth);
        assert_eq!(ev.ip, "192.168.1.1");
        assert!(ev.success);
        assert!(ev.user_id.is_none());
        assert!(ev.tenant_id.is_none());
        assert!(ev.user_agent.is_none());
        assert!(!ev.id.is_empty());
    }

    #[test]
    fn auth_event_kind_serialization() {
        let kinds = vec![AuthEventKind::SmtpAuth, AuthEventKind::ApiLogin, AuthEventKind::ApiKey];
        for kind in kinds {
            let json = serde_json::to_value(&kind).unwrap();
            let parsed: AuthEventKind = serde_json::from_value(json).unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn auth_event_serialization_roundtrip() {
        let ev = AuthEvent {
            id: "test-id".into(),
            ts: "2026-01-01T00:00:00Z".into(),
            kind: AuthEventKind::ApiLogin,
            user_id: Some("user-1".into()),
            ip: "10.0.0.1".into(),
            success: false,
            tenant_id: Some("tenant-1".into()),
            user_agent: Some("Mozilla/5.0".into()),
        };
        let json = serde_json::to_value(&ev).unwrap();
        assert_eq!(json["kind"], "api_login");
        assert_eq!(json["ip"], "10.0.0.1");
        assert_eq!(json["success"], false);
        let parsed: AuthEvent = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.kind, AuthEventKind::ApiLogin);
        assert_eq!(parsed.user_id, Some("user-1".to_string()));
    }
}
