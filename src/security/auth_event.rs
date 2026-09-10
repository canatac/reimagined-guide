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
    fn new_auth_event_defaults() {
        let ev = AuthEvent::new(AuthEventKind::ApiLogin, "10.0.0.1", true);
        assert_eq!(ev.kind, AuthEventKind::ApiLogin);
        assert_eq!(ev.ip, "10.0.0.1");
        assert!(ev.success);
        assert_eq!(ev.user_id, None);
        assert_eq!(ev.tenant_id, None);
        assert_eq!(ev.user_agent, None);
        assert!(!ev.id.is_empty());
        assert!(!ev.ts.is_empty());
    }

    #[test]
    fn new_auth_event_smtp_auth() {
        let ev = AuthEvent::new(AuthEventKind::SmtpAuth, "::1", false);
        assert_eq!(ev.kind, AuthEventKind::SmtpAuth);
        assert!(!ev.success);
        assert_eq!(ev.ip, "::1");
    }

    #[test]
    fn new_auth_event_api_key() {
        let ev = AuthEvent::new(AuthEventKind::ApiKey, "192.168.1.1", true);
        assert_eq!(ev.kind, AuthEventKind::ApiKey);
        assert!(ev.success);
    }

    #[test]
    fn auth_event_id_is_uuid() {
        let ev = AuthEvent::new(AuthEventKind::ApiLogin, "1.2.3.4", true);
        // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(ev.id.len(), 36);
        assert!(ev.id.contains('-'));
    }

    #[test]
    fn auth_event_kind_roundtrip() {
        // Verify Serialize/Deserialize works for all variants
        for kind in [AuthEventKind::SmtpAuth, AuthEventKind::ApiLogin, AuthEventKind::ApiKey] {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: AuthEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, parsed);
        }
    }
}
