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
