use serde::{Deserialize, Serialize};
use mongodb::bson;

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
