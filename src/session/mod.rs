use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Per-session data: username + mailbox stored separately so set_mailbox
/// doesn't overwrite the username (which was the original bug).
struct SessionData {
    username: String,
    mailbox: Option<String>,
}

pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the first (and typically only) active session id.
    pub fn get_session_id(&self) -> Option<String> {
        self.sessions.lock().unwrap().keys().next().cloned()
    }

    /// Create a new session and return its id.
    pub fn create_session(&self, username: &str) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        self.sessions.lock().unwrap().insert(
            session_id.clone(),
            SessionData {
                username: username.to_string(),
                mailbox: None,
            },
        );
        session_id
    }

    /// Get the username associated with a session.
    pub fn get_username(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .get(session_id)
            .map(|d| d.username.clone())
    }

    /// Set the mailbox for a session (does NOT overwrite the username).
    pub fn set_mailbox(&self, session_id: &str, mailbox: &str) {
        if let Some(data) = self.sessions.lock().unwrap().get_mut(session_id) {
            data.mailbox = Some(mailbox.to_string());
        }
    }

    /// Get the mailbox for a session.
    pub fn get_mailbox(&self, session_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .get(session_id)
            .and_then(|d| d.mailbox.clone())
    }
}
