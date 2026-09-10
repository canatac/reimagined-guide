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

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_manager_empty() {
        let mgr = SessionManager::new();
        assert!(mgr.get_session_id().is_none());
    }

    #[test]
    fn create_session_returns_uuid() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("testuser");
        assert!(!id.is_empty());
        assert_eq!(id.len(), 36); // UUID v4 format
    }

    #[test]
    fn get_username_returns_username() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("testuser");
        assert_eq!(mgr.get_username(&id), Some("testuser".to_string()));
    }

    #[test]
    fn get_username_missing_session() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.get_username("nonexistent"), None);
    }

    #[test]
    fn set_and_get_mailbox() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("testuser");
        assert_eq!(mgr.get_mailbox(&id), None);
        mgr.set_mailbox(&id, "INBOX");
        assert_eq!(mgr.get_mailbox(&id), Some("INBOX".to_string()));
    }

    #[test]
    fn set_mailbox_missing_session_no_panic() {
        let mgr = SessionManager::new();
        // Should not panic
        mgr.set_mailbox("nonexistent", "INBOX");
    }

    #[test]
    fn get_mailbox_missing_session() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.get_mailbox("nonexistent"), None);
    }

    #[test]
    fn multiple_sessions_independent() {
        let mgr = SessionManager::new();
        let id1 = mgr.create_session("user1");
        let id2 = mgr.create_session("user2");
        mgr.set_mailbox(&id1, "INBOX");
        mgr.set_mailbox(&id2, "Sent");
        assert_eq!(mgr.get_mailbox(&id1), Some("INBOX".to_string()));
        assert_eq!(mgr.get_mailbox(&id2), Some("Sent".to_string()));
        assert_eq!(mgr.get_username(&id1), Some("user1".to_string()));
        assert_eq!(mgr.get_username(&id2), Some("user2".to_string()));
    }

    #[test]
    fn default_trait_works() {
        let mgr: SessionManager = Default::default();
        assert!(mgr.get_session_id().is_none());
    }
}
