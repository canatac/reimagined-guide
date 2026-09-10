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
    fn new_manager_has_no_sessions() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.get_session_id(), None);
    }

    #[test]
    fn create_session_returns_id() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("alice");
        assert!(!id.is_empty());
        assert_eq!(mgr.get_session_id(), Some(id));
    }

    #[test]
    fn get_username_returns_username() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("alice");
        assert_eq!(mgr.get_username(&id), Some("alice".to_string()));
    }

    #[test]
    fn get_username_returns_none_for_unknown() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.get_username("unknown"), None);
    }

    #[test]
    fn set_and_get_mailbox() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("alice");
        assert_eq!(mgr.get_mailbox(&id), None);
        mgr.set_mailbox(&id, "inbox");
        assert_eq!(mgr.get_mailbox(&id), Some("inbox".to_string()));
    }

    #[test]
    fn set_mailbox_does_not_overwrite_username() {
        let mgr = SessionManager::new();
        let id = mgr.create_session("alice");
        mgr.set_mailbox(&id, "sent");
        assert_eq!(mgr.get_username(&id), Some("alice".to_string()));
        assert_eq!(mgr.get_mailbox(&id), Some("sent".to_string()));
    }

    #[test]
    fn set_mailbox_unknown_session_no_panic() {
        let mgr = SessionManager::new();
        mgr.set_mailbox("unknown", "inbox");
    }

    #[test]
    fn get_mailbox_unknown_session_returns_none() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.get_mailbox("unknown"), None);
    }

    #[test]
    fn multiple_sessions() {
        let mgr = SessionManager::new();
        let id1 = mgr.create_session("alice");
        let id2 = mgr.create_session("bob");
        assert_ne!(id1, id2);
        assert_eq!(mgr.get_username(&id1), Some("alice".to_string()));
        assert_eq!(mgr.get_username(&id2), Some("bob".to_string()));
    }

    #[test]
    fn default_trait_works() {
        let mgr: SessionManager = Default::default();
        assert_eq!(mgr.get_session_id(), None);
    }
}
