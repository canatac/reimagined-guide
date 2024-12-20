use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, String>>>, // Map de session_id à username
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_session_id(&self) -> Option<String> {
        self.sessions.lock().unwrap().keys().next().cloned()
    }

    pub fn create_session(&self, username: &str) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        self.sessions.lock().unwrap().insert(session_id.clone(), username.to_string());
        session_id
    }

    pub fn get_username(&self, session_id: &str) -> Option<String> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    pub fn set_mailbox(&self, session_id: &str, mailbox: &str) {
        self.sessions.lock().unwrap().insert(session_id.to_string(), mailbox.to_string());
    }

    pub fn get_mailbox(&self, session_id: &str) -> Option<String> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }
}
