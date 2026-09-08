use super::super::*;
use super::Sessions;

impl ImapServer {
    pub(super) fn handle_logout(tag: &str, sessions: &Sessions, session_id: &mut Option<String>) -> String {
        if let Some(id) = session_id.take() {
            sessions.lock().unwrap().remove(&id);
        }
        format!("* BYE IMAP4rev1 Server logging out\r\n{} OK LOGOUT completed\r\n", tag)
    }

    pub(super) async fn handle_login(
        &mut self,
        tag: &str,
        command_parts: &[&str],
        sessions: &Sessions,
        session_id: &mut Option<String>,
    ) -> String {
        if command_parts.len() < 4 {
            return format!("{} BAD LOGIN requires a username and password\r\n", tag);
        }
        let username = command_parts[2].trim_matches('"');
        let password = command_parts[3].trim_matches('"');

        match self.logic.authenticate_user(username, password).await {
            Ok(Some(user)) => {
                let new_session_id = Uuid::new_v4().to_string();
                sessions.lock().unwrap().insert(new_session_id.clone(), user.username.clone());
                *session_id = Some(new_session_id);
                format!("{} OK LOGIN completed\r\n", tag)
            }
            Ok(None) => {
                sleep(Duration::from_secs(1)).await;
                format!("{} NO LOGIN failed: Invalid credentials\r\n", tag)
            }
            Err(_) => format!("{} NO LOGIN failed: Internal error\r\n", tag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::{Logic, MockDatabaseInterface, User};

    #[tokio::test]
    async fn handle_login_returns_ok_and_sets_session_on_valid_credentials() {
        let mut mock_client = Box::new(MockDatabaseInterface::new());
        mock_client
            .expect_authenticate_user()
            .times(1)
            .returning(|_, _| {
                Ok(Some(User {
                    id: None,
                    username: "testuser".to_string(),
                    password: "secret".to_string(),
                    mailbox: "inbox".to_string(),
                    condition_accepted: false,
                    locale: None,
                }))
            });

        let logic = Arc::new(Logic::new_with_mock(mock_client));
        let mut server = ImapServer::new(logic);
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        let mut session_id = None;
        let command_parts = ["A1", "LOGIN", "\"testuser\"", "\"secret\""];

        let response = server
            .handle_login("A1", &command_parts, &sessions, &mut session_id)
            .await;

        assert_eq!(response, "A1 OK LOGIN completed\r\n");
        assert!(session_id.is_some());
        let stored_user = sessions
            .lock()
            .unwrap()
            .get(session_id.as_ref().unwrap())
            .cloned();
        assert_eq!(stored_user.as_deref(), Some("testuser"));
    }
}
