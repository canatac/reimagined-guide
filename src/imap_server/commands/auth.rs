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
