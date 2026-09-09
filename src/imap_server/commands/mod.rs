use super::*;
use crate::imap_server::trace::{generate_trace_id, log_imap_command, log_imap_completion};

mod auth;
mod mailbox;
mod message;

type Sessions = Arc<Mutex<HashMap<String, String>>>;

impl ImapServer {
    pub(super) async fn dispatch_command(
        &mut self,
        command_parts: &[&str],
        sessions: &Sessions,
        session_id: &mut Option<String>,
    ) -> String {
        let tag = command_parts[0];
        let command_name = command_parts[1].to_uppercase();
        let trace_id = generate_trace_id();
        let user = Self::current_user(sessions, session_id);

        log_imap_command(
            session_id,
            user.as_deref(),
            &command_name,
            &trace_id,
            &command_parts[2..],
        );

        let start = std::time::Instant::now();
        let result = match command_name.as_str() {
            "APPEND" => self.handle_append(tag, command_parts),
            "CAPABILITY" => format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN NAMESPACE\r\n{} OK CAPABILITY completed\r\n", tag),
            "NOOP" => format!("{} OK NOOP completed\r\n", tag),
            "LOGOUT" => Self::handle_logout(tag, sessions, session_id),
            "NAMESPACE" => format!("* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{} OK NAMESPACE completed\r\n", tag),
            "LOGIN" => self.handle_login(tag, command_parts, sessions, session_id).await,
            "LIST" => self.handle_list(tag, command_parts, sessions, session_id).await,
            "SELECT" => self.handle_select(tag, command_parts, sessions, session_id).await,
            "EXAMINE" => self.handle_examine(tag, command_parts, sessions, session_id).await,
            "CREATE" => self.handle_create(tag, command_parts, sessions, session_id).await,
            "DELETE" => self.handle_delete(tag, command_parts, sessions, session_id).await,
            "RENAME" => self.handle_rename(tag, command_parts, sessions, session_id).await,
            "SUBSCRIBE" => self.handle_subscribe(tag, command_parts, sessions, session_id).await,
            "UNSUBSCRIBE" => self.handle_unsubscribe(tag, command_parts, sessions, session_id).await,
            "LSUB" => self.handle_lsub(tag, command_parts, sessions, session_id).await,
            "STATUS" => self.handle_status(tag, command_parts, sessions, session_id).await,
            "CHECK" => self.handle_check(tag, sessions, session_id).await,
            "CLOSE" => self.handle_close(tag, sessions, session_id).await,
            "EXPUNGE" => self.handle_expunge(tag, sessions, session_id).await,
            "SEARCH" => self.handle_search(tag, command_parts, sessions, session_id).await,
            "COPY" => self.handle_copy(tag, command_parts, sessions, session_id).await,
            _ => format!("{} BAD Command not recognized\r\n", tag),
        };

        let duration = start.elapsed().as_millis() as u64;
        let success = !result.contains("BAD") && !result.contains("NO ");
        log_imap_completion(&trace_id, &command_name, success, duration);
        result
    }

    fn current_user(sessions: &Sessions, session_id: &Option<String>) -> Option<String> {
        let id = session_id.as_ref()?;
        sessions.lock().unwrap().get(id).cloned()
    }
}
