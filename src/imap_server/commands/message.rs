use super::super::*;
use super::Sessions;

impl ImapServer {
    pub(super) fn handle_append(&mut self, tag: &str, command_parts: &[&str]) -> String {
        if command_parts.len() < 5 {
            return format!("{} BAD APPEND requires a mailbox name and message\r\n", tag);
        }
        println!("Command parts: {:?}", command_parts);
        self.mailbox = command_parts[2].trim_matches('"').to_string();
        self.message_size = command_parts[4].trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);

        if self.message_size == 0 {
            return format!("{} BAD APPEND failed: Message size is zero\r\n", tag);
        }
        self.tag = tag.to_string();
        self.expecting_message = true;

        format!("{} OK APPEND command received, waiting for message content\r\n", tag)
    }

    pub(super) async fn handle_expunge(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO EXPUNGE failed: User not authenticated\r\n", tag);
        };
        match self.logic.expunge_mailbox(&user).await {
            Ok(_) => format!("{} OK EXPUNGE completed\r\n", tag),
            Err(_) => format!("{} NO EXPUNGE failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_search(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        let search_criteria = command_parts[2..].join(" ");
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO SEARCH failed: User not authenticated\r\n", tag);
        };
        match self.logic.search_messages(&user, &search_criteria).await {
            Ok(results) => {
                let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
                format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", result_str, tag)
            }
            Err(_) => format!("{} NO SEARCH failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_copy(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 4 {
            return format!("{} BAD COPY requires message set and mailbox name\r\n", tag);
        }
        let message_set = command_parts[2];
        let mailbox = command_parts[3];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO COPY failed: User not authenticated\r\n", tag);
        };
        match self.logic.copy_messages(&user, message_set, mailbox).await {
            Ok(_) => format!("{} OK COPY completed\r\n", tag),
            Err(_) => format!("{} NO COPY failed: Internal error\r\n", tag),
        }
    }
}
