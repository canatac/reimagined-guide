use super::super::*;
use super::Sessions;

impl ImapServer {
    pub(super) async fn handle_list(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        let reference = command_parts.get(2).unwrap_or(&"");
        let mailbox = command_parts.get(3).unwrap_or(&"*");
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO LIST failed: User not authenticated\r\n", tag);
        };
        match self.logic.list_mailboxes(&user, reference, mailbox).await {
            Ok(mailboxes) => {
                let mut response = String::new();
                for mailbox in mailboxes {
                    response.push_str(&format!("* LIST (\\HasNoChildren) \"/\" \"{}\"\r\n", mailbox));
                }
                response.push_str(&format!("{} OK LIST completed\r\n", tag));
                response
            }
            Err(_) => format!("{} NO LIST failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_select(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 3 {
            return format!("{} BAD SELECT requires a mailbox name\r\n", tag);
        }
        let mailbox = command_parts[2];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO SELECT failed: User not authenticated\r\n", tag);
        };
        match self.logic.select_mailbox(&user, mailbox).await {
            Ok(status) => {
                let flags = "\\Seen \\Answered \\Flagged \\Deleted \\Draft";
                format!(
                    "* FLAGS ({})\r\n* {} EXISTS\r\n* {} RECENT\r\n* OK [UNSEEN {}] Message {} is first unseen\r\n* OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n{} OK [READ-WRITE] SELECT completed\r\n",
                    flags, status.exists, status.recent, status.unseen, status.unseen, status.uid_validity, status.uid_next, tag
                )
            }
            Err(_) => format!("{} NO SELECT failed: Mailbox not found\r\n", tag),
        }
    }

    pub(super) async fn handle_examine(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 3 {
            return format!("{} BAD EXAMINE requires a mailbox name\r\n", tag);
        }
        let mailbox = command_parts[2];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO EXAMINE failed: User not authenticated\r\n", tag);
        };
        match self.logic.get_mailbox_status(&user, mailbox).await {
            Ok(status) => {
                let flags = "\\Seen \\Answered \\Flagged \\Deleted \\Draft \\Recent";
                format!("* FLAGS ({})\r\n* {} EXISTS\r\n* {} RECENT\r\n{} OK [READ-ONLY] EXAMINE completed\r\n", flags, status.exists, status.recent, tag)
            }
            Err(_) => format!("{} NO EXAMINE failed: Mailbox not found\r\n", tag),
        }
    }

    pub(super) async fn handle_create(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 3 {
            return format!("{} BAD CREATE requires a mailbox name\r\n", tag);
        }
        let mailbox = command_parts[2];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO CREATE failed: User not authenticated\r\n", tag);
        };
        match self.logic.create_mailbox(&user, mailbox).await {
            Ok(_) => format!("{} OK CREATE completed\r\n", tag),
            Err(_) => format!("{} NO CREATE failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_delete(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 3 {
            return format!("{} BAD DELETE requires a mailbox name\r\n", tag);
        }
        let mailbox = command_parts[2];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO DELETE failed: User not authenticated\r\n", tag);
        };
        match self.logic.delete_mailbox(&user, mailbox).await {
            Ok(_) => format!("{} OK DELETE completed\r\n", tag),
            Err(_) => format!("{} NO DELETE failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_rename(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 4 {
            return format!("{} BAD RENAME requires old and new mailbox names\r\n", tag);
        }
        let old_name = command_parts[2];
        let new_name = command_parts[3];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO RENAME failed: User not authenticated\r\n", tag);
        };
        match self.logic.rename_mailbox(&user, old_name, new_name).await {
            Ok(_) => format!("{} OK RENAME completed\r\n", tag),
            Err(_) => format!("{} NO RENAME failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_subscribe(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 3 {
            return format!("{} BAD SUBSCRIBE requires a mailbox name\r\n", tag);
        }
        let mailbox = command_parts[2];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO SUBSCRIBE failed: User not authenticated\r\n", tag);
        };
        match self.logic.subscribe_mailbox(&user, mailbox).await {
            Ok(_) => format!("{} OK SUBSCRIBE completed\r\n", tag),
            Err(_) => format!("{} NO SUBSCRIBE failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_unsubscribe(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 3 {
            return format!("{} BAD UNSUBSCRIBE requires a mailbox name\r\n", tag);
        }
        let mailbox = command_parts[2];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO UNSUBSCRIBE failed: User not authenticated\r\n", tag);
        };
        match self.logic.unsubscribe_mailbox(&user, mailbox).await {
            Ok(_) => format!("{} OK UNSUBSCRIBE completed\r\n", tag),
            Err(_) => format!("{} NO UNSUBSCRIBE failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_lsub(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        let reference = command_parts.get(2).unwrap_or(&"%");
        let mailbox = command_parts.get(3).unwrap_or(&"*");
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO LSUB failed: User not authenticated\r\n", tag);
        };
        match self.logic.list_subscribed_mailboxes(&user, reference, mailbox).await {
            Ok(mailboxes) => {
                let mut response = String::new();
                for mailbox in mailboxes {
                    response.push_str(&format!("* LSUB (\\HasNoChildren) \"{}\"\r\n", mailbox));
                }
                response.push_str(&format!("{} OK LSUB completed\r\n", tag));
                response
            }
            Err(_) => format!("{} NO LSUB failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_status(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 4 {
            return format!("{} BAD STATUS requires a mailbox name and status data items\r\n", tag);
        }
        let mailbox = command_parts[2];
        let data_items = command_parts[3..].join(" ");
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO STATUS failed: User not authenticated\r\n", tag);
        };
        match self.logic.get_mailbox_status_items(&user, mailbox, &data_items).await {
            Ok(status_items) => format!("* STATUS {} ({})\r\n{} OK STATUS completed\r\n", mailbox, status_items, tag),
            Err(_) => format!("{} NO STATUS failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_check(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(_user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO CHECK failed: User not authenticated\r\n", tag);
        };
        match self.logic.check_mailbox().await {
            Ok(_) => format!("{} OK CHECK completed\r\n", tag),
            Err(_) => format!("{} NO CHECK failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_close(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO CLOSE failed: User not authenticated\r\n", tag);
        };
        match self.logic.close_mailbox(&user).await {
            Ok(_) => format!("{} OK CLOSE completed\r\n", tag),
            Err(_) => format!("{} NO CLOSE failed: Internal error\r\n", tag),
        }
    }
}
