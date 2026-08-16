use super::*;

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
        println!(
            "Command name: {}, Arguments: {:?}",
            command_name,
            &command_parts[2..]
        );

        match command_name.as_str() {
            "APPEND" => self.handle_append(tag, command_parts),
            "CAPABILITY" => format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS MULTIAPPEND\r\n{} OK CAPABILITY completed\r\n", tag),
            "NOOP" => format!("{} OK NOOP completed\r\n", tag),
            "LOGOUT" => Self::handle_logout(tag, sessions, session_id),
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
        }
    }

    fn current_user(sessions: &Sessions, session_id: &Option<String>) -> Option<String> {
        let id = session_id.as_ref()?;
        sessions.lock().unwrap().get(id).cloned()
    }

    fn handle_append(&mut self, tag: &str, command_parts: &[&str]) -> String {
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

    fn handle_logout(tag: &str, sessions: &Sessions, session_id: &mut Option<String>) -> String {
        if let Some(id) = session_id.take() {
            sessions.lock().unwrap().remove(&id);
        }
        format!("* BYE IMAP4rev1 Server logging out\r\n{} OK LOGOUT completed\r\n", tag)
    }

    async fn handle_login(
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

    async fn handle_list(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_select(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_examine(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_create(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_delete(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_rename(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_subscribe(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_unsubscribe(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_lsub(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_status(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_check(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(_user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO CHECK failed: User not authenticated\r\n", tag);
        };
        match self.logic.check_mailbox().await {
            Ok(_) => format!("{} OK CHECK completed\r\n", tag),
            Err(_) => format!("{} NO CHECK failed: Internal error\r\n", tag),
        }
    }

    async fn handle_close(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO CLOSE failed: User not authenticated\r\n", tag);
        };
        match self.logic.close_mailbox(&user).await {
            Ok(_) => format!("{} OK CLOSE completed\r\n", tag),
            Err(_) => format!("{} NO CLOSE failed: Internal error\r\n", tag),
        }
    }

    async fn handle_expunge(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO EXPUNGE failed: User not authenticated\r\n", tag);
        };
        match self.logic.expunge_mailbox(&user).await {
            Ok(_) => format!("{} OK EXPUNGE completed\r\n", tag),
            Err(_) => format!("{} NO EXPUNGE failed: Internal error\r\n", tag),
        }
    }

    async fn handle_search(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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

    async fn handle_copy(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
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
