use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::logic::Logic;
use std::time::Duration;
use tokio::time::sleep;

pub struct ImapServer {
    logic: Arc<Logic>,
    sessions: Arc<Mutex<HashMap<String, bool>>>, // Track active sessions
}

impl ImapServer {
    pub fn new(logic: Arc<Logic>) -> Self {
        ImapServer {
            logic,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn run(&self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("IMAP Server listening on {}", addr);

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            println!("New IMAP client connected from {}", peer_addr);

            let greeting = "* OK IMAP4rev1 Server Ready\r\n";
            if let Err(e) = socket.write_all(greeting.as_bytes()).await {
                eprintln!("Failed to send greeting; err = {:?}", e);
                continue;
            }

            let logic = self.logic.clone();
            let sessions = self.sessions.clone();

            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                let mut current_session: Option<String> = None;

                loop {
                    let n = match socket.read(&mut buffer).await {
                        Ok(n) if n == 0 => {
                            println!("Connection closed by client");
                            if let Some(session) = &current_session {
                                sessions.lock().unwrap().remove(session);
                            }
                            return;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("Failed to read from socket; err = {:?}", e);
                            if let Some(session) = &current_session {
                                sessions.lock().unwrap().remove(session);
                            }
                            return;
                        }
                    };

                    let command_str = String::from_utf8_lossy(&buffer[..n]);
                    let response = process_imap_command(&command_str, &logic, &sessions, &mut current_session).await;

                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        eprintln!("Failed to write to socket; err = {:?}", e);
                        if let Some(session) = &current_session {
                            sessions.lock().unwrap().remove(session);
                        }
                        return;
                    }
                }
            });
        }
    }
}

async fn process_imap_command(
    command: &str,
    logic: &Arc<Logic>,
    sessions: &Arc<Mutex<HashMap<String, bool>>>,
    current_session: &mut Option<String>,
) -> String {
    let command_parts: Vec<&str> = command.trim().split_whitespace().collect();
    if command_parts.len() < 2 {
        return "BAD Invalid command format\r\n".to_string();
    }

    let tag = command_parts[0];
    let cmd = command_parts[1].to_uppercase();

    match cmd.as_str() {
        "CAPABILITY" => {
            format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS MULTIAPPEND\r\n{} OK CAPABILITY completed\r\n", tag)
        }
        "NOOP" => {
            format!("{} OK NOOP completed\r\n", tag)
        }
        "LOGOUT" => {
            format!("* BYE IMAP4rev1 Server logging out\r\n{} OK LOGOUT completed\r\n", tag)
        }
        "LOGIN" => {
            if command_parts.len() < 4 {
                return format!("{} BAD LOGIN requires a username and password\r\n", tag);
            }
            let username = command_parts[2].trim_matches('"');
            let password = command_parts[3].trim_matches('"');

            match logic.authenticate_user(username, password).await {
                Ok(Some(_)) => {
                    sessions.lock().unwrap().insert(username.to_string(), true);
                    *current_session = Some(username.to_string());
                    format!("{} OK LOGIN completed\r\n", tag)
                }
                Ok(None) => {
                    sleep(Duration::from_secs(1)).await; // Delay to prevent brute force
                    format!("{} NO LOGIN failed: Invalid credentials\r\n", tag)
                }
                Err(_) => format!("{} NO LOGIN failed: Internal error\r\n", tag),
            }
        }
        "EXAMINE" => {
            if current_session.is_none() {
                return format!("{} NO EXAMINE failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 3 {
                return format!("{} BAD EXAMINE requires a mailbox name\r\n", tag);
            }
            let mailbox = command_parts[2];
            match logic.get_mailbox_status(mailbox).await {
                Ok(status) => {
                    let flags = "\\Seen \\Answered \\Flagged \\Deleted \\Draft \\Recent";
                    let exists = status.exists;
                    let recent = status.recent;
                    format!("* FLAGS ({})\r\n* {} EXISTS\r\n* {} RECENT\r\n{} OK [READ-ONLY] EXAMINE completed\r\n", flags, exists, recent, tag)
                }
                Err(_) => format!("{} NO EXAMINE failed: Mailbox not found\r\n", tag),
            }
        }
        "CREATE" => {
            if current_session.is_none() {
                return format!("{} NO CREATE failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 3 {
                return format!("{} BAD CREATE requires a mailbox name\r\n", tag);
            }
            let mailbox = command_parts[2];
            match logic.create_mailbox(mailbox).await {
                Ok(_) => format!("{} OK CREATE completed\r\n", tag),
                Err(_) => format!("{} NO CREATE failed: Internal error\r\n", tag),
            }
        }
        "DELETE" => {
            if current_session.is_none() {
                return format!("{} NO DELETE failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 3 {
                return format!("{} BAD DELETE requires a mailbox name\r\n", tag);
            }
            let mailbox = command_parts[2];
            match logic.delete_mailbox(mailbox).await {
                Ok(_) => format!("{} OK DELETE completed\r\n", tag),
                Err(_) => format!("{} NO DELETE failed: Internal error\r\n", tag),
            }
        }
        "RENAME" => {
            if current_session.is_none() {
                return format!("{} NO RENAME failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 4 {
                return format!("{} BAD RENAME requires old and new mailbox names\r\n", tag);
            }
            let old_name = command_parts[2];
            let new_name = command_parts[3];
            match logic.rename_mailbox(old_name, new_name).await {
                Ok(_) => format!("{} OK RENAME completed\r\n", tag),
                Err(_) => format!("{} NO RENAME failed: Internal error\r\n", tag),
            }
        }
        "SUBSCRIBE" => {
            if current_session.is_none() {
                return format!("{} NO SUBSCRIBE failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 3 {
                return format!("{} BAD SUBSCRIBE requires a mailbox name\r\n", tag);
            }
            let mailbox = command_parts[2];
            match logic.subscribe_mailbox(mailbox).await {
                Ok(_) => format!("{} OK SUBSCRIBE completed\r\n", tag),
                Err(_) => format!("{} NO SUBSCRIBE failed: Internal error\r\n", tag),
            }
        }
        "UNSUBSCRIBE" => {
            if current_session.is_none() {
                return format!("{} NO UNSUBSCRIBE failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 3 {
                return format!("{} BAD UNSUBSCRIBE requires a mailbox name\r\n", tag);
            }
            let mailbox = command_parts[2];
            match logic.unsubscribe_mailbox(mailbox).await {
                Ok(_) => format!("{} OK UNSUBSCRIBE completed\r\n", tag),
                Err(_) => format!("{} NO UNSUBSCRIBE failed: Internal error\r\n", tag),
            }
        }
        "LSUB" => {
            if current_session.is_none() {
                return format!("{} NO LSUB failed: Not authenticated\r\n", tag);
            }
            let reference = command_parts.get(2).unwrap_or(&"%");
            let mailbox = command_parts.get(3).unwrap_or(&"*");
            match logic.list_subscribed_mailboxes(reference, mailbox).await {
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
        "STATUS" => {
            if current_session.is_none() {
                return format!("{} NO STATUS failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 4 {
                return format!("{} BAD STATUS requires a mailbox name and status data items\r\n", tag);
            }
            let mailbox = command_parts[2];
            let data_items = command_parts[3..].join(" ");
            match logic.get_mailbox_status_items(mailbox, &data_items).await {
                Ok(status_items) => {
                    format!("* STATUS {} ({})\r\n{} OK STATUS completed\r\n", mailbox, status_items, tag)
                }
                Err(_) => format!("{} NO STATUS failed: Internal error\r\n", tag),
            }
        }
        "CHECK" => {
            if current_session.is_none() {
                return format!("{} NO CHECK failed: Not authenticated\r\n", tag);
            }
            match logic.check_mailbox().await {
                Ok(_) => format!("{} OK CHECK completed\r\n", tag),
                Err(_) => format!("{} NO CHECK failed: Internal error\r\n", tag),
            }
        }
        "CLOSE" => {
            if current_session.is_none() {
                return format!("{} NO CLOSE failed: Not authenticated\r\n", tag);
            }
            match logic.close_mailbox().await {
                Ok(_) => format!("{} OK CLOSE completed\r\n", tag),
                Err(_) => format!("{} NO CLOSE failed: Internal error\r\n", tag),
            }
        }
        "EXPUNGE" => {
            if current_session.is_none() {
                return format!("{} NO EXPUNGE failed: Not authenticated\r\n", tag);
            }
            match logic.expunge_mailbox().await {
                Ok(_) => format!("{} OK EXPUNGE completed\r\n", tag),
                Err(_) => format!("{} NO EXPUNGE failed: Internal error\r\n", tag),
            }
        }
        "SEARCH" => {
            if current_session.is_none() {
                return format!("{} NO SEARCH failed: Not authenticated\r\n", tag);
            }
            let search_criteria = command_parts[2..].join(" ");
            match logic.search_messages(&search_criteria).await {
                Ok(results) => {
                    let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
                    format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", result_str, tag)
                }
                Err(_) => format!("{} NO SEARCH failed: Internal error\r\n", tag),
            }
        }
        "COPY" => {
            if current_session.is_none() {
                return format!("{} NO COPY failed: Not authenticated\r\n", tag);
            }
            if command_parts.len() < 4 {
                return format!("{} BAD COPY requires message set and mailbox name\r\n", tag);
            }
            let message_set = command_parts[2];
            let mailbox = command_parts[3];
            match logic.copy_messages(message_set, mailbox).await {
                Ok(_) => format!("{} OK COPY completed\r\n", tag),
                Err(_) => format!("{} NO COPY failed: Internal error\r\n", tag),
            }
        }
        _ => format!("{} BAD Command not recognized\r\n", tag),
    }
}
