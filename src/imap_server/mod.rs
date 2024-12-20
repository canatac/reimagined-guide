use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use crate::logic::Logic;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;
use crate::entities::Email;

pub struct ImapServer {
    logic: Arc<Logic>,
    sessions: Arc<Mutex<HashMap<String, String>>>, // Track active sessions with user info
    expecting_message: bool, // Flag to indicate if we are expecting a message
    message_size: usize,     // Store the expected message size
    mailbox: String,         // Store the mailbox name
}

impl ImapServer {
    pub fn new(logic: Arc<Logic>) -> Self {
        ImapServer {
            logic,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            expecting_message: false,
            message_size: 0,
            mailbox: String::new(),
        }
    }

    pub async fn run(&mut self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("IMAP Server listening on {}", addr);

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            println!("New IMAP client connected from {}", peer_addr);
            // Send initial greeting
            let greeting = format!("* OK IMAP4rev1 Service Ready\r\n");
            if let Err(e) = socket.write_all(greeting.as_bytes()).await {
                eprintln!("Failed to send greeting; err = {:?}", e);
                return Ok(());
            }
            let logic = self.logic.clone();
            let sessions = self.sessions.clone();
            let mut server_clone = self.clone(); // Clone the server state
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                let mut session_id = None; // Track session ID for this connection
                loop {
                    let n = match socket.read(&mut buffer).await {
                        Ok(n) if n == 0 => {
                            println!("Connection closed by client");
                            return;
                        }
                        Ok(n) => {
                            let command = String::from_utf8_lossy(&buffer[..n]);
                            println!("Received command: {}", command.trim()); // Log the received command
                            n
                        }
                        Err(e) => {
                            eprintln!("Failed to read from socket; err = {:?}", e);
                            return;
                        }
                    };

                    println!("expecting_message: {}", server_clone.expecting_message);
                    let response = server_clone.process_imap_command(&buffer[..n], &sessions, &mut session_id, &mut socket).await;
                    println!("Response: {}", response);
                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        eprintln!("Failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
        }
    }

    async fn process_imap_command(
        &mut self,
        command: &[u8],
        sessions: &Arc<Mutex<HashMap<String, String>>>,
        session_id: &mut Option<String>,
        socket: &mut tokio::net::TcpStream,
    ) -> String {
        let command_str = String::from_utf8_lossy(command);
        println!("Processing command: {}", command_str.trim());
        println!("expecting_message: {}", self.expecting_message);
        println!("message_size: {}", self.message_size);
        println!("mailbox: {}", self.mailbox);
        if self.expecting_message {
            // We are expecting the message content
            let mut message_content = vec![0; self.message_size];
            println!("message_content: {:?}", message_content);
            match socket.read_exact(&mut message_content).await {
                Ok(_) => {
                    let message_str = String::from_utf8_lossy(&message_content);
                    println!("Received message content: {}", message_str);

                    // Traiter le contenu du message
                    let (headers, body) = parse_email(&message_str);
                    let to = headers.get("To").unwrap_or(&"unknown".to_string()).clone();
                    let from = headers.get("From").unwrap_or(&"unknown".to_string()).clone();
                    let subject = headers.get("Subject").unwrap_or(&"No Subject".to_string()).clone();

                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            let message = Email::new(&String::from(uuid::Uuid::new_v4()), &from, &to, &subject, &body);

                            match self.logic.store_email(&user, &self.mailbox, &message).await {
                                Ok(_) => {
                                    self.expecting_message = false; // Reset the flag
                                    format!("OK APPEND completed\r\n")
                                }
                                Err(_) => format!("NO APPEND failed: Internal error\r\n"),
                            }
                        } else {
                            format!("NO APPEND failed: User not authenticated\r\n")
                        }
                    } else {
                        format!("NO APPEND failed: User not authenticated\r\n")
                    }
                }
                Err(e) => {
                    eprintln!("Error reading message content: {:?}", e);
                    format!("NO APPEND failed: Could not read message content\r\n")
                }
            }
        } else {
            // Process regular commands
            let command_parts: Vec<&str> = command_str.split_whitespace().collect();
            if command_parts.is_empty() {
                return "BAD Command not recognized\r\n".to_string();
            }

            let tag = command_parts[0];
            let command_name = command_parts[1].to_uppercase();
            println!("Command name: {}, Arguments: {:?}", command_name, &command_parts[2..]);

            match command_name.as_str() {
                "APPEND" => {
                    if command_parts.len() < 5 {
                        return format!("{} BAD APPEND requires a mailbox name and message\r\n", tag);
                    }
                    println!("Command parts: {:?}", command_parts);
                    self.mailbox = command_parts[2].trim_matches('"').to_string();
                    self.message_size = command_parts[4].trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);

                    if self.message_size == 0 {
                        return format!("{} BAD APPEND failed: Message size is zero\r\n", tag);
                    }

                    self.expecting_message = true; // Set the flag to expect message content
                    
                    format!("{} OK APPEND command received, waiting for message content\r\n", tag)
                }
                "CAPABILITY" => format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN IDLE UIDPLUS MULTIAPPEND\r\n{} OK CAPABILITY completed\r\n", tag),
                "NOOP" => format!("{} OK NOOP completed\r\n", tag),
                "LOGOUT" => {
                    if let Some(id) = session_id.take() {
                        sessions.lock().unwrap().remove(&id);
                    }
                    format!("* BYE IMAP4rev1 Server logging out\r\n{} OK LOGOUT completed\r\n", tag)
                }
                "LOGIN" => {
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
                "LIST" => {
                    let reference = command_parts.get(2).unwrap_or(&"");
                    let mailbox = command_parts.get(3).unwrap_or(&"*");
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
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
                        } else {
                            format!("{} NO LIST failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO LIST failed: User not authenticated\r\n", tag)
                    }
                }
                "SELECT" => {
                    if command_parts.len() < 3 {
                        return format!("{} BAD SELECT requires a mailbox name\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.select_mailbox(&user, mailbox).await {
                                Ok(status) => {
                                    let flags = "\\Seen \\Answered \\Flagged \\Deleted \\Draft";
                                    let exists = status.exists;
                                    let recent = status.recent;
                                    let unseen = status.unseen;
                                    let uid_validity = status.uid_validity;
                                    let uid_next = status.uid_next;
                                    format!(
                                        "* FLAGS ({})\r\n* {} EXISTS\r\n* {} RECENT\r\n* OK [UNSEEN {}] Message {} is first unseen\r\n* OK [UIDVALIDITY {}] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n{} OK [READ-WRITE] SELECT completed\r\n",
                                        flags, exists, recent, unseen, unseen, uid_validity, uid_next, tag
                                    )
                                }
                                Err(_) => format!("{} NO SELECT failed: Mailbox not found\r\n", tag),
                            }
                        } else {
                            format!("{} NO SELECT failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO SELECT failed: User not authenticated\r\n", tag)
                    }
                }
                "EXAMINE" => {
                    if command_parts.len() < 3 {
                        return format!("{} BAD EXAMINE requires a mailbox name\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.get_mailbox_status(&user, mailbox).await {
                                Ok(status) => {
                                    let flags = "\\Seen \\Answered \\Flagged \\Deleted \\Draft \\Recent";
                                    let exists = status.exists;
                                    let recent = status.recent;
                                    format!("* FLAGS ({})\r\n* {} EXISTS\r\n* {} RECENT\r\n{} OK [READ-ONLY] EXAMINE completed\r\n", flags, exists, recent, tag)
                                }
                                Err(_) => format!("{} NO EXAMINE failed: Mailbox not found\r\n", tag),
                            }
                        } else {
                            format!("{} NO EXAMINE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO EXAMINE failed: User not authenticated\r\n", tag)
                    }
                }
                "CREATE" => {
                    if command_parts.len() < 3 {
                        return format!("{} BAD CREATE requires a mailbox name\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.create_mailbox(&user, mailbox).await {
                                Ok(_) => format!("{} OK CREATE completed\r\n", tag),
                                Err(_) => format!("{} NO CREATE failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO CREATE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO CREATE failed: User not authenticated\r\n", tag)
                    }
                }
                "DELETE" => {
                    if command_parts.len() < 3 {
                        return format!("{} BAD DELETE requires a mailbox name\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.delete_mailbox(&user, mailbox).await {
                                Ok(_) => format!("{} OK DELETE completed\r\n", tag),
                                Err(_) => format!("{} NO DELETE failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO DELETE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO DELETE failed: User not authenticated\r\n", tag)
                    }
                }
                "RENAME" => {
                    if command_parts.len() < 4 {
                        return format!("{} BAD RENAME requires old and new mailbox names\r\n", tag);
                    }
                    let old_name = command_parts[2];
                    let new_name = command_parts[3];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.rename_mailbox(&user, old_name, new_name).await {
                                Ok(_) => format!("{} OK RENAME completed\r\n", tag),
                                Err(_) => format!("{} NO RENAME failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO RENAME failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO RENAME failed: User not authenticated\r\n", tag)
                    }
                }
                "SUBSCRIBE" => {
                    if command_parts.len() < 3 {
                        return format!("{} BAD SUBSCRIBE requires a mailbox name\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.subscribe_mailbox(&user, mailbox).await {
                                Ok(_) => format!("{} OK SUBSCRIBE completed\r\n", tag),
                                Err(_) => format!("{} NO SUBSCRIBE failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO SUBSCRIBE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO SUBSCRIBE failed: User not authenticated\r\n", tag)
                    }
                }
                "UNSUBSCRIBE" => {
                    if command_parts.len() < 3 {
                        return format!("{} BAD UNSUBSCRIBE requires a mailbox name\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.unsubscribe_mailbox(&user, mailbox).await {
                                Ok(_) => format!("{} OK UNSUBSCRIBE completed\r\n", tag),
                                Err(_) => format!("{} NO UNSUBSCRIBE failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO UNSUBSCRIBE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO UNSUBSCRIBE failed: User not authenticated\r\n", tag)
                    }
                }
                "LSUB" => {
                    let reference = command_parts.get(2).unwrap_or(&"%");
                    let mailbox = command_parts.get(3).unwrap_or(&"*");
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
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
                        } else {
                            format!("{} NO LSUB failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO LSUB failed: User not authenticated\r\n", tag)
                    }
                }
                "STATUS" => {
                    if command_parts.len() < 4 {
                        return format!("{} BAD STATUS requires a mailbox name and status data items\r\n", tag);
                    }
                    let mailbox = command_parts[2];
                    let data_items = command_parts[3..].join(" ");
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.get_mailbox_status_items(&user, mailbox, &data_items).await {
                                Ok(status_items) => {
                                    format!("* STATUS {} ({})\r\n{} OK STATUS completed\r\n", mailbox, status_items, tag)
                                }
                                Err(_) => format!("{} NO STATUS failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO STATUS failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO STATUS failed: User not authenticated\r\n", tag)
                    }
                }
                "CHECK" => {
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.check_mailbox().await {
                                Ok(_) => format!("{} OK CHECK completed\r\n", tag),
                                Err(_) => format!("{} NO CHECK failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO CHECK failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO CHECK failed: User not authenticated\r\n", tag)
                    }
                }
                "CLOSE" => {
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.close_mailbox(&user).await {
                                Ok(_) => format!("{} OK CLOSE completed\r\n", tag),
                                Err(_) => format!("{} NO CLOSE failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO CLOSE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO CLOSE failed: User not authenticated\r\n", tag)
                    }
                }
                "EXPUNGE" => {
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.expunge_mailbox(&user).await {
                                Ok(_) => format!("{} OK EXPUNGE completed\r\n", tag),
                                Err(_) => format!("{} NO EXPUNGE failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO EXPUNGE failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO EXPUNGE failed: User not authenticated\r\n", tag)
                    }
                }
                "SEARCH" => {
                    let search_criteria = command_parts[2..].join(" ");
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.search_messages(&user, &search_criteria).await {
                                Ok(results) => {
                                    let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
                                    format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", result_str, tag)
                                }
                                Err(_) => format!("{} NO SEARCH failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO SEARCH failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO SEARCH failed: User not authenticated\r\n", tag)
                    }
                }
                "COPY" => {
                    if command_parts.len() < 4 {
                        return format!("{} BAD COPY requires message set and mailbox name\r\n", tag);
                    }
                    let message_set = command_parts[2];
                    let mailbox = command_parts[3];
                    if let Some(id) = session_id {
                        let username = sessions.lock().unwrap().get(id).cloned();
                        if let Some(user) = username {
                            match self.logic.copy_messages(&user, message_set, mailbox).await {
                                Ok(_) => format!("{} OK COPY completed\r\n", tag),
                                Err(_) => format!("{} NO COPY failed: Internal error\r\n", tag),
                            }
                        } else {
                            format!("{} NO COPY failed: User not authenticated\r\n", tag)
                        }
                    } else {
                        format!("{} NO COPY failed: User not authenticated\r\n", tag)
                    }
                }
                "APPEND" => {
                    if command_parts.len() < 5 {
                        return format!("{} BAD APPEND requires a mailbox name and message\r\n", tag);
                    }
                    println!("Command parts: {:?}", command_parts);
                    let mailbox = command_parts[2].trim_matches('"');
                    let message_size = command_parts[4].trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);

                    if message_size == 0 {
                        return format!("{} BAD APPEND failed: Message size is zero\r\n", tag);
                    }

                    // Ajoutez un délai pour attendre le contenu du message
                    //sleep(Duration::from_millis(5000)).await;

                    // Lire le contenu du message
                    let mut message_content = vec![0; message_size];
                    println!("Reading message content of size: {}", message_size);
                    println!("Message content: {:?}", message_content);
                    match socket.read_exact(&mut message_content).await {
                        Ok(_) => {
                            let message_str = String::from_utf8_lossy(&message_content);
                            let (headers, body) = parse_email(&message_str);
                            let to = headers.get("To").unwrap_or(&"unknown".to_string()).clone();
                            let from = headers.get("From").unwrap_or(&"unknown".to_string()).clone();
                            let subject = headers.get("Subject").unwrap_or(&"No Subject".to_string()).clone();

                            if let Some(id) = session_id {
                                let username = sessions.lock().unwrap().get(id).cloned();
                                if let Some(user) = username {
                                    let message = Email::new(&String::from(uuid::Uuid::new_v4()), &from, &to, &subject, &body);

                                    match self.logic.store_email(&user, mailbox, &message).await {
                                        Ok(_) => format!("{} OK APPEND completed\r\n", tag),
                                        Err(_) => format!("{} NO APPEND failed: Internal error\r\n", tag),
                                    }
                                } else {
                                    format!("{} NO APPEND failed: User not authenticated\r\n", tag)
                                }
                            } else {
                                format!("{} NO APPEND failed: User not authenticated\r\n", tag)
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading message content: {:?}", e);
                            format!("{} NO APPEND failed: Could not read message content\r\n", tag)
                        }
                    }
                }
                _ => format!("{} BAD Command not recognized\r\n", tag),
            }
        }
    }
}

fn parse_email(message: &str) -> (HashMap<String, String>, String) {
    println!("Parsing email: {}", message);
    let mut headers = HashMap::new();
    let mut lines = message.lines();
    let mut body = String::new();

    // Parse headers
    for line in &mut lines {
        println!("Parsing line: {}", line);
        if line.is_empty() {
            break; // End of headers
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.to_string(), value.to_string());
            println!("Parsed header: {} -> {}", key, value);
        }
    }

    // Parse body
    for line in lines {
        body.push_str(line);
        body.push('\n');
        println!("Parsed body line: {}", line);
    }
    println!("Parsed body: {}", body);
    println!("Parsed headers: {:?}", headers);
    println!("Parsed message: {}", message);

    (headers, body)
}

// Implement Clone for ImapServer if needed
impl Clone for ImapServer {
    fn clone(&self) -> Self {
        ImapServer {
            logic: self.logic.clone(),
            sessions: self.sessions.clone(),
            expecting_message: self.expecting_message,
            message_size: self.message_size,
            mailbox: self.mailbox.clone(),
        }
    }
}

