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

    pub async fn run(&self, addr: &str) -> std::io::Result<()> {
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
            let mut expecting_message = self.expecting_message;
            let mut message_size = self.message_size;
            let mut mailbox = self.mailbox.clone();
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

                    let response = process_imap_command(&buffer[..n], &logic, &sessions, &mut session_id, &mut socket, &mut expecting_message, &mut message_size, &mut mailbox).await;
                    println!("Response: {}", response);
                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        eprintln!("Failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
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

async fn process_imap_command(
    command: &[u8],
    logic: &Arc<Logic>,
    sessions: &Arc<Mutex<HashMap<String, String>>>,
    session_id: &mut Option<String>,
    socket: &mut tokio::net::TcpStream,
    expecting_message: &mut bool, // Flag to indicate if we are expecting a message
    message_size: &mut usize,     // Store the expected message size
    mailbox: &mut String,         // Store the mailbox name
) -> String {
    let command_str = String::from_utf8_lossy(command);
    println!("Processing command: {}", command_str.trim());

    if *expecting_message {
        // We are expecting the message content
        let mut message_content = vec![0; *message_size];
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

                        match logic.store_email(&user, mailbox, &message).await {
                            Ok(_) => {
                                *expecting_message = false; // Reset the flag
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
                *mailbox = command_parts[2].trim_matches('"').to_string();
                *message_size = command_parts[4].trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);

                if *message_size == 0 {
                    return format!("{} BAD APPEND failed: Message size is zero\r\n", tag);
                }

                *expecting_message = true; // Set the flag to expect message content
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

                match logic.authenticate_user(username, password).await {
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
                        match logic.list_mailboxes(&user, reference, mailbox).await {
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
                        match logic.select_mailbox(&user, mailbox).await {
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
            "CREATE" => {
                if command_parts.len() < 3 {
                    return format!("{} BAD CREATE requires a mailbox name\r\n", tag);
                }
                let mailbox = command_parts[2];
                if let Some(id) = session_id {
                    let username = sessions.lock().unwrap().get(id).cloned();
                    if let Some(user) = username {
                        match logic.create_mailbox(&user, mailbox).await {
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
                        match logic.delete_mailbox(&user, mailbox).await {
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
                        match logic.rename_mailbox(&user, old_name, new_name).await {
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
                        match logic.subscribe_mailbox(&user, mailbox).await {
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
                        match logic.unsubscribe_mailbox(&user, mailbox).await {
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
            // Add other command handlers here
            _ => format!("{} BAD Command not recognized\r\n", tag),
        }
    }
}