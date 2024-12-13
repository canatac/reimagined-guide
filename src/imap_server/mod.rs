use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::Mutex;
use crate::logic::Logic;

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

            let logic = self.logic.clone();
            let sessions = self.sessions.clone();
            
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                let mut current_session: Option<String> = None;

                loop {
                    let n = match socket.read(&mut buffer).await {
                        Ok(n) if n == 0 => {
                            println!("Connection closed by client");
                            if let Some(session) = current_session {
                                sessions.lock().unwrap().remove(&session);
                            }
                            return;
                        }
                        Ok(n) => {
                            println!("Read {} bytes from socket", n);
                            n
                        }
                        Err(e) => {
                            eprintln!("Failed to read from socket; err = {:?}", e);
                            if let Some(session) = current_session {
                                sessions.lock().unwrap().remove(&session);
                            }
                            return;
                        }
                    };

                    let response = process_imap_command(&buffer[..n], &logic, &sessions, &mut current_session).await;
                    println!("Response: {}", response);
                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        eprintln!("Failed to write to socket; err = {:?}", e);
                        if let Some(session) = current_session {
                            sessions.lock().unwrap().remove(&session);
                        }
                        return;
                    }
                }
            });
        }
    }
}

async fn process_imap_command(
    command: &[u8], 
    logic: &Arc<Logic>, 
    sessions: &Arc<Mutex<HashMap<String, bool>>>,
    current_session: &mut Option<String>
) -> String {
    let command_str = String::from_utf8_lossy(command);
    let parts: Vec<&str> = command_str.split_whitespace().collect();
    println!("Command: {:?}", parts);

    if parts.len() < 2 {
        return "BAD Command not recognized\r\n".to_string();
    }

    let tag = parts[0];
    let command_name = parts[1];

    match command_name {
        "LOGIN" => {
            if let (Some(username), Some(password)) = (parts.get(2), parts.get(3)) {
                match logic.authenticate_user(username, password).await {
                    Ok(Some(_)) => {
                        sessions.lock().unwrap().insert(username.to_string(), true);
                        *current_session = Some(username.to_string());
                        "OK LOGIN completed\r\n".to_string()
                    },
                    Ok(None) => "NO LOGIN failed: Invalid credentials\r\n".to_string(),
                    Err(_) => "NO LOGIN failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD LOGIN requires a username and password\r\n".to_string()
            }
        }
        "LOGOUT" => {
            if let Some(session) = current_session.take() {
                sessions.lock().unwrap().remove(&session);
                "OK LOGOUT completed\r\n".to_string()
            } else {
                "OK LOGOUT completed\r\n".to_string()
            }
        }
        _ => {
            // Check if user is logged in before processing other commands
            if current_session.is_none() {
                return "NO Not logged in\r\n".to_string();
            }

            match command_name {
                "SELECT" => {
                    if let Some(mailbox) = parts.get(2) {
                        match logic.get_emails(mailbox).await {
                            Ok(_) => "OK SELECT completed\r\n".to_string(),
                            Err(_) => "NO SELECT failed: Internal error\r\n".to_string(),
                        }
                    } else {
                        "BAD SELECT requires a mailbox name\r\n".to_string()
                    }
                }
                "FETCH" => {
                    if let Some(email_id) = parts.get(2) {
                        match logic.fetch_email(email_id).await {
                            Ok(Some(_)) => "OK FETCH completed\r\n".to_string(),
                            Ok(None) => "NO FETCH failed: Email not found\r\n".to_string(),
                            Err(_) => "NO FETCH failed: Internal error\r\n".to_string(),
                        }
                    } else {
                        "BAD FETCH requires an email ID\r\n".to_string()
                    }
                }
                "STORE" => {
                    if let (Some(email_id), Some(flag)) = (parts.get(2), parts.get(3)) {
                        match logic.store_email_flag(email_id, flag).await {
                            Ok(_) => "OK STORE completed\r\n".to_string(),
                            Err(_) => "NO STORE failed: Internal error\r\n".to_string(),
                        }
                    } else {
                        "BAD STORE requires an email ID and a flag\r\n".to_string()
                    }
                }
                "DELETE" => {
                    if let Some(email_id) = parts.get(2) {
                        match logic.delete_email(email_id).await {
                            Ok(_) => "OK DELETE completed\r\n".to_string(),
                            Err(_) => "NO DELETE failed: Internal error\r\n".to_string(),
                        }
                    } else {
                        "BAD DELETE requires an email ID\r\n".to_string()
                    }
                }
                _ => "BAD Command not recognized\r\n".to_string(),
            }
        }
    }
}