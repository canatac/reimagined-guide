use crate::entities::Email;
use crate::logic::Logic;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;
use uuid::Uuid;

mod commands;
mod parser;

#[derive(Clone)]
pub struct ImapServer {
    logic: Arc<Logic>,
    sessions: Arc<Mutex<HashMap<String, String>>>, // Track active sessions with user info
    tag: String,
    expecting_message: bool, // Flag to indicate if we are expecting a message
    message_size: usize,     // Store the expected message size
    mailbox: String,         // Store the mailbox name
}

impl ImapServer {
    pub fn new(logic: Arc<Logic>) -> Self {
        ImapServer {
            logic,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tag: String::new(),
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
            let _logic = self.logic.clone();
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
                    let response = server_clone
                        .process_imap_command(&buffer[..n], &sessions, &mut session_id, &mut socket)
                        .await;
                    println!("Response sent");
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
        _socket: &mut tokio::net::TcpStream,
    ) -> String {
        let command_str = String::from_utf8_lossy(command);
        println!("Processing command: {}", command_str.trim());
        println!("expecting_message: {}", self.expecting_message);
        println!("message_size: {}", self.message_size);
        println!("mailbox: {}", self.mailbox);
        if self.expecting_message {
            return self.handle_append_data(command, sessions, session_id).await;
        }

        let command_parts: Vec<&str> = command_str.split_whitespace().collect();
        if command_parts.is_empty() {
            return "BAD Command not recognized\r\n".to_string();
        }
        if command_parts.len() < 2 {
            return "BAD Command not recognized\r\n".to_string();
        }
        self.dispatch_command(&command_parts, sessions, session_id).await
    }
}
