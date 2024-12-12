use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;
use mongodb::Client;

use crate::logic::Logic;
pub struct ImapServer {
    logic: Arc<Logic>,
}

impl ImapServer {
    pub fn new(logic: Arc<Logic>) -> Self {
        ImapServer { logic }
    }

    pub async fn run(&self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("IMAP Server listening on {}", addr);

        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            println!("New IMAP client connected from {}", peer_addr);

            let logic = self.logic.clone();
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                loop {
                    let n = match socket.read(&mut buffer).await {
                        Ok(n) if n == 0 => return,
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("failed to read from socket; err = {:?}", e);
                            return;
                        }
                    };

                    let response = process_imap_command(&buffer[..n], &logic).await;
                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        eprintln!("failed to write to socket; err = {:?}", e);
                        return;
                    }
                }
            });
        }
    }
}

async fn process_imap_command(command: &[u8], logic: &Arc<Logic>) -> String {
    let command_str = String::from_utf8_lossy(command);
    let parts: Vec<&str> = command_str.split_whitespace().collect();

    match parts.get(0) {
        Some(&"LOGIN") => {
            if let (Some(username), Some(password)) = (parts.get(1), parts.get(2)) {
                match logic.authenticate_user(username, password).await {
                    Ok(Some(_)) => "OK LOGIN completed\r\n".to_string(),
                    Ok(None) => "NO LOGIN failed: Invalid credentials\r\n".to_string(),
                    Err(_) => "NO LOGIN failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD LOGIN requires a username and password\r\n".to_string()
            }
        }
        Some(&"SELECT") => {
            if let Some(mailbox) = parts.get(1) {
                match logic.get_emails(mailbox).await {
                    Ok(_) => "OK SELECT completed\r\n".to_string(),
                    Err(_) => "NO SELECT failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD SELECT requires a mailbox name\r\n".to_string()
            }
        }
        Some(&"FETCH") => {
            if let Some(email_id) = parts.get(1) {
                match logic.fetch_email(email_id).await {
                    Ok(Some(_)) => "OK FETCH completed\r\n".to_string(),
                    Ok(None) => "NO FETCH failed: Email not found\r\n".to_string(),
                    Err(_) => "NO FETCH failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD FETCH requires an email ID\r\n".to_string()
            }
        }
        Some(&"STORE") => {
            if let (Some(email_id), Some(flag)) = (parts.get(1), parts.get(2)) {
                match logic.store_email_flag(email_id, flag).await {
                    Ok(_) => "OK STORE completed\r\n".to_string(),
                    Err(_) => "NO STORE failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD STORE requires an email ID and a flag\r\n".to_string()
            }
        }
        Some(&"DELETE") => {
            if let Some(email_id) = parts.get(1) {
                match logic.delete_email(email_id).await {
                    Ok(_) => "OK DELETE completed\r\n".to_string(),
                    Err(_) => "NO DELETE failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD DELETE requires an email ID\r\n".to_string()
            }
        }
        Some(&"LOGOUT") => {
            "OK LOGOUT completed\r\n".to_string()
        }
        _ => "BAD Command not recognized\r\n".to_string(),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let client = Arc::new(Client::with_uri_str("mongodb://localhost:27017").await.unwrap());
    let logic = Arc::new(Logic::new(client));
    let server = ImapServer::new(logic);
    server.run("127.0.0.1:143").await
} 