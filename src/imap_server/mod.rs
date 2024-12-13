use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;


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
                        Ok(n) if n == 0 => {
                            println!("Connection closed by client");
                            return;
                        }
                        Ok(n) => {
                            println!("Read {} bytes from socket", n);
                            n
                        }
                        Err(e) => {
                            eprintln!("Failed to read from socket; err = {:?}", e);
                            return;
                        }
                    };

                    let response = process_imap_command(&buffer[..n], &logic).await;
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

async fn process_imap_command(command: &[u8], logic: &Arc<Logic>) -> String {
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
                    Ok(Some(_)) => "OK LOGIN completed\r\n".to_string(),
                    Ok(None) => "NO LOGIN failed: Invalid credentials\r\n".to_string(),
                    Err(_) => "NO LOGIN failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD LOGIN requires a username and password\r\n".to_string()
            }
        }
        "SELECT" => {
            if let Some(mailbox) = parts.get(1) {
                match logic.get_emails(mailbox).await {
                    Ok(_) => "OK SELECT completed\r\n".to_string(),
                    Err(_) => "NO SELECT failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD SELECT requires a mailbox name\r\n".to_string()
            }
        }
        "FETCH" => {
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
        "STORE" => {
            if let (Some(email_id), Some(flag)) = (parts.get(1), parts.get(2)) {
                match logic.store_email_flag(email_id, flag).await {
                    Ok(_) => "OK STORE completed\r\n".to_string(),
                    Err(_) => "NO STORE failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD STORE requires an email ID and a flag\r\n".to_string()
            }
        }
        "DELETE" => {
            if let Some(email_id) = parts.get(1) {
                match logic.delete_email(email_id).await {
                    Ok(_) => "OK DELETE completed\r\n".to_string(),
                    Err(_) => "NO DELETE failed: Internal error\r\n".to_string(),
                }
            } else {
                "BAD DELETE requires an email ID\r\n".to_string()
            }
        }
        "LOGOUT" => {
            "OK LOGOUT completed\r\n".to_string()
        }
        _ => "BAD Command not recognized\r\n".to_string(),
    }
}