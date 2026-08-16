use super::*;

pub(super) fn parse_email(email_content: &str) -> (HashMap<String, String>, String) {
    let mut headers = HashMap::new();
    let mut body = String::new();
    let lines = email_content.lines();
    let mut in_body = false;

    for line in lines {
        if line.trim().is_empty() {
            in_body = true;
            continue;
        }
        if !in_body {
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        } else {
            body.push_str(line);
            body.push_str("\n");
        }
    }

    (headers, body)
}

impl ImapServer {
    /// Handle raw message content received after an APPEND literal.
    pub(super) async fn handle_append_data(
        &mut self,
        command: &[u8],
        sessions: &Arc<Mutex<HashMap<String, String>>>,
        session_id: &mut Option<String>,
    ) -> String {
        let message_str = String::from_utf8_lossy(&command);
        println!("Received message content: {}", message_str);

        let (headers, body) = parse_email(&message_str);
        let to = headers.get("To").unwrap_or(&"unknown".to_string()).clone();
        let from = headers
            .get("From")
            .unwrap_or(&"unknown".to_string())
            .clone();
        let subject = headers
            .get("Subject")
            .unwrap_or(&"No Subject".to_string())
            .clone();

        if let Some(id) = session_id {
            let username = sessions.lock().unwrap().get(id).cloned();
            if let Some(user) = username {
                let message = Email::new(
                    &String::from(uuid::Uuid::new_v4()),
                    &from,
                    &to,
                    &subject,
                    &body,
                );

                match self.logic.store_email(&user, &self.mailbox, &message).await {
                    Ok(_) => {
                        self.expecting_message = false;
                        return format!("{} OK APPEND completed\r\n", self.tag);
                    }
                    Err(_) => return format!("NO APPEND failed: Internal error\r\n"),
                }
            } else {
                return format!("NO APPEND failed: User not authenticated\r\n");
            }
        } else {
            return format!("NO APPEND failed: User not authenticated\r\n");
        }
    }
}
