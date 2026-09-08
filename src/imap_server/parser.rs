use super::*;

pub(super) fn parse_imap_command_line(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = line.trim().chars().peekable();
    let mut in_quotes = false;
    let mut token_started = false;

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '\\' {
                if let Some(next_ch) = chars.next() {
                    current.push(next_ch);
                    token_started = true;
                }
                continue;
            }

            if ch == '"' {
                in_quotes = false;
                token_started = true;
                continue;
            }

            current.push(ch);
            token_started = true;
            continue;
        }

        if ch == '"' {
            in_quotes = true;
            token_started = true;
            continue;
        }

        if ch.is_whitespace() {
            if token_started {
                parts.push(current.clone());
                current.clear();
                token_started = false;
            }
            continue;
        }

        current.push(ch);
        token_started = true;
    }

    if token_started {
        parts.push(current);
    }

    parts
}

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

#[cfg(test)]
mod tests {
    use super::parse_imap_command_line;

    #[test]
    fn parses_list_with_quoted_mailbox_and_empty_reference() {
        let parts = parse_imap_command_line("A1 LIST \"\" \"Sent Items\"\r\n");
        assert_eq!(parts, vec!["A1", "LIST", "", "Sent Items"]);
    }

    #[test]
    fn parses_list_with_unquoted_wildcards() {
        let parts = parse_imap_command_line("A2 LIST \"\" *");
        assert_eq!(parts, vec!["A2", "LIST", "", "*"]);
    }
}
