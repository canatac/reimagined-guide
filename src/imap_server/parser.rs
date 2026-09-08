use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FetchArguments {
    pub sequence_set: String,
    pub data_items: String,
}

pub(super) fn parse_fetch_arguments(command_parts: &[String]) -> Option<FetchArguments> {
    if command_parts.len() < 4 {
        return None;
    }

    if command_parts[1].to_uppercase() != "FETCH" {
        return None;
    }

    let sequence_set = command_parts[2].trim().to_string();
    let data_items = command_parts[3..].join(" ").trim().to_string();

    if sequence_set.is_empty() || data_items.is_empty() {
        return None;
    }

    Some(FetchArguments {
        sequence_set,
        data_items,
    })
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
    use super::parse_fetch_arguments;

    #[test]
    fn parse_fetch_arguments_supports_single_data_item() {
        let parts = vec![
            "A1".to_string(),
            "FETCH".to_string(),
            "1".to_string(),
            "FLAGS".to_string(),
        ];

        let args = parse_fetch_arguments(&parts).expect("expected valid FETCH args");
        assert_eq!(args.sequence_set, "1");
        assert_eq!(args.data_items, "FLAGS");
    }

    #[test]
    fn parse_fetch_arguments_supports_parenthesized_data_items() {
        let parts = vec![
            "A2".to_string(),
            "FETCH".to_string(),
            "1:*".to_string(),
            "(FLAGS".to_string(),
            "BODY.PEEK[HEADER])".to_string(),
        ];

        let args = parse_fetch_arguments(&parts).expect("expected valid FETCH args");
        assert_eq!(args.sequence_set, "1:*");
        assert_eq!(args.data_items, "(FLAGS BODY.PEEK[HEADER])");
    }
}
