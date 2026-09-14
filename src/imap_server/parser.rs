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
            body.push('\n');
        }
    }

    (headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fetch_arguments_valid() {
        let parts = vec![
            "1".to_string(),
            "FETCH".to_string(),
            "1:5".to_string(),
            "BODY[]".to_string(),
        ];
        let result = parse_fetch_arguments(&parts).unwrap();
        assert_eq!(result.sequence_set, "1:5");
        assert_eq!(result.data_items, "BODY[]");
    }

    #[test]
    fn parse_fetch_arguments_lowercase() {
        let parts = vec![
            "1".to_string(),
            "fetch".to_string(),
            "1".to_string(),
            "FLAGS".to_string(),
        ];
        let result = parse_fetch_arguments(&parts).unwrap();
        assert_eq!(result.data_items, "FLAGS");
    }

    #[test]
    fn parse_fetch_arguments_multiple_data_items() {
        let parts = vec![
            "1".to_string(),
            "FETCH".to_string(),
            "1".to_string(),
            "BODY[]".to_string(),
            "FLAGS".to_string(),
        ];
        let result = parse_fetch_arguments(&parts).unwrap();
        assert_eq!(result.data_items, "BODY[] FLAGS");
    }

    #[test]
    fn parse_fetch_arguments_returns_none_for_short_input() {
        let parts = vec!["1".to_string(), "FETCH".to_string()];
        assert!(parse_fetch_arguments(&parts).is_none());
    }

    #[test]
    fn parse_fetch_arguments_returns_none_for_wrong_command() {
        let parts = vec![
            "1".to_string(),
            "SELECT".to_string(),
            "1".to_string(),
            "BODY[]".to_string(),
        ];
        assert!(parse_fetch_arguments(&parts).is_none());
    }

    #[test]
    fn parse_fetch_arguments_empty_sequence() {
        let parts = vec![
            "1".to_string(),
            "FETCH".to_string(),
            "".to_string(),
            "BODY[]".to_string(),
        ];
        assert!(parse_fetch_arguments(&parts).is_none());
    }

    #[test]
    fn parse_email_headers_and_body() {
        let content = "From: a@b.com\nTo: c@d.com\nSubject: Test\n\nHello World";
        let (headers, body) = parse_email(content);
        assert_eq!(headers.get("From"), Some(&"a@b.com".to_string()));
        assert_eq!(headers.get("To"), Some(&"c@d.com".to_string()));
        assert_eq!(headers.get("Subject"), Some(&"Test".to_string()));
        assert_eq!(body.trim(), "Hello World");
    }

    #[test]
    fn parse_email_multiline_body() {
        let content = "From: x@y.com\n\nLine 1\nLine 2\nLine 3";
        let (_, body) = parse_email(content);
        assert!(body.contains("Line 1"));
        assert!(body.contains("Line 2"));
        assert!(body.contains("Line 3"));
    }

    #[test]
    fn parse_email_empty_body() {
        let content = "From: a@b.com\n\n";
        let (headers, body) = parse_email(content);
        assert_eq!(headers.len(), 1);
        assert!(body.is_empty() || body.trim().is_empty());
    }

    #[test]
    fn parse_email_colon_in_header_value() {
        let content = "Subject: Re: Fw: Test\n\nBody";
        let (headers, _) = parse_email(content);
        assert_eq!(headers.get("Subject"), Some(&"Re: Fw: Test".to_string()));
    }

    #[test]
    fn parse_email_handles_trailing_whitespace() {
        let content = "From:   a@b.com  \nTo: c@d.com\n\nBody";
        let (headers, _) = parse_email(content);
        assert_eq!(headers.get("From"), Some(&"a@b.com".to_string()));
    }
}

impl ImapServer {
    /// Handle raw message content received after an APPEND literal.
    pub(super) async fn handle_append_data(
        &mut self,
        command: &[u8],
        sessions: &Arc<Mutex<HashMap<String, String>>>,
        session_id: &mut Option<String>,
    ) -> String {
        let message_str = String::from_utf8_lossy(command);
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
                        format!("{} OK APPEND completed\r\n", self.tag)
                    }
                    Err(_) => "NO APPEND failed: Internal error\r\n".to_string(),
                }
            } else {
                "NO APPEND failed: User not authenticated\r\n".to_string()
            }
        } else {
            "NO APPEND failed: User not authenticated\r\n".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_email;
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

    // --- parse_email tests ---

    #[test]
    fn parse_email_extracts_headers_and_body() {
        let raw = "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello World\r\n\r\nThis is the body.\r\n";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.get("From").unwrap(), "alice@example.com");
        assert_eq!(headers.get("To").unwrap(), "bob@example.com");
        assert_eq!(headers.get("Subject").unwrap(), "Hello World");
        assert!(body.contains("This is the body."));
    }

    #[test]
    fn parse_email_handles_empty_body() {
        let raw = "From: a@b.com\r\nTo: c@d.com\r\n\r\n";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.len(), 2);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_email_handles_empty_input() {
        let (headers, body) = parse_email("");
        assert!(headers.is_empty());
        assert!(body.is_empty());
    }

    #[test]
    fn parse_email_handles_multiline_body() {
        let raw = "From: a@b.com\r\n\r\nLine 1\r\nLine 2\r\nLine 3\r\n";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.len(), 1);
        assert!(body.contains("Line 1"));
        assert!(body.contains("Line 2"));
        assert!(body.contains("Line 3"));
    }

    #[test]
    fn parse_email_handles_colon_in_value() {
        let raw = "Subject: Re: meeting notes\r\n\r\nBody here";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.get("Subject").unwrap(), "Re: meeting notes");
        assert!(body.contains("Body here"));
    }

    #[test]
    fn parse_email_handles_whitespace_in_headers() {
        let raw = "From:   alice@example.com  \r\nTo:  bob@example.com\r\n\r\nBody";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.get("From").unwrap(), "alice@example.com");
        assert_eq!(headers.get("To").unwrap(), "bob@example.com");
    }

    #[test]
    fn parse_email_handles_no_body_separator() {
        let raw = "From: a@b.com\r\nTo: c@d.com\r\n";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.len(), 2);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_email_handles_multiple_headers_same_line_format() {
        let raw = "From: a@b.com\r\nTo: c@d.com\r\nX-Custom: value123\r\n\r\nBody text";
        let (headers, body) = parse_email(raw);
        assert_eq!(headers.len(), 3);
        assert_eq!(headers.get("X-Custom").unwrap(), "value123");
        assert!(body.contains("Body text"));
    }
}
