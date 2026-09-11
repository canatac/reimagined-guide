use super::*;

pub(super) async fn send_email_content(
    stream: &mut StreamType,
    email_content: &str,
    budget: &SmtpTimeoutBudget,
) -> std::io::Result<()> {
    let from_address = extract_email_address(email_content, "From:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid From address"))?;
    let to_address = extract_email_address(email_content, "To:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid To address"))?;

    match stream {
        StreamType::Plain(ref mut s) => {
            send_email_content_inner(s, &from_address, &to_address, email_content, budget).await
        }
        StreamType::Tls(ref mut s) => {
            send_email_content_inner(s, &from_address, &to_address, email_content, budget).await
        }
    }
}

pub fn extract_email_address(content: &str, header: &str) -> Option<String> {
    let line = content.lines().find(|line| line.starts_with(header))?;
    let value = line.split_once(':')?.1.trim();
    // Handle "Display Name <email@example.com>" format
    if let (Some(start), Some(end)) = (value.rfind('<'), value.rfind('>')) {
        if start < end {
            return Some(value[start + 1..end].trim().to_string());
        }
    }
    Some(value.to_string())
}

/// Extracts multiple email addresses from a comma-separated header value.
pub fn extract_email_addresses(content: &str, header: &str) -> Vec<String> {
    let line = match content.lines().find(|line| line.starts_with(header)) {
        Some(l) => l,
        None => return Vec::new(),
    };
    let value = match line.split_once(':') {
        Some((_, v)) => v.trim(),
        None => return Vec::new(),
    };
    
    // Split by comma and extract each address
    value
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            // Handle "Display Name <email@example.com>" format
            if let (Some(start), Some(end)) = (part.rfind('<'), part.rfind('>')) {
                if start < end {
                    return Some(part[start + 1..end].trim().to_string());
                }
            }
            Some(part.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_email_address_simple() {
        let content = "From: sender@example.com";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("sender@example.com".to_string())
        );
    }

    #[test]
    fn extract_email_address_with_display_name() {
        let content = "From: John Doe <john@example.com>";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("john@example.com".to_string())
        );
    }

    #[test]
    fn extract_email_address_missing_header() {
        let content = "Subject: Test";
        assert_eq!(extract_email_address(content, "From:"), None);
    }

    #[test]
    fn extract_email_address_to_header() {
        let content = "To: recipient@example.com";
        assert_eq!(
            extract_email_address(content, "To:"),
            Some("recipient@example.com".to_string())
        );
    }

    #[test]
    fn extract_email_address_without_angle_brackets() {
        let content = "From: plainaddress@example.com";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("plainaddress@example.com".to_string())
        );
    }

    #[test]
    fn extract_email_address_empty_content() {
        assert_eq!(extract_email_address("", "From:"), None);
    }

    #[test]
    fn extract_email_address_no_colon() {
        let content = "From sender@example.com";
        assert_eq!(extract_email_address(content, "From:"), None);
    }

    #[test]
    fn extract_email_addresses_single() {
        let content = "To: recipient@example.com";
        let addresses = extract_email_addresses(content, "To:");
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], "recipient@example.com");
    }

    #[test]
    fn extract_email_addresses_multiple() {
        let content = "To: a@example.com, b@example.com, c@example.com";
        let addresses = extract_email_addresses(content, "To:");
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0], "a@example.com");
        assert_eq!(addresses[1], "b@example.com");
        assert_eq!(addresses[2], "c@example.com");
    }

    #[test]
    fn extract_email_addresses_with_display_names() {
        let content = "To: John <john@example.com>, Jane <jane@example.com>";
        let addresses = extract_email_addresses(content, "To:");
        assert_eq!(addresses.len(), 2);
        assert_eq!(addresses[0], "john@example.com");
        assert_eq!(addresses[1], "jane@example.com");
    }

    #[test]
    fn extract_email_addresses_missing_header() {
        let content = "Subject: Test";
        let addresses = extract_email_addresses(content, "To:");
        assert!(addresses.is_empty());
    }

    #[test]
    fn extract_email_addresses_empty_content() {
        let addresses = extract_email_addresses("", "To:");
        assert!(addresses.is_empty());
    }
}

async fn send_email_content_inner<T: AsyncWriteExt + AsyncReadExt + Unpin>(
    stream: &mut T,
    from: &str,
    to: &str,
    email_content: &str,
    budget: &SmtpTimeoutBudget,
) -> std::io::Result<()> {
    println!("Sending MAIL FROM: <{}>", from);
    stream
        .write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes())
        .await?;
    expect_code_for_phase(stream, "250", "mail_from", budget.mail_from_ms).await?;

    println!("Sending RCPT TO: <{}>", to);
    stream
        .write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes())
        .await?;
    expect_code_for_phase(stream, "250", "rcpt_to", budget.rcpt_to_ms).await?;

    println!("Sending DATA command");
    stream.write_all(b"DATA\r\n").await?;
    expect_code_for_phase(stream, "354", "data_cmd", budget.data_ms).await?;

    println!("++++++++++++++++++++++++++++Sending unaltered email content");
    stream.write_all(email_content.as_bytes()).await?;

    if !email_content.ends_with("\r\n.\r\n") {
        println!("Adding final .");
        stream.write_all(b"\r\n.\r\n").await?;
    }

    expect_code_for_phase(stream, "250", "data_body", budget.body_ms).await?;

    println!("Sending QUIT command");
    stream.write_all(b"QUIT\r\n").await?;
    expect_code_for_phase(stream, "221", "quit", budget.quit_ms).await?;

    Ok(())
}
