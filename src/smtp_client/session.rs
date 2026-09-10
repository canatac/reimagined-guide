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

#[cfg(test)]
mod extract_email_tests {
    use super::extract_email_address;

    #[test]
    fn extracts_plain_email_address() {
        let content = "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            extract_email_address(content, "To:"),
            Some("bob@example.com".to_string())
        );
    }

    #[test]
    fn extracts_email_from_angle_brackets() {
        let content = "From: Alice Smith <alice@example.com>\r\nTo: Bob Jones <bob@example.com>";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            extract_email_address(content, "To:"),
            Some("bob@example.com".to_string())
        );
    }

    #[test]
    fn returns_none_for_missing_header() {
        let content = "From: alice@example.com\r\nSubject: Hello";
        assert_eq!(extract_email_address(content, "To:"), None);
    }

    #[test]
    fn returns_none_for_empty_content() {
        assert_eq!(extract_email_address("", "From:"), None);
    }

    #[test]
    fn handles_colon_in_display_name() {
        let content = "From: \"Smith, Alice\" <alice@example.com>";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn handles_malformed_no_angle_brackets() {
        let content = "From: just-an-email@example.com";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("just-an-email@example.com".to_string())
        );
    }

    #[test]
    fn handles_whitespace_around_value() {
        let content = "From:   alice@example.com  ";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn returns_none_for_empty_value() {
        let content = "From:";
        assert_eq!(extract_email_address(content, "From:"), None);
    }

    #[test]
    fn handles_only_header_name_no_colon_after() {
        let content = "From";
        assert_eq!(extract_email_address(content, "From:"), None);
    }

    #[test]
    fn handles_multiple_colons_in_line() {
        let content = "From: alice@example.com: extra info";
        assert_eq!(
            extract_email_address(content, "From:"),
            Some("alice@example.com: extra info".to_string())
        );
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
