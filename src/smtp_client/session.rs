use super::*;

// Update this function to accept a string instead of an Email struct
pub(super) async fn send_email_content(stream: &mut StreamType, email_content: &str) -> std::io::Result<()> {
    let from_address = extract_email_address(email_content, "From:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid From address"))?;
    let to_address = extract_email_address(email_content, "To:")
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "Invalid To address"))?;

    match stream {
        StreamType::Plain(ref mut s) => {
            send_email_content_inner(s, &from_address, &to_address, email_content).await
        }
        StreamType::Tls(ref mut s) => {
            send_email_content_inner(s, &from_address, &to_address, email_content).await
        }
    }
}

// Helper function to extract email address from headers

pub fn extract_email_address(content: &str, header: &str) -> Option<String> {
    let line = content.lines().find(|line| line.starts_with(header))?;
    let value = line.splitn(2, ':').nth(1)?.trim();
    // Handle "Display Name <email@example.com>" format
    if let (Some(start), Some(end)) = (value.rfind('<'), value.rfind('>')) {
        if start < end {
            return Some(value[start + 1..end].trim().to_string());
        }
    }
    Some(value.to_string())
}

async fn send_email_content_inner<T: AsyncWriteExt + AsyncReadExt + Unpin>(
    stream: &mut T,
    from: &str,
    to: &str,
    email_content: &str,
) -> std::io::Result<()> {
    println!("Sending MAIL FROM: <{}>", from);
    stream
        .write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes())
        .await?;
    expect_code(stream, "250").await?;

    println!("Sending RCPT TO: <{}>", to);
    stream
        .write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes())
        .await?;
    expect_code(stream, "250").await?;

    println!("Sending DATA command");
    stream.write_all(b"DATA\r\n").await?;
    expect_code(stream, "354").await?;
    // Send the entire email content without alteration
    println!("++++++++++++++++++++++++++++Sending unaltered email content");
    stream.write_all(email_content.as_bytes()).await?;

    // Ensure the email content ends with \r\n.\r\n
    if !email_content.ends_with("\r\n.\r\n") {
        println!("Adding final .");
        stream.write_all(b"\r\n.\r\n").await?;
    }

    expect_code(stream, "250").await?;

    println!("Sending QUIT command");
    stream.write_all(b"QUIT\r\n").await?;
    expect_code(stream, "221").await?;

    return Ok(());
}
