use super::*;

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
    
    value
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
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
