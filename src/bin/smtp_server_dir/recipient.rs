//! Helpers de parsing d'adresse destinataire SMTP.
//! Extraits de smtp_server.rs (refactor architecte). Fonctions pures.

pub(crate) fn recipient_domain(raw_to: &str) -> Option<String> {
    let trimmed = raw_to.trim();
    let addr = if let (Some(start), Some(end)) = (trimmed.rfind('<'), trimmed.rfind('>')) {
        if start < end {
            &trimmed[start + 1..end]
        } else {
            trimmed
        }
    } else {
        trimmed.trim_matches(|c| c == '<' || c == '>')
    };

    addr.split('@').nth(1).map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
}

pub(crate) fn is_local_recipient(raw_to: &str) -> bool {
    matches!(recipient_domain(raw_to).as_deref(), Some("misfits.ai") | Some("mail.misfits.ai"))
}

pub(crate) fn recipient_local_part(raw_to: &str) -> Option<String> {
    let trimmed = raw_to.trim();
    let addr = if let (Some(start), Some(end)) = (trimmed.rfind('<'), trimmed.rfind('>')) {
        if start < end {
            &trimmed[start + 1..end]
        } else {
            trimmed
        }
    } else {
        trimmed.trim_matches(|c| c == '<' || c == '>')
    };

    let mut parts = addr.split('@');
    let local = parts.next()?.trim().to_ascii_lowercase();
    let domain = parts.next()?.trim().trim_end_matches('.').to_ascii_lowercase();
    if local.is_empty() {
        return None;
    }
    if matches!(domain.as_str(), "misfits.ai" | "mail.misfits.ai") {
        Some(local)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_domain_simple() {
        assert_eq!(recipient_domain("<EMAIL>"), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_with_angle_brackets() {
        assert_eq!(recipient_domain("<<EMAIL>>"), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_with_display_name() {
        assert_eq!(recipient_domain("John <<EMAIL>>"), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_uppercase() {
        assert_eq!(recipient_domain("<EMAIL>"), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_trailing_dot() {
        assert_eq!(recipient_domain("<EMAIL>."), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_no_at() {
        assert_eq!(recipient_domain("invalid"), None);
    }

    #[test]
    fn recipient_domain_empty() {
        assert_eq!(recipient_domain(""), None);
    }

    #[test]
    fn is_local_recipient_misfits() {
        assert!(is_local_recipient("<EMAIL>"));
    }

    #[test]
    fn is_local_recipient_mail_misfits() {
        assert!(is_local_recipient("<EMAIL>"));
    }

    #[test]
    fn is_local_recipient_not_local() {
        assert!(!is_local_recipient("<EMAIL>"));
    }

    #[test]
    fn is_local_recipient_with_brackets() {
        assert!(is_local_recipient("<<EMAIL>>"));
    }

    #[test]
    fn recipient_local_part_misfits() {
        assert_eq!(recipient_local_part("<EMAIL>"), Some("user".to_string()));
    }

    #[test]
    fn recipient_local_part_mail_misfits() {
        assert_eq!(recipient_local_part("<EMAIL>"), Some("user".to_string()));
    }

    #[test]
    fn recipient_local_part_not_local() {
        assert_eq!(recipient_local_part("<EMAIL>"), None);
    }

    #[test]
    fn recipient_local_part_empty_local() {
        assert_eq!(recipient_local_part("@misfits.ai"), None);
    }

    #[test]
    fn recipient_local_part_with_brackets() {
        assert_eq!(recipient_local_part("<<EMAIL>>"), Some("user".to_string()));
    }
}
