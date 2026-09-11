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
    fn recipient_domain_plain() {
        assert_eq!(recipient_domain("alice@misfits.ai"), Some("misfits.ai".to_string()));
    }

    #[test]
    fn recipient_domain_with_angle_brackets() {
        assert_eq!(recipient_domain("<alice@misfits.ai>"), Some("misfits.ai".to_string()));
    }

    #[test]
    fn recipient_domain_with_display_name() {
        assert_eq!(recipient_domain("Alice <alice@example.com>"), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_uppercase() {
        assert_eq!(recipient_domain("alice@EXAMPLE.COM"), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_trailing_dot() {
        assert_eq!(recipient_domain("alice@example.com."), Some("example.com".to_string()));
    }

    #[test]
    fn recipient_domain_no_at() {
        assert_eq!(recipient_domain("alice"), None);
    }

    #[test]
    fn recipient_domain_empty() {
        assert_eq!(recipient_domain(""), None);
    }

    #[test]
    fn is_local_recipient_misfits() {
        assert!(is_local_recipient("alice@misfits.ai"));
        assert!(is_local_recipient("<alice@misfits.ai>"));
    }

    #[test]
    fn is_local_recipient_mail_misfits() {
        assert!(is_local_recipient("alice@mail.misfits.ai"));
    }

    #[test]
    fn is_local_recipient_external() {
        assert!(!is_local_recipient("alice@gmail.com"));
        assert!(!is_local_recipient("alice@example.com"));
    }

    #[test]
    fn is_local_recipient_empty() {
        assert!(!is_local_recipient(""));
    }

    #[test]
    fn recipient_local_part_valid() {
        assert_eq!(recipient_local_part("alice@misfits.ai"), Some("alice".to_string()));
    }

    #[test]
    fn recipient_local_part_with_brackets() {
        assert_eq!(recipient_local_part("<bob@misfits.ai>"), Some("bob".to_string()));
    }

    #[test]
    fn recipient_local_part_mail_misfits() {
        assert_eq!(recipient_local_part("charlie@mail.misfits.ai"), Some("charlie".to_string()));
    }

    #[test]
    fn recipient_local_part_external() {
        assert_eq!(recipient_local_part("alice@gmail.com"), None);
    }

    #[test]
    fn recipient_local_part_uppercase() {
        assert_eq!(recipient_local_part("ALICE@Misfits.ai"), Some("alice".to_string()));
    }

    #[test]
    fn recipient_local_part_empty_local() {
        assert_eq!(recipient_local_part("@misfits.ai"), None);
    }

    #[test]
    fn recipient_local_part_empty() {
        assert_eq!(recipient_local_part(""), None);
    }

    #[test]
    fn recipient_local_part_no_at() {
        assert_eq!(recipient_local_part("alice"), None);
    }
}
