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
