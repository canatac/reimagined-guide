/// Parse SMTP error code from an error string (e.g. "Unexpected response: 550 …").
pub fn parse_smtp_code(msg: &str) -> Option<u16> {
    msg.split_whitespace()
        .find_map(|w| w.parse::<u16>().ok().filter(|&c| (200..600).contains(&c)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmtpRejectTaxonomy {
    pub reason_code: &'static str,
    pub action: &'static str,
}

/// Taxonomie normalisée des rejets SMTP.
///
/// Cette table est utilisée pour les logs structurés (reason_code + action)
/// et pour les agrégations dashboard (rejets par taxonomy).
pub const SMTP_REJECT_TAXONOMY_CATALOG: [SmtpRejectTaxonomy; 15] = [
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_INVALID_RECIPIENT", action: "verify_recipient" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_MAILBOX_UNAVAILABLE", action: "verify_recipient" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_DOMAIN_NOT_FOUND", action: "fix_dns_mx" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_POLICY_BLOCK", action: "review_provider_policy" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_SPF_FAIL", action: "fix_spf" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_DKIM_FAIL", action: "fix_dkim" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_DMARC_FAIL", action: "fix_dmarc_alignment" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_BLACKLISTED", action: "delist_sender_ip" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_RATE_LIMITED", action: "throttle_and_retry" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_GREYLISTED", action: "retry_later" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_TEMPORARY_UNAVAILABLE", action: "retry_later" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_MESSAGE_TOO_LARGE", action: "reduce_message_size" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_STORAGE_EXCEEDED", action: "notify_recipient_quota" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_TLS_REQUIRED", action: "enforce_tls" },
    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_AUTH_REQUIRED", action: "authenticate_sender" },
];

pub fn classify_smtp_reject(code: Option<u16>, reply: &str) -> SmtpRejectTaxonomy {
    let lower = reply.to_ascii_lowercase();

    let has_any = |needles: &[&str]| needles.iter().any(|n| lower.contains(n));

    if has_any(&["user unknown", "unknown user", "no such user", "invalid recipient", "recipient address rejected"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_INVALID_RECIPIENT", action: "verify_recipient" };
    }
    if has_any(&["mailbox unavailable", "mailbox disabled", "mailbox does not exist"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_MAILBOX_UNAVAILABLE", action: "verify_recipient" };
    }
    if has_any(&["domain not found", "host not found", "no such domain", "name service error"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_DOMAIN_NOT_FOUND", action: "fix_dns_mx" };
    }
    if has_any(&["spf", "sender policy framework"]) && has_any(&["fail", "softfail", "permerror"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_SPF_FAIL", action: "fix_spf" };
    }
    if has_any(&["dkim"]) && has_any(&["fail", "bad signature", "signature verification failed"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_DKIM_FAIL", action: "fix_dkim" };
    }
    if has_any(&["dmarc"]) && has_any(&["fail", "reject", "quarantine", "alignment"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_DMARC_FAIL", action: "fix_dmarc_alignment" };
    }
    if has_any(&["blacklist", "blocklist", "spamhaus", "rbl", "reputation blocked"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_BLACKLISTED", action: "delist_sender_ip" };
    }
    if has_any(&["too many", "rate limit", "throttl", "temporarily deferred"]) || matches!(code, Some(421)) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_RATE_LIMITED", action: "throttle_and_retry" };
    }
    if has_any(&["greylist", "graylist"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_GREYLISTED", action: "retry_later" };
    }
    if has_any(&["try again later", "temporary failure", "service not available", "mailbox busy"]) || matches!(code, Some(450) | Some(451) | Some(452)) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_TEMPORARY_UNAVAILABLE", action: "retry_later" };
    }
    if has_any(&["message size exceeds", "too large", "exceeded storage allocation"]) || matches!(code, Some(552)) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_MESSAGE_TOO_LARGE", action: "reduce_message_size" };
    }
    if has_any(&["mailbox full", "quota exceeded", "over quota"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_STORAGE_EXCEEDED", action: "notify_recipient_quota" };
    }
    if has_any(&["must issue a starttls", "tls required", "secure connection required"]) || matches!(code, Some(530)) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_TLS_REQUIRED", action: "enforce_tls" };
    }
    if has_any(&["authentication required", "auth required", "relay access denied"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_AUTH_REQUIRED", action: "authenticate_sender" };
    }
    if has_any(&["connection refused", "connection reset", "timeout", "timed out", "network is unreachable"]) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_NETWORK_FAILURE", action: "retry_with_backoff" };
    }
    if has_any(&["policy", "not authorized", "rejected", "access denied"]) || matches!(code, Some(553) | Some(554) | Some(550)) {
        return SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_POLICY_BLOCK", action: "review_provider_policy" };
    }

    SmtpRejectTaxonomy { reason_code: "SMTP_REJECT_UNKNOWN", action: "inspect_smtp_reply" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_network_failure() {
        let tax = classify_smtp_reject(Some(421), "421 connection refused by remote host");
        assert_eq!(tax.reason_code, "SMTP_REJECT_NETWORK_FAILURE");
        assert_eq!(tax.action, "retry_with_backoff");
    }

    #[test]
    fn test_classify_policy_block_554() {
        let tax = classify_smtp_reject(Some(554), "554 5.7.1 Message rejected due to policy");
        assert_eq!(tax.reason_code, "SMTP_REJECT_POLICY_BLOCK");
        assert_eq!(tax.action, "review_provider_policy");
    }

    #[test]
    fn test_classify_unknown_fallback() {
        let tax = classify_smtp_reject(None, "some unrecognized error");
        assert_eq!(tax.reason_code, "SMTP_REJECT_UNKNOWN");
        assert_eq!(tax.action, "inspect_smtp_reply");
    }

    #[test]
    fn test_parse_smtp_code_with_prefix() {
        assert_eq!(parse_smtp_code("Error: 421 service not available"), Some(421));
    }

    #[test]
    fn test_parse_smtp_code_no_match() {
        assert_eq!(parse_smtp_code("connection timed out"), None);
    }

    #[test]
    fn test_catalog_contains_required_codes() {
        let codes: Vec<&str> = SMTP_REJECT_TAXONOMY_CATALOG.iter().map(|t| t.reason_code).collect();
        assert!(codes.contains(&"SMTP_REJECT_INVALID_RECIPIENT"));
        assert!(codes.contains(&"SMTP_REJECT_DKIM_FAIL"));
        assert!(codes.contains(&"SMTP_REJECT_BLACKLISTED"));
        assert!(codes.contains(&"SMTP_REJECT_SPF_FAIL"));
    }
}
