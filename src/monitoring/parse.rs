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

    // --- parse_smtp_code tests ---

    #[test]
    fn parse_smtp_code_extracts_550() {
        assert_eq!(parse_smtp_code("Unexpected response: 550 mailbox unavailable"), Some(550));
    }

    #[test]
    fn parse_smtp_code_extracts_250() {
        assert_eq!(parse_smtp_code("OK 250 message accepted"), Some(250));
    }

    #[test]
    fn parse_smtp_code_returns_none_for_no_code() {
        assert_eq!(parse_smtp_code("connection failed"), None);
    }

    #[test]
    fn parse_smtp_code_filters_out_of_range() {
        assert_eq!(parse_smtp_code("code 999"), None);
        assert_eq!(parse_smtp_code("code 100"), None);
    }

    #[test]
    fn parse_smtp_code_handles_multiple_codes() {
        assert_eq!(parse_smtp_code("421 4.7.0 rate limited"), Some(421));
    }

    // --- classify_smtp_reject tests ---

    #[test]
    fn classify_invalid_recipient() {
        let result = classify_smtp_reject(Some(550), "550 user unknown");
        assert_eq!(result.reason_code, "SMTP_REJECT_INVALID_RECIPIENT");
        assert_eq!(result.action, "verify_recipient");
    }

    #[test]
    fn classify_mailbox_unavailable() {
        let result = classify_smtp_reject(Some(550), "550 mailbox unavailable");
        assert_eq!(result.reason_code, "SMTP_REJECT_MAILBOX_UNAVAILABLE");
    }

    #[test]
    fn classify_domain_not_found() {
        let result = classify_smtp_reject(Some(550), "550 domain not found");
        assert_eq!(result.reason_code, "SMTP_REJECT_DOMAIN_NOT_FOUND");
        assert_eq!(result.action, "fix_dns_mx");
    }

    #[test]
    fn classify_spf_fail() {
        let result = classify_smtp_reject(Some(550), "550 SPF fail");
        assert_eq!(result.reason_code, "SMTP_REJECT_SPF_FAIL");
        assert_eq!(result.action, "fix_spf");
    }

    #[test]
    fn classify_dkim_fail() {
        let result = classify_smtp_reject(Some(550), "550 DKIM fail");
        assert_eq!(result.reason_code, "SMTP_REJECT_DKIM_FAIL");
        assert_eq!(result.action, "fix_dkim");
    }

    #[test]
    fn classify_dmarc_fail() {
        let result = classify_smtp_reject(Some(550), "550 DMARC reject");
        assert_eq!(result.reason_code, "SMTP_REJECT_DMARC_FAIL");
        assert_eq!(result.action, "fix_dmarc_alignment");
    }

    #[test]
    fn classify_blacklisted() {
        let result = classify_smtp_reject(Some(550), "550 blacklist spamhaus");
        assert_eq!(result.reason_code, "SMTP_REJECT_BLACKLISTED");
        assert_eq!(result.action, "delist_sender_ip");
    }

    #[test]
    fn classify_rate_limited_by_text() {
        let result = classify_smtp_reject(None, "too many messages");
        assert_eq!(result.reason_code, "SMTP_REJECT_RATE_LIMITED");
        assert_eq!(result.action, "throttle_and_retry");
    }

    #[test]
    fn classify_rate_limited_by_code() {
        let result = classify_smtp_reject(Some(421), "service not available");
        assert_eq!(result.reason_code, "SMTP_REJECT_RATE_LIMITED");
    }

    #[test]
    fn classify_greylisted() {
        let result = classify_smtp_reject(None, "greylisted try again later");
        assert_eq!(result.reason_code, "SMTP_REJECT_GREYLISTED");
        assert_eq!(result.action, "retry_later");
    }

    #[test]
    fn classify_temporary_unavailable() {
        let result = classify_smtp_reject(Some(450), "mailbox busy");
        assert_eq!(result.reason_code, "SMTP_REJECT_TEMPORARY_UNAVAILABLE");
    }

    #[test]
    fn classify_message_too_large() {
        let result = classify_smtp_reject(Some(552), "message size exceeds");
        assert_eq!(result.reason_code, "SMTP_REJECT_MESSAGE_TOO_LARGE");
        assert_eq!(result.action, "reduce_message_size");
    }

    #[test]
    fn classify_storage_exceeded() {
        let result = classify_smtp_reject(None, "mailbox full quota exceeded");
        assert_eq!(result.reason_code, "SMTP_REJECT_STORAGE_EXCEEDED");
        assert_eq!(result.action, "notify_recipient_quota");
    }

    #[test]
    fn classify_tls_required() {
        let result = classify_smtp_reject(Some(530), "must issue a starttls");
        assert_eq!(result.reason_code, "SMTP_REJECT_TLS_REQUIRED");
        assert_eq!(result.action, "enforce_tls");
    }

    #[test]
    fn classify_auth_required() {
        let result = classify_smtp_reject(None, "relay access denied");
        assert_eq!(result.reason_code, "SMTP_REJECT_AUTH_REQUIRED");
        assert_eq!(result.action, "authenticate_sender");
    }

    #[test]
    fn classify_network_failure() {
        let result = classify_smtp_reject(None, "connection timeout");
        assert_eq!(result.reason_code, "SMTP_REJECT_NETWORK_FAILURE");
        assert_eq!(result.action, "retry_with_backoff");
    }

    #[test]
    fn classify_policy_block() {
        let result = classify_smtp_reject(Some(554), "policy rejected");
        assert_eq!(result.reason_code, "SMTP_REJECT_POLICY_BLOCK");
        assert_eq!(result.action, "review_provider_policy");
    }

    #[test]
    fn classify_unknown() {
        let result = classify_smtp_reject(None, "some random error");
        assert_eq!(result.reason_code, "SMTP_REJECT_UNKNOWN");
        assert_eq!(result.action, "inspect_smtp_reply");
    }

    #[test]
    fn taxonomy_catalog_has_15_entries() {
        assert_eq!(SMTP_REJECT_TAXONOMY_CATALOG.len(), 15);
    }
}
