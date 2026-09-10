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
    fn parse_smtp_code_extracts_code() {
        assert_eq!(parse_smtp_code("550 User unknown"), Some(550));
        assert_eq!(parse_smtp_code("421 Too many connections"), Some(421));
        assert_eq!(parse_smtp_code("250 OK"), Some(250));
    }

    #[test]
    fn parse_smtp_code_returns_none_for_invalid() {
        assert_eq!(parse_smtp_code("Connection refused"), None);
        assert_eq!(parse_smtp_code("no code here"), None);
        assert_eq!(parse_smtp_code(""), None);
    }

    #[test]
    fn parse_smtp_code_ignores_out_of_range() {
        assert_eq!(parse_smtp_code("1000 overflow"), None);
        assert_eq!(parse_smtp_code("199 too low"), None);
    }

    #[test]
    fn taxonomy_catalog_has_15_entries() {
        assert_eq!(SMTP_REJECT_TAXONOMY_CATALOG.len(), 15);
    }

    #[test]
    fn taxonomy_first_entry_is_invalid_recipient() {
        assert_eq!(SMTP_REJECT_TAXONOMY_CATALOG[0].reason_code, "SMTP_REJECT_INVALID_RECIPIENT");
        assert_eq!(SMTP_REJECT_TAXONOMY_CATALOG[0].action, "verify_recipient");
    }

    #[test]
    fn classify_invalid_recipient_variants() {
        assert_eq!(classify_smtp_reject(Some(550), "550 User unknown").reason_code, "SMTP_REJECT_INVALID_RECIPIENT");
        assert_eq!(classify_smtp_reject(Some(550), "no such user").reason_code, "SMTP_REJECT_INVALID_RECIPIENT");
        assert_eq!(classify_smtp_reject(Some(550), "invalid recipient").reason_code, "SMTP_REJECT_INVALID_RECIPIENT");
    }

    #[test]
    fn classify_mailbox_unavailable() {
        assert_eq!(classify_smtp_reject(Some(550), "mailbox unavailable").reason_code, "SMTP_REJECT_MAILBOX_UNAVAILABLE");
        assert_eq!(classify_smtp_reject(Some(550), "mailbox disabled").reason_code, "SMTP_REJECT_MAILBOX_UNAVAILABLE");
    }

    #[test]
    fn classify_spf_fail() {
        assert_eq!(classify_smtp_reject(Some(550), "spf fail").reason_code, "SMTP_REJECT_SPF_FAIL");
        assert_eq!(classify_smtp_reject(Some(550), "spf softfail").reason_code, "SMTP_REJECT_SPF_FAIL");
    }

    #[test]
    fn classify_dkim_fail() {
        assert_eq!(classify_smtp_reject(Some(550), "dkim fail").reason_code, "SMTP_REJECT_DKIM_FAIL");
        assert_eq!(classify_smtp_reject(Some(550), "dkim bad signature").reason_code, "SMTP_REJECT_DKIM_FAIL");
    }

    #[test]
    fn classify_dmarc_fail() {
        assert_eq!(classify_smtp_reject(Some(550), "dmarc fail").reason_code, "SMTP_REJECT_DMARC_FAIL");
        assert_eq!(classify_smtp_reject(Some(550), "dmarc reject").reason_code, "SMTP_REJECT_DMARC_FAIL");
    }

    #[test]
    fn classify_blacklisted() {
        assert_eq!(classify_smtp_reject(Some(550), "blacklist hit").reason_code, "SMTP_REJECT_BLACKLISTED");
        assert_eq!(classify_smtp_reject(Some(550), "spamhaus listed").reason_code, "SMTP_REJECT_BLACKLISTED");
    }

    #[test]
    fn classify_rate_limited_by_code() {
        assert_eq!(classify_smtp_reject(Some(421), "").reason_code, "SMTP_REJECT_RATE_LIMITED");
    }

    #[test]
    fn classify_rate_limited_by_text() {
        assert_eq!(classify_smtp_reject(Some(421), "rate limit exceeded").reason_code, "SMTP_REJECT_RATE_LIMITED");
        assert_eq!(classify_smtp_reject(Some(421), "throttled").reason_code, "SMTP_REJECT_RATE_LIMITED");
    }

    #[test]
    fn classify_greylisted() {
        assert_eq!(classify_smtp_reject(Some(450), "greylisted").reason_code, "SMTP_REJECT_GREYLISTED");
    }

    #[test]
    fn classify_temporary_unavailable_by_code() {
        assert_eq!(classify_smtp_reject(Some(450), "").reason_code, "SMTP_REJECT_TEMPORARY_UNAVAILABLE");
        assert_eq!(classify_smtp_reject(Some(451), "").reason_code, "SMTP_REJECT_TEMPORARY_UNAVAILABLE");
        assert_eq!(classify_smtp_reject(Some(452), "").reason_code, "SMTP_REJECT_TEMPORARY_UNAVAILABLE");
    }

    #[test]
    fn classify_message_too_large_by_code() {
        assert_eq!(classify_smtp_reject(Some(552), "").reason_code, "SMTP_REJECT_MESSAGE_TOO_LARGE");
    }

    #[test]
    fn classify_storage_exceeded() {
        assert_eq!(classify_smtp_reject(Some(552), "mailbox full").reason_code, "SMTP_REJECT_STORAGE_EXCEEDED");
        assert_eq!(classify_smtp_reject(Some(552), "quota exceeded").reason_code, "SMTP_REJECT_STORAGE_EXCEEDED");
    }

    #[test]
    fn classify_tls_required_by_code() {
        assert_eq!(classify_smtp_reject(Some(530), "").reason_code, "SMTP_REJECT_TLS_REQUIRED");
    }

    #[test]
    fn classify_tls_required_by_text() {
        assert_eq!(classify_smtp_reject(Some(530), "must issue a starttls").reason_code, "SMTP_REJECT_TLS_REQUIRED");
    }

    #[test]
    fn classify_auth_required() {
        assert_eq!(classify_smtp_reject(Some(530), "authentication required").reason_code, "SMTP_REJECT_AUTH_REQUIRED");
        assert_eq!(classify_smtp_reject(Some(530), "relay access denied").reason_code, "SMTP_REJECT_AUTH_REQUIRED");
    }

    #[test]
    fn classify_network_failure() {
        assert_eq!(classify_smtp_reject(None, "connection refused").reason_code, "SMTP_REJECT_NETWORK_FAILURE");
        assert_eq!(classify_smtp_reject(None, "timeout").reason_code, "SMTP_REJECT_NETWORK_FAILURE");
    }

    #[test]
    fn classify_policy_block_by_text() {
        assert_eq!(classify_smtp_reject(Some(553), "").reason_code, "SMTP_REJECT_POLICY_BLOCK");
        assert_eq!(classify_smtp_reject(Some(554), "").reason_code, "SMTP_REJECT_POLICY_BLOCK");
        assert_eq!(classify_smtp_reject(Some(550), "policy reject").reason_code, "SMTP_REJECT_POLICY_BLOCK");
    }

    #[test]
    fn classify_unknown_fallback() {
        assert_eq!(classify_smtp_reject(None, "some random error").reason_code, "SMTP_REJECT_UNKNOWN");
    }
}
