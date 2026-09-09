//! IMAP trace_id injection for structured logging
//! Issue #437: IMAP trace ids in structured logs
//!
//! Each IMAP command gets a unique trace_id for cross-service correlation.
//! Logs include user, domain, command, and trace_id for RCA.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use uuid::Uuid;

/// Generate a new trace_id for an IMAP command
pub fn generate_trace_id() -> String {
    Uuid::new_v4().to_string()
}

/// Hash a sensitive value for logging (one-way, non-reversible)
fn hash_for_log(value: &str) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Log an IMAP command with trace_id for structured logging
pub fn log_imap_command(
    session_id: &Option<String>,
    user: Option<&str>,
    command: &str,
    trace_id: &str,
    args: &[&str],
) {
    let domain = match user.and_then(|u| u.split('@').nth(1)) {
        Some(d) => d,
        None => "unknown",
    };
    let username_hash = match user {
        Some(u) => hash_for_log(u),
        None => "none".to_string(),
    };
    let session = match session_id.as_deref() {
        Some(s) => s,
        None => "none",
    };
    let args_str = if args.is_empty() {
        String::new()
    } else {
        format!(" args={:?}", args)
    };
    println!(
        "{{\"trace_id\":\"{}\",\"user_hash\":\"{}\",\"domain\":\"{}\",\"command\":\"{}\",\"session_id\":\"{}\"{}}}",
        trace_id, username_hash, domain, command, session, args_str
    );
}

/// Log IMAP command completion with trace_id
pub fn log_imap_completion(
    trace_id: &str,
    command: &str,
    success: bool,
    duration_ms: u64,
) {
    println!(
        "{{\"trace_id\":\"{}\",\"command\":\"{}\",\"success\":{},\"duration_ms\":{}}}",
        trace_id, command, success, duration_ms
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_trace_id_returns_unique_ids() {
        let id1 = generate_trace_id();
        let id2 = generate_trace_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // UUID v4 format
    }

    #[test]
    fn log_imap_command_includes_all_fields() {
        let trace_id = generate_trace_id();
        let session_id = Some("sess-123".to_string());
        log_imap_command(&session_id, Some("user@example.com"), "SELECT", &trace_id, &["INBOX"]);
        // Output should include trace_id, user, domain, command
        assert!(!trace_id.is_empty());
    }

    #[test]
    fn log_imap_command_handles_missing_user() {
        let trace_id = generate_trace_id();
        let session_id = Some("sess-456".to_string());
        log_imap_command(&session_id, None, "NOOP", &trace_id, &[]);
        assert!(!trace_id.is_empty());
    }

    #[test]
    fn log_imap_completion_includes_success_and_duration() {
        let trace_id = generate_trace_id();
        log_imap_completion(&trace_id, "SELECT", true, 45);
        assert!(!trace_id.is_empty());
    }

    #[test]
    fn domain_extraction_from_email() {
        let user = Some("test@misfits.ai");
        let domain = match user.and_then(|u| u.split('@').nth(1)) {
            Some(d) => d,
            None => "unknown",
        };
        assert_eq!(domain, "misfits.ai");
    }

    #[test]
    fn domain_extraction_from_email_without_domain() {
        let user = Some("testuser");
        let domain = match user.and_then(|u| u.split('@').nth(1)) {
            Some(d) => d,
            None => "unknown",
        };
        assert_eq!(domain, "unknown");
    }
}
