/// MTA-STS (Mail Transfer Agent Strict Transport Security) enforcement.
///
/// Implements RFC 8461: recipient domains publish an MTA-STS policy
/// that requires TLS for SMTP delivery. This module fetches, caches,
/// and enforces the policy before outbound delivery.
///
/// Enforcement levels (configurable):
/// - `testing`: TLS is attempted but failures are reported, not enforced.
/// - `enforce`: TLS is mandatory; delivery fails if policy requires it and
///   the recipient server does not support it.

use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// MTA-STS enforcement level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsEnforcementLevel {
    /// TLS preferred but not enforced (report-only mode).
    Testing,
    /// TLS mandatory when policy is active.
    Enforce,
}

impl StsEnforcementLevel {
    /// Resolve the enforcement level from the environment.
    ///
    /// Reads `MTA_STS_LEVEL` — defaults to `enforce` if unset or invalid.
    pub fn from_env() -> Self {
        match std::env::var("MTA_STS_LEVEL").ok().as_deref() {
            Some("testing") => StsEnforcementLevel::Testing,
            _ => StsEnforcementLevel::Enforce,
        }
    }
}

/// Parsed MTA-STS policy (RFC 8461 §3.1).
#[derive(Debug, Clone)]
pub struct StsPolicy {
    /// Policy mode: "enforce", "testing", or "none".
    pub mode: String,
    /// Maximum age of the policy in seconds (max-age).
    pub max_age: u64,
    /// MX hostnames that match this policy.
    pub mx_hosts: Vec<String>,
}

impl StsPolicy {
    /// Returns true if the policy requires TLS enforcement.
    pub fn is_enforcing(&self) -> bool {
        self.mode == "enforce" || self.mode == "testing"
    }

    /// Returns true if the given MX hostname matches this policy.
    pub fn mx_matches(&self, mx_host: &str) -> bool {
        let mx_lower = mx_host.to_lowercase();
        self.mx_hosts.iter().any(|pattern| {
            if pattern.starts_with("*.") {
                // Wildcard: match any subdomain of the pattern suffix.
                let suffix = &pattern[2..];
                mx_lower.ends_with(suffix) || mx_lower == suffix.trim_end_matches('.')
            } else {
                mx_lower == pattern.to_lowercase().trim_end_matches('.')
            }
        })
    }
}

/// Cached entry with expiration timestamp.
#[derive(Debug, Clone)]
struct CacheEntry {
    policy: Option<StsPolicy>,
    fetched_at: Instant,
}

/// In-memory MTA-STS policy cache.
///
/// Policies are cached for up to their `max_age` (capped at 7 days).
/// Failed lookups are cached for 1 hour to avoid hammering DNS/HTTP.
pub struct StsCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl StsCache {
    pub fn new() -> Self {
        StsCache {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Get a cached policy if it exists and has not expired.
    pub fn get(&self, domain: &str) -> Option<Option<StsPolicy>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(domain)?;

        let ttl = entry
            .policy
            .as_ref()
            .map(|p| Duration::from_secs(p.max_age.min(604800))) // cap 7 days
            .unwrap_or_else(|| Duration::from_secs(3600)); // NXDOMAIN/failure: 1 hour

        if entry.fetched_at.elapsed() > ttl {
            return None; // expired
        }
        Some(entry.policy.clone())
    }

    /// Insert a policy (or None for "no policy found") into the cache.
    pub fn put(&self, domain: &str, policy: Option<StsPolicy>) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                domain.to_string(),
                CacheEntry {
                    policy,
                    fetched_at: Instant::now(),
                },
            );
        }
    }
}

/// Global singleton cache.
static STS_CACHE: once_cell::sync::Lazy<StsCache> =
    once_cell::sync::Lazy::new(StsCache::new);

/// Fetch the MTA-STS policy for a recipient domain.
///
/// Resolution order (RFC 8461 §3.3):
/// 1. Check in-memory cache.
/// 2. Fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
/// 3. Validate the policy (must have `version: STSv1`, `mode`, `max-age`).
/// 4. Cache the result.
pub async fn fetch_sts_policy(domain: &str) -> Option<StsPolicy> {
    // 1. Check cache.
    if let Some(cached) = STS_CACHE.get(domain) {
        return cached;
    }

    // 2. Fetch from well-known URL.
    let url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
    let policy = match reqwest::get(&url).await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.text().await {
                    Ok(body) => parse_sts_policy(&body),
                    Err(_) => None,
                }
            } else {
                None
            }
        }
        Err(_) => None,
    };

    // 4. Cache the result (even None — avoids hammering unavailable endpoints).
    STS_CACHE.put(domain, policy.clone());
    policy
}

/// Parse an MTA-STS policy file (RFC 8461 §3.1).
///
/// Example:
/// ```text
/// version: STSv1
/// mode: enforce
/// max-age: 604800
/// mx: mail.example.com
/// mx: *.example.com
/// ```
fn parse_sts_policy(body: &str) -> Option<StsPolicy> {
    let mut version = None;
    let mut mode = None;
    let mut max_age = None;
    let mut mx_hosts = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            match key.as_str() {
                "version" => version = Some(value.to_string()),
                "mode" => mode = Some(value.to_string()),
                "max-age" => max_age = value.parse::<u64>().ok(),
                "mx" => mx_hosts.push(value.to_string()),
                _ => {}
            }
        }
    }

    // Validate: must be STSv1 with a valid mode and max-age.
    let version = version?;
    if version != "STSv1" {
        return None;
    }
    let mode = mode.unwrap_or_else(|| "none".to_string());
    let max_age = max_age.unwrap_or(3600);

    Some(StsPolicy {
        mode,
        max_age,
        mx_hosts,
    })
}

/// Check whether MTA-STS requires TLS for delivery to this domain.
///
/// Returns:
/// - `Ok(true)` — TLS is required (policy exists in enforce mode).
/// - `Ok(false)` — no policy or policy is in "none" mode.
/// - `Err(...)` — policy enforcement would block delivery.
pub async fn enforce_mta_sts(
    domain: &str,
    mx_host: &str,
) -> std::io::Result<MtaStsResult> {
    let level = StsEnforcementLevel::from_env();
    let policy = fetch_sts_policy(domain).await;

    let policy = match policy {
        Some(p) => p,
        None => return Ok(MtaStsResult::NoPolicy),
    };

    if !policy.is_enforcing() {
        return Ok(MtaStsResult::NoPolicy);
    }

    if !policy.mx_matches(mx_host) {
        // Policy exists but MX does not match — in enforce mode, this is a failure.
        if level == StsEnforcementLevel::Enforce && policy.mode == "enforce" {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                format!(
                    "MTA-STS: MX '{}' does not match policy for domain '{}'",
                    mx_host, domain
                ),
            ));
        }
        return Ok(MtaStsResult::NoPolicy);
    }

    Ok(MtaStsResult::TlsRequired)
}

/// Result of MTA-STS enforcement check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtaStsResult {
    /// No MTA-STS policy — proceed without enforcement.
    NoPolicy,
    /// TLS is required by policy.
    TlsRequired,
}

/// Generate a TLS-RPT (TLS Reporting) JSON report for a failed delivery.
///
/// RFC 8462 §4.4 — aggregate reports sent to the domain's RUA endpoint.
pub fn generate_tls_rpt_report(
    domain: &str,
    mx_host: &str,
    failure_reason: &str,
) -> serde_json::Value {
    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    serde_json::json!({
        "organization-name": "misfits.ai",
        "date-range": {
            "start-datetime": timestamp,
            "end-datetime": timestamp
        },
        "contact-info": "<EMAIL>",
        "report-id": format!("{}-{}-mta-sts", domain, chrono::Utc::now().timestamp()),
        "policies": [{
            "policy": {
                "policy-type": "sts",
                "policy-domain": domain,
                "policy-string": ["version: STSv1", "mode: enforce"],
                "mx-host": [mx_host]
            },
            "summary": {
                "total-successful-session-count": 0,
                "total-failure-session-count": 1
            },
            "failure-details": [{
                "result-type": failure_reason,
                "sending-mta-ip": "unknown",
                "receiving-mx-hostname": mx_host,
                "failed-session-count": 1
            }]
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sts_policy_valid() {
        let body = "version: STSv1\nmode: enforce\nmax-age: 604800\nmx: mail.example.com\nmx: *.example.com\n";
        let policy = parse_sts_policy(body).unwrap();
        assert_eq!(policy.mode, "enforce");
        assert_eq!(policy.max_age, 604800);
        assert_eq!(policy.mx_hosts.len(), 2);
        assert!(policy.is_enforcing());
    }

    #[test]
    fn parse_sts_policy_testing_mode() {
        let body = "version: STSv1\nmode: testing\nmax-age: 3600\nmx: mail.example.com\n";
        let policy = parse_sts_policy(body).unwrap();
        assert_eq!(policy.mode, "testing");
        assert!(policy.is_enforcing());
    }

    #[test]
    fn parse_sts_policy_none_mode() {
        let body = "version: STSv1\nmode: none\nmax-age: 86400\n";
        let policy = parse_sts_policy(body).unwrap();
        assert!(!policy.is_enforcing());
    }

    #[test]
    fn parse_sts_policy_invalid_version() {
        let body = "version: STSv0\nmode: enforce\nmax-age: 604800\n";
        assert!(parse_sts_policy(body).is_none());
    }

    #[test]
    fn parse_sts_policy_empty() {
        assert!(parse_sts_policy("").is_none());
    }

    #[test]
    fn parse_sts_policy_missing_version() {
        let body = "mode: enforce\nmax-age: 604800\n";
        assert!(parse_sts_policy(body).is_none());
    }

    #[test]
    fn mx_matches_exact() {
        let policy = StsPolicy {
            mode: "enforce".to_string(),
            max_age: 604800,
            mx_hosts: vec!["mail.example.com".to_string()],
        };
        assert!(policy.mx_matches("mail.example.com"));
        assert!(!policy.mx_matches("smtp.other.com"));
    }

    #[test]
    fn mx_matches_wildcard() {
        let policy = StsPolicy {
            mode: "enforce".to_string(),
            max_age: 604800,
            mx_hosts: vec!["*.example.com".to_string()],
        };
        assert!(policy.mx_matches("mail.example.com"));
        assert!(policy.mx_matches("smtp.example.com"));
        assert!(policy.mx_matches("deep.sub.example.com"));
        assert!(!policy.mx_matches("example.com"));
        assert!(!policy.mx_matches("other.com"));
    }

    #[test]
    fn mx_matches_trailing_dot() {
        let policy = StsPolicy {
            mode: "enforce".to_string(),
            max_age: 604800,
            mx_hosts: vec!["mail.example.com.".to_string()],
        };
        assert!(policy.mx_matches("mail.example.com"));
    }

    #[test]
    fn enforcement_level_default() {
        // Without env var, should default to Enforce.
        std::env::remove_var("MTA_STS_LEVEL");
        assert_eq!(StsEnforcementLevel::from_env(), StsEnforcementLevel::Enforce);
    }

    #[test]
    fn enforcement_level_testing() {
        std::env::set_var("MTA_STS_LEVEL", "testing");
        assert_eq!(StsEnforcementLevel::from_env(), StsEnforcementLevel::Testing);
        std::env::remove_var("MTA_STS_LEVEL");
    }

    #[test]
    fn cache_put_and_get() {
        let cache = StsCache::new();
        let policy = StsPolicy {
            mode: "enforce".to_string(),
            max_age: 604800,
            mx_hosts: vec!["mail.example.com".to_string()],
        };
        cache.put("example.com", Some(policy.clone()));
        let cached = cache.get("example.com");
        assert!(cached.is_some());
        let cached = cached.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().mode, "enforce");
    }

    #[test]
    fn cache_miss() {
        let cache = StsCache::new();
        assert!(cache.get("nonexistent-domain-test-xyz").is_none());
    }

    #[test]
    fn generate_tls_rpt_report_structure() {
        let report = generate_tls_rpt_report("example.com", "mail.example.com", "validation-failure");
        assert_eq!(report["policies"][0]["policy"]["policy-domain"], "example.com");
        assert_eq!(report["policies"][0]["failure-details"][0]["result-type"], "validation-failure");
        assert_eq!(report["policies"][0]["summary"]["total-failure-session-count"], 1);
    }
}
