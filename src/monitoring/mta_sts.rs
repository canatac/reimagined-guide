//! MTA-STS (Mail Transfer Agent Strict Transport Security) policy enforcement
//! RFC 8461 — DNS-based TLS policy for outbound SMTP
//!
//! Policy lifecycle:
//! 1. Fetch policy via DNS TXT record (`_mta-sts.<domain>`) + HTTPS well-known URL
//! 2. Validate policy (version, mode, max_age, mx matching)
//! 3. Enforce TLS when policy mode = `enforce` or `testing`
//! 4. Generate TLS-RPT reports for failures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// MTA-STS policy modes (RFC 8461 §4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StsMode {
    /// Policy is in testing mode — TLS failures reported but delivery continues
    Testing,
    /// Policy is in enforce mode — TLS failures block delivery
    Enforce,
    /// No policy configured
    None,
}

/// MTA-STS policy structure (RFC 8461 §4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsPolicy {
    /// Policy version (must be "STSv1")
    pub version: String,
    /// Policy mode (enforce/testing/none)
    pub mode: StsMode,
    /// Maximum age of policy in seconds
    pub max_age: u64,
    /// List of MX hostnames covered by this policy
    pub mx: Vec<String>,
    /// Timestamp when policy was fetched
    #[serde(skip)]
    pub fetched_at: Option<DateTime<Utc>>,
}

impl Default for MtaStsPolicy {
    fn default() -> Self {
        MtaStsPolicy {
            version: "STSv1".to_string(),
            mode: StsMode::None,
            max_age: 86400,
            mx: Vec::new(),
            fetched_at: None,
        }
    }
}

/// MTA-STS policy validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StsValidationResult {
    /// Policy is valid and TLS should be enforced
    Enforce,
    /// Policy is in testing mode — TLS preferred but not required
    Testing,
    /// No policy found — fall back to opportunistic TLS
    None,
    /// Policy is expired
    Expired,
    /// Policy validation failed (reason)
    Invalid(String),
}

/// MTA-STS policy cache entry
#[derive(Debug, Clone)]
struct PolicyCacheEntry {
    policy: MtaStsPolicy,
    cached_at: DateTime<Utc>,
}

/// MTA-STS policy manager — fetches, caches, and enforces policies
pub struct MtaStsManager {
    /// In-memory policy cache (domain → policy)
    cache: Arc<RwLock<HashMap<String, PolicyCacheEntry>>>,
    /// HTTP client for fetching policies
    http_client: reqwest::Client,
    /// Default policy when none found
    default_policy: MtaStsPolicy,
}

impl MtaStsManager {
    /// Create a new MTA-STS manager
    pub fn new() -> Self {
        MtaStsManager {
            cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
            default_policy: MtaStsPolicy::default(),
        }
    }

    /// Fetch MTA-STS policy for a domain
    ///
    /// Tries DNS TXT record first, then HTTPS well-known URL.
    /// Returns cached policy if still valid.
    pub async fn fetch_policy(&self, domain: &str) -> Result<MtaStsPolicy, String> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(domain) {
                let age = Utc::now() - entry.cached_at;
                if age.num_seconds() < entry.policy.max_age as i64 {
                    return Ok(entry.policy.clone());
                }
            }
        }

        // Try DNS TXT record first
        let policy = match self.fetch_policy_dns(domain).await {
            Ok(policy) => policy,
            Err(_) => self.fetch_policy_https(domain).await?,
        };

        // Cache the policy
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                domain.to_string(),
                PolicyCacheEntry {
                    policy: policy.clone(),
                    cached_at: Utc::now(),
                },
            );
        }

        Ok(policy)
    }

    /// Fetch policy from DNS TXT record (`_mta-sts.<domain>`)
    async fn fetch_policy_dns(&self, domain: &str) -> Result<MtaStsPolicy, String> {
        let resolver =
            trust_dns_resolver::TokioAsyncResolver::tokio(
                trust_dns_resolver::config::ResolverConfig::default(),
                trust_dns_resolver::config::ResolverOpts::default(),
            );

        let txt_name = format!("_mta-sts.{}", domain);
        let lookup = resolver
            .txt_lookup(&txt_name)
            .await
            .map_err(|e| format!("DNS TXT lookup failed for {}: {}", txt_name, e))?;

        for record in lookup.iter() {
            let txt = record.to_string();
            if txt.contains("v=STSv1") {
                return parse_sts_dns_txt(&txt);
            }
        }

        Err("No STSv1 TXT record found".to_string())
    }

    /// Fetch policy from HTTPS well-known URL (`https://mta-sts.<domain>/.well-known/mta-sts.txt`)
    async fn fetch_policy_https(&self, domain: &str) -> Result<MtaStsPolicy, String> {
        let url = format!("https://mta-sts.{}/.well-known/mta-sts.txt", domain);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("HTTPS policy fetch failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Policy fetch returned HTTP {}",
                response.status()
            ));
        }

        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read policy body: {}", e))?;

        parse_sts_policy_text(&body)
    }

    /// Validate MTA-STS policy for a destination domain
    ///
    /// Returns the validation result indicating whether TLS should be enforced.
    pub async fn validate(&self, domain: &str, mx_host: &str) -> StsValidationResult {
        let policy = match self.fetch_policy(domain).await {
            Ok(p) => p,
            Err(_) => return StsValidationResult::None,
        };

        // Check version
        if policy.version != "STSv1" {
            return StsValidationResult::Invalid(format!(
                "Unsupported policy version: {}",
                policy.version
            ));
        }

        // Check expiry
        if let Some(fetched_at) = policy.fetched_at {
            let age = Utc::now() - fetched_at;
            if age.num_seconds() > policy.max_age as i64 {
                return StsValidationResult::Expired;
            }
        }

        // Check if MX host matches policy
        let mx_matches = policy.mx.iter().any(|mx_pattern| {
            if mx_pattern.starts_with("*.") {
                // Wildcard matching
                let suffix = &mx_pattern[2..];
                mx_host.ends_with(suffix)
            } else {
                mx_host.eq_ignore_ascii_case(mx_pattern)
            }
        });

        if !mx_matches && !policy.mx.is_empty() {
            return StsValidationResult::Invalid(format!(
                "MX host {} does not match policy",
                mx_host
            ));
        }

        match policy.mode {
            StsMode::Enforce => StsValidationResult::Enforce,
            StsMode::Testing => StsValidationResult::Testing,
            StsMode::None => StsValidationResult::None,
        }
    }

    /// Check if a domain has a valid MTA-STS policy
    pub async fn has_policy(&self, domain: &str) -> bool {
        self.fetch_policy(domain).await.is_ok()
    }

    /// Invalidate cached policy for a domain
    pub async fn invalidate(&self, domain: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(domain);
    }

    /// Clear all cached policies
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear()
    }
}

impl Default for MtaStsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse MTA-STS DNS TXT record content
///
/// Expected format: `v=STSv1; id=20260909T000000;`
fn parse_sts_dns_txt(txt: &str) -> Result<MtaStsPolicy, String> {
    let mut policy = MtaStsPolicy::default();
    policy.fetched_at = Some(Utc::now());

    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((key, value)) = part.split_once('=') {
            match key.trim() {
                "v" => policy.version = value.trim().to_string(),
                "id" => {} // Policy version identifier (informational)
                _ => {}
            }
        }
    }

    if policy.version != "STSv1" {
        return Err(format!("Invalid policy version: {}", policy.version));
    }

    Ok(policy)
}

/// Parse MTA-STS policy text (HTTPS well-known format)
///
/// Expected format (RFC 8461 §4):
/// ```
/// version: STSv1
/// mode: enforce
/// max_age: 86400
/// mx: mail.example.com
/// mx: *.example.com
/// ```
pub fn parse_sts_policy_text(text: &str) -> Result<MtaStsPolicy, String> {
    let mut policy = MtaStsPolicy::default();
    policy.fetched_at = Some(Utc::now());

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();

            match key {
                "version" => policy.version = value.to_string(),
                "mode" => {
                    policy.mode = match value {
                        "enforce" => StsMode::Enforce,
                        "testing" => StsMode::Testing,
                        "none" => StsMode::None,
                        _ => {
                            return Err(format!("Invalid policy mode: {}", value));
                        }
                    };
                }
                "max_age" => {
                    policy.max_age = value
                        .parse()
                        .map_err(|_| format!("Invalid max_age: {}", value))?;
                }
                "mx" => policy.mx.push(value.to_string()),
                _ => {} // Unknown field — ignore per RFC
            }
        }
    }

    if policy.version != "STSv1" {
        return Err(format!(
            "Invalid or missing policy version: {}",
            policy.version
        ));
    }

    Ok(policy)
}

/// Generate MTA-STS policy text for publication
pub fn generate_policy_text(mode: StsMode, max_age: u64, mx_hosts: &[String]) -> String {
    let mode_str = match mode {
        StsMode::Enforce => "enforce",
        StsMode::Testing => "testing",
        StsMode::None => "none",
    };

    let mut text = format!(
        "version: STSv1\nmode: {}\nmax_age: {}\n",
        mode_str, max_age
    );

    for mx in mx_hosts {
        text.push_str(&format!("mx: {}\n", mx));
    }

    text
}

/// Check if TLS enforcement should be applied based on STS validation
pub fn should_enforce_tls(result: &StsValidationResult) -> bool {
    matches!(
        result,
        StsValidationResult::Enforce | StsValidationResult::Testing
    )
}

/// Check if delivery should be blocked on TLS failure
pub fn should_block_on_failure(result: &StsValidationResult) -> bool {
    matches!(result, StsValidationResult::Enforce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sts_policy_text_valid_enforce() {
        let text = "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mail.example.com\nmx: *.example.com\n";
        let policy = parse_sts_policy_text(text).unwrap();

        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mode, StsMode::Enforce);
        assert_eq!(policy.max_age, 86400);
        assert_eq!(policy.mx.len(), 2);
        assert_eq!(policy.mx[0], "mail.example.com");
        assert_eq!(policy.mx[1], "*.example.com");
    }

    #[test]
    fn parse_sts_policy_text_valid_testing() {
        let text = "version: STSv1\nmode: testing\nmax_age: 3600\nmx: mx.example.org\n";
        let policy = parse_sts_policy_text(text).unwrap();

        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mode, StsMode::Testing);
        assert_eq!(policy.max_age, 3600);
        assert_eq!(policy.mx.len(), 1);
    }

    #[test]
    fn parse_sts_policy_text_invalid_version() {
        let text = "version: STSv2\nmode: enforce\nmax_age: 86400\n";
        let result = parse_sts_policy_text(text);
        assert!(result.is_err());
    }

    #[test]
    fn parse_sts_policy_text_invalid_mode() {
        let text = "version: STSv1\nmode: invalid\nmax_age: 86400\n";
        let result = parse_sts_policy_text(text);
        assert!(result.is_err());
    }

    #[test]
    fn parse_sts_policy_text_invalid_max_age() {
        let text = "version: STSv1\nmode: enforce\nmax_age: not_a_number\n";
        let result = parse_sts_policy_text(text);
        assert!(result.is_err());
    }

    #[test]
    fn parse_sts_policy_text_empty() {
        let result = parse_sts_policy_text("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_sts_policy_text_with_comments() {
        let text = "# This is a comment\nversion: STSv1\n# Another comment\nmode: enforce\nmax_age: 86400\n";
        let policy = parse_sts_policy_text(text).unwrap();
        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mode, StsMode::Enforce);
    }

    #[test]
    fn parse_sts_dns_txt_valid() {
        let txt = "v=STSv1; id=20260909T000000;";
        let policy = parse_sts_dns_txt(txt).unwrap();
        assert_eq!(policy.version, "STSv1");
    }

    #[test]
    fn parse_sts_dns_txt_invalid_version() {
        let txt = "v=STSv2; id=20260909T000000;";
        let result = parse_sts_dns_txt(txt);
        assert!(result.is_err());
    }

    #[test]
    fn generate_policy_text_enforce() {
        let text = generate_policy_text(
            StsMode::Enforce,
            86400,
            &["mail.example.com".to_string()],
        );
        assert!(text.contains("version: STSv1"));
        assert!(text.contains("mode: enforce"));
        assert!(text.contains("max_age: 86400"));
        assert!(text.contains("mx: mail.example.com"));
    }

    #[test]
    fn generate_policy_text_testing() {
        let text = generate_policy_text(StsMode::Testing, 3600, &[]);
        assert!(text.contains("mode: testing"));
        assert!(text.contains("max_age: 3600"));
    }

    #[test]
    fn should_enforce_tls_enforce() {
        assert!(should_enforce_tls(&StsValidationResult::Enforce));
    }

    #[test]
    fn should_enforce_tls_testing() {
        assert!(should_enforce_tls(&StsValidationResult::Testing));
    }

    #[test]
    fn should_not_enforce_tls_none() {
        assert!(!should_enforce_tls(&StsValidationResult::None));
    }

    #[test]
    fn should_block_on_failure_enforce() {
        assert!(should_block_on_failure(&StsValidationResult::Enforce));
    }

    #[test]
    fn should_not_block_on_failure_testing() {
        assert!(!should_block_on_failure(&StsValidationResult::Testing));
    }

    #[test]
    fn should_not_block_on_failure_none() {
        assert!(!should_block_on_failure(&StsValidationResult::None));
    }

    #[test]
    fn mx_wildcard_matching() {
        let text = "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: *.example.com\n";
        let policy = parse_sts_policy_text(text).unwrap();
        assert_eq!(policy.mx.len(), 1);
        assert!(policy.mx[0].starts_with("*."));
    }

    #[test]
    fn policy_default_values() {
        let policy = MtaStsPolicy::default();
        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mode, StsMode::None);
        assert_eq!(policy.max_age, 86400);
        assert!(policy.mx.is_empty());
    }
}
