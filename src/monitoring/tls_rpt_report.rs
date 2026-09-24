//! TLS-RPT Report Generation (RFC 8460)
//!
//! Generates TLS-RPT reports from connection logs for submission
//! to destination domains' reporting endpoints.

use chrono::{DateTime, Datelike, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::monitoring::tls_rpt::{TlsRptDateRange, TlsRptReport};
use crate::monitoring::tls_rpt_log::{TlsConnectionRecord, TlsConnectionResult, TlsDomainStats};

/// Generate a TLS-RPT report for a specific domain and time range
pub fn generate_report(
    domain: &str,
    records: &[TlsConnectionRecord],
    organization_name: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> TlsRptReport {
    let domain_records: Vec<&TlsConnectionRecord> = records
        .iter()
        .filter(|r| r.destination_domain == domain)
        .collect();

    let total_success = domain_records
        .iter()
        .filter(|r| r.result == TlsConnectionResult::Success)
        .count() as i64;

    let total_failure = domain_records
        .iter()
        .filter(|r| r.result == TlsConnectionResult::Failed)
        .count() as i64;

    // Collect failure details
    let failure_details: Vec<serde_json::Value> = domain_records
        .iter()
        .filter(|r| r.result == TlsConnectionResult::Failed)
        .map(|r| {
            serde_json::json!({
                "result-type": r.failure_reason.as_ref().map(|f| f.to_string()).unwrap_or_else(|| "unknown".to_string()),
                "sending-mta-ip": "0.0.0.0",
                "receiving-mx-hostname": r.mx_host.as_deref().unwrap_or("unknown"),
                "receiving-ip": r.remote_ip.as_deref().unwrap_or(""),
                "failed-session-count": 1,
                "additional-information": serde_json::Value::Null,
            })
        })
        .collect();

    // Group failure details by result-type + mx-host
    let mut grouped_failures: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for detail in &failure_details {
        let key = format!(
            "{}|{}",
            detail["result-type"].as_str().unwrap_or("unknown"),
            detail["receiving-mx-hostname"].as_str().unwrap_or("unknown")
        );
        if let Some(existing) = grouped_failures.get_mut(&key) {
            let count = existing["failed-session-count"].as_i64().unwrap_or(0) + 1;
            existing["failed-session-count"] = serde_json::json!(count);
        } else {
            grouped_failures.insert(key, detail.clone());
        }
    }

    let failure_details_grouped: Vec<serde_json::Value> =
        grouped_failures.into_values().collect();

    // Convert to the proper struct format
    let policies = vec![serde_json::json!({
        "policy": {
            "policy-type": "sts",
            "policy-domain": domain,
            "mx-host": domain_records.first().and_then(|r| r.mx_host.as_deref()),
        },
        "summary": {
            "total-successful-session-count": total_success,
            "total-failure-session-count": total_failure,
        },
        "failure-details": failure_details_grouped,
    })];

    TlsRptReport {
        organization_name: organization_name.to_string(),
        date_range: TlsRptDateRange {
            start_datetime: start.to_rfc3339(),
            end_datetime: end.to_rfc3339(),
        },
        contact_info: None,
        report_id: format!("{}-{}-{}-{}", domain, start.year(), start.month(), Uuid::new_v4()),
        policies: serde_json::from_value(serde_json::Value::Array(policies)).unwrap_or_default(),
    }
}

/// Generate reports for all domains that have TLS connection data
pub fn generate_all_reports(
    records: &[TlsConnectionRecord],
    organization_name: &str,
    window_hours: i64,
) -> Vec<TlsRptReport> {
    let end = Utc::now();
    let start = end - Duration::hours(window_hours);

    // Collect unique domains
    let mut domains: Vec<String> = records
        .iter()
        .map(|r| r.destination_domain.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    domains.sort();

    domains
        .iter()
        .map(|domain| generate_report(domain, records, organization_name, start, end))
        .collect()
}

/// Summarize stats for admin dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptDashboardSummary {
    pub total_domains: usize,
    pub total_success: i64,
    pub total_failure: i64,
    pub overall_failure_rate: f64,
    pub domains_with_failures: usize,
    pub top_failure_reasons: Vec<(String, i64)>,
    pub period_start: String,
    pub period_end: String,
}

pub fn build_dashboard_summary(
    stats: &[TlsDomainStats],
    period_start: &str,
    period_end: &str,
) -> TlsRptDashboardSummary {
    let total_success: i64 = stats.iter().map(|s| s.total_success as i64).sum();
    let total_failure: i64 = stats.iter().map(|s| s.total_failure as i64).sum();
    let total_attempts = total_success + total_failure;
    let overall_failure_rate = if total_attempts > 0 {
        (total_failure as f64 / total_attempts as f64) * 100.0
    } else {
        0.0
    };

    let domains_with_failures = stats.iter().filter(|s| s.total_failure > 0).count();

    // Aggregate failure reasons across all domains
    let mut all_reasons: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for stat in stats {
        for (reason, count) in &stat.failure_reasons {
            *all_reasons.entry(reason.clone()).or_insert(0) += *count as i64;
        }
    }

    let mut top_failure_reasons: Vec<(String, i64)> = all_reasons.into_iter().collect();
    top_failure_reasons.sort_by(|a, b| b.1.cmp(&a.1));
    top_failure_reasons.truncate(10);

    TlsRptDashboardSummary {
        total_domains: stats.len(),
        total_success,
        total_failure,
        overall_failure_rate,
        domains_with_failures,
        top_failure_reasons,
        period_start: period_start.to_string(),
        period_end: period_end.to_string(),
    }
}

/// Check if any domain exceeds alert thresholds
pub fn check_tls_alerts(
    stats: &[TlsDomainStats],
    failure_rate_threshold: f64,
    min_failures: i64,
) -> Vec<TlsAlertEvent> {
    let mut alerts = Vec::new();

    for stat in stats {
        if stat.total_failure as i64 >= min_failures
            && stat.failure_rate() >= failure_rate_threshold
        {
            alerts.push(TlsAlertEvent {
                domain: stat.domain.clone(),
                severity: if stat.failure_rate() >= 50.0 {
                    "critical".to_string()
                } else if stat.failure_rate() >= 25.0 {
                    "warning".to_string()
                } else {
                    "info".to_string()
                },
                message: format!(
                    "TLS failure rate for {}: {:.1}% ({} of {} attempts failed)",
                    stat.domain,
                    stat.failure_rate(),
                    stat.total_failure,
                    stat.total_attempts
                ),
                failure_rate: stat.failure_rate(),
                total_failures: stat.total_failure as i64,
            });
        }
    }

    alerts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAlertEvent {
    pub domain: String,
    pub severity: String,
    pub message: String,
    pub failure_rate: f64,
    pub total_failures: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::tls_rpt_log::{TlsConnectionRecord, TlsConnectionResult, TlsFailureReason};

    fn sample_records() -> Vec<TlsConnectionRecord> {
        vec![
            TlsConnectionRecord::new("example.com", TlsConnectionResult::Success),
            TlsConnectionRecord::new("example.com", TlsConnectionResult::Success),
            TlsConnectionRecord::new("example.com", TlsConnectionResult::Failed)
                .with_failure_reason(TlsFailureReason::CertificateExpired),
            TlsConnectionRecord::new("other.org", TlsConnectionResult::Success),
        ]
    }

    #[test]
    fn generate_report_basic() {
        let records = sample_records();
        let start = Utc::now() - Duration::hours(24);
        let end = Utc::now();

        let report = generate_report("example.com", &records, "Test Org", start, end);

        assert_eq!(report.organization_name, "Test Org");
        assert!(!report.report_id.is_empty());
        assert!(!report.policies.is_empty());
    }

    #[test]
    fn generate_all_reports_covers_unique_domains() {
        let records = sample_records();
        let reports = generate_all_reports(&records, "Test Org", 24);
        assert_eq!(reports.len(), 2); // example.com and other.org
    }

    #[test]
    fn build_dashboard_summary() {
        let stats = vec![
            TlsDomainStats {
                domain: "example.com".to_string(),
                total_attempts: 10,
                total_success: 8,
                total_failure: 2,
                failure_reasons: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("certificate-expired".to_string(), 2);
                    m
                },
                last_attempt: None,
                last_failure: None,
            },
            TlsDomainStats {
                domain: "other.org".to_string(),
                total_attempts: 5,
                total_success: 5,
                total_failure: 0,
                failure_reasons: std::collections::HashMap::new(),
                last_attempt: None,
                last_failure: None,
            },
        ];

        let summary = build_dashboard_summary(&stats, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z");

        assert_eq!(summary.total_domains, 2);
        assert_eq!(summary.total_success, 13);
        assert_eq!(summary.total_failure, 2);
        assert_eq!(summary.domains_with_failures, 1);
        assert_eq!(summary.top_failure_reasons.len(), 1);
        assert_eq!(summary.top_failure_reasons[0].0, "certificate-expired");
        assert_eq!(summary.top_failure_reasons[0].1, 2);
    }

    #[test]
    fn check_tls_alerts_triggers() {
        let stats = vec![TlsDomainStats {
            domain: "bad-ssl.example".to_string(),
            total_attempts: 10,
            total_success: 3,
            total_failure: 7,
            failure_reasons: std::collections::HashMap::new(),
            last_attempt: None,
            last_failure: None,
        }];

        let alerts = check_tls_alerts(&stats, 10.0, 5);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].domain, "bad-ssl.example");
        assert_eq!(alerts[0].severity, "critical"); // 70% failure rate
    }

    #[test]
    fn check_tls_alerts_no_trigger_below_threshold() {
        let stats = vec![TlsDomainStats {
            domain: "mostly-ok.example".to_string(),
            total_attempts: 100,
            total_success: 95,
            total_failure: 5,
            failure_reasons: std::collections::HashMap::new(),
            last_attempt: None,
            last_failure: None,
        }];

        let alerts = check_tls_alerts(&stats, 10.0, 10); // min 10 failures required
        assert!(alerts.is_empty());
    }

    #[test]
    fn check_tls_alerts_severity_levels() {
        let stats = vec![
            TlsDomainStats {
                domain: "critical.example".to_string(),
                total_attempts: 10,
                total_success: 2,
                total_failure: 8,
                failure_reasons: std::collections::HashMap::new(),
                last_attempt: None,
                last_failure: None,
            },
            TlsDomainStats {
                domain: "warning.example".to_string(),
                total_attempts: 10,
                total_success: 5,
                total_failure: 5,
                failure_reasons: std::collections::HashMap::new(),
                last_attempt: None,
                last_failure: None,
            },
        ];

        let alerts = check_tls_alerts(&stats, 10.0, 1);
        assert_eq!(alerts.len(), 2);

        let critical = alerts.iter().find(|a| a.domain == "critical.example").unwrap();
        assert_eq!(critical.severity, "critical");

        let warning = alerts.iter().find(|a| a.domain == "warning.example").unwrap();
        assert_eq!(warning.severity, "warning");
    }

    #[test]
    fn dashboard_summary_empty_stats() {
        let summary = build_dashboard_summary(&[], "2026-01-01", "2026-01-02");
        assert_eq!(summary.total_domains, 0);
        assert_eq!(summary.total_success, 0);
        assert_eq!(summary.total_failure, 0);
        assert_eq!(summary.overall_failure_rate, 0.0);
    }

    #[test]
    fn overall_failure_rate_calculation() {
        let stats = vec![TlsDomainStats {
            domain: "test.example".to_string(),
            total_attempts: 4,
            total_success: 1,
            total_failure: 3,
            failure_reasons: std::collections::HashMap::new(),
            last_attempt: None,
            last_failure: None,
        }];

        let summary = build_dashboard_summary(&stats, "start", "end");
        assert!((summary.overall_failure_rate - 75.0).abs() < 0.01);
    }
}
