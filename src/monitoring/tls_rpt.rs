//! TLS-RPT (TLS Reporting) aggregation module
//! RFC 8460 - SMTP TLS Reporting
//!
//! Receives, parses, and aggregates TLS-RPT reports for monitoring
//! TLS connection failures with destination domains.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TLS-RPT report structure (RFC 8460)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptReport {
    pub organization_name: String,
    pub date_range: TlsRptDateRange,
    pub contact_info: Option<String>,
    pub report_id: String,
    pub policies: Vec<TlsRptPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptDateRange {
    pub start_datetime: String,
    pub end_datetime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptPolicy {
    pub policy: TlsRptPolicyDetails,
    pub summary: TlsRptSummary,
    pub failure_details: Vec<TlsRptFailureDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptPolicyDetails {
    #[serde(rename = "policy-type")]
    pub policy_type: String,
    #[serde(rename = "policy-domain")]
    pub policy_domain: String,
    #[serde(rename = "mx-host")]
    pub mx_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptSummary {
    #[serde(rename = "total-successful-session-count")]
    pub total_successful_session_count: i64,
    #[serde(rename = "total-failure-session-count")]
    pub total_failure_session_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptFailureDetail {
    #[serde(rename = "result-type")]
    pub result_type: String,
    #[serde(rename = "sending-mta-ip")]
    pub sending_mta_ip: String,
    #[serde(rename = "receiving-mx-hostname")]
    pub receiving_mx_hostname: String,
    #[serde(rename = "receiving-ip")]
    pub receiving_ip: Option<String>,
    #[serde(rename = "failed-session-count")]
    pub failed_session_count: i64,
    #[serde(rename = "additional-information")]
    pub additional_information: Option<String>,
}

/// Aggregated TLS-RPT data by destination domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptAggregation {
    pub domain: String,
    pub total_success: i64,
    pub total_failure: i64,
    pub failure_rate: f64,
    pub failures_by_type: HashMap<String, i64>,
    pub last_reported: String,
}

/// Alert configuration for TLS-RPT failures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptAlertConfig {
    pub threshold_percent: f64,
    pub min_failures: i64,
    pub enabled: bool,
}

impl Default for TlsRptAlertConfig {
    fn default() -> Self {
        TlsRptAlertConfig {
            threshold_percent: 10.0,
            min_failures: 5,
            enabled: true,
        }
    }
}

/// Parse TLS-RPT JSON report
pub fn parse_tls_rpt_report(json_content: &str) -> Result<TlsRptReport, String> {
    serde_json::from_str(json_content).map_err(|e| format!("Failed to parse TLS-RPT report: {}", e))
}

/// Aggregate TLS-RPT reports by destination domain
pub fn aggregate_by_domain(reports: &[TlsRptReport]) -> Vec<TlsRptAggregation> {
    let mut domain_map: HashMap<String, (i64, i64, HashMap<String, i64>, String)> = HashMap::new();

    for report in reports {
        for policy in &report.policies {
            let domain = policy.policy.policy_domain.clone();
            let success = policy.summary.total_successful_session_count;
            let failure = policy.summary.total_failure_session_count;

            let entry = domain_map.entry(domain.clone()).or_insert((0, 0, HashMap::new(), report.date_range.end_datetime.clone()));
            entry.0 += success;
            entry.1 += failure;

            for detail in &policy.failure_details {
                *entry.2.entry(detail.result_type.clone()).or_insert(0) += detail.failed_session_count;
            }
        }
    }

    domain_map
        .into_iter()
        .map(|(domain, (success, failure, failures_by_type, last_reported))| {
            let total = success + failure;
            let failure_rate = if total > 0 {
                (failure as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            TlsRptAggregation {
                domain,
                total_success: success,
                total_failure: failure,
                failure_rate,
                failures_by_type,
                last_reported,
            }
        })
        .collect()
}

/// Check if aggregation triggers an alert
pub fn check_alert(aggregation: &TlsRptAggregation, config: &TlsRptAlertConfig) -> bool {
    if !config.enabled {
        return false;
    }
    aggregation.total_failure >= config.min_failures
        && aggregation.failure_rate >= config.threshold_percent
}

/// Get failure type distribution across all reports
pub fn get_failure_type_distribution(reports: &[TlsRptReport]) -> HashMap<String, i64> {
    let mut distribution: HashMap<String, i64> = HashMap::new();

    for report in reports {
        for policy in &report.policies {
            for detail in &policy.failure_details {
                *distribution.entry(detail.result_type.clone()).or_insert(0) += detail.failed_session_count;
            }
        }
    }

    distribution
}

/// Calculate trends from multiple reports
pub fn calculate_trends(reports: &[TlsRptReport]) -> Vec<TlsRptTrend> {
    let mut trends: Vec<TlsRptTrend> = Vec::new();

    for report in reports {
        for policy in &report.policies {
            let total = policy.summary.total_successful_session_count + policy.summary.total_failure_session_count;
            let failure_rate = if total > 0 {
                (policy.summary.total_failure_session_count as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            trends.push(TlsRptTrend {
                date: report.date_range.end_datetime.clone(),
                domain: policy.policy.policy_domain.clone(),
                success_count: policy.summary.total_successful_session_count,
                failure_count: policy.summary.total_failure_session_count,
                failure_rate,
            });
        }
    }

    trends.sort_by(|a, b| a.date.cmp(&b.date));
    trends
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptTrend {
    pub date: String,
    pub domain: String,
    pub success_count: i64,
    pub failure_count: i64,
    pub failure_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> TlsRptReport {
        TlsRptReport {
            organization_name: "Test Org".to_string(),
            date_range: TlsRptDateRange {
                start_datetime: "2026-09-01T00:00:00Z".to_string(),
                end_datetime: "2026-09-02T00:00:00Z".to_string(),
            },
            contact_info: Some("admin@test.org".to_string()),
            report_id: "test-report-1".to_string(),
            policies: vec![TlsRptPolicy {
                policy: TlsRptPolicyDetails {
                    policy_type: "sts".to_string(),
                    policy_domain: "example.com".to_string(),
                    mx_host: Some("mx.example.com".to_string()),
                },
                summary: TlsRptSummary {
                    total_successful_session_count: 100,
                    total_failure_session_count: 10,
                },
                failure_details: vec![TlsRptFailureDetail {
                    result_type: "certificate-expired".to_string(),
                    sending_mta_ip: "192.0.2.1".to_string(),
                    receiving_mx_hostname: "mx.example.com".to_string(),
                    receiving_ip: Some("192.0.2.2".to_string()),
                    failed_session_count: 5,
                    additional_information: Some("Certificate expired".to_string()),
                }],
            }],
        }
    }

    #[test]
    fn parse_tls_rpt_report_valid_json() {
        let json = r#"{
            "organization_name": "Test Org",
            "date_range": {
                "start_datetime": "2026-09-01T00:00:00Z",
                "end_datetime": "2026-09-02T00:00:00Z"
            },
            "contact_info": "admin@test.org",
            "report_id": "test-123",
            "policies": []
        }"#;

        let result = parse_tls_rpt_report(json);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.organization_name, "Test Org");
        assert_eq!(report.report_id, "test-123");
    }

    #[test]
    fn parse_tls_rpt_report_invalid_json() {
        let json = "not valid json";
        let result = parse_tls_rpt_report(json);
        assert!(result.is_err());
    }

    #[test]
    fn aggregate_by_domain_calculates_totals() {
        let reports = vec![sample_report()];
        let aggregated = aggregate_by_domain(&reports);

        assert_eq!(aggregated.len(), 1);
        let agg = &aggregated[0];
        assert_eq!(agg.domain, "example.com");
        assert_eq!(agg.total_success, 100);
        assert_eq!(agg.total_failure, 10);
        assert!((agg.failure_rate - 9.09).abs() < 0.01);
    }

    #[test]
    fn check_alert_triggers_when_threshold_exceeded() {
        let aggregation = TlsRptAggregation {
            domain: "example.com".to_string(),
            total_success: 100,
            total_failure: 20,
            failure_rate: 16.67,
            failures_by_type: HashMap::new(),
            last_reported: "2026-09-02T00:00:00Z".to_string(),
        };

        let config = TlsRptAlertConfig {
            threshold_percent: 10.0,
            min_failures: 5,
            enabled: true,
        };

        assert!(check_alert(&aggregation, &config));
    }

    #[test]
    fn check_alert_does_not_trigger_when_below_threshold() {
        let aggregation = TlsRptAggregation {
            domain: "example.com".to_string(),
            total_success: 100,
            total_failure: 2,
            failure_rate: 1.96,
            failures_by_type: HashMap::new(),
            last_reported: "2026-09-02T00:00:00Z".to_string(),
        };

        let config = TlsRptAlertConfig {
            threshold_percent: 10.0,
            min_failures: 5,
            enabled: true,
        };

        assert!(!check_alert(&aggregation, &config));
    }

    #[test]
    fn check_alert_does_not_trigger_when_disabled() {
        let aggregation = TlsRptAggregation {
            domain: "example.com".to_string(),
            total_success: 100,
            total_failure: 20,
            failure_rate: 16.67,
            failures_by_type: HashMap::new(),
            last_reported: "2026-09-02T00:00:00Z".to_string(),
        };

        let config = TlsRptAlertConfig {
            threshold_percent: 10.0,
            min_failures: 5,
            enabled: false,
        };

        assert!(!check_alert(&aggregation, &config));
    }

    #[test]
    fn get_failure_type_distribution_counts_correctly() {
        let reports = vec![sample_report()];
        let distribution = get_failure_type_distribution(&reports);

        assert_eq!(distribution.get("certificate-expired"), Some(&5));
    }

    #[test]
    fn calculate_trends_returns_sorted_data() {
        let reports = vec![sample_report()];
        let trends = calculate_trends(&reports);

        assert_eq!(trends.len(), 1);
        assert_eq!(trends[0].domain, "example.com");
        assert_eq!(trends[0].success_count, 100);
        assert_eq!(trends[0].failure_count, 10);
    }
}
