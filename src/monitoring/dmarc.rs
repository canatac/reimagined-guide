//! DMARC aggregate report parsing (RFC 7489)
//! Issue #482: DMARC aggregate report parsing
//!
//! Parses XML aggregate reports (RUA) and provides authentication statistics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// DMARC aggregate report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcReport {
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    pub records: Vec<DmarcRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: Option<String>,
    pub report_id: String,
    pub date_range_begin: i64,
    pub date_range_end: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPublished {
    pub domain: String,
    pub adkim: Option<String>,
    pub aspf: Option<String>,
    pub p: Option<String>,
    pub sp: Option<String>,
    pub pct: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcRecord {
    pub source_ip: String,
    pub count: u32,
    pub disposition: Option<String>,
    pub dkim: Option<String>,
    pub spf: Option<String>,
    pub header_from: Option<String>,
    pub envelope_from: Option<String>,
    pub envelope_to: Option<String>,
}

/// Aggregated DMARC statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcStats {
    pub total_records: usize,
    pub total_messages: u32,
    pub pass_count: u32,
    pub fail_count: u32,
    pub pass_rate: f64,
    pub dkim_pass_count: u32,
    pub dkim_fail_count: u32,
    pub spf_pass_count: u32,
    pub spf_fail_count: u32,
    pub by_source: Vec<SourceStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceStats {
    pub source_ip: String,
    pub total_messages: u32,
    pub pass_count: u32,
    pub fail_count: u32,
    pub pass_rate: f64,
    pub dkim_pass: u32,
    pub dkim_fail: u32,
    pub spf_pass: u32,
    pub spf_fail: u32,
}

/// Parse a DMARC aggregate report from XML string
pub fn parse_dmarc_report(xml: &str) -> Result<DmarcReport, String> {
    let report: DmarcReport = quick_xml::de::from_str(xml)
        .map_err(|e| format!("Failed to parse DMARC report XML: {}", e))?;
    Ok(report)
}

/// Aggregate DMARC records into statistics
pub fn aggregate_dmarc_stats(records: &[DmarcRecord]) -> DmarcStats {
    let mut total_messages = 0u32;
    let mut pass_count = 0u32;
    let mut fail_count = 0u32;
    let mut dkim_pass = 0u32;
    let mut dkim_fail = 0u32;
    let mut spf_pass = 0u32;
    let mut spf_fail = 0u32;

    let mut source_map: HashMap<String, (u32, u32, u32, u32, u32, u32, u32)> = HashMap::new();

    for record in records {
        total_messages += record.count;

        let is_pass = record.disposition.as_deref() == Some("none")
            || record.dkim.as_deref() == Some("pass")
            || record.spf.as_deref() == Some("pass");

        if is_pass {
            pass_count += record.count;
        } else {
            fail_count += record.count;
        }

        if record.dkim.as_deref() == Some("pass") {
            dkim_pass += record.count;
        } else if record.dkim.as_deref() == Some("fail") {
            dkim_fail += record.count;
        }

        if record.spf.as_deref() == Some("pass") {
            spf_pass += record.count;
        } else if record.spf.as_deref() == Some("fail") {
            spf_fail += record.count;
        }

        let entry = source_map.entry(record.source_ip.clone()).or_insert((0, 0, 0, 0, 0, 0, 0));
        entry.0 += record.count;
        if is_pass {
            entry.1 += record.count;
        } else {
            entry.2 += record.count;
        }
        if record.dkim.as_deref() == Some("pass") {
            entry.3 += record.count;
        } else if record.dkim.as_deref() == Some("fail") {
            entry.4 += record.count;
        }
        if record.spf.as_deref() == Some("pass") {
            entry.5 += record.count;
        } else if record.spf.as_deref() == Some("fail") {
            entry.6 += record.count;
        }
    }

    let pass_rate = if total_messages > 0 {
        pass_count as f64 / total_messages as f64
    } else {
        0.0
    };

    let mut by_source: Vec<SourceStats> = source_map
        .into_iter()
        .map(|(ip, (total, pass, fail, dkim_p, dkim_f, spf_p, spf_f))| SourceStats {
            source_ip: ip,
            total_messages: total,
            pass_count: pass,
            fail_count: fail,
            pass_rate: if total > 0 { pass as f64 / total as f64 } else { 0.0 },
            dkim_pass: dkim_p,
            dkim_fail: dkim_f,
            spf_pass: spf_p,
            spf_fail: spf_f,
        })
        .collect();

    by_source.sort_by(|a, b| b.total_messages.cmp(&a.total_messages));

    DmarcStats {
        total_records: records.len(),
        total_messages,
        pass_count,
        fail_count,
        pass_rate,
        dkim_pass_count: dkim_pass,
        dkim_fail_count: dkim_fail,
        spf_pass_count: spf_pass,
        spf_fail_count: spf_fail,
        by_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_dmarc_report() {
        let xml = r#"<?xml version="1"?>
<feedback>
  <report_metadata>
    <org_name>Example Corp</org_name>
    <email>dmarc@example.com</email>
    <report_id>report-123</report_id>
    <date_range><begin>1725148800</begin><end>1725235200</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>100</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

        let report = parse_dmarc_report(xml).expect("parse succeeds");
        assert_eq!(report.report_metadata.org_name, "Example Corp");
        assert_eq!(report.policy_published.domain, "example.com");
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].source_ip, "192.0.2.1");
        assert_eq!(report.records[0].count, 100);
    }

    #[test]
    fn aggregate_stats() {
        let records = vec![
            DmarcRecord {
                source_ip: "192.0.2.1".into(),
                count: 100,
                disposition: Some("none".into()),
                dkim: Some("pass".into()),
                spf: Some("pass".into()),
                header_from: Some("example.com".into()),
                envelope_from: None,
                envelope_to: None,
            },
            DmarcRecord {
                source_ip: "192.0.2.2".into(),
                count: 50,
                disposition: Some("reject".into()),
                dkim: Some("fail".into()),
                spf: Some("fail".into()),
                header_from: Some("example.com".into()),
                envelope_from: None,
                envelope_to: None,
            },
        ];

        let stats = aggregate_dmarc_stats(&records);
        assert_eq!(stats.total_messages, 150);
        assert_eq!(stats.pass_count, 100);
        assert_eq!(stats.fail_count, 50);
        assert!((stats.pass_rate - 0.6667).abs() < 0.01);
        assert_eq!(stats.dkim_pass_count, 100);
        assert_eq!(stats.dkim_fail_count, 50);
        assert_eq!(stats.by_source.len(), 2);
    }

    #[test]
    fn empty_records() {
        let stats = aggregate_dmarc_stats(&[]);
        assert_eq!(stats.total_messages, 0);
        assert_eq!(stats.pass_rate, 0.0);
    }
}
