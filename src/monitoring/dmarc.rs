use quick_xml::de::from_str;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmarcReport {
    pub org_name: String,
    pub email: Option<String>,
    pub date_range_begin: Option<i64>,
    pub date_range_end: Option<i64>,
    pub records: Vec<DmarcRecord>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmarcRecord {
    pub source_ip: String,
    pub count: i64,
    pub disposition: String,
    pub dkim: String,
    pub spf: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DmarcStats {
    pub total_reports: usize,
    pub total_records: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub sources: HashMap<String, i64>,
}

#[derive(Debug, Deserialize)]
struct DmarcXml {
    #[serde(rename = "report_metadata", default)]
    report_metadata: Option<ReportMetadata>,
    #[serde(rename = "record", default)]
    record: Vec<XmlRecord>,
}

#[derive(Debug, Deserialize)]
struct ReportMetadata {
    #[serde(rename = "org_name", default)]
    org_name: String,
    #[serde(rename = "email", default)]
    email: Option<String>,
    #[serde(rename = "date_range", default)]
    date_range: Option<DateRange>,
}

#[derive(Debug, Deserialize)]
struct DateRange {
    #[serde(rename = "begin", default)]
    begin: Option<i64>,
    #[serde(rename = "end", default)]
    end: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct XmlRecord {
    #[serde(rename = "row", default)]
    row: Option<Row>,
    #[serde(rename = "identifiers", default)]
    identifiers: Option<Identifiers>,
    #[serde(rename = "auth_results", default)]
    auth_results: Option<AuthResults>,
}

#[derive(Debug, Deserialize)]
struct Row {
    #[serde(rename = "source_ip", default)]
    source_ip: String,
    #[serde(rename = "count", default)]
    count: Option<i64>,
    #[serde(rename = "policy_evaluated", default)]
    policy_evaluated: Option<PolicyEvaluated>,
}

#[derive(Debug, Deserialize)]
struct PolicyEvaluated {
    #[serde(rename = "disposition", default)]
    disposition: String,
    #[serde(rename = "dkim", default)]
    dkim: String,
    #[serde(rename = "spf", default)]
    spf: String,
}

#[derive(Debug, Deserialize)]
struct Identifiers {
    #[serde(rename = "header_from", default)]
    header_from: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthResults {
    #[serde(rename = "dkim", default)]
    dkim: Option<AuthCheck>,
    #[serde(rename = "spf", default)]
    spf: Option<AuthCheck>,
}

#[derive(Debug, Deserialize)]
struct AuthCheck {
    #[serde(rename = "result", default)]
    result: String,
}

pub fn parse_dmarc_report(xml: &str) -> Result<DmarcReport, String> {
    let parsed: DmarcXml =
        from_str(xml).map_err(|e| format!("XML parse error: {}", e))?;

    let metadata = parsed.report_metadata.unwrap_or(ReportMetadata {
        org_name: String::new(),
        email: None,
        date_range: None,
    });

    let date_range = metadata.date_range.unwrap_or(DateRange {
        begin: None,
        end: None,
    });

    let records: Vec<DmarcRecord> = parsed
        .record
        .iter()
        .filter_map(|r| {
            let row = r.row.as_ref()?;
            let policy = row.policy_evaluated.as_ref()?;
            let auth = r.auth_results.as_ref();
            let dkim_result = auth
                .and_then(|a| a.dkim.as_ref())
                .map(|d| d.result.clone())
                .unwrap_or_else(|| policy.dkim.clone());
            let spf_result = auth
                .and_then(|a| a.spf.as_ref())
                .map(|s| s.result.clone())
                .unwrap_or_else(|| policy.spf.clone());
            Some(DmarcRecord {
                source_ip: row.source_ip.clone(),
                count: row.count.unwrap_or(1),
                disposition: policy.disposition.clone(),
                dkim: dkim_result,
                spf: spf_result,
            })
        })
        .collect();

    Ok(DmarcReport {
        org_name: metadata.org_name,
        email: metadata.email,
        date_range_begin: date_range.begin,
        date_range_end: date_range.end,
        records,
    })
}

pub fn aggregate_stats(reports: &[serde_json::Value]) -> DmarcStats {
    let mut stats = DmarcStats::default();
    for report in reports {
        stats.total_reports += 1;
        let records = report
            .get("records")
            .and_then(|r| r.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        stats.total_records += records;
        if let Some(arr) = report.get("records").and_then(|r| r.as_array()) {
            for rec in arr {
                let dkim_pass = rec
                    .get("dkim")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "pass")
                    .unwrap_or(false);
                let spf_pass = rec
                    .get("spf")
                    .and_then(|v| v.as_str())
                    .map(|s| s == "pass")
                    .unwrap_or(false);
                if dkim_pass && spf_pass {
                    stats.pass_count += 1;
                } else {
                    stats.fail_count += 1;
                }
                if let Some(ip) = rec.get("source_ip").and_then(|v| v.as_str()) {
                    let count = rec.get("count").and_then(|v| v.as_i64()).unwrap_or(1);
                    *stats.sources.entry(ip.to_string()).or_insert(0) += count;
                }
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_dmarc_report() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>example.com</org_name>
    <email>dmarc@example.com</email>
    <date_range><begin>1700000000</begin><end>1700086400</end></date_range>
  </report_metadata>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><result>pass</result></dkim>
      <spf><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"#;
        let report = parse_dmarc_report(xml).unwrap();
        assert_eq!(report.org_name, "example.com");
        assert_eq!(report.records.len(), 1);
        assert_eq!(report.records[0].source_ip, "192.0.2.1");
        assert_eq!(report.records[0].count, 5);
    }

    #[test]
    fn test_aggregate_stats() {
        let reports = vec![serde_json::json!({
            "records": [
                {"source_ip": "192.0.2.1", "count": 3, "dkim": "pass", "spf": "pass"},
                {"source_ip": "192.0.2.2", "count": 2, "dkim": "fail", "spf": "pass"},
            ]
        })];
        let stats = aggregate_stats(&reports);
        assert_eq!(stats.total_reports, 1);
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.pass_count, 1);
        assert_eq!(stats.fail_count, 1);
        assert_eq!(stats.sources.get("192.0.2.1"), Some(&3));
        assert_eq!(stats.sources.get("192.0.2.2"), Some(&2));
    }

    #[test]
    fn test_empty_records() {
        let reports = vec![serde_json::json!({"records": []})];
        let stats = aggregate_stats(&reports);
        assert_eq!(stats.total_reports, 1);
        assert_eq!(stats.total_records, 0);
        assert_eq!(stats.pass_count, 0);
        assert_eq!(stats.fail_count, 0);
    }
}
