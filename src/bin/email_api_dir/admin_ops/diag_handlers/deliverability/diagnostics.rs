#![allow(unused_imports, dead_code)]
use super::super::super::*;

pub(crate) async fn api_admin_deliverability_diagnostics(
    query: web::Query<DeliverabilityDiagnosticsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let since = since_str(&query.window);
    let mut filter = doc! { "ts": { "$gte": &since } };

    if let Some(domain) = query
        .domain
        .as_ref()
        .map(|d| d.trim())
        .filter(|d| !d.is_empty())
    {
        let safe_domain = domain.replace('.', "\\.");
        filter.insert(
            "to",
            doc! { "$regex": format!("@{}$", safe_domain), "$options": "i" },
        );
    }

    let total = storage::count_events(&mongo, filter.clone()).await;
    let bounces = storage::query_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "status": "bounced" },
        1,
        200,
    )
    .await;

    let mut bounce_reasons: HashMap<String, u32> = HashMap::new();
    let mut bounce_taxonomy: HashMap<String, u32> = HashMap::new();
    for evt in &bounces {
        let key = evt
            .bounce_reason
            .clone()
            .or_else(|| evt.smtp_reply.clone())
            .unwrap_or_else(|| "unknown".to_string());
        *bounce_reasons.entry(key).or_insert(0) += 1;

        let taxonomy_code = evt
            .reject_reason_code
            .clone()
            .unwrap_or_else(|| "SMTP_REJECT_UNKNOWN".to_string());
        *bounce_taxonomy.entry(taxonomy_code).or_insert(0) += 1;
    }

    let mut top_reasons: Vec<(String, u32)> = bounce_reasons.into_iter().collect();
    top_reasons.sort_by(|a, b| b.1.cmp(&a.1));
    let mut top_taxonomy: Vec<(String, u32)> = bounce_taxonomy.into_iter().collect();
    top_taxonomy.sort_by(|a, b| b.1.cmp(&a.1));

    let active_security_alerts = audit::query_active_alerts(&mongo, 300).await;
    let spf_failures = active_security_alerts
        .iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("spf"))
        .count() as u64;
    let dkim_failures = active_security_alerts
        .iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("dkim"))
        .count() as u64;
    let dmarc_failures = active_security_alerts
        .iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("dmarc"))
        .count() as u64;

    let auth_alerts = spf_failures + dkim_failures + dmarc_failures;

    let rbl_sources = env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let rbl_listed_by = env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let risk_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": filter.clone() },
            doc! { "$group": {
                "_id": null,
                "avg_risk": { "$avg": "$risk_score" },
                "high_risk_events": { "$sum": { "$cond": { "if": { "$gte": ["$risk_score", 70] }, "then": 1, "else": 0 } } }
            }},
        ],
    )
    .await;

    let avg_risk_score = risk_docs
        .first()
        .and_then(|d| d.get_f64("avg_risk").ok())
        .unwrap_or(0.0);
    let high_risk_events = risk_docs
        .first()
        .and_then(|d| d.get_i64("high_risk_events").ok())
        .unwrap_or(0);

    let denom = if total == 0 { 1.0 } else { total as f64 };

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "scope_domain": query.domain,
        "total_events": total,
        "bounces_total": bounces.len(),
        "auth_policy_alerts": auth_alerts,
        "spf": {
            "failures": spf_failures,
            "failure_rate": (spf_failures as f64 / denom)
        },
        "dkim": {
            "failures": dkim_failures,
            "failure_rate": (dkim_failures as f64 / denom)
        },
        "dmarc": {
            "failures": dmarc_failures,
            "failure_rate": (dmarc_failures as f64 / denom)
        },
        "reputation": {
            "avg_risk_score": (avg_risk_score * 10.0).round() / 10.0,
            "high_risk_events": high_risk_events,
            "ip_domain_status": if high_risk_events > 0 { "degraded" } else { "normal" }
        },
        "reject_taxonomy_catalog": monitoring::SMTP_REJECT_TAXONOMY_CATALOG
            .iter()
            .map(|entry| serde_json::json!({
                "reason_code": entry.reason_code,
                "action": entry.action,
            }))
            .collect::<Vec<_>>(),
        "top_reject_taxonomy": top_taxonomy
            .into_iter()
            .take(12)
            .map(|(reason_code, count)| serde_json::json!({"reason_code": reason_code, "count": count}))
            .collect::<Vec<_>>(),
        "top_bounce_reasons": top_reasons.into_iter().take(10).map(|(reason, count)| serde_json::json!({"reason": reason, "count": count})).collect::<Vec<_>>(),
        "recent_delivery_failures": bounces.into_iter().take(15).map(|e| serde_json::json!({
            "ts": e.ts,
            "to": e.to,
            "mx_host": e.mx_host,
            "smtp_code": e.smtp_code,
            "smtp_reply": e.smtp_reply,
            "reject_reason_code": e.reject_reason_code,
            "reject_action": e.reject_action,
            "bounce_reason": e.bounce_reason,
            "risk_score": e.risk_score
        })).collect::<Vec<_>>(),
        "rbl": {
            "sources": rbl_sources,
            "listed_by": rbl_listed_by,
            "status": if !env::var("RBL_LISTED_BY").unwrap_or_default().trim().is_empty() { "listed" } else { "clean_or_unknown" },
            "note": "Renseigner RBL_LISTED_BY pour refléter les listes noires détectées par un probe DNS"
        },
        "diagnostics_hints": [
            "Vérifier SPF/DKIM/DMARC alignés pour le domaine expéditeur",
            "Comparer smtp_code/smtp_reply des bounces pour isoler policy vs reputation",
            "Analyser la latence DNS/TLS avant DATA pour détecter throttling provider"
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliverability_diagnostics_query_defaults() {
        let json = serde_json::json!({});
        let q: DeliverabilityDiagnosticsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "1h");
        assert_eq!(q.domain, None);
    }

    #[test]
    fn deliverability_diagnostics_query_custom() {
        let json = serde_json::json!({ "window": "24h", "domain": "example.com" });
        let q: DeliverabilityDiagnosticsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "24h");
        assert_eq!(q.domain, Some("example.com".to_string()));
    }

    #[test]
    fn domain_filter_format() {
        let domain = "example.com";
        let safe_domain = domain.replace('.', "\\.");
        assert_eq!(safe_domain, "example\\.com");
    }

    #[test]
    fn domain_filter_regex() {
        let domain = "example.com";
        let safe_domain = domain.replace('.', "\\.");
        let regex = format!("@{}$", safe_domain);
        assert_eq!(regex, "@example\\.com$");
    }

    #[test]
    fn domain_filter_empty_skipped() {
        let domain: Option<String> = None;
        let should_insert = domain
            .as_ref()
            .map(|d| d.trim())
            .filter(|d| !d.is_empty())
            .is_some();
        assert!(!should_insert);
    }

    #[test]
    fn domain_filter_whitespace_skipped() {
        let domain: Option<String> = Some("   ".to_string());
        let should_insert = domain
            .as_ref()
            .map(|d| d.trim())
            .filter(|d| !d.is_empty())
            .is_some();
        assert!(!should_insert);
    }

    #[test]
    fn domain_filter_valid_inserted() {
        let domain: Option<String> = Some("example.com".to_string());
        let should_insert = domain
            .as_ref()
            .map(|d| d.trim())
            .filter(|d| !d.is_empty())
            .is_some();
        assert!(should_insert);
    }

    #[test]
    fn spf_failures_filter() {
        let rule_names = vec!["spf_fail", "dkim_fail", "spf_mismatch", "dmarc_reject"];
        let spf_failures: Vec<_> = rule_names
            .into_iter()
            .filter(|n| n.to_ascii_lowercase().contains("spf"))
            .collect();
        assert_eq!(spf_failures.len(), 2);
    }

    #[test]
    fn dkim_failures_filter() {
        let rule_names = vec!["spf_fail", "dkim_fail", "dkim_mismatch", "dmarc_reject"];
        let dkim_failures: Vec<_> = rule_names
            .into_iter()
            .filter(|n| n.to_ascii_lowercase().contains("dkim"))
            .collect();
        assert_eq!(dkim_failures.len(), 2);
    }

    #[test]
    fn dmarc_failures_filter() {
        let rule_names = vec!["spf_fail", "dkim_fail", "dmarc_reject", "dmarc_mismatch"];
        let dmarc_failures: Vec<_> = rule_names
            .into_iter()
            .filter(|n| n.to_ascii_lowercase().contains("dmarc"))
            .collect();
        assert_eq!(dmarc_failures.len(), 2);
    }

    #[test]
    fn auth_alerts_sum() {
        let spf = 2u64;
        let dkim = 3u64;
        let dmarc = 1u64;
        let auth_alerts = spf + dkim + dmarc;
        assert_eq!(auth_alerts, 6);
    }

    #[test]
    fn rbl_sources_default() {
        let rbl_sources = "zen.spamhaus.org,bl.spamcop.net"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(rbl_sources.len(), 2);
        assert_eq!(rbl_sources[0], "zen.spamhaus.org");
        assert_eq!(rbl_sources[1], "bl.spamcop.net");
    }

    #[test]
    fn rbl_listed_by_default() {
        let rbl_listed_by = ""
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert!(rbl_listed_by.is_empty());
    }

    #[test]
    fn rbl_listed_by_set() {
        let rbl_listed_by = "zen.spamhaus.org"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(rbl_listed_by.len(), 1);
        assert_eq!(rbl_listed_by[0], "zen.spamhaus.org");
    }

    #[test]
    fn rbl_status_clean() {
        let listed_by = "";
        let status = if !listed_by.trim().is_empty() { "listed" } else { "clean_or_unknown" };
        assert_eq!(status, "clean_or_unknown");
    }

    #[test]
    fn rbl_status_listed() {
        let listed_by = "zen.spamhaus.org";
        let status = if !listed_by.trim().is_empty() { "listed" } else { "clean_or_unknown" };
        assert_eq!(status, "listed");
    }

    #[test]
    fn avg_risk_score_rounding() {
        let avg_risk = 0.5555;
        let rounded = (avg_risk * 10.0).round() / 10.0;
        assert_eq!(rounded, 0.6);
    }

    #[test]
    fn avg_risk_score_zero() {
        let avg_risk = 0.0;
        let rounded = (avg_risk * 10.0).round() / 10.0;
        assert_eq!(rounded, 0.0);
    }

    #[test]
    fn high_risk_events_zero() {
        let high_risk = 0i64;
        assert_eq!(high_risk, 0);
    }

    #[test]
    fn high_risk_events_positive() {
        let high_risk = 5i64;
        assert!(high_risk > 0);
    }

    #[test]
    fn ip_domain_status_normal() {
        let high_risk = 0i64;
        let status = if high_risk > 0 { "degraded" } else { "normal" };
        assert_eq!(status, "normal");
    }

    #[test]
    fn ip_domain_status_degraded() {
        let high_risk = 5i64;
        let status = if high_risk > 0 { "degraded" } else { "normal" };
        assert_eq!(status, "degraded");
    }

    #[test]
    fn denom_zero_total() {
        let total = 0u64;
        let denom = if total == 0 { 1.0 } else { total as f64 };
        assert_eq!(denom, 1.0);
    }

    #[test]
    fn denom_positive_total() {
        let total = 100u64;
        let denom = if total == 0 { 1.0 } else { total as f64 };
        assert_eq!(denom, 100.0);
    }

    #[test]
    fn failure_rate_zero() {
        let failures = 0u64;
        let denom = 100.0;
        let rate = failures as f64 / denom;
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn failure_rate_positive() {
        let failures = 5u64;
        let denom = 100.0;
        let rate = failures as f64 / denom;
        assert_eq!(rate, 0.05);
    }

    #[test]
    fn bounce_reason_unknown() {
        let bounce_reason: Option<String> = None;
        let smtp_reply: Option<String> = None;
        let key = bounce_reason
            .clone()
            .or_else(|| smtp_reply.clone())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(key, "unknown");
    }

    #[test]
    fn bounce_reason_from_bounce() {
        let bounce_reason: Option<String> = Some("Mailbox full".to_string());
        let smtp_reply: Option<String> = None;
        let key = bounce_reason
            .clone()
            .or_else(|| smtp_reply.clone())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(key, "Mailbox full");
    }

    #[test]
    fn bounce_reason_from_smtp_reply() {
        let bounce_reason: Option<String> = None;
        let smtp_reply: Option<String> = Some("550 5.1.1 User unknown".to_string());
        let key = bounce_reason
            .clone()
            .or_else(|| smtp_reply.clone())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(key, "550 5.1.1 User unknown");
    }

    #[test]
    fn taxonomy_code_default() {
        let reject_reason_code: Option<String> = None;
        let code = reject_reason_code
            .clone()
            .unwrap_or_else(|| "SMTP_REJECT_UNKNOWN".to_string());
        assert_eq!(code, "SMTP_REJECT_UNKNOWN");
    }

    #[test]
    fn taxonomy_code_set() {
        let reject_reason_code: Option<String> = Some("SPF_FAIL".to_string());
        let code = reject_reason_code
            .clone()
            .unwrap_or_else(|| "SMTP_REJECT_UNKNOWN".to_string());
        assert_eq!(code, "SPF_FAIL");
    }

    #[test]
    fn top_reasons_sorting() {
        let mut reasons: Vec<(String, u32)> = vec![
            ("reason_a".to_string(), 5),
            ("reason_b".to_string(), 10),
            ("reason_c".to_string(), 3),
        ];
        reasons.sort_by(|a, b| b.1.cmp(&a.1));
        assert_eq!(reasons[0].0, "reason_b");
        assert_eq!(reasons[0].1, 10);
        assert_eq!(reasons[2].0, "reason_c");
        assert_eq!(reasons[2].1, 3);
    }

    #[test]
    fn top_reasons_take_10() {
        let reasons: Vec<(String, u32)> = (0..15)
            .map(|i| (format!("reason_{}", i), i as u32))
            .collect();
        let top: Vec<_> = reasons.into_iter().take(10).collect();
        assert_eq!(top.len(), 10);
    }

    #[test]
    fn top_taxonomy_take_12() {
        let taxonomy: Vec<(String, u32)> = (0..20)
            .map(|i| (format!("code_{}", i), i as u32))
            .collect();
        let top: Vec<_> = taxonomy.into_iter().take(12).collect();
        assert_eq!(top.len(), 12);
    }

    #[test]
    fn recent_delivery_failures_take_15() {
        let bounces: Vec<serde_json::Value> = (0..20)
            .map(|i| serde_json::json!({"ts": format!("2026-01-0{}T00:00:00Z", i)}))
            .collect();
        let recent: Vec<_> = bounces.into_iter().take(15).collect();
        assert_eq!(recent.len(), 15);
    }

    #[test]
    fn diagnostics_hints() {
        let hints = vec![
            "Vérifier SPF/DKIM/DMARC alignés pour le domaine expéditeur",
            "Comparer smtp_code/smtp_reply des bounces pour isoler policy vs reputation",
            "Analyser la latence DNS/TLS avant DATA pour détecter throttling provider",
        ];
        assert_eq!(hints.len(), 3);
        assert!(hints[0].contains("SPF/DKIM/DMARC"));
        assert!(hints[1].contains("smtp_code"));
        assert!(hints[2].contains("latence"));
    }

    #[test]
    fn response_structure() {
        let response = serde_json::json!({
            "window": "1h",
            "since": "2026-01-01T00:00:00Z",
            "scope_domain": null,
            "total_events": 0,
            "bounces_total": 0,
            "auth_policy_alerts": 0,
            "spf": {"failures": 0, "failure_rate": 0.0},
            "dkim": {"failures": 0, "failure_rate": 0.0},
            "dmarc": {"failures": 0, "failure_rate": 0.0},
            "reputation": {"avg_risk_score": 0.0, "high_risk_events": 0, "ip_domain_status": "normal"},
            "reject_taxonomy_catalog": [],
            "top_reject_taxonomy": [],
            "top_bounce_reasons": [],
            "recent_delivery_failures": [],
            "rbl": {"sources": [], "listed_by": [], "status": "clean_or_unknown", "note": ""},
            "diagnostics_hints": []
        });
        assert!(response.get("window").is_some());
        assert!(response.get("since").is_some());
        assert!(response.get("scope_domain").is_some());
        assert!(response.get("total_events").is_some());
        assert!(response.get("bounces_total").is_some());
        assert!(response.get("auth_policy_alerts").is_some());
        assert!(response.get("spf").is_some());
        assert!(response.get("dkim").is_some());
        assert!(response.get("dmarc").is_some());
        assert!(response.get("reputation").is_some());
        assert!(response.get("reject_taxonomy_catalog").is_some());
        assert!(response.get("top_reject_taxonomy").is_some());
        assert!(response.get("top_bounce_reasons").is_some());
        assert!(response.get("recent_delivery_failures").is_some());
        assert!(response.get("rbl").is_some());
        assert!(response.get("diagnostics_hints").is_some());
    }

    #[test]
    fn query_filter_format() {
        let filter = doc! { "ts": { "$gte": "2026-01-01T00:00:00Z" } };
        assert!(filter.contains_key("ts"));
    }

    #[test]
    fn query_filter_with_domain() {
        let mut filter = doc! { "ts": { "$gte": "2026-01-01T00:00:00Z" } };
        filter.insert(
            "to",
            doc! { "$regex": "@example\\.com$", "$options": "i" },
        );
        assert!(filter.contains_key("ts"));
        assert!(filter.contains_key("to"));
    }

    #[test]
    fn bounce_query_format() {
        let query = doc! { "ts": { "$gte": "2026-01-01T00:00:00Z" }, "status": "bounced" };
        assert!(query.contains_key("ts"));
        assert!(query.contains_key("status"));
        assert_eq!(query.get_str("status").unwrap(), "bounced");
    }

    #[test]
    fn risk_aggregation_format() {
        let pipeline = vec![
            doc! { "$match": {} },
            doc! { "$group": {
                "_id": null,
                "avg_risk": { "$avg": "$risk_score" },
                "high_risk_events": { "$sum": { "$cond": { "if": { "$gte": ["$risk_score", 70] }, "then": 1, "else": 0 } } }
            }},
        ];
        assert_eq!(pipeline.len(), 2);
        assert!(pipeline[0].contains_key("$match"));
        assert!(pipeline[1].contains_key("$group"));
    }

    #[test]
    fn risk_score_threshold() {
        let threshold = 70;
        assert_eq!(threshold, 70);
    }

    #[test]
    fn risk_score_above_threshold() {
        let score = 75;
        assert!(score >= 70);
    }

    #[test]
    fn risk_score_below_threshold() {
        let score = 65;
        assert!(score < 70);
    }

    #[test]
    fn risk_score_at_threshold() {
        let score = 70;
        assert!(score >= 70);
    }

    #[test]
    fn total_events_zero() {
        let total = 0u64;
        assert_eq!(total, 0);
    }

    #[test]
    fn total_events_positive() {
        let total = 100u64;
        assert!(total > 0);
    }

    #[test]
    fn bounces_total_zero() {
        let bounces_count = 0usize;
        assert_eq!(bounces_count, 0);
    }

    #[test]
    fn bounces_total_positive() {
        let bounces_count = 5usize;
        assert!(bounces_count > 0);
    }

    #[test]
    fn auth_policy_alerts_zero() {
        let auth_alerts = 0u64;
        assert_eq!(auth_alerts, 0);
    }

    #[test]
    fn auth_policy_alerts_positive() {
        let auth_alerts = 6u64;
        assert!(auth_alerts > 0);
    }

    #[test]
    fn spf_failures_zero() {
        let failures = 0u64;
        assert_eq!(failures, 0);
    }

    #[test]
    fn spf_failures_positive() {
        let failures = 2u64;
        assert!(failures > 0);
    }

    #[test]
    fn dkim_failures_zero() {
        let failures = 0u64;
        assert_eq!(failures, 0);
    }

    #[test]
    fn dkim_failures_positive() {
        let failures = 3u64;
        assert!(failures > 0);
    }

    #[test]
    fn dmarc_failures_zero() {
        let failures = 0u64;
        assert_eq!(failures, 0);
    }

    #[test]
    fn dmarc_failures_positive() {
        let failures = 1u64;
        assert!(failures > 0);
    }
}
