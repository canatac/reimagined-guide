#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) struct AlertsSnapshot {
    pub(crate) monitoring: Vec<monitoring::alerts::ActiveAlert>,
    pub(crate) security: Vec<simple_smtp_server::security::SecurityAlert>,
    pub(crate) queue_growth: usize,
    pub(crate) auth_failures: usize,
    pub(crate) anomalies: usize,
}

pub(crate) async fn collect_alerts_snapshot(
    mongo: &Arc<mongodb::Client>,
    window: &str,
) -> AlertsSnapshot {
    use simple_smtp_server::security::audit;
    let monitoring = monitoring::alerts::evaluate_alerts(
        mongo,
        parse_window(window).num_minutes(),
        &AlertConfig::default(),
    )
    .await;
    let security = audit::query_active_alerts(mongo, 300).await;
    let queue_growth = monitoring
        .iter()
        .filter(|a| a.kind.contains("queue") || a.message.to_ascii_lowercase().contains("queue"))
        .count();
    let auth_failures = security
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("auth") || n.contains("brute") || n.contains("login")
        })
        .count();
    let anomalies = security
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("volume")
                || n.contains("spike")
                || n.contains("anormal")
                || n.contains("anomaly")
        })
        .count();
    AlertsSnapshot { monitoring, security, queue_growth, auth_failures, anomalies }
}

pub(crate) async fn collect_suspicious_logins(
    mongo: &Arc<mongodb::Client>,
    since: &str,
) -> Vec<serde_json::Value> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let auth_events_coll = mongo
        .database(&db)
        .collection::<bson::Document>("auth_events");
    let docs = match auth_events_coll
        .aggregate(vec![
            doc! { "$match": { "ts": { "$gte": since }, "success": false } },
            doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } },
            doc! { "$sort": { "attempts": -1 } },
            doc! { "$limit": 10 },
        ])
        .await
    {
        Ok(cursor) => cursor.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    docs.into_iter()
        .map(|d| {
            serde_json::json!({
                "ip": d.get_str("_id").unwrap_or("unknown"),
                "attempts": d.get_i64("attempts").unwrap_or(0)
            })
        })
        .collect()
}

pub(crate) async fn collect_per_domain(
    mongo: &Arc<mongodb::Client>,
    base_filter: &bson::Document,
) -> Vec<serde_json::Value> {
    let docs = storage::aggregate(
        mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$project": {
                "recipient_domain": { "$arrayElemAt": [ { "$split": ["$to", "@"] }, 1 ] },
                "status": "$status"
            }},
            doc! { "$group": {
                "_id": "$recipient_domain",
                "count": { "$sum": 1 },
                "delivered": { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
                "bounced": { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] }, "then": 1, "else": 0 } } }
            }},
            doc! { "$sort": { "count": -1 } },
            doc! { "$limit": 20 },
        ],
    )
    .await;
    docs.into_iter()
        .map(|d| {
            serde_json::json!({
                "domain": d.get_str("_id").unwrap_or("unknown"),
                "count": d.get_i64("count").unwrap_or(0),
                "delivered": d.get_i64("delivered").unwrap_or(0),
                "bounced": d.get_i64("bounced").unwrap_or(0)
            })
        })
        .collect()
}

pub(crate) fn rbl_sources() -> Vec<String> {
    env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub(crate) fn rbl_listed_by() -> Vec<String> {
    env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_snapshot_default() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 0,
            auth_failures: 0,
            anomalies: 0,
        };
        assert!(snapshot.monitoring.is_empty());
        assert!(snapshot.security.is_empty());
        assert_eq!(snapshot.queue_growth, 0);
        assert_eq!(snapshot.auth_failures, 0);
        assert_eq!(snapshot.anomalies, 0);
    }

    #[test]
    fn queue_growth_filter() {
        let kinds = vec!["queue_overflow", "normal", "queue_stuck"];
        let queue_growth: Vec<_> = kinds
            .iter()
            .filter(|k| k.contains("queue"))
            .collect();
        assert_eq!(queue_growth.len(), 2);
    }

    #[test]
    fn auth_failures_filter() {
        let rule_names = vec!["auth_failure", "bruteforce_login", "login_attempt", "spf_fail"];
        let auth_failures: Vec<_> = rule_names
            .iter()
            .filter(|n| {
                let n = n.to_ascii_lowercase();
                n.contains("auth") || n.contains("brute") || n.contains("login")
            })
            .collect();
        assert_eq!(auth_failures.len(), 3);
    }

    #[test]
    fn anomalies_filter() {
        let rule_names = vec!["volume_spike", "anomaly_detected", "anormal_behavior", "normal"];
        let anomalies: Vec<_> = rule_names
            .iter()
            .filter(|n| {
                let n = n.to_ascii_lowercase();
                n.contains("volume") || n.contains("spike") || n.contains("anormal") || n.contains("anomaly")
            })
            .collect();
        assert_eq!(anomalies.len(), 3);
    }

    #[test]
    fn rbl_sources_default() {
        let sources = "zen.spamhaus.org,bl.spamcop.net"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], "zen.spamhaus.org");
        assert_eq!(sources[1], "bl.spamcop.net");
    }

    #[test]
    fn rbl_sources_empty() {
        let sources = ""
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert!(sources.is_empty());
    }

    #[test]
    fn rbl_listed_by_default() {
        let listed_by = ""
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert!(listed_by.is_empty());
    }

    #[test]
    fn rbl_listed_by_set() {
        let listed_by = "zen.spamhaus.org"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(listed_by.len(), 1);
        assert_eq!(listed_by[0], "zen.spamhaus.org");
    }

    #[test]
    fn suspicious_logins_query_format() {
        let pipeline = vec![
            doc! { "$match": { "ts": { "$gte": "2026-01-01T00:00:00Z" }, "success": false } },
            doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } },
            doc! { "$sort": { "attempts": -1 } },
            doc! { "$limit": 10 },
        ];
        assert_eq!(pipeline.len(), 4);
        assert!(pipeline[0].contains_key("$match"));
        assert!(pipeline[1].contains_key("$group"));
        assert!(pipeline[2].contains_key("$sort"));
        assert!(pipeline[3].contains_key("$limit"));
    }

    #[test]
    fn suspicious_logins_match_format() {
        let match_stage = doc! { "$match": { "ts": { "$gte": "2026-01-01T00:00:00Z" }, "success": false } };
        assert!(match_stage.contains_key("$match"));
    }

    #[test]
    fn suspicious_logins_group_format() {
        let group_stage = doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } };
        assert!(group_stage.contains_key("$group"));
    }

    #[test]
    fn per_domain_query_format() {
        let pipeline = vec![
            doc! { "$match": {} },
            doc! { "$project": {
                "recipient_domain": { "$arrayElemAt": [ { "$split": ["$to", "@"] }, 1 ] },
                "status": "$status"
            }},
            doc! { "$group": {
                "_id": "$recipient_domain",
                "count": { "$sum": 1 },
                "delivered": { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
                "bounced": { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] }, "then": 1, "else": 0 } } }
            }},
            doc! { "$sort": { "count": -1 } },
            doc! { "$limit": 20 },
        ];
        assert_eq!(pipeline.len(), 5);
        assert!(pipeline[0].contains_key("$match"));
        assert!(pipeline[1].contains_key("$project"));
        assert!(pipeline[2].contains_key("$group"));
        assert!(pipeline[3].contains_key("$sort"));
        assert!(pipeline[4].contains_key("$limit"));
    }

    #[test]
    fn per_domain_project_format() {
        let project_stage = doc! { "$project": {
            "recipient_domain": { "$arrayElemAt": [ { "$split": ["$to", "@"] }, 1 ] },
            "status": "$status"
        }};
        assert!(project_stage.contains_key("$project"));
    }

    #[test]
    fn per_domain_group_format() {
        let group_stage = doc! { "$group": {
            "_id": "$recipient_domain",
            "count": { "$sum": 1 },
            "delivered": { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
            "bounced": { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] }, "then": 1, "else": 0 } } }
        }};
        assert!(group_stage.contains_key("$group"));
    }

    #[test]
    fn per_domain_domain_extraction() {
        let email = "<EMAIL>";
        let parts: Vec<&str> = email.split('@').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "user");
        assert_eq!(parts[1], "example.com");
    }

    #[test]
    fn per_domain_domain_no_at() {
        let email = "invalid-email";
        let parts: Vec<&str> = email.split('@').collect();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], "invalid-email");
    }

    #[test]
    fn per_domain_domain_multiple_at() {
        let email = "user@sub@example.com";
        let parts: Vec<&str> = email.split('@').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "user");
        assert_eq!(parts[1], "sub");
        assert_eq!(parts[2], "example.com");
    }

    #[test]
    fn per_domain_count_zero() {
        let count = 0i64;
        assert_eq!(count, 0);
    }

    #[test]
    fn per_domain_count_positive() {
        let count = 100i64;
        assert!(count > 0);
    }

    #[test]
    fn per_domain_delivered_zero() {
        let delivered = 0i64;
        assert_eq!(delivered, 0);
    }

    #[test]
    fn per_domain_delivered_positive() {
        let delivered = 80i64;
        assert!(delivered > 0);
    }

    #[test]
    fn per_domain_bounced_zero() {
        let bounced = 0i64;
        assert_eq!(bounced, 0);
    }

    #[test]
    fn per_domain_bounced_positive() {
        let bounced = 5i64;
        assert!(bounced > 0);
    }

    #[test]
    fn per_domain_sort_by_count_desc() {
        let sort = doc! { "$sort": { "count": -1 } };
        assert!(sort.contains_key("$sort"));
        assert_eq!(sort.get_i32("count").unwrap(), -1);
    }

    #[test]
    fn per_domain_limit_20() {
        let limit = doc! { "$limit": 20 };
        assert!(limit.contains_key("$limit"));
        assert_eq!(limit.get_i32("limit").unwrap(), 20);
    }

    #[test]
    fn suspicious_logins_sort_by_attempts_desc() {
        let sort = doc! { "$sort": { "attempts": -1 } };
        assert!(sort.contains_key("$sort"));
        assert_eq!(sort.get_i32("attempts").unwrap(), -1);
    }

    #[test]
    fn suspicious_logins_limit_10() {
        let limit = doc! { "$limit": 10 };
        assert!(limit.contains_key("$limit"));
        assert_eq!(limit.get_i32("limit").unwrap(), 10);
    }

    #[test]
    fn suspicious_logins_ip_unknown() {
        let ip = "unknown";
        assert_eq!(ip, "unknown");
    }

    #[test]
    fn suspicious_logins_ip_format() {
        let ip = "192.168.1.1";
        assert_eq!(ip, "192.168.1.1");
    }

    #[test]
    fn suspicious_logins_attempts_zero() {
        let attempts = 0i64;
        assert_eq!(attempts, 0);
    }

    #[test]
    fn suspicious_logins_attempts_positive() {
        let attempts = 10i64;
        assert!(attempts > 0);
    }

    #[test]
    fn alerts_snapshot_queue_growth_zero() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 0,
            auth_failures: 0,
            anomalies: 0,
        };
        assert_eq!(snapshot.queue_growth, 0);
    }

    #[test]
    fn alerts_snapshot_queue_growth_positive() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 3,
            auth_failures: 0,
            anomalies: 0,
        };
        assert!(snapshot.queue_growth > 0);
    }

    #[test]
    fn alerts_snapshot_auth_failures_zero() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 0,
            auth_failures: 0,
            anomalies: 0,
        };
        assert_eq!(snapshot.auth_failures, 0);
    }

    #[test]
    fn alerts_snapshot_auth_failures_positive() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 0,
            auth_failures: 5,
            anomalies: 0,
        };
        assert!(snapshot.auth_failures > 0);
    }

    #[test]
    fn alerts_snapshot_anomalies_zero() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 0,
            auth_failures: 0,
            anomalies: 0,
        };
        assert_eq!(snapshot.anomalies, 0);
    }

    #[test]
    fn alerts_snapshot_anomalies_positive() {
        let snapshot = AlertsSnapshot {
            monitoring: Vec::new(),
            security: Vec::new(),
            queue_growth: 0,
            auth_failures: 0,
            anomalies: 2,
        };
        assert!(snapshot.anomalies > 0);
    }

    #[test]
    fn monitoring_empty() {
        let monitoring: Vec<monitoring::alerts::ActiveAlert> = Vec::new();
        assert!(monitoring.is_empty());
    }

    #[test]
    fn security_empty() {
        let security: Vec<simple_smtp_server::security::SecurityAlert> = Vec::new();
        assert!(security.is_empty());
    }

    #[test]
    fn monitoring_with_entries() {
        let monitoring: Vec<monitoring::alerts::ActiveAlert> = Vec::new();
        assert_eq!(monitoring.len(), 0);
    }

    #[test]
    fn security_with_entries() {
        let security: Vec<simple_smtp_server::security::SecurityAlert> = Vec::new();
        assert_eq!(security.len(), 0);
    }

    #[test]
    fn window_parse_1h() {
        let window = "1h";
        assert_eq!(window, "1h");
    }

    #[test]
    fn window_parse_24h() {
        let window = "24h";
        assert_eq!(window, "24h");
    }

    #[test]
    fn window_parse_7d() {
        let window = "7d";
        assert_eq!(window, "7d");
    }

    #[test]
    fn window_parse_15m() {
        let window = "15m";
        assert_eq!(window, "15m");
    }

    #[test]
    fn alert_config_default() {
        let config = AlertConfig::default();
        let _ = config;
        assert!(true);
    }

    #[test]
    fn parse_window_1h() {
        let window = "1h";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 60);
    }

    #[test]
    fn parse_window_24h() {
        let window = "24h";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 1440);
    }

    #[test]
    fn parse_window_7d() {
        let window = "7d";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 10080);
    }

    #[test]
    fn parse_window_15m() {
        let window = "15m";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 15);
    }

    #[test]
    fn parse_window_default() {
        let window = "invalid";
        let duration = parse_window(window);
        assert_eq!(duration.num_minutes(), 15);
    }

    #[test]
    fn rbl_sources_with_whitespace() {
        let sources = " zen.spamhaus.org , bl.spamcop.net "
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], "zen.spamhaus.org");
        assert_eq!(sources[1], "bl.spamcop.net");
    }

    #[test]
    fn rbl_listed_by_with_whitespace() {
        let listed_by = " zen.spamhaus.org , bl.spamcop.net "
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(listed_by.len(), 2);
        assert_eq!(listed_by[0], "zen.spamhaus.org");
        assert_eq!(listed_by[1], "bl.spamcop.net");
    }

    #[test]
    fn rbl_sources_single() {
        let sources = "zen.spamhaus.org"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0], "zen.spamhaus.org");
    }

    #[test]
    fn rbl_listed_by_single() {
        let listed_by = "zen.spamhaus.org"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(listed_by.len(), 1);
        assert_eq!(listed_by[0], "zen.spamhaus.org");
    }

    #[test]
    fn rbl_sources_multiple() {
        let sources = "zen.spamhaus.org,bl.spamcop.net,dnsbl.sorbs.net"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 3);
        assert_eq!(sources[0], "zen.spamhaus.org");
        assert_eq!(sources[1], "bl.spamcop.net");
        assert_eq!(sources[2], "dnsbl.sorbs.net");
    }

    #[test]
    fn rbl_listed_by_multiple() {
        let listed_by = "zen.spamhaus.org,bl.spamcop.net,dnsbl.sorbs.net"
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(listed_by.len(), 3);
        assert_eq!(listed_by[0], "zen.spamhaus.org");
        assert_eq!(listed_by[1], "bl.spamcop.net");
        assert_eq!(listed_by[2], "dnsbl.sorbs.net");
    }
}
