#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) struct AlertsSnapshot {
    pub(crate) monitoring: Vec<monitoring::alerts::ActiveAlert>,
    pub(crate) security: Vec<simple_smtp_server::security::SecurityAlert>,
    pub(crate) queue_growth: usize,
    pub(crate) auth_failures: usize,
    pub(crate) anomalies: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_snapshot_new() {
        let snapshot = AlertsSnapshot {
            monitoring: vec![],
            security: vec![],
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
    fn alerts_snapshot_with_counts() {
        let snapshot = AlertsSnapshot {
            monitoring: vec![],
            security: vec![],
            queue_growth: 3,
            auth_failures: 5,
            anomalies: 2,
        };
        assert_eq!(snapshot.queue_growth, 3);
        assert_eq!(snapshot.auth_failures, 5);
        assert_eq!(snapshot.anomalies, 2);
    }
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
            doc! { "$limit": 20 }
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
    fn rbl_sources_default() {
        let sources = rbl_sources();
        assert!(sources.contains(&"zen.spamhaus.org".to_string()));
        assert!(sources.contains(&"bl.spamcop.net".to_string()));
    }

    #[test]
    fn rbl_sources_custom() {
        std::env::set_var("RBL_CHECK_HOSTS", "custom1.example.com,custom2.example.com");
        let sources = rbl_sources();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], "custom1.example.com");
        assert_eq!(sources[1], "custom2.example.com");
        std::env::remove_var("RBL_CHECK_HOSTS");
    }

    #[test]
    fn rbl_sources_empty() {
        std::env::set_var("RBL_CHECK_HOSTS", "");
        let sources = rbl_sources();
        assert!(sources.is_empty());
        std::env::remove_var("RBL_CHECK_HOSTS");
    }

    #[test]
    fn rbl_sources_whitespace_trimmed() {
        std::env::set_var("RBL_CHECK_HOSTS", " host1 , host2 ");
        let sources = rbl_sources();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0], "host1");
        assert_eq!(sources[1], "host2");
        std::env::remove_var("RBL_CHECK_HOSTS");
    }

    #[test]
    fn rbl_listed_by_default_empty() {
        std::env::remove_var("RBL_LISTED_BY");
        let listed = rbl_listed_by();
        assert!(listed.is_empty());
    }

    #[test]
    fn rbl_listed_by_custom() {
        std::env::set_var("RBL_LISTED_BY", "source1,source2");
        let listed = rbl_listed_by();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], "source1");
        assert_eq!(listed[1], "source2");
        std::env::remove_var("RBL_LISTED_BY");
    }

    #[test]
    fn alerts_snapshot_new() {
        let snapshot = AlertsSnapshot {
            monitoring: vec![],
            security: vec![],
            queue_growth: 5,
            auth_failures: 3,
            anomalies: 2,
        };
        assert!(snapshot.monitoring.is_empty());
        assert!(snapshot.security.is_empty());
        assert_eq!(snapshot.queue_growth, 5);
        assert_eq!(snapshot.auth_failures, 3);
        assert_eq!(snapshot.anomalies, 2);
    }

    #[test]
    fn alerts_snapshot_with_data() {
        let snapshot = AlertsSnapshot {
            monitoring: vec![monitoring::alerts::ActiveAlert {
                id: "alert-1".to_string(),
                kind: "queue_growth".to_string(),
                message: "Queue depth exceeds threshold".to_string(),
                severity: "warning".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
            }],
            security: vec![],
            queue_growth: 1,
            auth_failures: 0,
            anomalies: 0,
        };
        assert_eq!(snapshot.monitoring.len(), 1);
        assert_eq!(snapshot.monitoring[0].id, "alert-1");
        assert_eq!(snapshot.queue_growth, 1);
    }
}
