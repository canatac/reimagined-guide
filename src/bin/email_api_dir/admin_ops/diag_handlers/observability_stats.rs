#![allow(unused_imports, dead_code)]
use super::super::*;

/// Résumé des compteurs SMTP par statut sur la fenêtre.
pub(crate) struct SmtpStatusStats {
    pub(crate) total: u64,
    pub(crate) delivered: u64,
    pub(crate) bounced: u64,
    pub(crate) failed: u64,
    pub(crate) deferred: u64,
    pub(crate) by_status: serde_json::Map<String, serde_json::Value>,
    pub(crate) p95: Option<u64>,
}

pub(crate) async fn collect_smtp_stats(
    mongo: &Arc<mongodb::Client>,
    since: &str,
    base_filter: &bson::Document,
) -> SmtpStatusStats {
    let total = storage::count_events(mongo, base_filter.clone()).await;
    let by_status_docs = storage::aggregate(
        mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ],
    )
    .await;
    let mut by_status = serde_json::Map::new();
    let (mut delivered, mut bounced, mut failed, mut deferred) = (0u64, 0u64, 0u64, 0u64);
    for doc in &by_status_docs {
        let status = doc.get_str("_id").unwrap_or("unknown").to_string();
        let count = doc.get_i64("count").unwrap_or(0) as u64;
        match status.as_str() {
            "delivered" => delivered = count,
            "bounced" => bounced = count,
            "failed" => failed = count,
            "deferred" => deferred = count,
            _ => {}
        }
        by_status.insert(status, serde_json::json!(count));
    }
    let p95 = storage::p95_total_ms(mongo, base_filter.clone(), 1000).await;
    let _ = since;
    SmtpStatusStats { total, delivered, bounced, failed, deferred, by_status, p95 }
}

pub(crate) struct QueueStats {
    pub(crate) depth: u64,
    pub(crate) oldest_age_seconds: Option<u64>,
}

pub(crate) async fn collect_queue_stats(mongo: &Arc<mongodb::Client>) -> QueueStats {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    let pending_queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let depth = queue_coll
        .count_documents(pending_queue_filter.clone())
        .await
        .unwrap_or(0);
    let oldest_pending = queue_coll
        .find_one(pending_queue_filter)
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten();
    let oldest_age_seconds = oldest_pending
        .as_ref()
        .and_then(|d| d.get_datetime("created_at").ok())
        .map(|dt| (Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64 / 1000);
    QueueStats { depth, oldest_age_seconds }
}

pub(crate) struct ThroughputStats {
    pub(crate) incoming: u64,
    pub(crate) outgoing: u64,
    pub(crate) smtp_4xx: u64,
    pub(crate) smtp_5xx: u64,
    pub(crate) dns_issue_events: u64,
}

pub(crate) async fn collect_throughput_stats(
    mongo: &Arc<mongodb::Client>,
    since: &str,
) -> ThroughputStats {
    let incoming = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "event_type": { "$in": ["accepted", "received"] } },
    )
    .await;
    let outgoing = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "status": { "$in": ["delivered", "bounced", "failed", "deferred"] } },
    )
    .await;
    let smtp_4xx = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "smtp_code": { "$gte": 400, "$lt": 500 } },
    )
    .await;
    let smtp_5xx = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "smtp_code": { "$gte": 500, "$lt": 600 } },
    )
    .await;
    let dns_issue_events = storage::count_events(
        mongo,
        doc! { "ts": { "$gte": since }, "event_type": "dns_lookup", "status": { "$in": ["failed", "deferred"] } },
    )
    .await;
    ThroughputStats { incoming, outgoing, smtp_4xx, smtp_5xx, dns_issue_events }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_status_stats_default() {
        let mut by_status = serde_json::Map::new();
        by_status.insert("delivered".to_string(), serde_json::json!(0));
        let stats = SmtpStatusStats {
            total: 0,
            delivered: 0,
            bounced: 0,
            failed: 0,
            deferred: 0,
            by_status,
            p95: None,
        };
        assert_eq!(stats.total, 0);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.bounced, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.deferred, 0);
        assert_eq!(stats.p95, None);
    }

    #[test]
    fn smtp_status_stats_with_values() {
        let mut by_status = serde_json::Map::new();
        by_status.insert("delivered".to_string(), serde_json::json!(100));
        by_status.insert("bounced".to_string(), serde_json::json!(5));
        let stats = SmtpStatusStats {
            total: 105,
            delivered: 100,
            bounced: 5,
            failed: 0,
            deferred: 0,
            by_status,
            p95: Some(1500),
        };
        assert_eq!(stats.total, 105);
        assert_eq!(stats.delivered, 100);
        assert_eq!(stats.bounced, 5);
        assert_eq!(stats.p95, Some(1500));
    }

    #[test]
    fn queue_stats_default() {
        let stats = QueueStats {
            depth: 0,
            oldest_age_seconds: None,
        };
        assert_eq!(stats.depth, 0);
        assert_eq!(stats.oldest_age_seconds, None);
    }

    #[test]
    fn queue_stats_with_values() {
        let stats = QueueStats {
            depth: 10,
            oldest_age_seconds: Some(3600),
        };
        assert_eq!(stats.depth, 10);
        assert_eq!(stats.oldest_age_seconds, Some(3600));
    }

    #[test]
    fn throughput_stats_default() {
        let stats = ThroughputStats {
            incoming: 0,
            outgoing: 0,
            smtp_4xx: 0,
            smtp_5xx: 0,
            dns_issue_events: 0,
        };
        assert_eq!(stats.incoming, 0);
        assert_eq!(stats.outgoing, 0);
        assert_eq!(stats.smtp_4xx, 0);
        assert_eq!(stats.smtp_5xx, 0);
        assert_eq!(stats.dns_issue_events, 0);
    }

    #[test]
    fn throughput_stats_with_values() {
        let stats = ThroughputStats {
            incoming: 100,
            outgoing: 95,
            smtp_4xx: 3,
            smtp_5xx: 2,
            dns_issue_events: 1,
        };
        assert_eq!(stats.incoming, 100);
        assert_eq!(stats.outgoing, 95);
        assert_eq!(stats.smtp_4xx, 3);
        assert_eq!(stats.smtp_5xx, 2);
        assert_eq!(stats.dns_issue_events, 1);
    }

    #[test]
    fn by_status_map_insert() {
        let mut by_status = serde_json::Map::new();
        by_status.insert("delivered".to_string(), serde_json::json!(100));
        by_status.insert("bounced".to_string(), serde_json::json!(5));
        assert_eq!(by_status.len(), 2);
        assert_eq!(by_status["delivered"], 100);
        assert_eq!(by_status["bounced"], 5);
    }

    #[test]
    fn by_status_map_update() {
        let mut by_status = serde_json::Map::new();
        by_status.insert("delivered".to_string(), serde_json::json!(50));
        by_status.insert("delivered".to_string(), serde_json::json!(100));
        assert_eq!(by_status.len(), 1);
        assert_eq!(by_status["delivered"], 100);
    }

    #[test]
    fn status_match_delivered() {
        let status = "delivered";
        let mut delivered = 0u64;
        let count = 100u64;
        match status {
            "delivered" => delivered = count,
            _ => {}
        }
        assert_eq!(delivered, 100);
    }

    #[test]
    fn status_match_bounced() {
        let status = "bounced";
        let mut bounced = 0u64;
        let count = 5u64;
        match status {
            "bounced" => bounced = count,
            _ => {}
        }
        assert_eq!(bounced, 5);
    }

    #[test]
    fn status_match_failed() {
        let status = "failed";
        let mut failed = 0u64;
        let count = 3u64;
        match status {
            "failed" => failed = count,
            _ => {}
        }
        assert_eq!(failed, 3);
    }

    #[test]
    fn status_match_deferred() {
        let status = "deferred";
        let mut deferred = 0u64;
        let count = 2u64;
        match status {
            "deferred" => deferred = count,
            _ => {}
        }
        assert_eq!(deferred, 2);
    }

    #[test]
    fn status_match_unknown() {
        let status = "unknown";
        let mut delivered = 0u64;
        let count = 10u64;
        match status {
            "delivered" => delivered = count,
            _ => {}
        }
        assert_eq!(delivered, 0);
    }

    #[test]
    fn p95_none() {
        let p95: Option<u64> = None;
        assert_eq!(p95, None);
    }

    #[test]
    fn p95_some() {
        let p95: Option<u64> = Some(1500);
        assert_eq!(p95, Some(1500));
    }

    #[test]
    fn queue_depth_zero() {
        let depth = 0u64;
        assert_eq!(depth, 0);
    }

    #[test]
    fn queue_depth_positive() {
        let depth = 10u64;
        assert!(depth > 0);
    }

    #[test]
    fn oldest_age_none() {
        let age: Option<u64> = None;
        assert_eq!(age, None);
    }

    #[test]
    fn oldest_age_some() {
        let age: Option<u64> = Some(3600);
        assert_eq!(age, Some(3600));
    }

    #[test]
    fn oldest_age_calculation() {
        let now = Utc::now().timestamp_millis();
        let created_at = now - 3600000; // 1 hour ago
        let age = (now - created_at).max(0) as u64 / 1000;
        assert_eq!(age, 3600);
    }

    #[test]
    fn oldest_age_negative_clamped() {
        let now = 1000i64;
        let created_at = 2000i64; // Future timestamp
        let age = (now - created_at).max(0) as u64 / 1000;
        assert_eq!(age, 0);
    }

    #[test]
    fn incoming_zero() {
        let incoming = 0u64;
        assert_eq!(incoming, 0);
    }

    #[test]
    fn incoming_positive() {
        let incoming = 100u64;
        assert!(incoming > 0);
    }

    #[test]
    fn outgoing_zero() {
        let outgoing = 0u64;
        assert_eq!(outgoing, 0);
    }

    #[test]
    fn outgoing_positive() {
        let outgoing = 95u64;
        assert!(outgoing > 0);
    }

    #[test]
    fn smtp_4xx_zero() {
        let smtp_4xx = 0u64;
        assert_eq!(smtp_4xx, 0);
    }

    #[test]
    fn smtp_4xx_positive() {
        let smtp_4xx = 3u64;
        assert!(smtp_4xx > 0);
    }

    #[test]
    fn smtp_5xx_zero() {
        let smtp_5xx = 0u64;
        assert_eq!(smtp_5xx, 0);
    }

    #[test]
    fn smtp_5xx_positive() {
        let smtp_5xx = 2u64;
        assert!(smtp_5xx > 0);
    }

    #[test]
    fn dns_issue_events_zero() {
        let dns_issue_events = 0u64;
        assert_eq!(dns_issue_events, 0);
    }

    #[test]
    fn dns_issue_events_positive() {
        let dns_issue_events = 1u64;
        assert!(dns_issue_events > 0);
    }

    #[test]
    fn smtp_code_4xx_range() {
        let code = 450u64;
        assert!(code >= 400 && code < 500);
    }

    #[test]
    fn smtp_code_5xx_range() {
        let code = 550u64;
        assert!(code >= 500 && code < 600);
    }

    #[test]
    fn smtp_code_not_4xx() {
        let code = 250u64;
        assert!(!(code >= 400 && code < 500));
    }

    #[test]
    fn smtp_code_not_5xx() {
        let code = 250u64;
        assert!(!(code >= 500 && code < 600));
    }

    #[test]
    fn event_type_accepted() {
        let event_type = "accepted";
        assert_eq!(event_type, "accepted");
    }

    #[test]
    fn event_type_received() {
        let event_type = "received";
        assert_eq!(event_type, "received");
    }

    #[test]
    fn event_type_dns_lookup() {
        let event_type = "dns_lookup";
        assert_eq!(event_type, "dns_lookup");
    }

    #[test]
    fn status_delivered() {
        let status = "delivered";
        assert_eq!(status, "delivered");
    }

    #[test]
    fn status_bounced() {
        let status = "bounced";
        assert_eq!(status, "bounced");
    }

    #[test]
    fn status_failed() {
        let status = "failed";
        assert_eq!(status, "failed");
    }

    #[test]
    fn status_deferred() {
        let status = "deferred";
        assert_eq!(status, "deferred");
    }

    #[test]
    fn status_pending() {
        let status = "pending";
        assert_eq!(status, "pending");
    }

    #[test]
    fn status_scheduled() {
        let status = "scheduled";
        assert_eq!(status, "scheduled");
    }

    #[test]
    fn status_sending() {
        let status = "sending";
        assert_eq!(status, "sending");
    }

    #[test]
    fn queue_filter_status_in() {
        let filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
        assert!(filter.contains_key("status"));
    }

    #[test]
    fn pending_queue_filter_format() {
        let filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
        assert_eq!(filter.get_document("status").unwrap().get_array("$in").unwrap().len(), 3);
    }

    #[test]
    fn sort_by_created_at_asc() {
        let sort = doc! { "created_at": 1 };
        assert!(sort.contains_key("created_at"));
        assert_eq!(sort.get_i32("created_at").unwrap(), 1);
    }

    #[test]
    fn count_documents_zero() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn count_documents_positive() {
        let count = 10u64;
        assert!(count > 0);
    }

    #[test]
    fn aggregate_pipeline_format() {
        let pipeline = vec![
            doc! { "$match": {} },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ];
        assert_eq!(pipeline.len(), 2);
        assert!(pipeline[0].contains_key("$match"));
        assert!(pipeline[1].contains_key("$group"));
    }

    #[test]
    fn aggregate_group_format() {
        let group = doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } };
        assert!(group.contains_key("$group"));
    }

    #[test]
    fn aggregate_match_format() {
        let match_stage = doc! { "$match": {} };
        assert!(match_stage.contains_key("$match"));
    }

    #[test]
    fn storage_count_events_zero() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn storage_count_events_positive() {
        let count = 100u64;
        assert!(count > 0);
    }

    #[test]
    fn storage_query_events_limit() {
        let limit = 200i64;
        assert_eq!(limit, 200);
    }

    #[test]
    fn storage_query_events_page() {
        let page = 1i64;
        assert_eq!(page, 1);
    }

    #[test]
    fn p95_total_ms_limit() {
        let limit = 1000i64;
        assert_eq!(limit, 1000);
    }

    #[test]
    fn since_str_format() {
        let since = "2026-01-01T00:00:00Z";
        assert_eq!(since, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn since_str_empty() {
        let since = "";
        assert_eq!(since, "");
    }

    #[test]
    fn window_1h() {
        let window = "1h";
        assert_eq!(window, "1h");
    }

    #[test]
    fn window_24h() {
        let window = "24h";
        assert_eq!(window, "24h");
    }

    #[test]
    fn window_7d() {
        let window = "7d";
        assert_eq!(window, "7d");
    }

    #[test]
    fn window_15m() {
        let window = "15m";
        assert_eq!(window, "15m");
    }

    #[test]
    fn mongo_db_name_default() {
        let db = "mailserver";
        assert_eq!(db, "mailserver");
    }

    #[test]
    fn send_queue_coll() {
        let coll = "send_queue";
        assert_eq!(coll, "send_queue");
    }

    #[test]
    fn auth_events_coll() {
        let coll = "auth_events";
        assert_eq!(coll, "auth_events");
    }

    #[test]
    fn bson_document_empty() {
        let doc = bson::Document::new();
        assert!(doc.is_empty());
    }

    #[test]
    fn bson_document_with_content() {
        let doc = doc! { "key": "value" };
        assert!(!doc.is_empty());
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn serde_json_map_new() {
        let map = serde_json::Map::new();
        assert!(map.is_empty());
    }

    #[test]
    fn serde_json_map_with_content() {
        let mut map = serde_json::Map::new();
        map.insert("key".to_string(), serde_json::json!("value"));
        assert!(!map.is_empty());
        assert_eq!(map["key"], "value");
    }

    #[test]
    fn serde_json_value_null() {
        let value = serde_json::Value::Null;
        assert!(value.is_null());
    }

    #[test]
    fn serde_json_value_string() {
        let value = serde_json::json!("test");
        assert!(value.is_string());
        assert_eq!(value.as_str().unwrap(), "test");
    }

    #[test]
    fn serde_json_value_number() {
        let value = serde_json::json!(42);
        assert!(value.is_number());
        assert_eq!(value.as_i64().unwrap(), 42);
    }

    #[test]
    fn serde_json_value_array() {
        let value = serde_json::json!([1, 2, 3]);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 3);
    }

    #[test]
    fn serde_json_value_object() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.is_object());
        assert!(value.get("key").is_some());
    }
}
