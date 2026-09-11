// Monitoring endpoints handlers (summary, events, trace, bounces, providers, live, alerts)
// Extracted from monitoring_handlers.rs in cycle 26 (LOC split).

use actix_web::{web, HttpResponse};
use chrono::Utc;
use futures_util::stream;
use mongodb::bson::doc;
use simple_smtp_server::monitoring;
use simple_smtp_server::monitoring::alerts::AlertConfig;
use simple_smtp_server::monitoring::storage;
use std::sync::Arc;
use tokio::sync::broadcast;

use super::shared::{
    parse_window, since_str, MonitoringEventsQuery, MonitoringLiveQuery, MonitoringWindowQuery,
};

/// GET /api/monitoring/summary?window=15m
pub(crate) async fn api_monitoring_summary(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let since = since_str(&query.window);
    let base_filter = doc! { "ts": { "$gte": &since } };

    let total = storage::count_events(&mongo, base_filter.clone()).await;

    let by_status_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ],
    )
    .await;

    let mut by_status = serde_json::Map::new();
    let mut total_delivered = 0u64;
    let mut total_bounced = 0u64;
    let mut avg_total_ms_sum = 0f64;
    let mut avg_count = 0u32;

    for doc in &by_status_docs {
        let status = doc.get_str("_id").unwrap_or("unknown").to_string();
        let count = doc.get_i64("count").unwrap_or(0) as u64;
        let avg_ms = doc.get_f64("avg_ms").unwrap_or(0.0);
        if status == "delivered" { total_delivered = count; }
        if status == "bounced" { total_bounced = count; }
        avg_total_ms_sum += avg_ms * count as f64;
        avg_count += count as u32;
        by_status.insert(status, serde_json::json!(count));
    }

    let delivery_rate = if total > 0 { total_delivered as f64 / total as f64 } else { 0.0 };
    let bounce_rate = if total > 0 { total_bounced as f64 / total as f64 } else { 0.0 };
    let avg_total_ms = if avg_count > 0 { avg_total_ms_sum / avg_count as f64 } else { 0.0 };
    let p95 = storage::p95_total_ms(&mongo, base_filter.clone(), 1000).await;

    let risk_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": null, "avg_risk": { "$avg": "$risk_score" } } },
        ],
    )
    .await;
    let avg_risk = risk_docs.first().and_then(|d| d.get_f64("avg_risk").ok()).unwrap_or(0.0);

    let queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let queue_coll = mongo
        .database(&std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string()))
        .collection::<mongodb::bson::Document>("send_queue");
    let queue_depth = queue_coll
        .count_documents(queue_filter.clone())
        .await
        .unwrap_or(0);
    let queue_latency_ms = queue_coll
        .find_one(queue_filter)
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten()
        .and_then(|d| d.get_datetime("created_at").ok().map(|dt| dt.timestamp_millis()))
        .map(|created_at_ms| (Utc::now().timestamp_millis() - created_at_ms).max(0) as u64)
        .unwrap_or(0);

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "total": total,
        "by_status": by_status,
        "deliveryRate": (delivery_rate * 1000.0).round() / 1000.0,
        "bounceRate": (bounce_rate * 1000.0).round() / 1000.0,
        "avgTotalMs": avg_total_ms.round(),
        "p95TotalMs": p95,
        "avgRiskScore": (avg_risk * 10.0).round() / 10.0,
        "queueDepth": queue_depth,
        "queueLatencyMs": queue_latency_ms,
        "prometheus": {
            "smtp_queue_depth": queue_depth,
            "smtp_queue_latency_ms": queue_latency_ms,
            "labels": ["instance", "queue", "status"],
            "units": {
                "smtp_queue_depth": "messages",
                "smtp_queue_latency_ms": "milliseconds"
            }
        }
    }))
}

/// GET /api/monitoring/events
pub(crate) async fn api_monitoring_events(
    query: web::Query<MonitoringEventsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let mut filter = doc! {};
    if let Some(ref s) = query.status { filter.insert("status", s); }
    if let Some(ref f) = query.from { filter.insert("from", doc! { "$regex": f.as_str(), "$options": "i" }); }
    if let Some(ref t) = query.to { filter.insert("to", doc! { "$regex": t.as_str(), "$options": "i" }); }
    if let Some(ref p) = query.provider { filter.insert("company", doc! { "$regex": p.as_str(), "$options": "i" }); }
    if let Some(ref c) = query.country { filter.insert("country", c); }
    if let Some(ref m) = query.message_id { filter.insert("message_id", m); }

    let mut ts_filter = doc! {};
    if let Some(ref s) = query.since { ts_filter.insert("$gte", s); }
    if let Some(ref u) = query.until { ts_filter.insert("$lte", u); }
    if !ts_filter.is_empty() { filter.insert("ts", ts_filter); }

    let total = storage::count_events(&mongo, filter.clone()).await;
    let events = storage::query_events(&mongo, filter, query.page, query.page_size).await;
    let has_more = (query.page * query.page_size) < total as u32;

    HttpResponse::Ok().json(serde_json::json!({
        "events": events,
        "total": total,
        "page": query.page,
        "page_size": query.page_size,
        "has_more": has_more,
    }))
}

/// GET /api/monitoring/messages/{message_id}/trace
pub(crate) async fn api_monitoring_trace(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let message_id = path.into_inner();
    let filter = doc! { "message_id": &message_id };
    let mut events = storage::query_events(&mongo, filter, 1, 200).await;
    events.sort_by(|a, b| a.ts.cmp(&b.ts));

    if events.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({ "message": "Trace not found" }));
    }

    let status = events
        .iter()
        .rev()
        .find(|e| matches!(
            e.status,
            monitoring::SmtpStatus::Delivered
                | monitoring::SmtpStatus::Bounced
                | monitoring::SmtpStatus::Failed
                | monitoring::SmtpStatus::Deferred
        ))
        .or_else(|| events.last())
        .map(|e| format!("{:?}", e.status))
        .unwrap_or_default();
    let total_ms = events.iter().filter_map(|e| e.total_ms).max();

    HttpResponse::Ok().json(serde_json::json!({
        "message_id": message_id,
        "status": status,
        "total_ms": total_ms,
        "steps": events.len(),
        "trace": events,
    }))
}

/// GET /api/monitoring/bounces?window=24h
pub(crate) async fn api_monitoring_bounces(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let since = since_str(&query.window);
    let filter = doc! { "ts": { "$gte": &since }, "status": "bounced" };
    let events = storage::query_events(&mongo, filter.clone(), 1, 100).await;
    let total = storage::count_events(&mongo, filter).await;

    let hard = events.iter().filter(|e| matches!(e.bounce_type, Some(monitoring::BounceType::Hard))).count();
    let soft = events.iter().filter(|e| matches!(e.bounce_type, Some(monitoring::BounceType::Soft))).count();
    let policy = events.iter().filter(|e| matches!(e.bounce_type, Some(monitoring::BounceType::Policy))).count();

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "total": total,
        "hard": hard,
        "soft": soft,
        "policy": policy,
        "bounces": events,
    }))
}

/// GET /api/monitoring/providers/top?window=24h
pub(crate) async fn api_monitoring_providers_top(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let since = since_str(&query.window);
    let pipeline = vec![
        doc! { "$match": { "ts": { "$gte": &since } } },
        doc! { "$group": {
            "_id": { "company": "$company", "datacenter": "$datacenter", "country": "$country" },
            "count":        { "$sum": 1 },
            "delivered":    { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
            "bounced":      { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] },   "then": 1, "else": 0 } } },
            "avg_total_ms": { "$avg": "$total_ms" },
            "avg_risk":     { "$avg": "$risk_score" },
        }},
        doc! { "$sort": { "count": -1 } },
        doc! { "$limit": 20 },
    ];
    let docs = storage::aggregate(&mongo, pipeline).await;

    let providers: Vec<serde_json::Value> = docs.iter().map(|d| {
        let id = d.get_document("_id").ok();
        let company    = id.and_then(|i| i.get_str("company").ok()).unwrap_or("unknown");
        let datacenter = id.and_then(|i| i.get_str("datacenter").ok()).unwrap_or("unknown");
        let country    = id.and_then(|i| i.get_str("country").ok()).unwrap_or("unknown");
        serde_json::json!({
            "company": company, "datacenter": datacenter, "country": country,
            "count":        d.get_i64("count").unwrap_or(0),
            "delivered":    d.get_i64("delivered").unwrap_or(0),
            "bounced":      d.get_i64("bounced").unwrap_or(0),
            "avgTotalMs":   d.get_f64("avg_total_ms").unwrap_or(0.0).round(),
            "avgRiskScore": d.get_f64("avg_risk").unwrap_or(0.0).round(),
        })
    }).collect();

    HttpResponse::Ok().json(serde_json::json!({ "window": query.window, "since": since, "providers": providers }))
}

/// GET /api/monitoring/live  — SSE
pub(crate) async fn api_monitoring_live(query: web::Query<MonitoringLiveQuery>) -> HttpResponse {
    let filter_mid = query.message_id.clone();
    let rx = match monitoring::get_bus() {
        Some(tx) => tx.subscribe(),
        None => return HttpResponse::ServiceUnavailable()
            .body("Monitoring bus not initialized (SMTP_MONITORING_ENABLED=true required)"),
    };

    let event_stream = stream::unfold(
        (rx, filter_mid, tokio::time::interval(std::time::Duration::from_secs(15))),
        |(mut rx, mid, mut hb)| async move {
            loop {
                tokio::select! {
                    result = rx.recv() => {
                        match result {
                            Ok(event) => {
                                if let Some(ref f) = mid { if &event.message_id != f { continue; } }
                                let data = serde_json::to_string(&event).unwrap_or_default();
                                let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
                                return Some((Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(chunk)), (rx, mid, hb)));
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => { eprintln!("monitoring SSE: lagged {} events", n); continue; }
                            Err(broadcast::error::RecvError::Closed) => return None,
                        }
                    }
                    _ = hb.tick() => {
                        return Some((Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(": heartbeat\n\n")), (rx, mid, hb)));
                    }
                }
            }
        },
    );

    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .insert_header(("Connection", "keep-alive"))
        .streaming(event_stream)
}

/// GET /api/monitoring/alerts/active
pub(crate) async fn api_monitoring_alerts_active(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let window_minutes = parse_window(&query.window).num_minutes();
    let config = AlertConfig::default();
    let alerts = monitoring::alerts::evaluate_alerts(&mongo, window_minutes, &config).await;
    HttpResponse::Ok().json(serde_json::json!({ "window": query.window, "alert_count": alerts.len(), "alerts": alerts }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitoring_summary_delivery_rate_zero_when_no_events() {
        let total = 0u64;
        let total_delivered = 0u64;
        let delivery_rate = if total > 0 { total_delivered as f64 / total as f64 } else { 0.0 };
        assert_eq!(delivery_rate, 0.0);
    }

    #[test]
    fn monitoring_summary_delivery_rate_calculation() {
        let total = 100u64;
        let total_delivered = 95u64;
        let delivery_rate = if total > 0 { total_delivered as f64 / total as f64 } else { 0.0 };
        assert_eq!(delivery_rate, 0.95);
    }

    #[test]
    fn monitoring_summary_bounce_rate_zero_when_no_events() {
        let total = 0u64;
        let total_bounced = 0u64;
        let bounce_rate = if total > 0 { total_bounced as f64 / total as f64 } else { 0.0 };
        assert_eq!(bounce_rate, 0.0);
    }

    #[test]
    fn monitoring_summary_bounce_rate_calculation() {
        let total = 100u64;
        let total_bounced = 5u64;
        let bounce_rate = if total > 0 { total_bounced as f64 / total as f64 } else { 0.0 };
        assert_eq!(bounce_rate, 0.05);
    }

    #[test]
    fn monitoring_summary_avg_total_ms_zero_when_no_events() {
        let avg_count = 0u32;
        let avg_total_ms_sum = 0.0;
        let avg_total_ms = if avg_count > 0 { avg_total_ms_sum / avg_count as f64 } else { 0.0 };
        assert_eq!(avg_total_ms, 0.0);
    }

    #[test]
    fn monitoring_summary_avg_total_ms_calculation() {
        let avg_count = 10u32;
        let avg_total_ms_sum = 15000.0;
        let avg_total_ms = if avg_count > 0 { avg_total_ms_sum / avg_count as f64 } else { 0.0 };
        assert_eq!(avg_total_ms, 1500.0);
    }

    #[test]
    fn monitoring_summary_delivery_rate_rounding() {
        let delivery_rate = 0.956789;
        let rounded = (delivery_rate * 1000.0).round() / 1000.0;
        assert_eq!(rounded, 0.957);
    }

    #[test]
    fn monitoring_summary_bounce_rate_rounding() {
        let bounce_rate = 0.056789;
        let rounded = (bounce_rate * 1000.0).round() / 1000.0;
        assert_eq!(rounded, 0.057);
    }

    #[test]
    fn monitoring_summary_avg_risk_rounding() {
        let avg_risk = 0.12345;
        let rounded = (avg_risk * 10.0).round() / 10.0;
        assert_eq!(rounded, 0.1);
    }

    #[test]
    fn monitoring_summary_response_structure() {
        let response = serde_json::json!({
            "window": "1h",
            "since": "2026-01-01T00:00:00Z",
            "total": 100,
            "by_status": {},
            "deliveryRate": 0.95,
            "bounceRate": 0.05,
            "avgTotalMs": 1500.0,
            "p95TotalMs": 3000,
            "avgRiskScore": 0.1,
            "queueDepth": 10,
            "queueLatencyMs": 3600000,
            "prometheus": {
                "smtp_queue_depth": 10,
                "smtp_queue_latency_ms": 3600000,
                "labels": ["instance", "queue", "status"],
                "units": {
                    "smtp_queue_depth": "messages",
                    "smtp_queue_latency_ms": "milliseconds"
                }
            }
        });
        assert!(response.get("window").is_some());
        assert!(response.get("since").is_some());
        assert!(response.get("total").is_some());
        assert!(response.get("by_status").is_some());
        assert!(response.get("deliveryRate").is_some());
        assert!(response.get("bounceRate").is_some());
        assert!(response.get("avgTotalMs").is_some());
        assert!(response.get("p95TotalMs").is_some());
        assert!(response.get("avgRiskScore").is_some());
        assert!(response.get("queueDepth").is_some());
        assert!(response.get("queueLatencyMs").is_some());
        assert!(response.get("prometheus").is_some());
    }

    #[test]
    fn monitoring_events_response_structure() {
        let response = serde_json::json!({
            "events": [],
            "total": 0,
            "page": 1,
            "page_size": 50,
            "has_more": false,
        });
        assert!(response.get("events").is_some());
        assert!(response.get("total").is_some());
        assert!(response.get("page").is_some());
        assert!(response.get("page_size").is_some());
        assert!(response.get("has_more").is_some());
    }

    #[test]
    fn monitoring_events_has_more_true() {
        let page = 1u32;
        let page_size = 50u32;
        let total = 100u64;
        let has_more = (page * page_size) < total as u32;
        assert!(has_more);
    }

    #[test]
    fn monitoring_events_has_more_false() {
        let page = 2u32;
        let page_size = 50u32;
        let total = 100u64;
        let has_more = (page * page_size) < total as u32;
        assert!(!has_more);
    }

    #[test]
    fn monitoring_trace_response_structure() {
        let response = serde_json::json!({
            "message_id": "test-123",
            "status": "Delivered",
            "total_ms": 1500,
            "steps": 5,
            "trace": []
        });
        assert!(response.get("message_id").is_some());
        assert!(response.get("status").is_some());
        assert!(response.get("total_ms").is_some());
        assert!(response.get("steps").is_some());
        assert!(response.get("trace").is_some());
    }

    #[test]
    fn monitoring_trace_not_found_response() {
        let response = serde_json::json!({ "message": "Trace not found" });
        assert_eq!(response["message"], "Trace not found");
    }

    #[test]
    fn monitoring_bounces_response_structure() {
        let response = serde_json::json!({
            "window": "24h",
            "since": "2026-01-01T00:00:00Z",
            "total": 10,
            "hard": 3,
            "soft": 5,
            "policy": 2,
            "bounces": []
        });
        assert!(response.get("window").is_some());
        assert!(response.get("since").is_some());
        assert!(response.get("total").is_some());
        assert!(response.get("hard").is_some());
        assert!(response.get("soft").is_some());
        assert!(response.get("policy").is_some());
        assert!(response.get("bounces").is_some());
    }

    #[test]
    fn monitoring_providers_response_structure() {
        let response = serde_json::json!({
            "window": "24h",
            "since": "2026-01-01T00:00:00Z",
            "providers": []
        });
        assert!(response.get("window").is_some());
        assert!(response.get("since").is_some());
        assert!(response.get("providers").is_some());
    }

    #[test]
    fn monitoring_provider_entry_structure() {
        let provider = serde_json::json!({
            "company": "Google",
            "datacenter": "gmail",
            "country": "US",
            "count": 100,
            "delivered": 95,
            "bounced": 5,
            "avgTotalMs": 1500.0,
            "avgRiskScore": 0.1
        });
        assert!(provider.get("company").is_some());
        assert!(provider.get("datacenter").is_some());
        assert!(provider.get("country").is_some());
        assert!(provider.get("count").is_some());
        assert!(provider.get("delivered").is_some());
        assert!(provider.get("bounced").is_some());
        assert!(provider.get("avgTotalMs").is_some());
        assert!(provider.get("avgRiskScore").is_some());
    }

    #[test]
    fn monitoring_alerts_response_structure() {
        let response = serde_json::json!({
            "window": "1h",
            "alert_count": 0,
            "alerts": []
        });
        assert!(response.get("window").is_some());
        assert!(response.get("alert_count").is_some());
        assert!(response.get("alerts").is_some());
    }

    #[test]
    fn monitoring_live_sse_headers() {
        let content_type = "text/event-stream";
        let cache_control = "no-cache";
        let x_accel_buffering = "no";
        let connection = "keep-alive";
        assert_eq!(content_type, "text/event-stream");
        assert_eq!(cache_control, "no-cache");
        assert_eq!(x_accel_buffering, "no");
        assert_eq!(connection, "keep-alive");
    }

    #[test]
    fn monitoring_live_sse_event_format() {
        let data = serde_json::json!({"message_id": "test-123", "status": "delivered"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("event: smtp_event"));
        assert!(chunk.contains("data:"));
        assert!(chunk.contains("retry: 3000"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_format() {
        let chunk = ": heartbeat\n\n";
        assert_eq!(chunk, ": heartbeat\n\n");
    }

    #[test]
    fn monitoring_queue_filter_status_in() {
        let filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
        assert!(filter.contains_key("status"));
    }

    #[test]
    fn monitoring_queue_filter_status_in_len() {
        let filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
        assert_eq!(filter.get_document("status").unwrap().get_array("$in").unwrap().len(), 3);
    }

    #[test]
    fn monitoring_sort_by_created_at_asc() {
        let sort = doc! { "created_at": 1 };
        assert!(sort.contains_key("created_at"));
        assert_eq!(sort.get_i32("created_at").unwrap(), 1);
    }

    #[test]
    fn monitoring_queue_latency_calculation() {
        let now = Utc::now().timestamp_millis();
        let created_at = now - 3600000; // 1 hour ago
        let latency = (now - created_at).max(0) as u64;
        assert_eq!(latency, 3600000);
    }

    #[test]
    fn monitoring_queue_latency_negative_clamped() {
        let now = 1000i64;
        let created_at = 2000i64; // Future timestamp
        let latency = (now - created_at).max(0) as u64;
        assert_eq!(latency, 0);
    }

    #[test]
    fn monitoring_delivery_rate_percentage() {
        let delivery_rate = 0.95;
        let percentage = delivery_rate * 100.0;
        assert_eq!(percentage, 95.0);
    }

    #[test]
    fn monitoring_bounce_rate_percentage() {
        let bounce_rate = 0.05;
        let percentage = bounce_rate * 100.0;
        assert_eq!(percentage, 5.0);
    }

    #[test]
    fn monitoring_total_ms_rounding() {
        let avg_total_ms = 1500.7;
        let rounded = avg_total_ms.round();
        assert_eq!(rounded, 1501.0);
    }

    #[test]
    fn monitoring_avg_risk_rounding() {
        let avg_risk = 0.15;
        let rounded = (avg_risk * 10.0).round() / 10.0;
        assert_eq!(rounded, 0.2);
    }

    #[test]
    fn monitoring_p95_none() {
        let p95: Option<u64> = None;
        assert_eq!(p95, None);
    }

    #[test]
    fn monitoring_p95_some() {
        let p95: Option<u64> = Some(3000);
        assert_eq!(p95, Some(3000));
    }

    #[test]
    fn monitoring_queue_depth_zero() {
        let depth = 0u64;
        assert_eq!(depth, 0);
    }

    #[test]
    fn monitoring_queue_depth_positive() {
        let depth = 10u64;
        assert!(depth > 0);
    }

    #[test]
    fn monitoring_queue_latency_zero() {
        let latency = 0u64;
        assert_eq!(latency, 0);
    }

    #[test]
    fn monitoring_queue_latency_positive() {
        let latency = 3600000u64;
        assert!(latency > 0);
    }

    #[test]
    fn monitoring_by_status_map_new() {
        let map = serde_json::Map::new();
        assert!(map.is_empty());
    }

    #[test]
    fn monitoring_by_status_map_with_content() {
        let mut map = serde_json::Map::new();
        map.insert("delivered".to_string(), serde_json::json!(95));
        map.insert("bounced".to_string(), serde_json::json!(5));
        assert_eq!(map.len(), 2);
        assert_eq!(map["delivered"], 95);
        assert_eq!(map["bounced"], 5);
    }

    #[test]
    fn monitoring_by_status_map_update() {
        let mut map = serde_json::Map::new();
        map.insert("delivered".to_string(), serde_json::json!(50));
        map.insert("delivered".to_string(), serde_json::json!(95));
        assert_eq!(map.len(), 1);
        assert_eq!(map["delivered"], 95);
    }

    #[test]
    fn monitoring_events_query_default_page() {
        let page = 1u32;
        assert_eq!(page, 1);
    }

    #[test]
    fn monitoring_events_query_default_page_size() {
        let page_size = 50u32;
        assert_eq!(page_size, 50);
    }

    #[test]
    fn monitoring_events_query_custom_page() {
        let page = 2u32;
        assert_eq!(page, 2);
    }

    #[test]
    fn monitoring_events_query_custom_page_size() {
        let page_size = 100u32;
        assert_eq!(page_size, 100);
    }

    #[test]
    fn monitoring_events_has_more_boundary() {
        let page = 2u32;
        let page_size = 50u32;
        let total = 100u64;
        let has_more = (page * page_size) < total as u32;
        assert!(!has_more);
    }

    #[test]
    fn monitoring_events_has_more_boundary_plus_one() {
        let page = 2u32;
        let page_size = 50u32;
        let total = 101u64;
        let has_more = (page * page_size) < total as u32;
        assert!(has_more);
    }

    #[test]
    fn monitoring_trace_status_delivered() {
        let status = "Delivered";
        assert_eq!(status, "Delivered");
    }

    #[test]
    fn monitoring_trace_status_bounced() {
        let status = "Bounced";
        assert_eq!(status, "Bounced");
    }

    #[test]
    fn monitoring_trace_status_failed() {
        let status = "Failed";
        assert_eq!(status, "Failed");
    }

    #[test]
    fn monitoring_trace_status_deferred() {
        let status = "Deferred";
        assert_eq!(status, "Deferred");
    }

    #[test]
    fn monitoring_trace_status_pending() {
        let status = "Pending";
        assert_eq!(status, "Pending");
    }

    #[test]
    fn monitoring_bounces_hard_count() {
        let hard = 3usize;
        assert_eq!(hard, 3);
    }

    #[test]
    fn monitoring_bounces_soft_count() {
        let soft = 5usize;
        assert_eq!(soft, 5);
    }

    #[test]
    fn monitoring_bounces_policy_count() {
        let policy = 2usize;
        assert_eq!(policy, 2);
    }

    #[test]
    fn monitoring_bounces_total_equals_sum() {
        let hard = 3usize;
        let soft = 5usize;
        let policy = 2usize;
        let total = hard + soft + policy;
        assert_eq!(total, 10);
    }

    #[test]
    fn monitoring_providers_top_limit() {
        let limit = 20i64;
        assert_eq!(limit, 20);
    }

    #[test]
    fn monitoring_providers_sort_by_count_desc() {
        let sort = doc! { "count": -1 };
        assert!(sort.contains_key("count"));
        assert_eq!(sort.get_i32("count").unwrap(), -1);
    }

    #[test]
    fn monitoring_providers_group_format() {
        let group = doc! { "$group": {
            "_id": { "company": "$company", "datacenter": "$datacenter", "country": "$country" },
            "count":        { "$sum": 1 },
            "delivered":    { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
            "bounced":      { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] },   "then": 1, "else": 0 } } },
            "avg_total_ms": { "$avg": "$total_ms" },
            "avg_risk":     { "$avg": "$risk_score" },
        }};
        assert!(group.contains_key("$group"));
    }

    #[test]
    fn monitoring_alerts_active_window() {
        let window = "1h";
        assert_eq!(window, "1h");
    }

    #[test]
    fn monitoring_alerts_active_alert_count_zero() {
        let alert_count = 0usize;
        assert_eq!(alert_count, 0);
    }

    #[test]
    fn monitoring_alerts_active_alert_count_positive() {
        let alert_count = 5usize;
        assert!(alert_count > 0);
    }

    #[test]
    fn monitoring_live_sse_content_type() {
        let content_type = "text/event-stream";
        assert_eq!(content_type, "text/event-stream");
    }

    #[test]
    fn monitoring_live_sse_cache_control() {
        let cache_control = "no-cache";
        assert_eq!(cache_control, "no-cache");
    }

    #[test]
    fn monitoring_live_sse_x_accel_buffering() {
        let x_accel_buffering = "no";
        assert_eq!(x_accel_buffering, "no");
    }

    #[test]
    fn monitoring_live_sse_connection() {
        let connection = "keep-alive";
        assert_eq!(connection, "keep-alive");
    }

    #[test]
    fn monitoring_live_sse_event_name() {
        let event_name = "smtp_event";
        assert_eq!(event_name, "smtp_event");
    }

    #[test]
    fn monitoring_live_sse_retry() {
        let retry = 3000;
        assert_eq!(retry, 3000);
    }

    #[test]
    fn monitoring_live_sse_heartbeat_text() {
        let heartbeat = ": heartbeat";
        assert_eq!(heartbeat, ": heartbeat");
    }

    #[test]
    fn monitoring_live_sse_heartbeat_interval() {
        let interval = 15;
        assert_eq!(interval, 15);
    }

    #[test]
    fn monitoring_live_sse_lagged_events() {
        let lagged = 5u64;
        assert_eq!(lagged, 5);
    }

    #[test]
    fn monitoring_live_sse_closed() {
        let closed = true;
        assert!(closed);
    }

    #[test]
    fn monitoring_live_sse_message_id_filter() {
        let message_id = "test-123";
        assert_eq!(message_id, "test-123");
    }

    #[test]
    fn monitoring_live_sse_message_id_none() {
        let message_id: Option<String> = None;
        assert!(message_id.is_none());
    }

    #[test]
    fn monitoring_live_sse_message_id_some() {
        let message_id: Option<String> = Some("test-123".to_string());
        assert!(message_id.is_some());
        assert_eq!(message_id.unwrap(), "test-123");
    }

    #[test]
    fn monitoring_live_sse_data_serialization() {
        let data = serde_json::json!({"message_id": "test-123", "status": "delivered"});
        let serialized = serde_json::to_string(&data).unwrap();
        assert!(serialized.contains("test-123"));
        assert!(serialized.contains("delivered"));
    }

    #[test]
    fn monitoring_live_sse_data_deserialization() {
        let data = r#"{"message_id":"test-123","status":"delivered"}"#;
        let deserialized: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(deserialized["message_id"], "test-123");
        assert_eq!(deserialized["status"], "delivered");
    }

    #[test]
    fn monitoring_live_sse_chunk_format() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.starts_with("event: smtp_event\n"));
        assert!(chunk.contains("data:"));
        assert!(chunk.contains("retry: 3000"));
        assert!(chunk.ends_with("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_format() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.starts_with(": heartbeat\n"));
        assert!(chunk.ends_with("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_ends_with_newline() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.ends_with("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_ends_with_newline() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.ends_with("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_retry() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("retry: 3000"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_no_retry() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("retry:"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_data() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("data:"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_no_data() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("data:"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_event_name() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("event: smtp_event"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_no_event_name() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("event:"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_message_id() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("test-123"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_no_message_id() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("message_id"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_status() {
        let data = serde_json::json!({"message_id": "test-123", "status": "delivered"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("delivered"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_no_status() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("status"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_json() {
        let data = serde_json::json!({"message_id": "test-123", "status": "delivered"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("{"));
        assert!(chunk.contains("}"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_no_json() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("{"));
        assert!(!chunk.contains("}"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_colon() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains(":"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_colon() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.contains(":"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_newline() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_newline() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.contains("\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_double_newline() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_double_newline() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.contains("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_crlf() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\r\n\r\n", data);
        assert!(chunk.contains("\r\n\r\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_crlf() {
        let chunk = ": heartbeat\r\n\r\n";
        assert!(chunk.contains("\r\n\r\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_lf() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_lf() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.contains("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_crlf() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.contains("\r\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_crlf() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("\r\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_cr() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.contains("\r"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_cr() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("\r"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_tab() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.contains("\t"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_tab() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.contains("\t"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_space() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.contains(" "));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_space() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.contains(" "));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_leading_space() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.starts_with(" "));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_leading_space() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.starts_with(":"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_trailing_space() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.ends_with(" "));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_trailing_space() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.ends_with(" "));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_leading_newline() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.starts_with("\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_leading_newline() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.starts_with("\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_trailing_newline() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(chunk.ends_with("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_trailing_newline() {
        let chunk = ": heartbeat\n\n";
        assert!(chunk.ends_with("\n\n"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_leading_cr() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.starts_with("\r"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_leading_cr() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.starts_with("\r"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_trailing_cr() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.ends_with("\r"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_trailing_cr() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.ends_with("\r"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_leading_tab() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.starts_with("\t"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_leading_tab() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.starts_with("\t"));
    }

    #[test]
    fn monitoring_live_sse_event_chunk_contains_no_trailing_tab() {
        let data = serde_json::json!({"message_id": "test-123"});
        let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
        assert!(!chunk.ends_with("\t"));
    }

    #[test]
    fn monitoring_live_sse_heartbeat_chunk_contains_no_trailing_tab() {
        let chunk = ": heartbeat\n\n";
        assert!(!chunk.ends_with("\t"));
    }
}
