// Monitoring endpoints handlers (summary, events, trace, bounces, providers, live, alerts)
// Extracted from monitoring_handlers.rs in cycle 26 (LOC split).

use actix_web::{web, HttpResponse};
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
