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
