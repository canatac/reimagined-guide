// event_handlers.rs — split from main.rs (Sprint 9)
#![allow(unused_imports)]
use super::*;

async fn persist_event(mongo: &mongodb::Client, event: &MailEvent) {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("mail_events");
    if let Ok(doc) = bson::to_document(event) {
        if let Err(e) = coll.insert_one(doc).await {
            eprintln!("persist_event error: {}", e);
        }
    }
}

async fn emit_event(bus: &EventBus, mongo: &mongodb::Client, event: MailEvent) {
    persist_event(mongo, &event).await;
    let _ = bus.send(event);
}

async fn api_events(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("mail_events");
    let filter = doc! { "user_id": &user_id };
    match coll
        .find(filter)
        .sort(doc! { "timestamp": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => match cursor.try_collect::<Vec<_>>().await {
            Ok(docs) => {
                let events: Vec<serde_json::Value> = docs
                    .into_iter()
                    .filter_map(|d| bson::from_document::<MailEvent>(d).ok())
                    .filter_map(|e| serde_json::to_value(&e).ok())
                    .collect();
                HttpResponse::Ok().json(serde_json::json!({ "events": events }))
            }
            Err(e) => HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() })),
        },
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

async fn api_events_stream(bus: web::Data<EventBus>, req: actix_web::HttpRequest) -> HttpResponse {
    let user_id = resolve_user_id(&req);
    let rx = bus.subscribe();
    let event_stream = stream::unfold((rx, user_id), |(mut rx, uid)| async move {
        loop {
            match rx.recv().await {
                Ok(event) if event.user_id == uid => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let chunk = format!("data: {}\n\n", data);
                    return Some((
                        Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(chunk)),
                        (rx, uid),
                    ));
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(event_stream)
}

// ===========================================================================
// SMTP Monitoring endpoints
// ===========================================================================

use simple_smtp_server::monitoring;
use simple_smtp_server::monitoring::alerts::AlertConfig;
use simple_smtp_server::monitoring::storage;
use simple_smtp_server::security;

// parse_window, since_str, env_bool, monitoring query types, dns_txt_lookup
// api_monitoring_*, SecurityAlertsQuery, api_security_*
// → moved to monitoring_handlers module



// ↑ monitoring/security handlers moved to monitoring_handlers module ↑



#[derive(Deserialize)]
struct DeliverabilityDiagnosticsQuery {
    #[serde(default = "default_window")]
    window: String,
    domain: Option<String>,
}

#[derive(Deserialize)]
struct DeliverabilityProcedureUpdateRequest {
    checklist: Option<Vec<DeliverabilityChecklistUpdate>>,
    reminder: Option<DeliverabilityReminderUpdate>,
}

#[derive(Deserialize)]
struct DeliverabilityChecklistUpdate {
    id: String,
    checked: bool,
    note: Option<String>,
}

#[derive(Deserialize)]
struct DeliverabilityReminderUpdate {
    enabled: bool,
    cadence_hours: u32,
}

/// GET /api/monitoring/summary?window=15m
// monitoring + security handlers → monitoring_handlers module


