// Security endpoints handlers (alerts, incidents, tenant status, rollback, live SSE)
// Extracted from monitoring_handlers.rs in cycle 26 (LOC split).

use actix_web::{web, HttpResponse};
use futures_util::stream;
use mongodb::bson::doc;
use simple_smtp_server::security;
use std::sync::Arc;

use super::shared::{SecurityAlertsQuery, SecurityIncidentsQuery};

pub(crate) async fn api_security_alerts_active(
    query: web::Query<SecurityAlertsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    use simple_smtp_server::security::audit;
    let mut alerts = audit::query_active_alerts(&mongo, 100).await;
    if let Some(ref sev) = query.severity {
        let sev_lc = sev.to_lowercase();
        alerts.retain(|a| format!("{:?}", a.severity).to_lowercase() == sev_lc);
    }
    if let Some(ref tid) = query.tenant_id {
        alerts.retain(|a| a.tenant_id.as_deref() == Some(tid.as_str()));
    }
    HttpResponse::Ok().json(serde_json::json!({ "window": query.window, "alert_count": alerts.len(), "alerts": alerts }))
}

pub(crate) async fn api_security_incidents(
    query: web::Query<SecurityIncidentsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    use simple_smtp_server::security::audit;
    let mut filter = doc! {};
    if let Some(ref tid) = query.tenant_id { filter.insert("tenant_id", tid.as_str()); }
    if let Some(ref sev) = query.severity  { filter.insert("severity",  sev.as_str()); }
    let alerts = audit::query_alerts(&mongo, filter, query.page, query.page_size).await;
    HttpResponse::Ok().json(serde_json::json!({ "page": query.page, "page_size": query.page_size, "count": alerts.len(), "alerts": alerts }))
}

pub(crate) async fn api_security_tenant_status(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    let tenant_id = path.into_inner();
    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo.database(&db).collection::<mongodb::bson::Document>("tenant_state");
    match coll.find_one(doc! { "tenant_id": &tenant_id }).await {
        Ok(Some(doc)) => HttpResponse::Ok().json(serde_json::json!({ "tenant_id": tenant_id, "state": doc })),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({ "tenant_id": tenant_id, "state": null })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() })),
    }
}

pub(crate) async fn api_security_rollback(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl actix_web::Responder {
    use simple_smtp_server::security::remediation;
    let alert_id = path.into_inner();
    match remediation::rollback_remediation(&mongo, &alert_id).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "rolled_back": true, "alert_id": alert_id })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

pub(crate) async fn api_security_live(mongo: web::Data<Arc<mongodb::Client>>) -> impl actix_web::Responder {
    let rx = match security::get_bus() {
        Some(tx) => tx.subscribe(),
        None => return HttpResponse::ServiceUnavailable().body("security bus unavailable"),
    };
    let stream = stream::unfold(
        (rx, tokio::time::interval(std::time::Duration::from_secs(15)), mongo.clone()),
        |(mut rx, mut hb, mongo)| async move {
            tokio::select! {
                Ok(alert) = rx.recv() => {
                    let data = serde_json::to_string(&alert).unwrap_or_default();
                    let msg = format!("event: security_alert\ndata: {}\nretry: 3000\n\n", data);
                    Some((Ok::<_, actix_web::Error>(actix_web::web::Bytes::from(msg)), (rx, hb, mongo)))
                }
                _ = hb.tick() => {
                    Some((Ok(actix_web::web::Bytes::from_static(b": heartbeat\n\n")), (rx, hb, mongo)))
                }
            }
        },
    );
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(stream)
}
