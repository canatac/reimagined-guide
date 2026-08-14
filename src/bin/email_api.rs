/*
This is an API server implementation for the SMTP service.

To run this API server, use the following command from the project root:

cargo run --bin email_api

Make sure you have set the necessary environment variables in your .env file:
    API_SERVER_ADDR: The address and port for the API server (e.g., "127.0.0.1:3000")
    SMTP_USERNAME: Your SMTP username
    SMTP_PASSWORD: Your SMTP password
    FULLCHAIN_PATH: Path to your SSL certificate chain file

The API server provides the following endpoint:

POST /send_email
    Accepts JSON payload with the following structure:
    {
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Test Email",
        "body": "This is a test email sent via the API server."
    }

Example usage with curl:
curl -X POST http://localhost:3000/send_email \
     -H "Content-Type: application/json" \
     -d '{
         "from": "sender@example.com",
         "to": "recipient@example.com",
         "subject": "Test Email",
         "body": "This is a test email sent via the API server."
     }'

The API server will attempt to send the email using the SMTP client and return the result.
*/

use actix_cors::Cors;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::{engine::general_purpose, Engine as _};
use bcrypt;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

// PR1 (RBAC admin) — module local, gated par ADMIN_RBAC_ENFORCE (feature flag).
// Ne modifie AUCUN comportement tant que le flag est OFF (défaut).
#[path = "admin_auth.rs"]
mod admin_auth;
use sha1::Sha1;

use chrono::{DateTime, Utc};
use dotenv::dotenv;
use futures_util::{stream, TryStreamExt};
use mongodb::bson;
use mongodb::bson::doc;
use reqwest;
use simple_smtp_server::entities::{
    AdminUserActivity, AdminUserRecord, CalendarEvent, ChangeRequestItem, Email, WorkflowEvent,
    WorkflowStage,
};
use simple_smtp_server::external_imap::{
    CreateExternalAccountInput, ExternalFolderMappingInput, ExternalImapService,
    ExternalMessageActionInput, StartSyncInput, UpdateExternalAccountInput,
};
use simple_smtp_server::i18n;
use simple_smtp_server::logic::Logic;
use simple_smtp_server::smtp_client::send_outgoing_email;
use std::collections::HashMap;
use std::env;
use std::fs::{create_dir_all, File};
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

// --- Mail event monitoring ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MailEventKind {
    Sent,
    Received,
    Read,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MailEvent {
    id: String,
    kind: MailEventKind,
    user_id: String,
    email_id: String,
    subject: String,
    from: String,
    to: String,
    timestamp: String,
}

type EventBus = broadcast::Sender<MailEvent>;

// --- Auth types ---

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    first_name: String,
    #[serde(default)]
    last_name: String,
    /// Alias optionnel → adresse alias@misfits.ai redirigeant vers prenom.nom@misfits.ai
    #[serde(default)]
    alias: Option<String>,
    password: String,
    #[serde(default)]
    condition_accepted: bool,
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

// --- 2FA types ---

fn default_2fa_method() -> String {
    "email".to_string()
}

#[derive(Deserialize)]
struct TwoFactorVerifyRequest {
    email: String,
    code: String,
    #[serde(default = "default_2fa_method")]
    method: String,
}

// --- Password reset types ---

#[derive(Deserialize)]
struct PasswordResetRequestBody {
    email: String,
}

#[derive(Deserialize)]
struct PasswordResetConfirmBody {
    token: String,
    new_password: String,
}

// --- Send queue types ---

const SEND_QUEUE_COLL: &str = "send_queue";

#[derive(Deserialize)]
struct UndoSendRequest {
    id: String,
}

#[derive(Deserialize)]
struct ScheduleSendBody {
    #[serde(default)]
    to: Vec<ComposerRecipient>,
    #[serde(default)]
    cc: Vec<ComposerRecipient>,
    #[serde(default)]
    bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    from: Option<String>,
    send_at: String,
}

// --- OAuth provider response types ---

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    email: String,
    display_name: String,
    role: String,
    two_factor_enabled: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct SessionResponse {
    id: String,
    user: UserResponse,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    refresh_expires_at: u64,
    issued_at: u64,
}

#[derive(Serialize)]
struct AuthResponse {
    session: SessionResponse,
}

fn make_session(email: &str, display_name: &str) -> AuthResponse {
    let now = Utc::now().timestamp_millis() as u64;
    AuthResponse {
        session: SessionResponse {
            id: Uuid::new_v4().to_string(),
            user: UserResponse {
                id: Uuid::new_v4().to_string(),
                email: email.to_string(),
                display_name: display_name.to_string(),
                role: "admin".to_string(),
                two_factor_enabled: false,
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            access_token: Uuid::new_v4().to_string(),
            refresh_token: Uuid::new_v4().to_string(),
            expires_at: now + 3600_000,
            refresh_expires_at: now + 604_800_000,
            issued_at: now,
        },
    }
}

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

fn parse_window(s: &str) -> chrono::Duration {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('m').and_then(|n| n.parse::<i64>().ok()) {
        chrono::Duration::minutes(n)
    } else if let Some(n) = s.strip_suffix('h').and_then(|n| n.parse::<i64>().ok()) {
        chrono::Duration::hours(n)
    } else if let Some(n) = s.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
        chrono::Duration::days(n)
    } else {
        chrono::Duration::minutes(15)
    }
}

fn since_str(window: &str) -> String {
    let dur = parse_window(window);
    (Utc::now() - dur).to_rfc3339()
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[derive(Deserialize)]
struct MonitoringWindowQuery {
    #[serde(default = "default_monitoring_window")]
    window: String,
}
fn default_monitoring_window() -> String {
    "15m".into()
}

fn default_window() -> String {
    "1h".into()
}

#[derive(Deserialize)]
struct MonitoringEventsQuery {
    status: Option<String>,
    from: Option<String>,
    to: Option<String>,
    provider: Option<String>,
    country: Option<String>,
    since: Option<String>,
    until: Option<String>,
    message_id: Option<String>,
    #[serde(default = "default_mon_page")]
    page: u32,
    #[serde(default = "default_mon_page_size")]
    page_size: u32,
}
fn default_mon_page() -> u32 {
    1
}
fn default_mon_page_size() -> u32 {
    50
}

#[derive(Deserialize)]
struct MonitoringLiveQuery {
    message_id: Option<String>,
}

#[derive(Deserialize)]
struct AdminWindowQuery {
    #[serde(default = "default_window")]
    window: String,
}

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

async fn dns_txt_lookup(name: &str) -> Vec<String> {
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut rows: Vec<String> = Vec::new();

    if let Ok(lookup) = resolver.txt_lookup(name).await {
        for txt in lookup.iter() {
            for part in txt.txt_data() {
                if let Ok(s) = std::str::from_utf8(part) {
                    rows.push(s.to_string());
                }
            }
        }
    }

    rows
}

/// GET /api/monitoring/summary?window=15m
async fn api_monitoring_summary(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let since = since_str(&query.window);
    let base_filter = doc! { "ts": { "$gte": &since } };

    let total = storage::count_events(&mongo, base_filter.clone()).await;

    let by_status_docs = storage::aggregate(&mongo, vec![
        doc! { "$match": base_filter.clone() },
        doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
    ]).await;

    let mut by_status = serde_json::Map::new();
    let mut total_delivered = 0u64;
    let mut total_bounced = 0u64;
    let mut avg_total_ms_sum = 0f64;
    let mut avg_count = 0u32;

    for doc in &by_status_docs {
        let status = doc.get_str("_id").unwrap_or("unknown").to_string();
        let count = doc.get_i64("count").unwrap_or(0) as u64;
        let avg_ms = doc.get_f64("avg_ms").unwrap_or(0.0);
        if status == "delivered" {
            total_delivered = count;
        }
        if status == "bounced" {
            total_bounced = count;
        }
        avg_total_ms_sum += avg_ms * count as f64;
        avg_count += count as u32;
        by_status.insert(status, serde_json::json!(count));
    }

    let delivery_rate = if total > 0 {
        total_delivered as f64 / total as f64
    } else {
        0.0
    };
    let bounce_rate = if total > 0 {
        total_bounced as f64 / total as f64
    } else {
        0.0
    };
    let avg_total_ms = if avg_count > 0 {
        avg_total_ms_sum / avg_count as f64
    } else {
        0.0
    };
    let p95 = storage::p95_total_ms(&mongo, base_filter.clone(), 1000).await;

    // Average risk score
    let risk_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": null, "avg_risk": { "$avg": "$risk_score" } } },
        ],
    )
    .await;
    let avg_risk = risk_docs
        .first()
        .and_then(|d| d.get_f64("avg_risk").ok())
        .unwrap_or(0.0);

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "total_events": total,
        "by_status": by_status,
        "delivery_rate": (delivery_rate * 1000.0).round() / 1000.0,
        "bounce_rate": (bounce_rate * 1000.0).round() / 1000.0,
        "avg_total_ms": avg_total_ms.round(),
        "p95_total_ms": p95,
        "avg_risk_score": (avg_risk * 10.0).round() / 10.0,
    }))
}

/// GET /api/monitoring/events?status=&from=&to=&provider=&country=&since=&until=&page=
async fn api_monitoring_events(
    query: web::Query<MonitoringEventsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let mut filter = doc! {};

    if let Some(ref s) = query.status {
        filter.insert("status", s);
    }
    if let Some(ref f) = query.from {
        filter.insert("from", doc! { "$regex": f.as_str(), "$options": "i" });
    }
    if let Some(ref t) = query.to {
        filter.insert("to", doc! { "$regex": t.as_str(), "$options": "i" });
    }
    if let Some(ref p) = query.provider {
        filter.insert("company", doc! { "$regex": p.as_str(), "$options": "i" });
    }
    if let Some(ref c) = query.country {
        filter.insert("country", c);
    }
    if let Some(ref m) = query.message_id {
        filter.insert("message_id", m);
    }

    let mut ts_filter = doc! {};
    if let Some(ref s) = query.since {
        ts_filter.insert("$gte", s);
    }
    if let Some(ref u) = query.until {
        ts_filter.insert("$lte", u);
    }
    if !ts_filter.is_empty() {
        filter.insert("ts", ts_filter);
    }

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
async fn api_monitoring_trace(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let message_id = path.into_inner();
    let filter = doc! { "message_id": &message_id };
    let mut events = storage::query_events(&mongo, filter, 1, 200).await;
    // Chronological order for trace view
    events.sort_by(|a, b| a.ts.cmp(&b.ts));

    if events.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({ "message": "Trace not found" }));
    }

    let status = events
        .iter()
        .rev()
        .find(|e| {
            matches!(
                e.status,
                monitoring::SmtpStatus::Delivered
                    | monitoring::SmtpStatus::Bounced
                    | monitoring::SmtpStatus::Failed
                    | monitoring::SmtpStatus::Deferred
            )
        })
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
async fn api_monitoring_bounces(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let since = since_str(&query.window);
    let filter = doc! { "ts": { "$gte": &since }, "status": "bounced" };
    let events = storage::query_events(&mongo, filter.clone(), 1, 100).await;
    let total = storage::count_events(&mongo, filter).await;

    let hard = events
        .iter()
        .filter(|e| matches!(e.bounce_type, Some(monitoring::BounceType::Hard)))
        .count();
    let soft = events
        .iter()
        .filter(|e| matches!(e.bounce_type, Some(monitoring::BounceType::Soft)))
        .count();
    let policy = events
        .iter()
        .filter(|e| matches!(e.bounce_type, Some(monitoring::BounceType::Policy)))
        .count();

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
async fn api_monitoring_providers_top(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let since = since_str(&query.window);
    let pipeline = vec![
        doc! { "$match": { "ts": { "$gte": &since } } },
        doc! { "$group": {
            "_id": { "company": "$company", "datacenter": "$datacenter", "country": "$country" },
            "count":     { "$sum": 1 },
            "delivered": { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
            "bounced":   { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] },   "then": 1, "else": 0 } } },
            "avg_total_ms": { "$avg": "$total_ms" },
            "avg_risk":     { "$avg": "$risk_score" },
        }},
        doc! { "$sort": { "count": -1 } },
        doc! { "$limit": 20 },
    ];
    let docs = storage::aggregate(&mongo, pipeline).await;

    let providers: Vec<serde_json::Value> = docs
        .iter()
        .map(|d| {
            let id = d.get_document("_id").ok();
            let company = id
                .and_then(|i| i.get_str("company").ok())
                .unwrap_or("unknown");
            let datacenter = id
                .and_then(|i| i.get_str("datacenter").ok())
                .unwrap_or("unknown");
            let country = id
                .and_then(|i| i.get_str("country").ok())
                .unwrap_or("unknown");
            serde_json::json!({
                "company":      company,
                "datacenter":   datacenter,
                "country":      country,
                "count":        d.get_i64("count").unwrap_or(0),
                "delivered":    d.get_i64("delivered").unwrap_or(0),
                "bounced":      d.get_i64("bounced").unwrap_or(0),
                "avg_total_ms": d.get_f64("avg_total_ms").unwrap_or(0.0).round(),
                "avg_risk_score": d.get_f64("avg_risk").unwrap_or(0.0).round(),
            })
        })
        .collect();

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "providers": providers,
    }))
}

/// GET /api/monitoring/live?message_id=<optional>  — SSE
async fn api_monitoring_live(query: web::Query<MonitoringLiveQuery>) -> HttpResponse {
    let filter_mid = query.message_id.clone();

    let rx = match monitoring::get_bus() {
        Some(tx) => tx.subscribe(),
        None => {
            return HttpResponse::ServiceUnavailable()
                .body("Monitoring bus not initialized (SMTP_MONITORING_ENABLED=true required)");
        }
    };

    let event_stream = stream::unfold(
        (
            rx,
            filter_mid,
            tokio::time::interval(std::time::Duration::from_secs(15)),
        ),
        |(mut rx, mid, mut hb)| async move {
            loop {
                tokio::select! {
                    result = rx.recv() => {
                        match result {
                            Ok(event) => {
                                if let Some(ref f) = mid {
                                    if &event.message_id != f { continue; }
                                }
                                let data = serde_json::to_string(&event).unwrap_or_default();
                                let chunk = format!("event: smtp_event\ndata: {}\nretry: 3000\n\n", data);
                                return Some((
                                    Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(chunk)),
                                    (rx, mid, hb),
                                ));
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                eprintln!("monitoring SSE: lagged {} events", n);
                                continue;
                            }
                            Err(broadcast::error::RecvError::Closed) => return None,
                        }
                    }
                    _ = hb.tick() => {
                        return Some((
                            Ok::<web::Bytes, actix_web::Error>(
                                web::Bytes::from(": heartbeat\n\n")
                            ),
                            (rx, mid, hb),
                        ));
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
async fn api_monitoring_alerts_active(
    query: web::Query<MonitoringWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let window_minutes = parse_window(&query.window).num_minutes();
    let config = AlertConfig::default();
    let alerts = monitoring::alerts::evaluate_alerts(&mongo, window_minutes, &config).await;

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "alert_count": alerts.len(),
        "alerts": alerts,
    }))
}

// ---------------------------------------------------------------------------
// Security endpoints
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct SecurityAlertsQuery {
    #[serde(default = "default_window")]
    window: String,
    severity: Option<String>,
    tenant_id: Option<String>,
}

#[derive(serde::Deserialize)]
struct SecurityIncidentsQuery {
    #[serde(default = "one")]
    page: u32,
    #[serde(default = "twenty")]
    page_size: u32,
    tenant_id: Option<String>,
    severity: Option<String>,
}

fn one() -> u32 {
    1
}
fn twenty() -> u32 {
    20
}

async fn api_security_alerts_active(
    query: web::Query<SecurityAlertsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let limit = 100i64;
    let mut alerts = audit::query_active_alerts(&mongo, limit).await;

    // Optional filters
    if let Some(ref sev) = query.severity {
        let sev_lc = sev.to_lowercase();
        alerts.retain(|a| format!("{:?}", a.severity).to_lowercase() == sev_lc);
    }
    if let Some(ref tid) = query.tenant_id {
        alerts.retain(|a| a.tenant_id.as_deref() == Some(tid.as_str()));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "alert_count": alerts.len(),
        "alerts": alerts,
    }))
}

async fn api_security_incidents(
    query: web::Query<SecurityIncidentsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use mongodb::bson::doc;
    use simple_smtp_server::security::audit;

    let mut filter = doc! {};
    if let Some(ref tid) = query.tenant_id {
        filter.insert("tenant_id", tid.as_str());
    }
    if let Some(ref sev) = query.severity {
        filter.insert("severity", sev.as_str());
    }

    let alerts = audit::query_alerts(&mongo, filter, query.page, query.page_size).await;
    HttpResponse::Ok().json(serde_json::json!({
        "page": query.page,
        "page_size": query.page_size,
        "count": alerts.len(),
        "alerts": alerts,
    }))
}

async fn api_security_tenant_status(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use mongodb::bson::doc;
    let tenant_id = path.into_inner();
    let db = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<mongodb::bson::Document>("tenant_state");

    match coll.find_one(doc! { "tenant_id": &tenant_id }).await {
        Ok(Some(doc)) => HttpResponse::Ok().json(serde_json::json!({
            "tenant_id": tenant_id,
            "state": doc,
        })),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "tenant_id": tenant_id,
            "state": null,
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

async fn api_security_rollback(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::remediation;
    let alert_id = path.into_inner();
    match remediation::rollback_remediation(&mongo, &alert_id).await {
        Ok(()) => HttpResponse::Ok()
            .json(serde_json::json!({ "rolled_back": true, "alert_id": alert_id })),
        Err(e) => HttpResponse::BadRequest().json(serde_json::json!({ "error": e })),
    }
}

async fn api_security_live(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
    use futures_util::stream;
    use simple_smtp_server::security;
    use std::time::Duration;

    let rx = match security::get_bus() {
        Some(tx) => tx.subscribe(),
        None => return HttpResponse::ServiceUnavailable().body("security bus unavailable"),
    };

    let stream = stream::unfold(
        (
            rx,
            tokio::time::interval(Duration::from_secs(15)),
            mongo.clone(),
        ),
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

async fn api_admin_security_posture(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let active_alerts = audit::query_active_alerts(&mongo, 300).await;

    let brute_force_alerts = active_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("bruteforce") || n.contains("brute") || n.contains("rate")
        })
        .count();

    let auth_fail_alerts = active_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("spf") || n.contains("dkim") || n.contains("dmarc")
        })
        .count();

    let domain = env::var("DOMAIN_NAME")
        .or_else(|_| env::var("MAIL_DOMAIN"))
        .unwrap_or_else(|_| "misfits.ai".to_string());
    let smtp_public_ip =
        env::var("SMTP_PUBLIC_IP").unwrap_or_else(|_| "51.158.114.182".to_string());
    let dkim_selector = env::var("KEY_SELECTOR").unwrap_or_else(|_| "default".to_string());

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "security": {
            "tls": {
                "smtp_starttls_required": env_bool("SMTP_REQUIRE_STARTTLS", true),
                "smtps_listener": env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string()),
                "imaps_listener": env::var("IMAP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8993".to_string()),
                "imap_starttls_required": env_bool("IMAP_REQUIRE_STARTTLS", true)
            },
            "authentication": {
                "sasl_mechanisms": ["PLAIN", "LOGIN"],
                "oauth2_enabled": env::var("GITHUB_CLIENT_ID").map(|v| !v.trim().is_empty()).unwrap_or(false),
                "admin_mfa_required": env_bool("ADMIN_MFA_REQUIRED", true)
            },
            "anti_abuse": {
                "rate_limit_enabled": env_bool("RATE_LIMIT_ENABLED", true),
                "rate_limit_per_minute": env::var("RATE_LIMIT_PER_MINUTE").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(120),
                "fail2ban_enabled": env_bool("FAIL2BAN_ENABLED", true),
                "bruteforce_signals_24h": brute_force_alerts,
                "auth_policy_signals_24h": auth_fail_alerts
            },
            "mail_auth_dns": {
                "domain": domain,
                "spf_expected": format!("v=spf1 ip4:{} -all", smtp_public_ip),
                "dkim_selector": dkim_selector,
                "dmarc_expected": "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=100",
                "ptr_rdns_note": "Configurer PTR/rDNS de l'IP publique vers un host mail stable (ex: mail.<domain>)"
            }
        }
    }))
}

async fn api_admin_deliverability_diagnostics(
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
    for evt in &bounces {
        let key = evt
            .bounce_reason
            .clone()
            .or_else(|| evt.smtp_reply.clone())
            .unwrap_or_else(|| "unknown".to_string());
        *bounce_reasons.entry(key).or_insert(0) += 1;
    }

    let mut top_reasons: Vec<(String, u32)> = bounce_reasons.into_iter().collect();
    top_reasons.sort_by(|a, b| b.1.cmp(&a.1));

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
        "top_bounce_reasons": top_reasons.into_iter().take(10).map(|(reason, count)| serde_json::json!({"reason": reason, "count": count})).collect::<Vec<_>>(),
        "recent_delivery_failures": bounces.into_iter().take(15).map(|e| serde_json::json!({
            "ts": e.ts,
            "to": e.to,
            "mx_host": e.mx_host,
            "smtp_code": e.smtp_code,
            "smtp_reply": e.smtp_reply,
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

async fn api_admin_deliverability_procedure(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let domain = env::var("DOMAIN_NAME")
        .or_else(|_| env::var("MAIL_DOMAIN"))
        .unwrap_or_else(|_| "misfits.ai".to_string())
        .trim()
        .trim_end_matches('.')
        .to_string();
    let selector = env::var("KEY_SELECTOR").unwrap_or_else(|_| "default".to_string());

    let spf_rows = dns_txt_lookup(&domain).await;
    let dmarc_rows = dns_txt_lookup(&format!("_dmarc.{}", domain)).await;
    let helo_rows = dns_txt_lookup(&format!("mail.{}", domain)).await;
    let dkim_rows = dns_txt_lookup(&format!("{}._domainkey.{}", selector, domain)).await;

    let spf_joined = spf_rows.join(" ").to_ascii_lowercase();
    let dmarc_joined = dmarc_rows.join(" ").to_ascii_lowercase();
    let helo_joined = helo_rows.join(" ").to_ascii_lowercase();

    let dmarc_policy = if dmarc_joined.contains("p=reject") {
        "reject"
    } else if dmarc_joined.contains("p=quarantine") {
        "quarantine"
    } else if dmarc_joined.contains("p=none") {
        "none"
    } else {
        "missing"
    };

    let smtp_public_ip =
        env::var("SMTP_PUBLIC_IP").unwrap_or_else(|_| "51.158.114.182".to_string());
    let spf_apex_ok = spf_joined.contains("v=spf1") && spf_joined.contains(&smtp_public_ip);
    let dkim_dns_ok = dkim_rows
        .iter()
        .any(|row| row.to_ascii_lowercase().contains("v=dkim1"));
    let helo_spf_ok = helo_joined.contains("v=spf1");

    let since = since_str(&query.window);
    let gmail_blocks = storage::count_events(
        &mongo,
        doc! {
            "ts": {"$gte": &since},
            "to": {"$regex": "@gmail\\.com$", "$options": "i"},
            "smtp_reply": {"$regex": "NotAuthorizedError|550-5\\.7\\.1", "$options": "i"}
        },
    )
    .await;

    let dkim_alerts = simple_smtp_server::security::audit::query_active_alerts(&mongo, 300)
        .await
        .into_iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("dkim"))
        .count() as u64;

    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");
    let saved = coll
        .find_one(doc! {"key": "deliverability_procedure"})
        .await
        .ok()
        .flatten();

    let mut reminder_enabled = true;
    let mut reminder_cadence_hours = 24u32;
    let mut reminder_anchor = Utc::now();
    let mut checklist_overrides = bson::Document::new();

    if let Some(saved_doc) = saved.as_ref() {
        if let Ok(reminder) = saved_doc.get_document("reminder") {
            reminder_enabled = reminder.get_bool("enabled").unwrap_or(true);
            reminder_cadence_hours = reminder
                .get_i32("cadence_hours")
                .ok()
                .map(|v| v.max(1) as u32)
                .unwrap_or(24);

            if let Ok(last_ack_at) = reminder.get_str("last_ack_at") {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(last_ack_at) {
                    reminder_anchor = parsed.with_timezone(&Utc);
                }
            }
        }

        if let Ok(updated_at) = saved_doc.get_str("updated_at") {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(updated_at) {
                reminder_anchor = parsed.with_timezone(&Utc);
            }
        }

        if let Ok(overrides) = saved_doc.get_document("checklist_overrides") {
            checklist_overrides = overrides.clone();
        }
    }

    let next_reminder_due_at = if reminder_enabled {
        (reminder_anchor + chrono::Duration::hours(reminder_cadence_hours as i64)).to_rfc3339()
    } else {
        String::new()
    };

    let mut checklist = vec![
        serde_json::json!({
            "id": "dmarc-enforcement",
            "title": "Activer DMARC enforcement progressif",
            "status": if dmarc_policy == "reject" {"done"} else if dmarc_policy == "quarantine" {"in_progress"} else {"todo"},
            "evidence": format!("policy actuelle: {}", dmarc_policy),
            "cta": {
                "label": "Mettre à jour _dmarc",
                "kind": "dns",
                "details": "v=DMARC1; p=quarantine; pct=25; adkim=s; aspf=s; rua=mailto:dmarc@misfits.ai"
            }
        }),
        serde_json::json!({
            "id": "spf-helo",
            "title": "Corriger SPF_HELO_NONE",
            "status": if helo_spf_ok {"done"} else {"todo"},
            "evidence": if helo_spf_ok {"TXT SPF trouvé sur mail.<domain>"} else {"TXT SPF absent sur mail.<domain>"},
            "cta": {
                "label": "Ajouter TXT SPF HELO",
                "kind": "dns",
                "details": "host=mail value=v=spf1 a -all"
            }
        }),
        serde_json::json!({
            "id": "dkim-dns",
            "title": "Vérifier la clé DKIM publique",
            "status": if dkim_dns_ok {"done"} else {"todo"},
            "evidence": format!("selector {}._domainkey.{}", selector, domain),
            "cta": {
                "label": "Valider la clé DKIM",
                "kind": "dns",
                "details": format!("dig +short TXT {}._domainkey.{}", selector, domain)
            }
        }),
        serde_json::json!({
            "id": "gmail-policy",
            "title": "Traiter les rejets policy Gmail",
            "status": if gmail_blocks == 0 {"done"} else {"blocked"},
            "evidence": format!("NotAuthorizedError sur fenêtre {}: {}", query.window, gmail_blocks),
            "cta": {
                "label": "Lancer plan warmup Gmail",
                "kind": "ops",
                "details": "Réputation IP/domain + Postmaster + ramp-up progressif"
            }
        }),
        serde_json::json!({
            "id": "dkim-runtime",
            "title": "Confirmer absence de régression DKIM",
            "status": if dkim_alerts == 0 {"done"} else {"todo"},
            "evidence": format!("alertes DKIM actives: {}", dkim_alerts),
            "cta": {
                "label": "Exécuter un probe externe",
                "kind": "probe",
                "details": "Envoyer un test mail-tester + vérifier DKIM/SPF/DMARC"
            }
        }),
        serde_json::json!({
            "id": "apex-spf",
            "title": "Conserver SPF apex aligné IP prod",
            "status": if spf_apex_ok {"done"} else {"todo"},
            "evidence": format!("SPF apex contient {}: {}", smtp_public_ip, spf_apex_ok),
            "cta": {
                "label": "Mettre à jour SPF apex",
                "kind": "dns",
                "details": format!("v=spf1 ip4:{} -all", smtp_public_ip)
            }
        }),
    ];

    for entry in &mut checklist {
        if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
            if let Ok(override_doc) = checklist_overrides.get_document(id) {
                if let Ok(checked) = override_doc.get_bool("checked") {
                    if checked {
                        entry["status"] = serde_json::json!("done_manual");
                    }
                }
                if let Ok(note) = override_doc.get_str("note") {
                    if !note.trim().is_empty() {
                        entry["operator_note"] = serde_json::json!(note);
                    }
                }
            }
        }
    }

    let done_count = checklist
        .iter()
        .filter(|item| {
            item.get("status")
                .and_then(|v| v.as_str())
                .map(|s| s == "done" || s == "done_manual")
                .unwrap_or(false)
        })
        .count();

    let overall_status = if gmail_blocks > 0 {
        "blocked_gmail_policy"
    } else if done_count == checklist.len() {
        "ready_for_reject"
    } else {
        "in_progress"
    };

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "domain": domain,
        "overall_status": overall_status,
        "progress": {
            "done": done_count,
            "total": checklist.len()
        },
        "automation": {
            "auto_checks": ["dns_txt", "smtp_events", "security_alerts"],
            "last_computed_at": Utc::now().to_rfc3339(),
            "next_recompute_hint": "refresh tab or call endpoint"
        },
        "reminder": {
            "enabled": reminder_enabled,
            "cadence_hours": reminder_cadence_hours,
            "next_due_at": next_reminder_due_at
        },
        "checklist": checklist,
        "cta_details": [
            {
                "id": "run_external_probe",
                "label": "Lancer un test externe",
                "description": "Envoi test + vérification mail-tester + trace monitoring"
            },
            {
                "id": "publish_dmarc_stage",
                "label": "Publier DMARC stage suivant",
                "description": "none -> quarantine(25) -> quarantine(100) -> reject(100)"
            },
            {
                "id": "ack_review",
                "label": "Marquer revue hebdomadaire",
                "description": "Cocher les items validés et conserver une note opérateur"
            }
        ]
    }))
}

async fn api_admin_deliverability_procedure_update(
    body: web::Json<DeliverabilityProcedureUpdateRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");

    let mut set_doc = doc! {
        "key": "deliverability_procedure",
        "updated_at": Utc::now().to_rfc3339(),
    };

    if let Some(reminder) = body.reminder.as_ref() {
        set_doc.insert(
            "reminder",
            doc! {
                "enabled": reminder.enabled,
                "cadence_hours": (reminder.cadence_hours.max(1) as i32),
                "updated_at": Utc::now().to_rfc3339(),
            },
        );
    }

    if let Some(items) = body.checklist.as_ref() {
        let mut overrides = bson::Document::new();
        for item in items {
            overrides.insert(
                item.id.clone(),
                bson::Bson::Document(doc! {
                    "checked": item.checked,
                    "note": item.note.clone().unwrap_or_default(),
                    "updated_at": Utc::now().to_rfc3339(),
                }),
            );
        }
        set_doc.insert("checklist_overrides", overrides);
    }

    match coll
        .update_one(
            doc! {"key": "deliverability_procedure"},
            doc! {"$set": set_doc},
        )
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "ok": false,
            "error": format!("deliverability_procedure_update_failed: {}", e)
        })),
    }
}

async fn api_admin_observability_overview(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let since = since_str(&query.window);
    let window_minutes = parse_window(&query.window).num_minutes().max(1) as f64;
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
    let mut delivered = 0u64;
    let mut bounced = 0u64;
    let mut failed = 0u64;
    let mut deferred = 0u64;

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

    let p95 = storage::p95_total_ms(&mongo, base_filter.clone(), 1000).await;

    let outcome_total = delivered + bounced + failed + deferred;
    let success_rate = if outcome_total == 0 {
        0.0
    } else {
        delivered as f64 / outcome_total as f64
    };

    // SMTP queue depth + oldest age
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    let pending_queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let queue_depth = queue_coll
        .count_documents(pending_queue_filter.clone())
        .await
        .unwrap_or(0);

    let oldest_pending = queue_coll
        .find_one(pending_queue_filter.clone())
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten();
    let queue_oldest_age_seconds = oldest_pending
        .as_ref()
        .and_then(|d| d.get_datetime("created_at").ok())
        .map(|dt| (Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64 / 1000);

    // Throughput and SMTP response classes
    let incoming_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "event_type": { "$in": ["accepted", "received"] } },
    )
    .await;
    let outgoing_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "status": { "$in": ["delivered", "bounced", "failed", "deferred"] } },
    )
    .await;

    let smtp_4xx = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "smtp_code": { "$gte": 400, "$lt": 500 } },
    )
    .await;
    let smtp_5xx = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "smtp_code": { "$gte": 500, "$lt": 600 } },
    )
    .await;

    let monitoring_alerts = monitoring::alerts::evaluate_alerts(
        &mongo,
        parse_window(&query.window).num_minutes(),
        &AlertConfig::default(),
    )
    .await;
    let security_alerts = audit::query_active_alerts(&mongo, 300).await;

    let queue_growth_alerts = monitoring_alerts
        .iter()
        .filter(|a| a.kind.contains("queue") || a.message.to_ascii_lowercase().contains("queue"))
        .count();
    let auth_failure_alerts = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("auth") || n.contains("brute") || n.contains("login")
        })
        .count();
    let anomaly_alerts = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("volume")
                || n.contains("spike")
                || n.contains("anormal")
                || n.contains("anomaly")
        })
        .count();

    let dns_issue_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "event_type": "dns_lookup", "status": { "$in": ["failed", "deferred"] } },
    )
    .await;

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

    let auth_events_coll = mongo
        .database(&db)
        .collection::<bson::Document>("auth_events");
    let suspicious_login_docs = match auth_events_coll
        .aggregate(vec![
            doc! { "$match": { "ts": { "$gte": &since }, "success": false } },
            doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } },
            doc! { "$sort": { "attempts": -1 } },
            doc! { "$limit": 10 },
        ])
        .await
    {
        Ok(cursor) => cursor.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let suspicious_logins_top = suspicious_login_docs
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "ip": d.get_str("_id").unwrap_or("unknown"),
                "attempts": d.get_i64("attempts").unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();

    let by_domain_docs = storage::aggregate(
        &mongo,
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

    let per_domain = by_domain_docs
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "domain": d.get_str("_id").unwrap_or("unknown"),
                "count": d.get_i64("count").unwrap_or(0),
                "delivered": d.get_i64("delivered").unwrap_or(0),
                "bounced": d.get_i64("bounced").unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "smtp": {
            "total_events": total,
            "failure_events": failed + bounced,
            "p95_total_ms": p95,
            "by_status": by_status
        },
        "health_realtime": {
            "queue": {
                "depth": queue_depth,
                "oldest_age_seconds": queue_oldest_age_seconds
            },
            "throughput": {
                "incoming_per_min": ((incoming_events as f64 / window_minutes) * 100.0).round() / 100.0,
                "outgoing_per_min": ((outgoing_events as f64 / window_minutes) * 100.0).round() / 100.0
            },
            "delivery": {
                "success_rate": (success_rate * 10000.0).round() / 10000.0,
                "smtp_4xx_rate": if total == 0 { 0.0 } else { ((smtp_4xx as f64 / total as f64) * 10000.0).round() / 10000.0 },
                "smtp_5xx_rate": if total == 0 { 0.0 } else { ((smtp_5xx as f64 / total as f64) * 10000.0).round() / 10000.0 },
                "p95_total_ms": p95
            }
        },
        "proactive_alerting": {
            "threshold_alerts": {
                "queue_growth": queue_growth_alerts,
                "auth_failures": auth_failure_alerts,
                "imap_latency_alert": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok()).map(|v| v > env::var("IMAP_P95_MS_THRESHOLD").ok().and_then(|t| t.parse::<u64>().ok()).unwrap_or(4000)).unwrap_or(false)
            },
            "anomaly_detection": {
                "anomaly_alerts": anomaly_alerts,
                "spam_or_volume_spike": anomaly_alerts > 0,
                "sudden_bounce_signal": monitoring_alerts.iter().any(|a| a.kind == "bounce_rate")
            },
            "correlation": {
                "smtp": { "events": total, "smtp_4xx": smtp_4xx, "smtp_5xx": smtp_5xx },
                "imap": {
                    "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
                    "p95_ms": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok())
                },
                "dns": { "lookup_issue_events": dns_issue_events },
                "blacklist": {
                    "sources": rbl_sources,
                    "listed_by": rbl_listed_by,
                    "listed": !env::var("RBL_LISTED_BY").unwrap_or_default().trim().is_empty()
                }
            }
        },
        "security_deliverability": {
            "suspicious_logins_top": suspicious_logins_top,
            "active_security_alerts": security_alerts.len(),
            "active_monitoring_alerts": monitoring_alerts.len()
        },
        "imap": {
            "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
            "note": "Connecter un compteur runtime IMAP pour une métrique live fiable"
        },
        "realtime_alerts": {
            "monitoring_active": monitoring_alerts.len(),
            "security_active": security_alerts.len()
        },
        "per_domain": per_domain,
        "exports": {
            "prometheus_enabled": env_bool("PROMETHEUS_EXPORT_ENABLED", true),
            "prometheus_path": env::var("PROMETHEUS_EXPORT_PATH").unwrap_or_else(|_| "/metrics".to_string()),
            "siem_webhook_configured": env::var("SIEM_WEBHOOK_URL").map(|v| !v.trim().is_empty()).unwrap_or(false)
        }
    }))
}

/// Accents → ASCII, non-alphanumériques supprimés, minuscules.
fn normalize_segment(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            'æ' => 'a',
            'œ' => 'o',
            _ => c,
        })
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Retourne `prenom.nom` normalisé, ou None si prénom ou nom est absent.
fn build_misfits_local(first_name: &str, last_name: &str) -> Option<String> {
    let first = normalize_segment(first_name.trim());
    let last = normalize_segment(last_name.trim());
    if first.is_empty() || last.is_empty() {
        return None;
    }
    Some(format!("{}.{}", first, last))
}

fn normalize_oauth_provider(provider: &str) -> Option<String> {
    let p = provider.trim().to_ascii_lowercase();
    match p.as_str() {
        "github" => Some(p),
        _ => None,
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct EmailRequest {
    from: String,
    to: String,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct MailingListRequest {
    label: String,
    emails: Vec<String>,
}

#[derive(Deserialize)]
struct MailingListEmailRequest {
    from: String,
    subject: String,
    body: String,
    mailing_list: String,
}

async fn create_mailing_list(mailing_list: web::Json<MailingListRequest>) -> impl Responder {
    let mailing_list_dir = Path::new("mailing-lists");
    if !mailing_list_dir.exists() {
        if let Err(e) = create_dir_all(mailing_list_dir) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create mailing list directory: {}", e)
            }));
        }
    }

    let file_path = mailing_list_dir.join(format!("{}.csv", mailing_list.label));
    let mut file = match File::create(&file_path) {
        Ok(file) => file,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create file: {}", e)
            }))
        }
    };

    for email in &mailing_list.emails {
        if let Err(e) = writeln!(file, "{}", email) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to write to file: {}", e)
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Mailing list '{}' created successfully", mailing_list.label)
    }))
}

async fn send_to_mailing_list(email_req: web::Json<MailingListEmailRequest>) -> impl Responder {
    let mailing_list_path =
        Path::new("mailing-lists").join(format!("{}.csv", email_req.mailing_list));

    if !mailing_list_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "status": "error",
            "message": format!("Mailing list '{}' not found", email_req.mailing_list)
        }));
    }

    let file = match File::open(&mailing_list_path) {
        Ok(file) => file,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to open mailing list file: {}", e)
            }))
        }
    };

    let reader = BufReader::new(file);
    let mut success_count = 0;
    let mut failure_count = 0;

    for line in reader.lines() {
        let to_email = match line {
            Ok(email) => email.trim().to_string(),
            Err(_e) => {
                failure_count += 1;
                continue;
            }
        };

        let from = email_req.from.clone();
        let to = to_email;
        let subject = email_req.subject.clone();
        let body = email_req.body.clone();

        let _email_content = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
            from, to, subject, body
        );
        let client = reqwest::Client::new();
        let dkim_service_url = env::var("DKIM_SERVICE_URL").expect("DKIM_SERVICE_URL not set");

        let _dkim_response = match client
            .post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": from,
                "to": to,
                "subject": subject,
                "text": body
            }))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    success_count += 1;
                } else {
                    failure_count += 1;
                }
            }
            Err(_) => {
                failure_count += 1;
            }
        };
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Emails sent to mailing list '{}'. Successful: {}, Failed: {}",
                           email_req.mailing_list, success_count, failure_count)
    }))
}

async fn send_email_handler(
    email_req: web::Json<EmailRequest>,
    dkim_service: web::Data<Box<dyn DkimService>>,
) -> impl Responder {
    println!("Received email request");

    match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            println!("DKIM service returned success");
            let message_id = dkim_result["messageId"].as_str().unwrap_or("");
            match dkim_result["status"].as_str() {
                Some("success") => {
                    let sig = dkim_result["dkimSignature"]
                        .as_str()
                        .or_else(|| dkim_result["dkim_signature"].as_str())
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if sig.is_empty() {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": "DKIM service returned success without a DKIM signature",
                        }));
                    }

                    // Construct the email with DKIM signature
                    let email = Email {
                        id: Uuid::new_v4().to_string(),
                        from: email_req.from.clone(),
                        to: email_req.to.clone(),
                        subject: email_req.subject.clone(),
                        body: email_req.body.clone(),
                        headers: vec![("DKIM-Signature".to_string(), sig.clone())],
                        flags: vec![],
                        sequence_number: 0,
                        uid: 0,
                        internal_date: mongodb::bson::DateTime::from_millis(
                            Utc::now().timestamp_millis(),
                        ),
                        dkim_signature: Some(sig),
                    };

                    // Send the email
                    match send_outgoing_email(&email).await {
                        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                            "status": "success",
                            "message": "Email signed and sent successfully",
                            "messageId": message_id
                        })),
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to send email: {}", e)
                        })),
                    }
                }
                _ => {
                    let error_message = dkim_result["message"].as_str().unwrap_or("Unknown error");
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to sign email: {}", error_message)
                    }))
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to call DKIM service: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": "Failed to generate DKIM signature"
            }))
        }
    }
}

// --- Auth handlers ---

fn req_ip_str(req: &actix_web::HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn get_accept_language(req: &actix_web::HttpRequest) -> String {
    req.headers()
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn welcome_email_html(
    locale: &str,
    display_name: &str,
    primary_email: &str,
    alias_email: Option<&str>,
) -> String {
    let dir = if i18n::is_rtl(locale) { "rtl" } else { "ltr" };
    let text_align = if i18n::is_rtl(locale) {
        "right"
    } else {
        "left"
    };
    let greeting = i18n::t(locale, "email-welcome-greeting", &[("name", display_name)]);
    let intro = i18n::t(locale, "email-welcome-intro", &[]);
    let primary_label = i18n::t(locale, "email-welcome-primary-label", &[]);
    let cta = i18n::t(locale, "email-welcome-cta", &[]);
    let signature = i18n::t(locale, "email-welcome-signature", &[]);
    let alias_row = alias_email
        .map(|a| {
            let lbl = i18n::t(locale, "email-welcome-alias-label", &[]);
            let detail = i18n::t(locale, "email-welcome-alias-detail", &[]);
            format!(
                "<tr><td style=\"padding:4px 0\"><b>{lbl}</b> \
                 <span class=\"addr\">{a}</span> {detail}</td></tr>"
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="{locale}" dir="{dir}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <style>
    body{{font-family:Tahoma,Arial,sans-serif;direction:{dir};text-align:{text_align};color:#222;background:#f5f5f5;margin:0;padding:0}}
    .wrap{{max-width:600px;margin:40px auto;background:#fff;border-radius:8px;padding:40px}}
    .addr{{font-family:monospace;background:#f0f0f0;padding:2px 6px;border-radius:3px}}
  </style>
</head>
<body><div class="wrap">
  <h2>{greeting}</h2>
  <p>{intro}</p>
  <table cellpadding="0" cellspacing="0">
    <tr><td style="padding:4px 0"><b>{primary_label}</b> <span class="addr">{primary_email}</span></td></tr>
    {alias_row}
  </table>
  <p>{cta}</p>
  <p>{signature}</p>
</div></body>
</html>"#,
    )
}

async fn auth_login(
    req: web::Json<LoginRequest>,
    req_http: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let locale = i18n::resolve_locale(&get_accept_language(&req_http), None);
    // Try to authenticate against MongoDB
    match logic.authenticate_user(&req.email, &req.password).await {
        Ok(Some(user)) => {
            let display = if user.mailbox.is_empty() {
                req.email.clone()
            } else {
                user.mailbox.clone()
            };
            HttpResponse::Ok().json(make_session(&req.email, &display))
        }
        Ok(None) => {
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    return HttpResponse::Ok().json(make_session(&req.email, &env_user));
                }
            }
            // Emit auth failure event for brute-force detection
            let ip = req_ip_str(&req_http);
            let ev = simple_smtp_server::security::AuthEvent::new(
                simple_smtp_server::security::AuthEventKind::ApiLogin,
                &ip,
                false,
            );
            let mc = mongo.clone();
            tokio::spawn(async move {
                simple_smtp_server::security::log_auth_event(&mc, ev).await;
            });
            HttpResponse::Unauthorized().json(serde_json::json!({
                "message": i18n::t(&locale, "error-login-invalid", &[])
            }))
        }
        Err(e) => {
            eprintln!("Auth error: {}", e);
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    return HttpResponse::Ok().json(make_session(&req.email, &env_user));
                }
            }
            HttpResponse::Unauthorized().json(serde_json::json!({
                "message": i18n::t(&locale, "error-login-invalid", &[])
            }))
        }
    }
}

async fn auth_register(
    req: web::Json<RegisterRequest>,
    req_http: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let locale = i18n::resolve_locale(&get_accept_language(&req_http), None);
    if !req.condition_accepted {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code": "CONDITIONS_NOT_ACCEPTED",
            "message": i18n::t(&locale, "error-conditions-required", &[])
        }));
    }
    if req.password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code": "INVALID_PASSWORD",
            "message": i18n::t(&locale, "error-password-too-short", &[])
        }));
    }

    let local_part = match build_misfits_local(&req.first_name, &req.last_name) {
        Some(l) => l,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "code": "MISSING_IDENTITY",
                "message": i18n::t(&locale, "error-name-required", &[])
            }));
        }
    };

    // Adresse principale : prenom.nom@misfits.ai
    let primary_email = format!("{}@misfits.ai", local_part);
    // Alias éventuel : alias@misfits.ai → redirige vers primary_email
    let alias_email: Option<String> = req
        .alias
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|a| normalize_segment(a))
        .filter(|n| !n.is_empty() && *n != local_part)
        .map(|n| format!("{}@misfits.ai", n));

    let display_name = {
        let first = req.first_name.trim();
        let last = req.last_name.trim();
        if first.is_empty() && last.is_empty() {
            local_part.clone()
        } else {
            format!("{} {}", first, last).trim().to_string()
        }
    };

    let password = req.password.clone();
    let password_hash = match web::block(move || bcrypt::hash(&password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("bcrypt error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": i18n::t(&locale, "error-account-creation-failed", &[])
            }));
        }
        Err(e) => {
            eprintln!("bcrypt task error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": i18n::t(&locale, "error-account-creation-failed", &[])
            }));
        }
    };

    match logic
        .create_user(&primary_email, &password_hash, "inbox")
        .await
    {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("E11000") || msg.contains("duplicate key") {
                return HttpResponse::Conflict().json(serde_json::json!({
                    "code": "EMAIL_TAKEN",
                    "message": i18n::t(&locale, "error-email-taken", &[("email", &primary_email)])
                }));
            }
            eprintln!("Register error ({}): {}", primary_email, e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": i18n::t(&locale, "error-account-creation-failed", &[])
            }));
        }
    }

    // Créer l'alias → primary si fourni
    if let Some(ref alias) = alias_email {
        if let Err(e) = logic.create_alias(alias, &primary_email).await {
            eprintln!(
                "Alias creation error ({} → {}): {}",
                alias, primary_email, e
            );
            // Non bloquant : le compte est créé, l'alias sera à recréer
        }
    }

    // Email de bienvenue HTML avec support RTL
    let welcome_subject = i18n::t(&locale, "email-welcome-subject", &[]);
    let welcome_body = welcome_email_html(
        &locale,
        &display_name,
        &primary_email,
        alias_email.as_deref(),
    );
    let welcome = Email {
        id: Uuid::new_v4().to_string(),
        from: "noreply@misfits.ai".to_string(),
        to: primary_email.clone(),
        subject: welcome_subject,
        body: welcome_body,
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        flags: vec![],
        sequence_number: 1,
        uid: 1,
        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: None,
    };
    if let Err(e) = logic.deliver_to_inbox(&local_part, &welcome).await {
        eprintln!("Welcome email delivery error ({}): {}", primary_email, e);
    } else {
        emit_event(
            &bus,
            &mongo,
            MailEvent {
                id: Uuid::new_v4().to_string(),
                kind: MailEventKind::Received,
                user_id: local_part.clone(),
                email_id: welcome.id.clone(),
                subject: welcome.subject.clone(),
                from: welcome.from.clone(),
                to: welcome.to.clone(),
                timestamp: Utc::now().to_rfc3339(),
            },
        )
        .await;
    }

    let session = make_session(&primary_email, &display_name);
    HttpResponse::Created()
        .insert_header(("Content-Language", locale.as_str()))
        .json(serde_json::json!({
            "email": primary_email,
            "alias": alias_email,
            "session": session.session,
            "locale": locale,
        }))
}

#[derive(Deserialize)]
struct PatchLocaleRequest {
    locale: String,
}

async fn api_patch_user_locale(
    req: actix_web::HttpRequest,
    body: web::Json<PatchLocaleRequest>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    if !i18n::SUPPORTED_LOCALES.contains(&body.locale.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "unsupported_locale",
            "supported": i18n::SUPPORTED_LOCALES,
        }));
    }
    let username = resolve_user_id(&req);
    match logic.update_user_locale(&username, &body.locale).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({ "locale": body.locale })),
        Err(e) => {
            eprintln!("update_user_locale error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": "internal" }))
        }
    }
}

async fn auth_logout() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

async fn auth_refresh() -> impl Responder {
    // Return a new mock session
    HttpResponse::Ok().json(serde_json::json!({
        "session": {
            "id": Uuid::new_v4().to_string(),
            "user": {
                "id": Uuid::new_v4().to_string(),
                "email": "admin@misfits.ai",
                "displayName": "admin",
                "role": "admin",
                "twoFactorEnabled": false,
                "createdAt": Utc::now().to_rfc3339(),
                "updatedAt": Utc::now().to_rfc3339(),
            },
            "accessToken": Uuid::new_v4().to_string(),
            "refreshToken": Uuid::new_v4().to_string(),
            "expiresAt": (Utc::now().timestamp_millis() + 3600000) as u64,
            "refreshExpiresAt": (Utc::now().timestamp_millis() + 604800000) as u64,
            "issuedAt": Utc::now().timestamp_millis() as u64,
        }
    }))
}

async fn auth_oauth_start(path: web::Path<String>) -> impl Responder {
    let provider_raw = path.into_inner();
    let provider = match normalize_oauth_provider(&provider_raw) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Unsupported OAuth provider."
            }))
        }
    };

    let state = Uuid::new_v4().to_string();
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());

    let auth_url = match provider.as_str() {
        "github" => {
            let client_id = match env::var("GITHUB_CLIENT_ID").ok().filter(|v| !v.is_empty()) {
                Some(id) => id,
                None => {
                    eprintln!("OAuth start: GITHUB_CLIENT_ID is not set");
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "message": "OAuth provider not configured."
                    }));
                }
            };
            let redirect_uri = format!(
                "{}/api/auth/oauth/github/callback",
                callback_base.trim_end_matches('/')
            );
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=user:email",
                client_id,
                urlencoding::encode(&redirect_uri),
                state
            )
        }
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Unsupported OAuth provider."
            }))
        }
    };

    HttpResponse::Found()
        .insert_header(("Location", auth_url))
        .finish()
}

async fn auth_oauth_callback(
    path: web::Path<String>,
    query: web::Query<OAuthCallbackQuery>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let provider_raw = path.into_inner();
    let provider = match normalize_oauth_provider(&provider_raw) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Unsupported OAuth provider."
            }))
        }
    };

    let code = match query
        .code
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        Some(v) => v.to_string(),
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Missing OAuth authorization code."
            }))
        }
    };

    let _state = query.state.clone().unwrap_or_default();
    let callback_base = env::var("OAUTH_CALLBACK_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());
    let frontend_base =
        env::var("FRONTEND_BASE_URL").unwrap_or_else(|_| "https://mail.misfits.ai".to_string());

    let http_client = reqwest::Client::builder()
        .user_agent("misfits-email-api/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let (subject, email, display) = match provider.as_str() {
        "github" => {
            let client_id = env::var("GITHUB_CLIENT_ID").unwrap_or_default();
            let client_secret = env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
            if client_id.is_empty() || client_secret.is_empty() {
                eprintln!("OAuth callback: GITHUB_CLIENT_ID or GITHUB_CLIENT_SECRET is not set");
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "message": "OAuth provider not configured."
                }));
            }
            let redirect_uri = format!(
                "{}/api/auth/oauth/github/callback",
                callback_base.trim_end_matches('/')
            );

            // Exchange code for access_token
            let token_resp = http_client
                .post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .json(&serde_json::json!({
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                }))
                .send()
                .await;

            let access_token = match token_resp {
                Ok(r) => match r.json::<GithubTokenResponse>().await {
                    Ok(t) => {
                        if let Some(err) = &t.error {
                            eprintln!(
                                "GitHub OAuth error: {} — {}",
                                err,
                                t.error_description.as_deref().unwrap_or("")
                            );
                            return HttpResponse::Unauthorized().json(serde_json::json!({
                                "message": "OAuth authentication failed."
                            }));
                        }
                        match t.access_token {
                            Some(tok) if !tok.is_empty() => tok,
                            _ => {
                                eprintln!("GitHub OAuth: missing access_token in response");
                                return HttpResponse::Unauthorized().json(serde_json::json!({
                                    "message": "OAuth authentication failed."
                                }));
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("GitHub OAuth token parse error: {}", e);
                        return HttpResponse::Unauthorized().json(serde_json::json!({
                            "message": "OAuth authentication failed."
                        }));
                    }
                },
                Err(e) => {
                    eprintln!("GitHub OAuth token request error: {}", e);
                    return HttpResponse::Unauthorized().json(serde_json::json!({
                        "message": "OAuth authentication failed."
                    }));
                }
            };

            // Fetch user profile
            let user_resp = http_client
                .get("https://api.github.com/user")
                .bearer_auth(&access_token)
                .header("Accept", "application/vnd.github+json")
                .send()
                .await;

            let gh_user = match user_resp {
                Ok(r) => match r.json::<GithubUser>().await {
                    Ok(u) => u,
                    Err(e) => {
                        eprintln!("GitHub user profile parse error: {}", e);
                        return HttpResponse::Unauthorized().json(serde_json::json!({
                            "message": "OAuth authentication failed."
                        }));
                    }
                },
                Err(e) => {
                    eprintln!("GitHub user profile request error: {}", e);
                    return HttpResponse::Unauthorized().json(serde_json::json!({
                        "message": "OAuth authentication failed."
                    }));
                }
            };

            let subject = gh_user.id.to_string();
            let display = gh_user
                .name
                .as_deref()
                .unwrap_or(&gh_user.login)
                .to_string();

            // Use profile email or fall back to emails endpoint
            let email = if let Some(e) = gh_user.email.filter(|e| !e.is_empty()) {
                e
            } else {
                let emails_resp = http_client
                    .get("https://api.github.com/user/emails")
                    .bearer_auth(&access_token)
                    .header("Accept", "application/vnd.github+json")
                    .send()
                    .await;

                match emails_resp {
                    Ok(r) => match r.json::<Vec<GithubEmail>>().await {
                        Ok(emails) => emails
                            .into_iter()
                            .find(|e| e.primary && e.verified)
                            .map(|e| e.email)
                            .unwrap_or_else(|| format!("github+{}@misfits.ai", subject)),
                        Err(_) => format!("github+{}@misfits.ai", subject),
                    },
                    Err(_) => format!("github+{}@misfits.ai", subject),
                }
            };

            (subject, email, display)
        }
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Unsupported OAuth provider."
            }))
        }
    };

    // Resolve the username: from MongoDB if available, else fall back to the OAuth email.
    let username = match logic
        .find_or_create_oauth_user(&provider, &subject, &email, Some(&display))
        .await
    {
        Ok(user) => user.username,
        Err(e) => {
            // MongoDB unavailable/auth failure — degrade gracefully like auth_register does.
            eprintln!("OAuth MongoDB error (degraded session): {}", e);
            email.to_string()
        }
    };

    let session = make_session(&username, &display);
    let access_token = session.session.access_token.clone();
    // Escape session JSON for safe inline embedding in a <script> block.
    let session_json = serde_json::to_string(&session)
        .unwrap_or_default()
        .replace('\\', "\\\\")
        .replace('`', "\\`");

    // Bridge page: stores session in mfa.session (localStorage + sessionStorage)
    // and sets the mfa_session cookie, then redirects to /, matching the FE auth contract.
    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Connexion…</title></head><body>
<script>(function(){{
  try {{
    const s = JSON.parse(`{session_json}`);
    localStorage.setItem('mfa.session', JSON.stringify(s));
    sessionStorage.setItem('mfa.session', JSON.stringify(s));
  }} catch(e) {{}}
  window.location.replace('/mail');
}})();</script>
</body></html>"#,
        session_json = session_json,
    );

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        // mfa_session cookie matches what the backend sets on normal login
        .insert_header((
            "Set-Cookie",
            format!(
                "mfa_session={}; Path=/; HttpOnly; Secure; SameSite=Lax",
                access_token
            ),
        ))
        .body(html)
}

// --- Mail list (Phase A1, issue #166) -----------------------------------------

#[derive(Deserialize)]
struct EmailListQuery {
    #[serde(default = "default_folder")]
    folder: String,
    #[serde(default = "default_page")]
    page: u32,
    #[serde(rename = "pageSize", default = "default_page_size")]
    page_size: u32,
}

fn default_folder() -> String {
    "inbox".to_string()
}
fn default_page() -> u32 {
    1
}
fn default_page_size() -> u32 {
    50
}

/// Canonical FE folder id → mailbox names to try in Mongo (SMTP historically used INBOX).
fn folder_to_mailboxes(folder: &str) -> Vec<String> {
    let f = folder.trim().to_ascii_lowercase();
    match f.as_str() {
        "inbox" => vec!["inbox".into(), "INBOX".into()],
        "sent" => vec!["sent".into(), "SENT".into(), "Sent".into()],
        "drafts" => vec!["drafts".into(), "DRAFTS".into(), "Drafts".into()],
        "archive" => vec!["archive".into(), "ARCHIVE".into(), "Archive".into()],
        "trash" => vec!["trash".into(), "TRASH".into(), "Trash".into()],
        "spam" => vec!["spam".into(), "SPAM".into(), "Spam".into(), "Junk".into()],
        other => vec![other.to_string(), other.to_ascii_uppercase()],
    }
}

fn canonical_folder(folder: &str) -> Option<String> {
    let f = folder.trim().to_ascii_lowercase();
    match f.as_str() {
        "inbox" | "sent" | "drafts" | "archive" | "trash" | "spam" => Some(f),
        _ => None,
    }
}

/// Resolve mailbox local-part. Convention: user_id = `admin` (not admin@misfits.ai).
fn resolve_user_id(req: &actix_web::HttpRequest) -> String {
    if let Some(id) = req
        .headers()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return id.to_string();
    }
    if let Some(email) = req
        .headers()
        .get("x-user-email")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return email.split('@').next().unwrap_or(email).to_string();
    }
    env::var("SMTP_USERNAME").unwrap_or_else(|_| "admin".to_string())
}

// --- TOTP helpers (RFC 6238) ---

fn compute_hotp(key: &[u8], counter: u64) -> u32 {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);
    code % 1_000_000
}

fn verify_totp(secret_b32: &str, code: &str) -> bool {
    use constant_time_eq::constant_time_eq;
    let s = secret_b32.to_uppercase();
    let pad = s.len() % 8;
    let padded = if pad == 0 {
        s
    } else {
        format!("{}{}", s, "=".repeat(8 - pad))
    };
    let key = match BASE32.decode(padded.as_bytes()) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let t = Utc::now().timestamp() / 30;
    for delta in [-1i64, 0, 1] {
        let counter = (t + delta).max(0) as u64;
        let candidate = format!("{:06}", compute_hotp(&key, counter));
        if constant_time_eq(candidate.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

fn generate_totp_secret() -> String {
    BASE32.encode(Uuid::new_v4().as_bytes())
}

fn generate_otp_code() -> String {
    let b = Uuid::new_v4();
    let n = u32::from_be_bytes([
        b.as_bytes()[0],
        b.as_bytes()[1],
        b.as_bytes()[2],
        b.as_bytes()[3],
    ]);
    format!("{:06}", n % 1_000_000)
}

// --- 2FA verify (POST /api/auth/2fa/verify) ---

async fn api_2fa_verify(
    body: web::Json<TwoFactorVerifyRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = mongo_db_name();

    if body.method == "totp" {
        let coll = mongo.database(&db).collection::<bson::Document>("users");
        let local = body.email.split('@').next().unwrap_or(&body.email);
        let user_doc = match coll
            .find_one(doc! { "$or": [{ "username": local }, { "username": &body.email }] })
            .await
        {
            Ok(Some(d)) => d,
            Ok(None) => {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "verified": false, "error": "User not found"
                }))
            }
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": e.to_string() }))
            }
        };

        let totp_secret = match user_doc
            .get_str("totp_secret")
            .ok()
            .filter(|s| !s.is_empty())
        {
            Some(s) => s.to_string(),
            None => {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "verified": false, "error": "TOTP not configured for this user"
                }))
            }
        };

        if !verify_totp(&totp_secret, &body.code) {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "verified": false, "error": "Invalid TOTP code"
            }));
        }
    } else {
        // Email OTP: verify code stored in two_factor_codes collection
        let coll = mongo
            .database(&db)
            .collection::<bson::Document>("two_factor_codes");
        let now_ms = Utc::now().timestamp_millis();

        match coll
            .find_one(doc! {
                "email": &body.email,
                "code": &body.code,
                "used": false,
                "expires_at": { "$gt": bson::DateTime::from_millis(now_ms) },
            })
            .await
        {
            Ok(Some(d)) => {
                if let Ok(oid) = d.get_object_id("_id") {
                    let _ = coll
                        .update_one(doc! { "_id": oid }, doc! { "$set": { "used": true } })
                        .await;
                }
            }
            Ok(None) => {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "verified": false, "error": "Invalid or expired code"
                }))
            }
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": e.to_string() }))
            }
        }
    }

    let display = body
        .email
        .split('@')
        .next()
        .unwrap_or(&body.email)
        .to_string();
    let session = make_session(&body.email, &display);
    HttpResponse::Ok().json(serde_json::json!({ "verified": true, "session": session.session }))
}

// --- Password reset (POST /api/auth/password-reset/request + /confirm) ---

async fn api_password_reset_request(
    body: web::Json<PasswordResetRequestBody>,
    mongo: web::Data<Arc<mongodb::Client>>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let db = mongo_db_name();
    let email = body.email.trim().to_lowercase();
    let local = email.split('@').next().unwrap_or(&email).to_string();

    let users_coll = mongo.database(&db).collection::<bson::Document>("users");
    let user_exists = matches!(
        users_coll
            .find_one(doc! { "$or": [{ "username": &local }, { "username": &email }] })
            .await,
        Ok(Some(_))
    );

    // Always return 200 to avoid user enumeration
    if !user_exists {
        return HttpResponse::Ok().json(serde_json::json!({
            "message": "If the address is registered, a reset link has been sent."
        }));
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = bson::DateTime::from_millis(Utc::now().timestamp_millis() + 3_600_000); // 1 hour

    let tokens_coll = mongo
        .database(&db)
        .collection::<bson::Document>("password_reset_tokens");
    // Invalidate any previous pending tokens for this email
    let _ = tokens_coll
        .update_many(
            doc! { "email": &email, "used": false },
            doc! { "$set": { "used": true } },
        )
        .await;

    if let Err(e) = tokens_coll
        .insert_one(doc! {
            "token": &token,
            "email": &email,
            "expires_at": expires_at,
            "used": false,
        })
        .await
    {
        eprintln!("password_reset_request insert error: {}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Failed to create reset token" }));
    }

    let frontend_url =
        env::var("FRONTEND_URL").unwrap_or_else(|_| "https://app.misfits.ai".to_string());
    let reset_url = format!("{}/auth/reset-password?token={}", frontend_url, token);
    let body_html = format!(
        "<p>Click <a href=\"{url}\">here</a> to reset your password. This link expires in 1 hour.</p>\
         <p>Or copy this link: {url}</p>",
        url = reset_url
    );
    let reset_email = Email {
        id: Uuid::new_v4().to_string(),
        from: "noreply@misfits.ai".to_string(),
        to: email.clone(),
        subject: "Password Reset Request".to_string(),
        body: body_html,
        headers: vec![(
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        )],
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: None,
    };
    if let Err(e) = logic.deliver_to_inbox(&local, &reset_email).await {
        eprintln!("password reset email delivery error: {}", e);
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "If the address is registered, a reset link has been sent."
    }))
}

async fn api_password_reset_confirm(
    body: web::Json<PasswordResetConfirmBody>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if body.new_password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "Password must be at least 8 characters" }));
    }

    let db = mongo_db_name();
    let tokens_coll = mongo
        .database(&db)
        .collection::<bson::Document>("password_reset_tokens");
    let now_ms = Utc::now().timestamp_millis();

    let token_doc = match tokens_coll
        .find_one(doc! {
            "token": &body.token,
            "used": false,
            "expires_at": { "$gt": bson::DateTime::from_millis(now_ms) },
        })
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Invalid or expired token" }))
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() }))
        }
    };

    let email = match token_doc.get_str("email") {
        Ok(e) => e.to_string(),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Token data corrupted" }))
        }
    };
    let local = email.split('@').next().unwrap_or(&email).to_string();

    let new_password = body.new_password.clone();
    let password_hash = match web::block(move || bcrypt::hash(&new_password, 12)).await {
        Ok(Ok(h)) => h,
        _ => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Password hashing failed" }))
        }
    };

    let users_coll = mongo.database(&db).collection::<bson::Document>("users");
    match users_coll
        .update_one(
            doc! { "$or": [{ "username": &local }, { "username": &email }] },
            doc! { "$set": { "password": &password_hash } },
        )
        .await
    {
        Ok(r) if r.matched_count == 0 => {
            return HttpResponse::NotFound().json(serde_json::json!({ "error": "User not found" }))
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() }))
        }
        _ => {}
    }

    // Invalidate the token
    if let Ok(oid) = token_doc.get_object_id("_id") {
        let _ = tokens_coll
            .update_one(doc! { "_id": oid }, doc! { "$set": { "used": true } })
            .await;
    }

    HttpResponse::Ok().json(serde_json::json!({ "message": "Password updated successfully" }))
}

#[derive(Serialize)]
struct EmailAddressDto {
    name: String,
    address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailDto {
    id: String,
    thread_id: String,
    folder: String,
    from: EmailAddressDto,
    to: Vec<EmailAddressDto>,
    subject: String,
    preview: String,
    body: String,
    body_type: String,
    date: String,
    received_at: String,
    is_read: bool,
    is_starred: bool,
    is_important: bool,
    has_attachments: bool,
    attachments: Vec<serde_json::Value>,
    labels: Vec<String>,
    size: u64,
    message_id: String,
}

fn parse_address(raw: &str) -> EmailAddressDto {
    let raw = raw.trim();
    // "Name <addr@x>" or bare addr. Guard against malformed inputs where
    // '>' appears before '<' (e.g. `">" <admin@misfits.ai`) — naive slicing
    // panics on start > end. Pick the last '<' and the matching '>' after it.
    if let Some(start) = raw.rfind('<') {
        // Only treat as bracketed form when a '>' exists AFTER the '<'.
        if let Some(rel_end) = raw[start + 1..].find('>') {
            let end = start + 1 + rel_end;
            let name = raw[..start].trim().trim_matches('"').trim().to_string();
            let address = raw[start + 1..end].trim().to_string();
            if !address.is_empty() {
                return EmailAddressDto {
                    name: if name.is_empty() {
                        address.split('@').next().unwrap_or("").to_string()
                    } else {
                        name
                    },
                    address,
                };
            }
        }
    }
    // Bare address fallback: strip any stray angle brackets/quotes.
    let cleaned = raw
        .trim_matches(|c| c == '<' || c == '>' || c == '"')
        .trim();
    EmailAddressDto {
        name: cleaned.split('@').next().unwrap_or(cleaned).to_string(),
        address: cleaned.to_string(),
    }
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn email_to_dto(email: &Email, folder: &str, include_body: bool) -> EmailDto {
    let flags_l: Vec<String> = email.flags.iter().map(|f| f.to_ascii_lowercase()).collect();
    let is_read = flags_l.iter().any(|f| f == "seen" || f == "\\seen");
    let is_starred = flags_l
        .iter()
        .any(|f| f == "flagged" || f == "\\flagged" || f == "starred");
    let body_type = if email.body.to_ascii_lowercase().contains("<html")
        || email.body.contains("</")
        || email.body.contains("<p")
    {
        "html"
    } else {
        "text"
    };
    let plain = if body_type == "html" {
        strip_tags(&email.body)
    } else {
        email.body.clone()
    };
    let preview: String = plain.chars().take(160).collect();
    let date = {
        let ms = email.internal_date.timestamp_millis();
        chrono::DateTime::from_timestamp_millis(ms)
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(|| Utc::now().to_rfc3339())
    };
    // SMTP/Nodemailer inbound often leaves `id` blank and packs DKIM-/Message-ID
    // into weird header tuples ("Message-ID: <...>", "Message-ID: <...>").
    let message_id = email
        .headers
        .iter()
        .find_map(|(k, v)| {
            if k.eq_ignore_ascii_case("message-id") && !v.is_empty() {
                Some(v.clone())
            } else if k.to_ascii_lowercase().starts_with("message-id:") {
                let val = k.splitn(2, ':').nth(1).unwrap_or("").trim();
                if !val.is_empty() {
                    Some(val.to_string())
                } else if !v.is_empty() {
                    Some(v.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if !email.id.is_empty() {
                email.id.clone()
            } else if email.uid > 0 {
                format!("uid-{}", email.uid)
            } else {
                Uuid::new_v4().to_string()
            }
        });
    let id = if email.id.is_empty() {
        message_id
            .trim_matches(|c| c == '<' || c == '>')
            .to_string()
    } else {
        email.id.clone()
    };
    let to_list: Vec<EmailAddressDto> = email
        .to
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_address)
        .collect();
    EmailDto {
        id,
        thread_id: message_id.clone(),
        folder: folder.to_ascii_lowercase(),
        from: parse_address(&email.from),
        to: to_list,
        subject: email.subject.clone(),
        preview,
        // List payloads stay lean — detail fetch fills body via GET /api/emails/:id
        body: if include_body {
            email.body.clone()
        } else {
            String::new()
        },
        body_type: body_type.to_string(),
        date: date.clone(),
        received_at: date,
        is_read,
        is_starred,
        is_important: false,
        has_attachments: false,
        attachments: vec![],
        labels: vec![],
        size: email.body.len() as u64,
        message_id,
    }
}

fn email_to_list_dto(email: &Email, folder: &str) -> EmailDto {
    email_to_dto(email, folder, false)
}

fn email_to_detail_dto(email: &Email, folder: &str) -> EmailDto {
    email_to_dto(email, folder, true)
}

async fn api_emails(
    query: web::Query<EmailListQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let folder = query.folder.trim().to_ascii_lowercase();
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    // Over-fetch a single page-sized chunk per mailbox candidate, then merge.
    // Skip huge dumps: limit from Mongo already newest-first.
    let fetch_limit = (page_size as i64)
        .saturating_mul(page as i64)
        .max(page_size as i64);

    let mut collected: Vec<Email> = Vec::new();
    for mailbox in folder_to_mailboxes(&folder) {
        match logic
            .get_emails_page(&user_id, &mailbox, fetch_limit, 0)
            .await
        {
            Ok(mut batch) => {
                collected.append(&mut batch);
            }
            Err(e) => {
                eprintln!("get_emails user={} mailbox={}: {}", user_id, mailbox, e);
            }
        }
    }

    // Newest first (Mongo sort already does this; keep stable merge)
    collected.sort_by(|a, b| b.internal_date.cmp(&a.internal_date));
    // Dedup by id / message-id fallback
    let mut seen = std::collections::HashSet::new();
    collected.retain(|e| {
        let key = if e.id.is_empty() {
            format!(
                "{}|{}|{}",
                e.from,
                e.subject,
                e.internal_date.timestamp_millis()
            )
        } else {
            e.id.clone()
        };
        seen.insert(key)
    });

    let total = collected.len() as u32;
    let start = ((page - 1) * page_size) as usize;
    let page_items: Vec<EmailDto> = collected
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .map(|e| email_to_list_dto(&e, &folder))
        .collect();
    let has_more = start + page_items.len() < total as usize;

    HttpResponse::Ok().json(serde_json::json!({
        "emails": page_items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "hasMore": has_more,
    }))
}

async fn api_tags() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"tags": []}))
}

// --- Send + get-by-id (Phase A3/A4, issues #168/#169) -------------------------

#[derive(Deserialize)]
struct ComposerRecipient {
    #[serde(default)]
    email: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct ComposeSendRequest {
    #[serde(default)]
    to: Vec<ComposerRecipient>,
    #[serde(default)]
    cc: Vec<ComposerRecipient>,
    #[serde(default)]
    bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    /// Some FE clients send flat strings instead of recipient objects.
    #[serde(default)]
    from: Option<String>,
}

fn format_recipient(r: &ComposerRecipient) -> Option<String> {
    let email = r.email.trim();
    if email.is_empty() {
        return None;
    }
    match r.name.as_ref().map(|n| n.trim()).filter(|n| !n.is_empty()) {
        Some(name) => Some(format!("{} <{}>", name, email)),
        None => Some(email.to_string()),
    }
}

fn join_recipients(list: &[ComposerRecipient]) -> String {
    list.iter()
        .filter_map(format_recipient)
        .collect::<Vec<_>>()
        .join(", ")
}

fn domain_from_env() -> String {
    env::var("DOMAIN_NAME").unwrap_or_else(|_| "misfits.ai".to_string())
}

fn from_address_for_user(user_id: &str) -> String {
    if user_id.contains('@') {
        user_id.to_string()
    } else {
        format!("{}@{}", user_id, domain_from_env())
    }
}

fn normalize_message_id(raw: &str) -> String {
    raw.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .to_string()
}

fn is_private_or_local_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast()
        }
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.is_unspecified(),
        Err(_) => false,
    }
}

fn is_internal_delivery_hop(
    mx_host: Option<&str>,
    remote_ip: Option<&str>,
    remote_port: Option<u16>,
    company: Option<&str>,
) -> bool {
    let host_internal = mx_host
        .map(|h| {
            let h = h.to_ascii_lowercase();
            h == "smtp-server" || h.ends_with(".local") || h.ends_with(".internal")
        })
        .unwrap_or(false);

    let ip_internal = remote_ip.map(is_private_or_local_ip).unwrap_or(false);
    let relay_port = matches!(remote_port, Some(8025 | 8465));
    let company_internal = company
        .map(|c| c.eq_ignore_ascii_case("dkim-service"))
        .unwrap_or(false);

    host_internal || ip_internal || (company_internal && relay_port)
}

async fn api_send(
    body: web::Json<ComposeSendRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "sent": false,
            "message": "At least one recipient (to) is required",
        }));
    }
    let cc = join_recipients(&body.cc);
    let bcc = join_recipients(&body.bcc);
    let subject = body.subject.clone();
    let mail_body = body.body.clone();

    let email_req = EmailRequest {
        from: from.clone(),
        to: to.clone(),
        subject: subject.clone(),
        body: mail_body.clone(),
    };

    // DKIM sign via shared service (same path as /send-email).
    // Note: studious-octo-rotary-phone exposes POST /generate-dkim and may
    // both sign and deliver via Nodemailer — when no dkimSignature is
    // returned we treat success as "already delivered by dkim-service".
    let dkim_service: Box<dyn DkimService> = Box::new(RealDkimService);
    let (
        dkim_sig,
        message_id_hdr,
        already_delivered,
        dkim_remote_accepted,
        dkim_remote_rejected,
        dkim_response,
        dkim_mx_host,
        dkim_remote_ip,
        dkim_remote_port,
    ) = match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            let status = dkim_result["status"].as_str().unwrap_or("");
            if status != "success" {
                let msg = dkim_result["message"]
                    .as_str()
                    .or_else(|| dkim_result["error"].as_str())
                    .unwrap_or("DKIM signing failed");
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "sent": false,
                    "message": format!("Failed to sign email: {}", msg),
                }));
            }

            let sig = dkim_result["dkimSignature"]
                .as_str()
                .or_else(|| dkim_result["dkim_signature"].as_str())
                .unwrap_or("")
                .to_string();
            let mid = dkim_result["messageId"]
                .as_str()
                .or_else(|| dkim_result["message_id"].as_str())
                .unwrap_or("")
                .to_string();

            let accepted_by_remote_mx =
                dkim_result["acceptedByRemoteMx"].as_bool().unwrap_or(false)
                    || dkim_result["accepted"]
                        .as_array()
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
            let rejected_by_remote_mx = dkim_result["rejected"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let upstream_response = dkim_result["response"].as_str().map(|s| s.to_string());
            let upstream_mx_host = dkim_result["smtpHost"].as_str().map(|s| s.to_string());
            let upstream_remote_ip = dkim_result["remoteIp"].as_str().map(|s| s.to_string());
            let upstream_remote_port = dkim_result["smtpPort"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok());

            // Distinguish true remote-MX acceptance from internal relay handoff.
            let internal_hop = is_internal_delivery_hop(
                upstream_mx_host.as_deref(),
                upstream_remote_ip.as_deref(),
                upstream_remote_port,
                Some("dkim-service"),
            );
            let effective_remote_accept = accepted_by_remote_mx && !internal_hop;

            // No DKIM signature means dkim-service likely performed SMTP itself.
            // Accept this path only with explicit SMTP handoff proof (`accepted*`).
            // We still keep `effective_remote_accept` separate so status can tell
            // true remote MX acceptance from internal relay handoff.
            let delivered = sig.is_empty() && accepted_by_remote_mx;
            if sig.is_empty() && !delivered {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                        "sent": false,
                        "message": "DKIM signer returned success without signature and without SMTP handoff proof; refusing unsigned send",
                    }));
            }
            (
                sig,
                mid,
                delivered,
                effective_remote_accept,
                rejected_by_remote_mx,
                upstream_response,
                upstream_mx_host,
                upstream_remote_ip,
                upstream_remote_port,
            )
        }
        Err(e) => {
            eprintln!("DKIM service error on /api/send: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "message": format!("Failed to generate DKIM signature: {}", e),
            }));
        }
    };

    let id = Uuid::new_v4().to_string();
    let message_id = if message_id_hdr.is_empty() {
        format!("<{}@{}>", id, domain_from_env())
    } else if message_id_hdr.starts_with('<') {
        message_id_hdr.clone()
    } else {
        format!("<{}>", message_id_hdr)
    };

    let mut headers = vec![
        ("Message-ID".to_string(), message_id.clone()),
        ("Date".to_string(), Utc::now().to_rfc2822()),
        ("MIME-Version".to_string(), "1.0".to_string()),
        (
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        ),
    ];
    if !cc.is_empty() {
        headers.push(("Cc".to_string(), cc.clone()));
    }
    if !bcc.is_empty() {
        // Envelope Bcc isn't fully separated yet; record header for stored copy only if present.
        headers.push(("Bcc".to_string(), bcc.clone()));
    }
    if !dkim_sig.is_empty() {
        headers.push(("DKIM-Signature".to_string(), dkim_sig.clone()));
    }

    let email = Email {
        id: id.clone(),
        from: from.clone(),
        to: to.clone(),
        subject: subject.clone(),
        body: mail_body.clone(),
        headers,
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        dkim_signature: if dkim_sig.is_empty() {
            None
        } else {
            Some(dkim_sig)
        },
    };

    // If the DKIM service already delivered the message (success response
    // without a dkim signature), skip direct SMTP relay. This prevents false
    // negatives when relay ports are closed but delivery already happened.

    // Undo window: queue the email instead of sending immediately.
    let undo_window_secs = env::var("SEND_UNDO_WINDOW_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    if undo_window_secs > 0 && !already_delivered {
        let send_after = bson::DateTime::from_millis(
            Utc::now().timestamp_millis() + (undo_window_secs as i64 * 1000),
        );
        let queue_doc = doc! {
            "id": &id,
            "user_id": &user_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &subject,
            "body": &mail_body,
            "dkim_signature": email.dkim_signature.as_deref().unwrap_or(""),
            "message_id": &message_id,
            "status": "pending",
            "send_after": send_after,
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        };
        let db = mongo_db_name();
        let sq_coll = mongo
            .database(&db)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        return match sq_coll.insert_one(queue_doc).await {
            Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                "sent": false,
                "queued": true,
                "id": id,
                "messageId": message_id,
                "deliveryState": "pending",
                "undoWindowSecs": undo_window_secs,
            })),
            Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false, "error": e.to_string()
            })),
        };
    }

    let send_result = if already_delivered {
        Ok(())
    } else {
        send_outgoing_email(&email).await
    };

    match send_result {
        Ok(_) => {
            if already_delivered && monitoring::monitoring_enabled() {
                // DKIM service did the SMTP handoff/delivery itself. Persist an
                // explicit monitoring event so trace API/status API can surface
                // whether upstream accepted recipient(s).
                let mut ev = monitoring::SmtpEvent::new(
                    &normalize_message_id(&message_id),
                    if dkim_remote_accepted {
                        monitoring::SmtpEventType::Delivered
                    } else {
                        monitoring::SmtpEventType::Queued
                    },
                    &from,
                    &to,
                );

                ev.status = if dkim_remote_accepted {
                    monitoring::SmtpStatus::Delivered
                } else if dkim_remote_rejected {
                    monitoring::SmtpStatus::Bounced
                } else {
                    monitoring::SmtpStatus::Pending
                };

                ev.company = Some("dkim-service".to_string());
                ev.mx_host = dkim_mx_host;
                ev.remote_ip = dkim_remote_ip;
                ev.remote_port = dkim_remote_port;
                ev.smtp_reply = dkim_response.or_else(|| {
                    Some(
                        if dkim_remote_accepted {
                            "Upstream SMTP accepted by DKIM service"
                        } else if dkim_remote_rejected {
                            "Upstream SMTP rejected recipient in DKIM service"
                        } else {
                            "Handoff accepted by DKIM service (remote mailbox receipt not independently verified)"
                        }
                        .to_string(),
                    )
                });
                monitoring::emit(ev);
            }

            // Store Sent copy for the sender. Local-domain inbox copies come
            // exclusively from SMTP inbound (Nodemailer/dkim or MX self-delivery)
            // to avoid duplicate messages.
            if let Err(e) = logic.store_email(&user_id, "sent", &email).await {
                eprintln!("store sent copy failed: {}", e);
            }
            emit_event(
                &bus,
                &mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Sent,
                    user_id: user_id.clone(),
                    email_id: id.clone(),
                    subject: subject.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let delivery_state = if dkim_remote_rejected {
                "failed"
            } else if dkim_remote_accepted {
                "sent"
            } else if already_delivered {
                "queued"
            } else {
                "sending"
            };

            HttpResponse::Ok().json(serde_json::json!({
                "sent": true,
                "id": id,
                "messageId": message_id,
                "deliveryState": delivery_state,
            }))
        }
        Err(e) => {
            eprintln!("send_outgoing_email failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "sent": false,
                "deliveryState": "failed",
                "message": format!("Failed to send email: {}", e),
            }))
        }
    }
}

// --- Send undo (POST /api/send/undo) ---

async fn api_send_undo(
    body: web::Json<UndoSendRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
    match coll
        .update_one(
            doc! {
                "id": &body.id,
                "user_id": &user_id,
                "status": "pending",
                "send_after": { "$gt": now },
            },
            doc! { "$set": { "status": "cancelled" } },
        )
        .await
    {
        Ok(r) if r.matched_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "cancelled": true, "id": &body.id }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "cancelled": false,
            "reason": "Email not found, already sent, or undo window has passed"
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

// --- Send schedule (POST /api/send/schedule) ---

async fn api_send_schedule(
    body: web::Json<ScheduleSendBody>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);

    let to = join_recipients(&body.to);
    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one recipient (to) is required"
        }));
    }

    let send_at = match chrono::DateTime::parse_from_rfc3339(&body.send_at) {
        Ok(dt) => dt,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": "Invalid send_at: use ISO 8601 format" }))
        }
    };
    if send_at.timestamp() <= Utc::now().timestamp() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "send_at must be in the future" }));
    }

    let from = body
        .from
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| from_address_for_user(&user_id));
    let cc = join_recipients(&body.cc);
    let bcc = join_recipients(&body.bcc);

    let id = Uuid::new_v4().to_string();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match coll
        .insert_one(doc! {
            "id": &id,
            "user_id": &user_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &body.subject,
            "body": &body.body,
            "dkim_signature": "",
            "message_id": format!("<{}@{}>", &id, domain_from_env()),
            "status": "scheduled",
            "send_after": bson::DateTime::from_millis(send_at.timestamp_millis()),
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        })
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "queued": true, "id": id, "sendAt": body.send_at
        })),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

// --- Send queue background worker ---

async fn send_queue_worker(mongo: Arc<mongodb::Client>) {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let coll = mongo
            .database(&db_name)
            .collection::<bson::Document>(SEND_QUEUE_COLL);
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());

        let cursor = match coll
            .find(doc! {
                "status": { "$in": ["pending", "scheduled"] },
                "send_after": { "$lte": now },
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("send_queue_worker find error: {}", e);
                continue;
            }
        };

        let entries = match cursor.try_collect::<Vec<bson::Document>>().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("send_queue_worker collect error: {}", e);
                continue;
            }
        };

        for entry in entries {
            let id = entry.get_str("id").unwrap_or("").to_string();
            let from = entry.get_str("from").unwrap_or("").to_string();
            let to = entry.get_str("to").unwrap_or("").to_string();
            let subject = entry.get_str("subject").unwrap_or("").to_string();
            let body_text = entry.get_str("body").unwrap_or("").to_string();
            let cc = entry.get_str("cc").unwrap_or("").to_string();
            let bcc = entry.get_str("bcc").unwrap_or("").to_string();
            let dkim_sig = entry.get_str("dkim_signature").unwrap_or("").to_string();
            let message_id = entry.get_str("message_id").unwrap_or("").to_string();

            // Optimistic lock: claim entry before sending
            let claim = coll
                .update_one(
                    doc! { "id": &id, "status": { "$in": ["pending", "scheduled"] } },
                    doc! { "$set": { "status": "sending" } },
                )
                .await;
            match claim {
                Ok(r) if r.matched_count == 0 => continue,
                Err(e) => {
                    eprintln!("send_queue claim error for {}: {}", id, e);
                    continue;
                }
                _ => {}
            }

            let mut headers = vec![
                (
                    "Message-ID".to_string(),
                    if message_id.is_empty() {
                        format!(
                            "<{}@{}>",
                            id,
                            std::env::var("DOMAIN_NAME")
                                .unwrap_or_else(|_| "misfits.ai".to_string())
                        )
                    } else {
                        message_id
                    },
                ),
                ("Date".to_string(), Utc::now().to_rfc2822()),
                ("MIME-Version".to_string(), "1.0".to_string()),
                (
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
            ];
            if !cc.is_empty() {
                headers.push(("Cc".to_string(), cc));
            }
            if !bcc.is_empty() {
                headers.push(("Bcc".to_string(), bcc));
            }
            if !dkim_sig.is_empty() {
                headers.push(("DKIM-Signature".to_string(), dkim_sig.clone()));
            }

            let email = Email {
                id: id.clone(),
                from,
                to,
                subject,
                body: body_text,
                headers,
                flags: vec![],
                sequence_number: 0,
                uid: 0,
                internal_date: bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                dkim_signature: if dkim_sig.is_empty() {
                    None
                } else {
                    Some(dkim_sig)
                },
            };

            let status = match send_outgoing_email(&email).await {
                Ok(_) => "sent",
                Err(e) => {
                    eprintln!("send_queue_worker send error for {}: {}", id, e);
                    "failed"
                }
            };

            let _ = coll
                .update_one(doc! { "id": &id }, doc! { "$set": { "status": status } })
                .await;
        }
    }
}

async fn api_send_status(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();

    let email = match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => email,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Email not found"
            }))
        }
        Err(e) => {
            eprintln!("api_send_status fetch_email error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch email"
            }));
        }
    };

    let message_id_header = email
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("message-id"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let message_id = normalize_message_id(&message_id_header);
    if message_id.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!({
            "id": email.id,
            "message": "No Message-ID found",
            "monitoring": {
                "traceable": false
            }
        }));
    }

    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("smtp_events");

    let events = match coll
        .find(doc! { "message_id": &message_id })
        .sort(doc! { "ts": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<_>>()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|d| bson::from_document::<monitoring::SmtpEvent>(d).ok())
            .collect::<Vec<_>>(),
        Err(e) => {
            eprintln!("api_send_status query smtp_events error: {}", e);
            vec![]
        }
    };

    let accepted_by_remote_mx = events.iter().any(|e| {
        matches!(e.event_type, monitoring::SmtpEventType::Delivered)
            && matches!(e.status, monitoring::SmtpStatus::Delivered)
            && !is_internal_delivery_hop(
                e.mx_host.as_deref(),
                e.remote_ip.as_deref(),
                e.remote_port,
                e.company.as_deref(),
            )
    });
    let bounced_or_failed = events.iter().any(|e| {
        matches!(
            e.status,
            monitoring::SmtpStatus::Bounced | monitoring::SmtpStatus::Failed
        )
    });
    let saw_internal_handoff = events.iter().any(|e| {
        is_internal_delivery_hop(
            e.mx_host.as_deref(),
            e.remote_ip.as_deref(),
            e.remote_port,
            e.company.as_deref(),
        )
    });
    let handoff_only = !accepted_by_remote_mx && !bounced_or_failed && saw_internal_handoff;

    let latest = events
        .iter()
        .find(|e| {
            matches!(
                e.status,
                monitoring::SmtpStatus::Delivered
                    | monitoring::SmtpStatus::Bounced
                    | monitoring::SmtpStatus::Failed
                    | monitoring::SmtpStatus::Deferred
            )
        })
        .or_else(|| events.first());
    let delivery_state = if accepted_by_remote_mx {
        "sent"
    } else if bounced_or_failed {
        "failed"
    } else if handoff_only {
        "queued"
    } else {
        "sending"
    };

    HttpResponse::Ok().json(serde_json::json!({
        "id": email.id,
        "messageId": message_id,
        "deliveryState": delivery_state,
        "from": email.from,
        "to": email.to,
        "subject": email.subject,
        "monitoring": {
            "traceable": true,
            "events": events.len(),
            "acceptedByRemoteMx": accepted_by_remote_mx,
            "bouncedOrFailed": bounced_or_failed,
            "handoffOnly": handoff_only,
            "latestEventType": latest.map(|e| format!("{:?}", e.event_type)),
            "latestStatus": latest.map(|e| format!("{:?}", e.status)),
            "latestSmtpCode": latest.and_then(|e| e.smtp_code),
            "latestSmtpReply": latest.and_then(|e| e.smtp_reply.clone()),
            "traceEndpoint": format!("/api/monitoring/messages/{}/trace", message_id),
            "note": if accepted_by_remote_mx {
                "Remote MX accepted the message (strong delivery signal)."
            } else if handoff_only {
                "Message handed off to DKIM service; remote mailbox receipt is not independently verified yet."
            } else if bounced_or_failed {
                "SMTP monitoring reports bounce/failure events."
            } else {
                "No conclusive delivery signal yet."
            }
        }
    }))
}

async fn api_email_by_id(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();
    match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => {
            emit_event(
                &bus,
                &mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Read,
                    user_id: user_id.clone(),
                    email_id: email.id.clone(),
                    subject: email.subject.clone(),
                    from: email.from.clone(),
                    to: email.to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let dto = email_to_detail_dto(&email, "inbox");
            HttpResponse::Ok().json(dto)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("fetch_email error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch email",
            }))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailActionRequest {
    action: String,
    #[serde(default)]
    target_folder: Option<String>,
}

async fn api_email_action(
    path: web::Path<String>,
    body: web::Json<EmailActionRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();
    let action = body.action.trim().to_ascii_lowercase();

    let result = match action.as_str() {
        "archive" => logic.move_email_to_mailbox(&user_id, &email_id, "archive").await,
        "trash" | "delete" => logic.move_email_to_mailbox(&user_id, &email_id, "trash").await,
        "restore" => logic.move_email_to_mailbox(&user_id, &email_id, "inbox").await,
        "move" => {
            let Some(target) = body
                .target_folder
                .as_ref()
                .and_then(|f| canonical_folder(f))
            else {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "ok": false,
                    "message": "targetFolder must be one of inbox|sent|drafts|archive|trash|spam",
                }));
            };
            logic.move_email_to_mailbox(&user_id, &email_id, &target).await
        }
        "markread" => logic.set_email_read(&user_id, &email_id, true).await,
        "markunread" => logic.set_email_read(&user_id, &email_id, false).await,
        "star" => logic.set_email_starred(&user_id, &email_id, true).await,
        "unstar" => logic.set_email_starred(&user_id, &email_id, false).await,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "message": "Unsupported action. Use move|archive|trash|delete|restore|markRead|markUnread|star|unstar",
            }))
        }
    };

    match result {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "id": email_id,
            "action": body.action,
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "ok": false,
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("api_email_action error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "message": "Failed to apply email action",
            }))
        }
    }
}

async fn api_drafts_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "updatedAt": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => {
            let mut drafts: Vec<serde_json::Value> = Vec::new();
            for mut docu in cursor
                .try_collect::<Vec<bson::Document>>()
                .await
                .unwrap_or_default()
            {
                docu.remove("_id");
                docu.remove("user_id");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu)) {
                    drafts.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({"drafts": drafts}))
        }
        Err(e) => {
            eprintln!("api_drafts_list error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to load drafts",
            }))
        }
    }
}

async fn api_drafts_upsert(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let Some(mut obj) = body.as_object().cloned() else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Invalid draft payload",
        }));
    };

    let draft_id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let now = Utc::now().to_rfc3339();
    obj.insert(
        "id".to_string(),
        serde_json::Value::String(draft_id.clone()),
    );
    obj.insert(
        "updatedAt".to_string(),
        serde_json::Value::String(now.clone()),
    );
    if !obj.contains_key("createdAt") {
        obj.insert(
            "createdAt".to_string(),
            serde_json::Value::String(now.clone()),
        );
    }

    let draft_value = serde_json::Value::Object(obj.clone());
    let mut draft_doc = match bson::to_document(&draft_value) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("api_drafts_upsert serialize error: {}", e);
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Draft payload is not serializable",
            }));
        }
    };
    draft_doc.insert("user_id", user_id.clone());
    // Avoid Mongo update conflict between $set and $setOnInsert on createdAt.
    draft_doc.remove("createdAt");

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    let created_at = obj
        .get("createdAt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| now.clone());
    let mut set_on_insert = bson::Document::new();
    set_on_insert.insert("createdAt", created_at);

    match coll
        .update_one(
            doc! { "user_id": &user_id, "id": &draft_id },
            doc! {
                "$set": draft_doc,
                "$setOnInsert": set_on_insert,
            },
        )
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(draft_value),
        Err(e) => {
            eprintln!("api_drafts_upsert db error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to save draft",
            }))
        }
    }
}

async fn api_drafts_delete(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let draft_id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    match coll
        .delete_one(doc! { "user_id": &user_id, "id": &draft_id })
        .await
    {
        Ok(r) if r.deleted_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "deleted": true,
            "id": draft_id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "deleted": false,
            "message": "Draft not found",
        })),
        Err(e) => {
            eprintln!("api_drafts_delete error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to delete draft",
            }))
        }
    }
}

const ADMIN_USERS_COLL: &str = "admin_users";
const ADMIN_CHANGE_REQUESTS_COLL: &str = "admin_change_requests";

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

fn admin_workflow_order() -> Vec<&'static str> {
    vec![
        "submitted",
        "triaged",
        "planned",
        "in_progress",
        "qa",
        "released",
    ]
}

fn compute_priority(urgency: &str, impact: &str) -> String {
    if urgency == "high" && impact == "high" {
        "P0".to_string()
    } else if urgency == "high" || impact == "high" {
        "P1".to_string()
    } else {
        "P2".to_string()
    }
}

fn build_initial_stages() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage {
            key: "discovery".to_string(),
            label: "Discovery produit".to_string(),
            owner: "product".to_string(),
            status: "active".to_string(),
            checklist: vec![
                "Clarifier le problème utilisateur".to_string(),
                "Mesurer impact business/ops".to_string(),
                "Valider la portée UX + Backend".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "spec".to_string(),
            label: "Spécification".to_string(),
            owner: "backend".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Définir contrat API + payload".to_string(),
                "Définir telemetry & changelog".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "build".to_string(),
            label: "Implémentation".to_string(),
            owner: "frontend".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Implémenter UI/UX".to_string(),
                "Implémenter endpoint backend".to_string(),
                "Ajouter tests critiques".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "qa".to_string(),
            label: "Validation".to_string(),
            owner: "qa".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Typecheck + lint + tests".to_string(),
                "Validation de non-régression admin".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "release".to_string(),
            label: "Rollout".to_string(),
            owner: "ops".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Publier changelog".to_string(),
                "Surveiller métriques post-release".to_string(),
                "Préparer rollback playbook".to_string(),
            ],
            done_at: None,
        },
    ]
}

fn build_acceptance_criteria(scope: &str) -> Vec<String> {
    let mut base = vec![
        "Le flux admin expose un état lisible de la demande".to_string(),
        "Le backend retourne un état workflow déterministe".to_string(),
        "Le changement apparaît dans le flux changelog une fois released".to_string(),
    ];

    if scope == "ux" || scope == "fullstack" {
        base.push("Parcours UX sans ambiguïté: soumission -> triage -> release".to_string());
    }
    if scope == "backend" || scope == "fullstack" {
        base.push("Contrat API versionné et validé sur payloads invalides".to_string());
    }
    if scope == "security" {
        base.push("Audit trail incluant owner, horodatage et note de transition".to_string());
    }

    base
}

fn advance_workflow(stages: &[WorkflowStage]) -> Vec<WorkflowStage> {
    let now = now_iso();
    let current_idx = stages.iter().position(|s| s.status == "active");
    if current_idx.is_none() {
        return stages.to_vec();
    }
    let current_idx = current_idx.unwrap();
    stages
        .iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == current_idx {
                let mut done = stage.clone();
                done.status = "done".to_string();
                done.done_at = Some(now.clone());
                done
            } else if idx == current_idx + 1 {
                let mut active = stage.clone();
                active.status = "active".to_string();
                active
            } else {
                stage.clone()
            }
        })
        .collect()
}

fn status_counts(items: &[ChangeRequestItem]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for status in [
        "submitted",
        "triaged",
        "planned",
        "in_progress",
        "qa",
        "released",
        "rejected",
    ] {
        map.insert(status.to_string(), serde_json::Value::from(0));
    }
    for item in items {
        if let Some(v) = map.get_mut(&item.status) {
            let next = v.as_i64().unwrap_or(0) + 1;
            *v = serde_json::Value::from(next);
        }
    }
    serde_json::Value::Object(map)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateAdminUserInput {
    id: Option<String>,
    email: String,
    display_name: Option<String>,
    role: String,
    status: Option<String>,
    two_factor_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateAdminUserInput {
    role: Option<String>,
    status: Option<String>,
    // PR3 — champs additionnels supportés par PATCH
    email: Option<String>,
    display_name: Option<String>,
    two_factor_enabled: Option<bool>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateChangeRequestInputApi {
    title: String,
    problem: String,
    desired_outcome: String,
    scope: String,
    urgency: String,
    impact: String,
    requested_by: String,
    linked_repo: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchChangeRequestInputApi {
    action: Option<String>,
    note: Option<String>,
    actor: Option<String>,
    title: Option<String>,
    problem: Option<String>,
    desired_outcome: Option<String>,
    status: Option<String>,
    execution_run_id: Option<String>,
    execution_error: Option<String>,
}

async fn api_admin_users_list(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll
        .find(doc! {})
        .sort(doc! { "lastActivityAt": -1 })
        .limit(500)
        .await
    {
        Ok(cursor) => {
            let users = cursor
                .try_collect::<Vec<AdminUserRecord>>()
                .await
                .unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "generatedAt": now_iso(),
                "users": users,
            }))
        }
        Err(e) => {
            eprintln!("api_admin_users_list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load admin users" }))
        }
    }
}

async fn api_admin_user_get(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(user)) => HttpResponse::Ok().json(serde_json::json!({ "user": user })),
        Ok(None) => {
            HttpResponse::NotFound().json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_user_get error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }))
        }
    }
}

async fn api_admin_user_create(
    req: HttpRequest,
    body: web::Json<CreateAdminUserInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let role = body.role.trim().to_ascii_lowercase();
    if !["user", "admin", "support"].contains(&role.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "role must be user|admin|support" }));
    }

    let status = body
        .status
        .as_deref()
        .unwrap_or("active")
        .trim()
        .to_ascii_lowercase();
    if !["active", "restricted"].contains(&status.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "status must be active|restricted" }));
    }

    let id = body
        .id
        .clone()
        .unwrap_or_else(|| format!("u_{}", Uuid::new_v4().simple()));
    let now = now_iso();

    let user = AdminUserRecord {
        id: id.clone(),
        email: body.email.trim().to_string(),
        display_name: body.display_name.clone(),
        role,
        status,
        two_factor_enabled: body.two_factor_enabled.unwrap_or(false),
        last_login_at: None,
        last_activity_at: Some(now.clone()),
        sessions24h: 0,
        actions7d: 0,
        change_requests30d: 0,
        recent_activity: vec![AdminUserActivity {
            at: now.clone(),
            label: "User created".to_string(),
            kind: "admin_action".to_string(),
        }],
        created_at: now.clone(),
        updated_at: now,
        password_hash: None,
        invite_token: None,
        invite_expires_at: None,
        invited_at: None,
        notes: None,
    };

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll.insert_one(&user).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "user": user })),
        Err(e) => {
            eprintln!("api_admin_user_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create user" }))
        }
    }
}

async fn api_admin_user_patch(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UpdateAdminUserInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    let current = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_user_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    let now = now_iso();
    let mut updated = current.clone();

    if let Some(role) = &body.role {
        let role = role.trim().to_ascii_lowercase();
        if !["user", "admin", "support"].contains(&role.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "role must be user|admin|support" }));
        }
        updated.role = role;
    }

    if let Some(status) = &body.status {
        let status = status.trim().to_ascii_lowercase();
        if !["active", "restricted"].contains(&status.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "status must be active|restricted" }));
        }
        updated.status = status;
    }

    if let Some(email) = &body.email {
        let email = email.trim();
        if email.is_empty() || !email.contains('@') {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "invalid email" }));
        }
        updated.email = email.to_string();
    }
    if let Some(dn) = &body.display_name {
        let dn = dn.trim();
        updated.display_name = if dn.is_empty() {
            None
        } else {
            Some(dn.to_string())
        };
    }
    if let Some(v) = body.two_factor_enabled {
        updated.two_factor_enabled = v;
    }
    if let Some(notes) = &body.notes {
        let notes = notes.trim();
        if notes.len() > 1024 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "notes too long (max 1024)" }));
        }
        updated.notes = if notes.is_empty() {
            None
        } else {
            Some(notes.to_string())
        };
    }

    updated.updated_at = now.clone();
    updated.last_activity_at = Some(now.clone());
    updated.actions7d += 1;
    let note = body
        .role
        .as_ref()
        .map(|r| format!("Role changed to {}", r))
        .unwrap_or_else(|| "User updated".to_string());
    let mut recent = updated.recent_activity;
    recent.insert(
        0,
        AdminUserActivity {
            at: now,
            label: note,
            kind: "role_change".to_string(),
        },
    );
    recent.truncate(8);
    updated.recent_activity = recent;

    match coll
        .replace_one(doc! { "id": &id }, &updated)
        .upsert(false)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "user": updated })),
        Err(e) => {
            eprintln!("api_admin_user_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update user" }))
        }
    }
}

async fn api_admin_user_delete(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll.delete_one(doc! { "id": &id }).await {
        Ok(res) if res.deleted_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "deleted": true, "id": id }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "deleted": false, "message": "User not found" })),
        Err(e) => {
            eprintln!("api_admin_user_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete user" }))
        }
    }
}

/// PR1 (RBAC) — GET /api/admin/whoami
///
/// Utilisé par le frontend pour connaître le rôle réel de l'utilisateur
/// courant et adapter l'UI (viewer vs admin). Respecte le feature flag :
/// - RBAC OFF → répond `{ role: "admin", email: "system@...", enforced: false }`
///   (compat rétro : le front continue à voir un admin).
/// - RBAC ON  → nécessite un token valide, renvoie l'identité réelle.
async fn api_admin_whoami(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(user) => HttpResponse::Ok().json(serde_json::json!({
            "userId": user.user_id,
            "email": user.email,
            "role": user.role,
            "enforced": admin_auth::rbac_enabled(),
        })),
        Err(resp) => resp,
    }
}

// ================================================================
// PR3 — Comptes admin réels
// ================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResetPasswordInput {
    /// Optionnel — si non fourni, un mot de passe temporaire est généré.
    new_password: Option<String>,
    /// Si true, invalide toutes les sessions existantes en plus.
    #[serde(default)]
    revoke_sessions: bool,
}

/// POST /api/admin/users/{id}/invite
///
/// Génère un token d'invitation (UUID v4, 72h par défaut), le persiste
/// sur l'AdminUserRecord, et déclenche l'envoi d'un mail via le service
/// DKIM interne (best-effort — la réussite du POST ne dépend pas de
/// l'envoi effectif, on trace l'erreur mais on renvoie 200).
async fn api_admin_user_invite(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    let mut user = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("invite: find_one error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    let ttl_hours: i64 = env::var("ADMIN_INVITE_TTL_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(72);
    let expires = now + chrono::Duration::hours(ttl_hours);

    user.invite_token = Some(token.clone());
    user.invite_expires_at = Some(expires.to_rfc3339());
    user.invited_at = Some(now.to_rfc3339());
    user.updated_at = now.to_rfc3339();
    let mut recent = user.recent_activity.clone();
    recent.insert(
        0,
        AdminUserActivity {
            at: now.to_rfc3339(),
            label: "Invitation sent".to_string(),
            kind: "admin_action".to_string(),
        },
    );
    recent.truncate(8);
    user.recent_activity = recent;

    if let Err(e) = coll
        .replace_one(doc! { "id": &id }, &user)
        .upsert(false)
        .await
    {
        eprintln!("invite: replace_one error: {}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "message": "Failed to save invite" }));
    }

    // Envoi email best-effort via le service DKIM. On ne bloque pas la
    // réponse HTTP en cas d'erreur de la chaîne d'envoi (le token reste
    // valide et peut être renvoyé manuellement au besoin).
    let dkim_url = env::var("DKIM_SERVICE_URL")
        .unwrap_or_else(|_| "http://dkim-service:3000".to_string());
    let invite_base = env::var("ADMIN_INVITE_BASE_URL")
        .unwrap_or_else(|_| "https://misfits.ai/admin/accept-invite".to_string());
    let sender = env::var("ADMIN_INVITE_FROM")
        .unwrap_or_else(|_| "no-reply@misfits.ai".to_string());
    let accept_url = format!("{}?token={}", invite_base, token);
    let display = user
        .display_name
        .clone()
        .unwrap_or_else(|| user.email.clone());
    let subject = "Invitation à rejoindre la console admin Misfits";
    let html = format!(
        "<p>Bonjour {display},</p>\
         <p>Vous avez été invité(e) à rejoindre la console admin de Misfits Mail.</p>\
         <p>Le lien ci-dessous est valable {ttl_hours}h et à usage unique :</p>\
         <p><a href=\"{accept_url}\">{accept_url}</a></p>\
         <p>Si vous n'attendiez pas cette invitation, ignorez ce message.</p>\
         <p>— L'équipe Misfits</p>",
        display = display,
        ttl_hours = ttl_hours,
        accept_url = accept_url
    );
    let payload = serde_json::json!({
        "from": sender,
        "to": user.email,
        "subject": subject,
        "html": html,
    });
    let mongo_for_send = mongo.clone();
    let email_for_log = user.email.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/generate-dkim", dkim_url.trim_end_matches('/')))
            .json(&payload)
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => eprintln!("invite: dkim-service {} for {}", r.status(), email_for_log),
            Err(e) => eprintln!("invite: dkim-service unreachable: {}", e),
        }
        let _ = mongo_for_send; // keep clone alive for future extension
    });

    HttpResponse::Ok().json(serde_json::json!({
        "invited": true,
        "user": user,
        "acceptUrl": accept_url,
        "expiresAt": expires.to_rfc3339(),
    }))
}

/// POST /api/admin/users/{id}/reset-password
///
/// Définit un nouveau mot de passe (bcrypt) sur l'AdminUserRecord.
/// Optionnellement révoque les sessions existantes.
async fn api_admin_user_reset_password(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<ResetPasswordInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    let mut user = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("reset_password: find_one error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    // Si aucun mot de passe fourni, on génère un temporaire.
    let (new_password, generated) = match &body.new_password {
        Some(p) if !p.trim().is_empty() => (p.trim().to_string(), false),
        _ => {
            let random = Uuid::new_v4().simple().to_string();
            (random[..12].to_string(), true)
        }
    };

    if new_password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "password must be at least 8 chars" }));
    }

    let hash = match web::block(move || bcrypt::hash(&new_password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("reset_password: bcrypt error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to hash password" }));
        }
        Err(e) => {
            eprintln!("reset_password: web::block error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to hash password" }));
        }
    };

    let now = now_iso();
    user.password_hash = Some(hash);
    user.updated_at = now.clone();
    // Consommer un éventuel jeton d'invitation en cours.
    user.invite_token = None;
    user.invite_expires_at = None;
    let mut recent = user.recent_activity.clone();
    recent.insert(
        0,
        AdminUserActivity {
            at: now,
            label: if generated {
                "Password reset (auto-generated)".to_string()
            } else {
                "Password reset".to_string()
            },
            kind: "admin_action".to_string(),
        },
    );
    recent.truncate(8);
    user.recent_activity = recent;

    if let Err(e) = coll
        .replace_one(doc! { "id": &id }, &user)
        .upsert(false)
        .await
    {
        eprintln!("reset_password: replace_one error: {}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "message": "Failed to update password" }));
    }

    // Révocation des sessions optionnelle.
    if body.revoke_sessions {
        let sessions = mongo
            .database(&mongo_db_name())
            .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
        if let Err(e) = sessions.delete_many(doc! { "userId": &id }).await {
            eprintln!("reset_password: revoke sessions error: {}", e);
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "reset": true,
        "user": user,
        "generatedPassword": if generated { serde_json::Value::Bool(true) } else { serde_json::Value::Null },
    }))
}

/// POST /api/admin/users/{id}/revoke-sessions
async fn api_admin_user_revoke_sessions(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let id = path.into_inner();
    let sessions = mongo
        .database(&mongo_db_name())
        .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
    match sessions.delete_many(doc! { "userId": &id }).await {
        Ok(res) => HttpResponse::Ok().json(serde_json::json!({
            "revoked": true,
            "deletedCount": res.deleted_count,
        })),
        Err(e) => {
            eprintln!("revoke_sessions: error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to revoke sessions" }))
        }
    }
}

async fn api_admin_change_requests_list(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll
        .find(doc! {})
        .sort(doc! { "updatedAt": -1 })
        .limit(500)
        .await
    {
        Ok(cursor) => {
            let items = cursor
                .try_collect::<Vec<ChangeRequestItem>>()
                .await
                .unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "generatedAt": now_iso(),
                "counts": status_counts(&items),
                "items": items,
            }))
        }
        Err(e) => {
            eprintln!("api_admin_change_requests_list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change requests" }))
        }
    }
}

async fn api_admin_change_request_get(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(item)) => HttpResponse::Ok().json(serde_json::json!({ "item": item })),
        Ok(None) => HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "Change request not found" })),
        Err(e) => {
            eprintln!("api_admin_change_request_get error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change request" }))
        }
    }
}

async fn api_admin_change_request_create(
    body: web::Json<CreateChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let scope = body.scope.trim().to_ascii_lowercase();
    let urgency = body.urgency.trim().to_ascii_lowercase();
    let impact = body.impact.trim().to_ascii_lowercase();
    let linked_repo = body.linked_repo.trim().to_ascii_lowercase();

    if !["ux", "backend", "fullstack", "security"].contains(&scope.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "scope must be ux|backend|fullstack|security" }));
    }
    if !["low", "medium", "high"].contains(&urgency.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "urgency must be low|medium|high" }));
    }
    if !["small", "medium", "high"].contains(&impact.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "impact must be small|medium|high" }));
    }
    if !["misfits-web", "reimagined-guide", "cross-repo"].contains(&linked_repo.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "linkedRepo must be misfits-web|reimagined-guide|cross-repo" }));
    }

    let now = now_iso();
    let submitter = body.requested_by.trim().to_string();
    let item = ChangeRequestItem {
        id: format!("cr_{}", Uuid::new_v4().simple()),
        title: body.title.trim().to_string(),
        problem: body.problem.trim().to_string(),
        desired_outcome: body.desired_outcome.trim().to_string(),
        scope: scope.clone(),
        priority: compute_priority(&urgency, &impact),
        status: "submitted".to_string(),
        requested_by: submitter.clone(),
        linked_repo,
        created_at: now.clone(),
        updated_at: now.clone(),
        taken_in_charge_at: None,
        taken_in_charge_by: None,
        target_release_window: if urgency == "high" {
            "next-24h".to_string()
        } else if urgency == "medium" {
            "next-72h".to_string()
        } else {
            "next-sprint".to_string()
        },
        acceptance_criteria: build_acceptance_criteria(&scope),
        workflow: build_initial_stages(),
        workflow_events: vec![WorkflowEvent {
            at: now,
            actor: submitter,
            action: "submitted".to_string(),
            from_status: "submitted".to_string(),
            to_status: "submitted".to_string(),
            note: Some("Change request créée".to_string()),
        }],
        execution_state: "idle".to_string(),
        execution_run_id: None,
        execution_started_at: None,
        execution_last_heartbeat_at: None,
        execution_finished_at: None,
        execution_last_error: None,
        changelog_entry: None,
    };

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.insert_one(&item).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create change request" }))
        }
    }
}

async fn api_admin_change_request_patch(
    path: web::Path<String>,
    body: web::Json<PatchChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    let mut item = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "Change request not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_change_request_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change request" }));
        }
    };

    if let Some(action) = &body.action {
        let action = action.trim().to_ascii_lowercase();
        let actor = body
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        let previous_status = item.status.clone();
        let mut transition_note = body.note.clone();

        if action == "reject" {
            item.status = "rejected".to_string();
            item.workflow = item
                .workflow
                .iter()
                .map(|stage| {
                    if stage.status == "active" {
                        let mut s = stage.clone();
                        s.status = "done".to_string();
                        s.done_at = Some(now_iso());
                        s
                    } else {
                        stage.clone()
                    }
                })
                .collect();
            item.execution_state = "idle".to_string();
            item.execution_run_id = None;
            item.execution_started_at = None;
            item.execution_last_heartbeat_at = None;
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = None;
        } else if action == "advance" {
            let order = admin_workflow_order();
            let idx = order.iter().position(|x| *x == item.status).unwrap_or(0);
            if idx < order.len() - 1 {
                item.status = order[idx + 1].to_string();
                item.workflow = advance_workflow(&item.workflow);
                if item.status == "in_progress" && item.execution_state == "idle" {
                    item.execution_state = "queued".to_string();
                    item.execution_last_error = None;
                    item.execution_finished_at = None;
                    if transition_note.is_none() {
                        transition_note = Some(
                            "Workflow in_progress atteint; en attente d’un run technique backend explicite".to_string(),
                        );
                    }
                }
                if item.status == "released" {
                    item.execution_state = "success".to_string();
                    item.execution_finished_at = Some(now_iso());
                    item.execution_last_error = None;
                    item.changelog_entry = Some(serde_json::json!({
                        "title": item.title,
                        "summary": body.note.clone().unwrap_or_else(|| item.desired_outcome.clone()),
                        "releasedAt": now_iso(),
                    }));
                }
            }
        } else if action == "execution_queue" {
            item.execution_state = "queued".to_string();
            item.execution_finished_at = None;
            item.execution_last_error = None;
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_start" {
            let now = now_iso();
            item.execution_state = "running".to_string();
            item.execution_started_at = Some(
                item.execution_started_at
                    .clone()
                    .unwrap_or_else(|| now.clone()),
            );
            item.execution_last_heartbeat_at = Some(now.clone());
            item.execution_finished_at = None;
            item.execution_last_error = None;
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_heartbeat" {
            item.execution_state = "running".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            if item.execution_started_at.is_none() {
                item.execution_started_at = Some(now_iso());
            }
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_fail" {
            item.execution_state = "failed".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = body
                .execution_error
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| transition_note.clone())
                .or(Some("Execution failed".to_string()));
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_success" {
            item.execution_state = "success".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = None;
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_reset" {
            item.execution_state = "idle".to_string();
            item.execution_run_id = None;
            item.execution_started_at = None;
            item.execution_last_heartbeat_at = None;
            item.execution_finished_at = None;
            item.execution_last_error = None;
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "message": "action must be advance|reject|execution_queue|execution_start|execution_heartbeat|execution_fail|execution_success|execution_reset" }));
        }

        if item.taken_in_charge_at.is_none()
            && previous_status == "submitted"
            && item.status != "submitted"
        {
            let intake_at = now_iso();
            item.taken_in_charge_at = Some(intake_at.clone());
            item.taken_in_charge_by = Some(actor.clone());
            if transition_note.is_none() {
                transition_note = Some("Prise en charge initiale".to_string());
            }
        }

        item.workflow_events.push(WorkflowEvent {
            at: now_iso(),
            actor,
            action,
            from_status: previous_status,
            to_status: item.status.clone(),
            note: transition_note,
        });
    }

    if let Some(title) = &body.title {
        item.title = title.trim().to_string();
    }
    if let Some(problem) = &body.problem {
        item.problem = problem.trim().to_string();
    }
    if let Some(desired) = &body.desired_outcome {
        item.desired_outcome = desired.trim().to_string();
    }
    if let Some(status) = &body.status {
        let status = status.trim().to_ascii_lowercase();
        if [
            "submitted",
            "triaged",
            "planned",
            "in_progress",
            "qa",
            "released",
            "rejected",
        ]
        .contains(&status.as_str())
        {
            item.status = status;
        }
    }

    item.updated_at = now_iso();

    match coll
        .replace_one(doc! { "id": &id }, &item)
        .upsert(false)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update change request" }))
        }
    }
}

async fn api_admin_change_request_delete(
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.delete_one(doc! { "id": &id }).await {
        Ok(res) if res.deleted_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "deleted": true, "id": id }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "deleted": false, "message": "Change request not found" })),
        Err(e) => {
            eprintln!("api_admin_change_request_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete change request" }))
        }
    }
}

// --- AI settings (Phase B1, issue #173) ----------------------------------------

const AI_SETTINGS_ID: &str = "global";
const DEFAULT_AI_MODEL: &str = "qwen/qwen3.7-flash";

fn default_ai_feature_models() -> HashMap<String, String> {
    let mut m = HashMap::new();
    for key in [
        "compose",
        "translate",
        "triage",
        "security",
        "rewrite",
        "subject",
        "complete",
    ] {
        m.insert(key.to_string(), DEFAULT_AI_MODEL.to_string());
    }
    m
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AiSettingsDoc {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "defaultModel", alias = "default_model")]
    default_model: String,
    features: HashMap<String, String>,
    #[serde(rename = "updatedAt", alias = "updated_at", default)]
    updated_at: Option<String>,
}

impl AiSettingsDoc {
    fn defaults() -> Self {
        Self {
            id: AI_SETTINGS_ID.to_string(),
            default_model: DEFAULT_AI_MODEL.to_string(),
            features: default_ai_feature_models(),
            updated_at: Some(Utc::now().to_rfc3339()),
        }
    }

    fn merge_with_defaults(mut self) -> Self {
        let defaults = default_ai_feature_models();
        for (k, v) in defaults {
            self.features.entry(k).or_insert(v);
        }
        if self.default_model.trim().is_empty() {
            self.default_model = DEFAULT_AI_MODEL.to_string();
        }
        self
    }

    fn to_public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "defaultModel": self.default_model,
            "features": self.features,
            "updatedAt": self.updated_at,
        })
    }
}

#[derive(Deserialize)]
struct AiSettingsUpdate {
    #[serde(rename = "defaultModel", alias = "default_model", default)]
    default_model: Option<String>,
    #[serde(default)]
    features: Option<HashMap<String, String>>,
}

fn mongo_db_name() -> String {
    env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

async fn load_ai_settings(client: &mongodb::Client) -> AiSettingsDoc {
    let coll = client
        .database(&mongo_db_name())
        .collection::<AiSettingsDoc>("ai_settings");
    match coll.find_one(doc! { "_id": AI_SETTINGS_ID }).await {
        Ok(Some(doc)) => doc.merge_with_defaults(),
        _ => AiSettingsDoc::defaults(),
    }
}

async fn api_get_ai_settings(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
    let settings = load_ai_settings(mongo.get_ref()).await;
    HttpResponse::Ok().json(settings.to_public_json())
}

async fn api_put_ai_settings(
    body: web::Json<AiSettingsUpdate>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let mut current = load_ai_settings(mongo.get_ref()).await;
    if let Some(model) = body.default_model.as_ref() {
        let m = model.trim();
        if !m.is_empty() {
            current.default_model = m.to_string();
        }
    }
    if let Some(features) = body.features.as_ref() {
        for (k, v) in features {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() && !val.is_empty() {
                current.features.insert(key.to_string(), val.to_string());
            }
        }
    }
    current = current.merge_with_defaults();
    current.updated_at = Some(Utc::now().to_rfc3339());

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AiSettingsDoc>("ai_settings");
    // mongodb 3.x: upsert via ReplaceOptions builder chain
    match coll
        .replace_one(doc! { "_id": AI_SETTINGS_ID }, current.clone())
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(current.to_public_json()),
        Err(e) => {
            eprintln!("ai_settings upsert failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to save AI settings",
            }))
        }
    }
}

async fn api_templates() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"templates": []}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HermesChatProxyRequest {
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
    #[serde(default)]
    temperature: Option<f32>,
    #[serde(default)]
    max_tokens: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HermesRunsProxyRequest {
    #[serde(default)]
    input: Option<serde_json::Value>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HermesRunsListQuery {
    #[serde(default)]
    limit: Option<u32>,
}

fn normalize_hermes_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some(without_v1) = trimmed.strip_suffix("/v1") {
        without_v1.to_string()
    } else {
        trimmed.to_string()
    }
}

fn resolve_hermes_base_url() -> String {
    let base =
        env::var("HERMES_BASE_URL").unwrap_or_else(|_| "http://172.16.12.2:8642".to_string());
    normalize_hermes_base_url(&base)
}

async fn api_hermes_chat(
    req: HttpRequest,
    body: web::Json<HermesChatProxyRequest>,
) -> impl Responder {
    if body.messages.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "messages is required"
        }));
    }

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/chat/completions", base);
    let model = body
        .model
        .clone()
        .unwrap_or_else(|| env::var("HERMES_MODEL").unwrap_or_else(|_| "hermes-agent".to_string()));

    let thread_id = body
        .thread_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let fallback_user_id = resolve_user_id(&req);
    let user_id = body
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_user_id);

    let session_id = body
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("mail-thread-{}", thread_id));

    let session_key = body
        .session_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("user-{}", user_id));

    let mut payload = serde_json::json!({
        "model": model,
        "messages": body.messages,
    });

    if let Some(temp) = body.temperature {
        payload["temperature"] = serde_json::json!(temp);
    }
    if let Some(max_tokens) = body.max_tokens {
        payload["max_tokens"] = serde_json::json!(max_tokens);
    }

    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id)
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

async fn api_hermes_runs_list(query: web::Query<HermesRunsListQuery>) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let limit = query.limit.unwrap_or(40).clamp(10, 200);
    let url = format!("{}/v1/runs?limit={}", base, limit);
    let client = reqwest::Client::new();
    let response = match client.get(url).bearer_auth(api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

async fn api_hermes_runs(
    req: HttpRequest,
    body: web::Json<HermesRunsProxyRequest>,
) -> impl Responder {
    let input = match body.input.clone().filter(|v| !v.is_null()) {
        Some(v) => v,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "input is required"
            }))
        }
    };

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs", base);
    let model = body
        .model
        .clone()
        .unwrap_or_else(|| env::var("HERMES_MODEL").unwrap_or_else(|_| "hermes-agent".to_string()));

    let thread_id = body
        .thread_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let fallback_user_id = resolve_user_id(&req);
    let user_id = body
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_user_id);

    let session_id = body
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("mail-thread-{}", thread_id));

    let session_key = body
        .session_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("user-{}", user_id));

    let payload = serde_json::json!({
        "model": model,
        "input": input,
    });

    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id)
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

#[derive(Deserialize)]
struct HermesRunPath {
    run_id: String,
}

async fn api_hermes_run_status(path: web::Path<HermesRunPath>) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs/{}", base, path.run_id);
    let client = reqwest::Client::new();
    let response = match client.get(url).bearer_auth(api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

async fn api_hermes_run_events(path: web::Path<HermesRunPath>, req: HttpRequest) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let url = format!("{}/v1/runs/{}/events{}", base, path.run_id, query_suffix);

    let client = reqwest::Client::new();
    let upstream = match client
        .get(url)
        .bearer_auth(api_key)
        .header("Accept", "text/event-stream")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = upstream.status();
    if !status.is_success() {
        let body_json = match upstream.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(_) => serde_json::json!({ "error": "Hermes upstream error" }),
        };
        return HttpResponse::build(
            actix_web::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
        )
        .json(body_json);
    }

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let bytes_stream = upstream
        .bytes_stream()
        .map_err(actix_web::error::ErrorBadGateway);

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .content_type(content_type)
    .insert_header(("Cache-Control", "no-cache"))
    .insert_header(("X-Accel-Buffering", "no"))
    .streaming(bytes_stream)
}

// --- Calendar types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalMessagesQuery {
    account_id: String,
    folder: Option<String>,
    page: Option<u64>,
    page_size: Option<u64>,
}

async fn api_openapi_json() -> impl Responder {
    static SPEC_JSON: &str = r#"{
        "openapi": "3.0.3",
        "info": {
            "title": "Email API",
            "version": "1.0.0",
            "description": "Backend API for the mail server"
        },
        "paths": {
            "/api/auth/login": { "post": { "tags": ["Auth"], "summary": "Login", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/register": { "post": { "tags": ["Auth"], "summary": "Register", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/logout": { "post": { "tags": ["Auth"], "summary": "Logout", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/refresh": { "post": { "tags": ["Auth"], "summary": "Refresh token", "responses": { "200": { "description": "OK" } } } },
            "/api/user/locale": { "patch": { "tags": ["Auth"], "summary": "Update user locale", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/oauth/{provider}": { "get": { "tags": ["Auth"], "summary": "Start OAuth flow", "parameters": [{ "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "302": { "description": "Redirect" } } } },
            "/api/auth/oauth/{provider}/callback": { "get": { "tags": ["Auth"], "summary": "OAuth callback", "parameters": [{ "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "302": { "description": "Redirect" } } } },
            "/api/emails": { "get": { "tags": ["Emails"], "summary": "List emails", "responses": { "200": { "description": "OK" } } } },
            "/api/emails/{id}": {
                "get": { "tags": ["Emails"], "summary": "Get email by ID", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/emails/{id}/action": {
                "post": { "tags": ["Emails"], "summary": "Perform action on email (move, delete, read, unread, star, unstar)", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/tags": { "get": { "tags": ["Emails"], "summary": "List tags", "responses": { "200": { "description": "OK" } } } },
            "/api/send": { "post": { "tags": ["Send"], "summary": "Send an email", "responses": { "200": { "description": "OK" } } } },
            "/api/send/{id}/status": { "get": { "tags": ["Send"], "summary": "Get send status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/drafts": {
                "get": { "tags": ["Drafts"], "summary": "List drafts", "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["Drafts"], "summary": "Create or update draft", "responses": { "200": { "description": "OK" } } }
            },
            "/api/drafts/{id}": { "delete": { "tags": ["Drafts"], "summary": "Delete draft", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/templates": { "get": { "tags": ["Templates"], "summary": "List templates", "responses": { "200": { "description": "OK" } } } },
            "/api/settings/ai": {
                "get": { "tags": ["AI"], "summary": "Get AI settings", "responses": { "200": { "description": "OK" } } },
                "put": { "tags": ["AI"], "summary": "Update AI settings", "responses": { "200": { "description": "OK" } } }
            },
            "/api/hermes/chat": { "post": { "tags": ["Hermes"], "summary": "Chat completions proxy", "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs": { "post": { "tags": ["Hermes"], "summary": "Create run", "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs/{run_id}": { "get": { "tags": ["Hermes"], "summary": "Get run status", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs/{run_id}/events": { "get": { "tags": ["Hermes"], "summary": "Stream run events (SSE)", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "SSE stream" } } } },
            "/api/calendar/events": {
                "get": { "tags": ["Calendar"], "summary": "List calendar events", "parameters": [{ "name": "start", "in": "query", "schema": { "type": "string", "format": "date-time" } }, { "name": "end", "in": "query", "schema": { "type": "string", "format": "date-time" } }], "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["Calendar"], "summary": "Create calendar event", "responses": { "201": { "description": "Created" } } }
            },
            "/api/calendar/events/{id}": {
                "get": { "tags": ["Calendar"], "summary": "Get calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "put": { "tags": ["Calendar"], "summary": "Update calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "tags": ["Calendar"], "summary": "Delete calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/events": { "get": { "tags": ["Events"], "summary": "List events", "responses": { "200": { "description": "OK" } } } },
            "/api/events/stream": { "get": { "tags": ["Events"], "summary": "SSE event stream", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/monitoring/summary": { "get": { "tags": ["Monitoring"], "summary": "SMTP monitoring summary", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/events": { "get": { "tags": ["Monitoring"], "summary": "SMTP monitoring events", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/messages/{message_id}/trace": { "get": { "tags": ["Monitoring"], "summary": "Message delivery trace", "parameters": [{ "name": "message_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/bounces": { "get": { "tags": ["Monitoring"], "summary": "Bounce list", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/providers/top": { "get": { "tags": ["Monitoring"], "summary": "Top providers", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/live": { "get": { "tags": ["Monitoring"], "summary": "Live SMTP events (SSE)", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/monitoring/alerts/active": { "get": { "tags": ["Monitoring"], "summary": "Active monitoring alerts", "responses": { "200": { "description": "OK" } } } },
            "/api/security/alerts/active": { "get": { "tags": ["Security"], "summary": "Active security alerts", "responses": { "200": { "description": "OK" } } } },
            "/api/security/incidents": { "get": { "tags": ["Security"], "summary": "Security incidents", "responses": { "200": { "description": "OK" } } } },
            "/api/security/live": { "get": { "tags": ["Security"], "summary": "Live security events (SSE)", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/security/tenant/{id}/status": { "get": { "tags": ["Security"], "summary": "Tenant security status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/security/remediation/{alert_id}/rollback": { "post": { "tags": ["Security"], "summary": "Rollback remediation", "parameters": [{ "name": "alert_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts": {
                "get": { "tags": ["External IMAP"], "summary": "List external accounts", "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["External IMAP"], "summary": "Create external account", "responses": { "200": { "description": "OK" } } }
            },
            "/api/external-accounts/{id}": {
                "get": { "tags": ["External IMAP"], "summary": "Get external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "patch": { "tags": ["External IMAP"], "summary": "Update external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "tags": ["External IMAP"], "summary": "Delete external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/external-accounts/{id}/test": { "post": { "tags": ["External IMAP"], "summary": "Test IMAP connection", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders": { "get": { "tags": ["External IMAP"], "summary": "List folders", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders/discover": { "post": { "tags": ["External IMAP"], "summary": "Discover folders", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders/{folder_id}/mapping": { "put": { "tags": ["External IMAP"], "summary": "Set folder mapping", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }, { "name": "folder_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync": { "post": { "tags": ["External IMAP"], "summary": "Start sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/status": { "get": { "tags": ["External IMAP"], "summary": "Get sync status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/pause": { "post": { "tags": ["External IMAP"], "summary": "Pause sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/resume": { "post": { "tags": ["External IMAP"], "summary": "Resume sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-sync-runs/{run_id}": { "get": { "tags": ["External IMAP"], "summary": "Get sync run", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-messages": { "get": { "tags": ["External IMAP"], "summary": "List external messages", "parameters": [{ "name": "account_id", "in": "query", "required": true, "schema": { "type": "string" } }, { "name": "folder", "in": "query", "schema": { "type": "string" } }, { "name": "page", "in": "query", "schema": { "type": "integer" } }, { "name": "page_size", "in": "query", "schema": { "type": "integer" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-messages/{id}/action": { "post": { "tags": ["External IMAP"], "summary": "Apply action on external message", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } }
        }
    }"#;
    let spec: serde_json::Value = serde_json::from_str(SPEC_JSON).unwrap_or_default();
    HttpResponse::Ok().json(spec)
}

async fn api_swagger_ui() -> impl Responder {
    let html = r##"<!DOCTYPE html>
<html>
<head>
  <title>Email API — Swagger UI</title>
  <meta charset="utf-8"/>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger-ui", presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset] });
</script>
</body>
</html>"##;
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

async fn api_external_openapi() -> impl Responder {
    static OPENAPI_YAML: &str = include_str!("../../ops/openapi/external-imap-v1.yaml");
    HttpResponse::Ok()
        .content_type("application/yaml; charset=utf-8")
        .body(OPENAPI_YAML)
}

async fn api_external_accounts_list(
    req: HttpRequest,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    match svc.list_accounts(&user_id).await {
        Ok(accounts) => HttpResponse::Ok().json(serde_json::json!({ "accounts": accounts })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNTS_LIST_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_accounts_create(
    req: HttpRequest,
    payload: web::Json<CreateExternalAccountInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    match svc.create_account(&user_id, payload.into_inner()).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_CREATE_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_account_get(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.get_account(&user_id, &account_id).await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_account_patch(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<UpdateExternalAccountInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc
        .update_account(&user_id, &account_id, payload.into_inner())
        .await
    {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_UPDATE_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_account_delete(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.delete_account(&user_id, &account_id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({ "deleted": true })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_DELETE_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_account_test(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    match svc.imap_test(&account).await {
        Ok(result) => {
            if result.ok {
                HttpResponse::Ok().json(result)
            } else {
                HttpResponse::UnprocessableEntity().json(serde_json::json!({
                    "ok": false,
                    "error": {"code": "IMAP_AUTH_FAILED", "message": result.message},
                    "capabilities": result.capabilities,
                    "greeting": result.greeting,
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(
            serde_json::json!({"error": {"code": "IMAP_TEST_FAILED", "message": e.to_string()}}),
        ),
    }
}

async fn api_external_folders_list(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.list_folders(&user_id, &account_id).await {
        Ok(folders) => HttpResponse::Ok().json(serde_json::json!({ "folders": folders })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDERS_LIST_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_folders_discover(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    match svc.discover_folders(&user_id, &account).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDERS_DISCOVER_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_folder_mapping_put(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    payload: web::Json<ExternalFolderMappingInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let (account_id, folder_id) = path.into_inner();
    match svc
        .upsert_folder_mapping(&user_id, &account_id, &folder_id, &payload.local_role)
        .await
    {
        Ok(Some(folder)) => HttpResponse::Ok().json(folder),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDER_NOT_FOUND", "message": "Folder not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDER_MAPPING_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_sync_start(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<StartSyncInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    let run = match svc.start_sync_run(&user_id, &account_id, &payload).await {
        Ok(run) => run,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_START_FAILED", "message": e.to_string()}})),
    };

    match svc.run_sync_now(&user_id, &account, &run).await {
        Ok(stats) => {
            let updated = svc
                .complete_sync_run(&user_id, &run.id, "success", stats, None)
                .await
                .ok()
                .flatten();
            HttpResponse::Ok()
                .json(serde_json::json!({ "runId": run.id, "status": "success", "run": updated }))
        }
        Err(e) => {
            let _ = svc
                .complete_sync_run(
                    &user_id,
                    &run.id,
                    "failed",
                    simple_smtp_server::external_imap::SyncExecutionResult {
                        fetched: 0,
                        updated: 0,
                        deleted: 0,
                        discovered_folders: 0,
                    },
                    Some(e.to_string()),
                )
                .await;
            HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_EXECUTION_FAILED", "message": e.to_string()}, "runId": run.id}))
        }
    }
}

async fn api_external_sync_run_get(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let run_id = path.into_inner();
    match svc.get_sync_run(&user_id, &run_id).await {
        Ok(Some(run)) => HttpResponse::Ok().json(run),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RUN_NOT_FOUND", "message": "Sync run not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RUN_FETCH_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_sync_status(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.get_sync_status(&user_id, &account_id).await {
        Ok(Some(run)) => HttpResponse::Ok().json(run),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({"status": "idle"})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_STATUS_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_sync_pause(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.set_account_status(&user_id, &account_id, "paused").await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_PAUSE_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_sync_resume(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.set_account_status(&user_id, &account_id, "active").await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RESUME_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_messages_list(
    req: HttpRequest,
    query: web::Query<ExternalMessagesQuery>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    match svc
        .list_messages(
            &user_id,
            &query.account_id,
            query.folder.as_deref(),
            page,
            page_size,
        )
        .await
    {
        Ok(messages) => HttpResponse::Ok().json(serde_json::json!({ "messages": messages, "page": page, "pageSize": page_size })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGES_LIST_FAILED", "message": e.to_string()}})),
    }
}

async fn api_external_message_action(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<ExternalMessageActionInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let message_id = path.into_inner();
    match svc
        .apply_message_action(&user_id, &message_id, &payload)
        .await
    {
        Ok(Some(message)) => HttpResponse::Ok().json(message),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGE_NOT_FOUND", "message": "Message not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGE_ACTION_FAILED", "message": e.to_string()}})),
    }
}

#[derive(Deserialize)]
struct CreateCalendarEventRequest {
    title: String,
    #[serde(default)]
    description: String,
    start: String, // ISO 8601
    end: String,   // ISO 8601
    #[serde(default = "default_event_type_str")]
    event_type: String,
    #[serde(default = "default_color_str")]
    color: String,
    #[serde(default)]
    location: String,
}

fn default_event_type_str() -> String {
    "default".to_string()
}
fn default_color_str() -> String {
    "#3788d8".to_string()
}

#[derive(Deserialize)]
struct UpdateCalendarEventRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    location: Option<String>,
}

#[derive(Deserialize)]
struct CalendarQueryParams {
    #[serde(default)]
    start: Option<String>, // ISO 8601
    #[serde(default)]
    end: Option<String>, // ISO 8601
}

fn parse_iso_to_bson(s: &str) -> Option<bson::DateTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()))
}

fn get_user_from_headers(req: &actix_web::HttpRequest) -> String {
    // Try x-user-email header, fallback to query param, fallback to env SMTP_USERNAME
    if let Some(email) = req
        .headers()
        .get("x-user-email")
        .and_then(|v| v.to_str().ok())
    {
        return email.to_string();
    }
    // Fallback: use SMTP_USERNAME env var
    env::var("SMTP_USERNAME").unwrap_or_else(|_| "admin@misfits.ai".to_string())
}

// --- Calendar handlers ---

async fn calendar_create_event(
    req_body: web::Json<CreateCalendarEventRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start = match parse_iso_to_bson(&req_body.start) {
        Some(dt) => dt,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid start date format, use ISO 8601"}))
        }
    };
    let end = match parse_iso_to_bson(&req_body.end) {
        Some(dt) => dt,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid end date format, use ISO 8601"}))
        }
    };

    let mut event = CalendarEvent::new(&user, &req_body.title, start, end);
    event.description = req_body.description.clone();
    event.event_type = req_body.event_type.clone();
    event.color = req_body.color.clone();
    event.location = req_body.location.clone();

    match logic.create_calendar_event(&event).await {
        Ok(_) => HttpResponse::Created().json(&event),
        Err(e) => {
            eprintln!("Calendar create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to create event"}))
        }
    }
}

async fn calendar_list_events(
    req: actix_web::HttpRequest,
    query: web::Query<CalendarQueryParams>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start_after = query.start.as_ref().and_then(|s| parse_iso_to_bson(s));
    let start_before = query.end.as_ref().and_then(|s| parse_iso_to_bson(s));

    match logic
        .get_calendar_events(&user, start_after, start_before)
        .await
    {
        Ok(events) => {
            HttpResponse::Ok().json(serde_json::json!({"events": events, "total": events.len()}))
        }
        Err(e) => {
            eprintln!("Calendar list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to list events"}))
        }
    }
}

async fn calendar_get_event(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    match logic.get_calendar_event(&user, &event_id).await {
        Ok(Some(event)) => HttpResponse::Ok().json(&event),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Event not found"})),
        Err(e) => {
            eprintln!("Calendar get error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to get event"}))
        }
    }
}

async fn calendar_update_event(
    req_body: web::Json<UpdateCalendarEventRequest>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    let mut update = bson::Document::new();
    if let Some(title) = &req_body.title {
        update.insert("title", title.clone());
    }
    if let Some(desc) = &req_body.description {
        update.insert("description", desc.clone());
    }
    if let Some(start) = &req_body.start {
        match parse_iso_to_bson(start) {
            Some(dt) => {
                update.insert("start", dt);
            }
            None => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Invalid start date format"}))
            }
        }
    }
    if let Some(end) = &req_body.end {
        match parse_iso_to_bson(end) {
            Some(dt) => {
                update.insert("end", dt);
            }
            None => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Invalid end date format"}))
            }
        }
    }
    if let Some(et) = &req_body.event_type {
        update.insert("event_type", et.clone());
    }
    if let Some(color) = &req_body.color {
        update.insert("color", color.clone());
    }
    if let Some(loc) = &req_body.location {
        update.insert("location", loc.clone());
    }

    if update.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "No fields to update"}));
    }

    match logic.update_calendar_event(&user, &event_id, update).await {
        Ok(Some(event)) => HttpResponse::Ok().json(&event),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Event not found"})),
        Err(e) => {
            eprintln!("Calendar update error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to update event"}))
        }
    }
}

async fn calendar_delete_event(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    match logic.delete_calendar_event(&user, &event_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Err(e) => {
            eprintln!("Calendar delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to delete event"}))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // rustls 0.23 requires an explicit process-level CryptoProvider.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Connect to MongoDB for auth
    let mongo_user = env::var("MONGODB_USERNAME").unwrap_or_default();
    let mongo_pass = env::var("MONGODB_PASSWORD").unwrap_or_default();
    let mongo_cluster =
        env::var("MONGODB_CLUSTER_URL").unwrap_or_else(|_| "mongodb:27017".to_string());
    let mongo_app = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    // If MONGODB_CLUSTER_URL is already a full URI (e.g. from 1Password), use it directly.
    let client_uri = if mongo_cluster.starts_with("mongodb://")
        || mongo_cluster.starts_with("mongodb+srv://")
    {
        let base = mongo_cluster.trim_end_matches('&').trim_end_matches('?');
        // Use ? or & depending on whether query params already exist
        let sep = if base.contains('?') { "&" } else { "?" };
        format!(
            "{}{}appName={}&serverSelectionTimeoutMS=5000",
            base, sep, mongo_app
        )
    } else if mongo_cluster.contains(".mongodb.net") {
        format!("mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000", mongo_user, mongo_pass, mongo_cluster, mongo_app)
    } else {
        format!(
            "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
            mongo_user, mongo_pass, mongo_cluster, mongo_app
        )
    };

    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";

    let mongo_client = if use_mongodb && !mongo_user.is_empty() {
        match mongodb::Client::with_uri_str(&client_uri).await {
            Ok(c) => {
                let c = Arc::new(c);
                // Warm-up: force DNS resolution + TLS + MongoDB handshake at startup
                // so the first user login is not delayed by 10-30s.
                if let Err(e) = c
                    .database("admin")
                    .run_command(mongodb::bson::doc! {"ping": 1})
                    .await
                {
                    eprintln!("MongoDB warm-up ping failed (non-fatal): {}", e);
                } else {
                    println!("MongoDB connection ready.");
                }
                Some(c)
            }
            Err(e) => {
                eprintln!("MongoDB connection failed: {}, auth will use env vars", e);
                None
            }
        }
    } else {
        None
    };

    let fallback_client = Arc::new(
        mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .unwrap(),
    );
    let shared_mongo = mongo_client
        .clone()
        .unwrap_or_else(|| fallback_client.clone());
    let logic = web::Data::new(Arc::new(Logic::new(
        mongo_client.unwrap_or(fallback_client),
    )));
    let mongo_data = web::Data::new(shared_mongo.clone());
    let external_imap_service =
        web::Data::new(Arc::new(ExternalImapService::new(shared_mongo.clone())));

    let (event_tx, _) = broadcast::channel::<MailEvent>(256);
    let event_bus = web::Data::new(event_tx);

    // Init global SMTP monitoring bus + background persistence task
    monitoring::init_bus();
    monitoring::storage::start_persistence_task(shared_mongo.clone());
    let shared_mongo_idx = shared_mongo.clone();
    tokio::spawn(async move {
        monitoring::storage::ensure_indexes(&shared_mongo_idx).await;
    });

    // Init security monitoring bus + background evaluation engine
    security::init_bus();
    let sec_mongo = shared_mongo.clone();
    tokio::spawn(async move {
        security::audit::ensure_indexes(&sec_mongo).await;
    });
    security::audit::start_engine(shared_mongo.clone());

    // Start send queue background worker
    let sq_mongo = shared_mongo.clone();
    tokio::spawn(send_queue_worker(sq_mongo));

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(
            env::var("PRIVKEY_PATH").expect("PRIVKEY_PATH must be set"),
            SslFiletype::PEM,
        )
        .unwrap();
    builder
        .set_certificate_chain_file(env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set"))
        .unwrap();

    // Start HTTP server on 8000 (for frontend proxy, no TLS)
    let http_logic = logic.clone();
    let http_mongo = mongo_data.clone();
    let http_event_bus = event_bus.clone();
    let http_external_imap = external_imap_service.clone();
    let http_addr = env::var("API_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    let http_server = actix_web::rt::spawn(async move {
        HttpServer::new(move || {
            let cors = Cors::permissive()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .supports_credentials()
                .max_age(3600);

            App::new()
                .wrap(cors)
                .app_data(http_logic.clone())
                .app_data(http_mongo.clone())
                .app_data(http_event_bus.clone())
                .app_data(http_external_imap.clone())
                .route("/api/openapi.json", web::get().to(api_openapi_json))
                .route("/api/docs", web::get().to(api_swagger_ui))
                .route(
                    "/api/openapi/external-imap.yaml",
                    web::get().to(api_external_openapi),
                )
                .route(
                    "/api/external-accounts",
                    web::get().to(api_external_accounts_list),
                )
                .route(
                    "/api/external-accounts",
                    web::post().to(api_external_accounts_create),
                )
                .route(
                    "/api/external-accounts/{id}",
                    web::get().to(api_external_account_get),
                )
                .route(
                    "/api/external-accounts/{id}",
                    web::patch().to(api_external_account_patch),
                )
                .route(
                    "/api/external-accounts/{id}",
                    web::delete().to(api_external_account_delete),
                )
                .route(
                    "/api/external-accounts/{id}/test",
                    web::post().to(api_external_account_test),
                )
                .route(
                    "/api/external-accounts/{id}/folders",
                    web::get().to(api_external_folders_list),
                )
                .route(
                    "/api/external-accounts/{id}/folders/discover",
                    web::post().to(api_external_folders_discover),
                )
                .route(
                    "/api/external-accounts/{id}/folders/{folder_id}/mapping",
                    web::put().to(api_external_folder_mapping_put),
                )
                .route(
                    "/api/external-accounts/{id}/sync",
                    web::post().to(api_external_sync_start),
                )
                .route(
                    "/api/external-accounts/{id}/sync/status",
                    web::get().to(api_external_sync_status),
                )
                .route(
                    "/api/external-accounts/{id}/sync/pause",
                    web::post().to(api_external_sync_pause),
                )
                .route(
                    "/api/external-accounts/{id}/sync/resume",
                    web::post().to(api_external_sync_resume),
                )
                .route(
                    "/api/external-sync-runs/{run_id}",
                    web::get().to(api_external_sync_run_get),
                )
                .route(
                    "/api/external-messages",
                    web::get().to(api_external_messages_list),
                )
                .route(
                    "/api/external-messages/{id}/action",
                    web::post().to(api_external_message_action),
                )
                .route("/api/auth/login", web::post().to(auth_login))
                .route("/api/auth/register", web::post().to(auth_register))
                .route("/api/auth/logout", web::post().to(auth_logout))
                .route("/api/auth/refresh", web::post().to(auth_refresh))
                .route("/api/auth/2fa/verify", web::post().to(api_2fa_verify))
                .route(
                    "/api/auth/password-reset/request",
                    web::post().to(api_password_reset_request),
                )
                .route(
                    "/api/auth/password-reset/confirm",
                    web::post().to(api_password_reset_confirm),
                )
                .route("/api/user/locale", web::patch().to(api_patch_user_locale))
                .route(
                    "/api/auth/oauth/{provider}",
                    web::get().to(auth_oauth_start),
                )
                .route(
                    "/api/auth/oauth/{provider}/start",
                    web::get().to(auth_oauth_start),
                )
                .route(
                    "/api/auth/oauth/{provider}/callback",
                    web::get().to(auth_oauth_callback),
                )
                .route("/api/emails", web::get().to(api_emails))
                .route("/api/emails/{id}", web::get().to(api_email_by_id))
                .route("/api/emails/{id}/action", web::post().to(api_email_action))
                .route("/api/tags", web::get().to(api_tags))
                .route("/api/send", web::post().to(api_send))
                .route("/api/send/{id}/status", web::get().to(api_send_status))
                .route("/api/drafts", web::get().to(api_drafts_list))
                .route("/api/drafts", web::post().to(api_drafts_upsert))
                .route("/api/drafts/{id}", web::delete().to(api_drafts_delete))
                .route("/api/templates", web::get().to(api_templates))
                .route("/api/settings/ai", web::get().to(api_get_ai_settings))
                .route("/api/settings/ai", web::put().to(api_put_ai_settings))
                .route("/api/hermes/chat", web::post().to(api_hermes_chat))
                .route("/api/hermes/runs", web::get().to(api_hermes_runs_list))
                .route("/api/hermes/runs", web::post().to(api_hermes_runs))
                .route(
                    "/api/hermes/runs/{run_id}",
                    web::get().to(api_hermes_run_status),
                )
                .route(
                    "/api/hermes/runs/{run_id}/events",
                    web::get().to(api_hermes_run_events),
                )
                .route("/api/send/undo", web::post().to(api_send_undo))
                .route("/api/send/schedule", web::post().to(api_send_schedule))
                .route(
                    "/api/calendar/events",
                    web::post().to(calendar_create_event),
                )
                .route("/api/calendar/events", web::get().to(calendar_list_events))
                .route(
                    "/api/calendar/events/{id}",
                    web::get().to(calendar_get_event),
                )
                .route(
                    "/api/calendar/events/{id}",
                    web::put().to(calendar_update_event),
                )
                .route(
                    "/api/calendar/events/{id}",
                    web::delete().to(calendar_delete_event),
                )
                .route("/send-email", web::post().to(send_email_handler))
                .route("/create-mailing-list", web::post().to(create_mailing_list))
                .route(
                    "/send-to-mailing-list",
                    web::post().to(send_to_mailing_list),
                )
                .route("/api/events", web::get().to(api_events))
                .route("/api/events/stream", web::get().to(api_events_stream))
                // SMTP monitoring
                .route(
                    "/api/monitoring/summary",
                    web::get().to(api_monitoring_summary),
                )
                .route(
                    "/api/monitoring/events",
                    web::get().to(api_monitoring_events),
                )
                .route(
                    "/api/monitoring/messages/{message_id}/trace",
                    web::get().to(api_monitoring_trace),
                )
                .route(
                    "/api/monitoring/bounces",
                    web::get().to(api_monitoring_bounces),
                )
                .route(
                    "/api/monitoring/providers/top",
                    web::get().to(api_monitoring_providers_top),
                )
                .route("/api/monitoring/live", web::get().to(api_monitoring_live))
                .route(
                    "/api/monitoring/alerts/active",
                    web::get().to(api_monitoring_alerts_active),
                )
                // Security endpoints
                .route(
                    "/api/security/alerts/active",
                    web::get().to(api_security_alerts_active),
                )
                .route(
                    "/api/security/incidents",
                    web::get().to(api_security_incidents),
                )
                .route("/api/security/live", web::get().to(api_security_live))
                .route(
                    "/api/security/tenant/{id}/status",
                    web::get().to(api_security_tenant_status),
                )
                .route(
                    "/api/security/remediation/{alert_id}/rollback",
                    web::post().to(api_security_rollback),
                )
                .route("/api/admin/users", web::get().to(api_admin_users_list))
                .route("/api/admin/users", web::post().to(api_admin_user_create))
                .route("/api/admin/whoami", web::get().to(api_admin_whoami))
                .route(
                    "/api/admin/users/{id}/invite",
                    web::post().to(api_admin_user_invite),
                )
                .route(
                    "/api/admin/users/{id}/reset-password",
                    web::post().to(api_admin_user_reset_password),
                )
                .route(
                    "/api/admin/users/{id}/revoke-sessions",
                    web::post().to(api_admin_user_revoke_sessions),
                )
                .route("/api/admin/users/{id}", web::get().to(api_admin_user_get))
                .route(
                    "/api/admin/users/{id}",
                    web::patch().to(api_admin_user_patch),
                )
                .route(
                    "/api/admin/users/{id}",
                    web::delete().to(api_admin_user_delete),
                )
                .route(
                    "/api/admin/change-requests",
                    web::get().to(api_admin_change_requests_list),
                )
                .route(
                    "/api/admin/change-requests",
                    web::post().to(api_admin_change_request_create),
                )
                .route(
                    "/api/admin/change-requests/{id}",
                    web::get().to(api_admin_change_request_get),
                )
                .route(
                    "/api/admin/change-requests/{id}",
                    web::patch().to(api_admin_change_request_patch),
                )
                .route(
                    "/api/admin/change-requests/{id}",
                    web::delete().to(api_admin_change_request_delete),
                )
                .route(
                    "/api/admin/security/posture",
                    web::get().to(api_admin_security_posture),
                )
                .route(
                    "/api/admin/deliverability/diagnostics",
                    web::get().to(api_admin_deliverability_diagnostics),
                )
                .route(
                    "/api/admin/deliverability/procedure",
                    web::get().to(api_admin_deliverability_procedure),
                )
                .route(
                    "/api/admin/deliverability/procedure",
                    web::post().to(api_admin_deliverability_procedure_update),
                )
                .route(
                    "/api/admin/observability/overview",
                    web::get().to(api_admin_observability_overview),
                )
        })
        .bind(http_addr)
        .expect("Failed to bind HTTP on 8000")
        .run()
        .await
        .expect("HTTP server error");
    });

    // Start HTTPS server on 8443 (original API)
    HttpServer::new(|| {
        let cors = Cors::permissive()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .app_data(web::Data::new(RealDkimService))
            .route("/send-email", web::post().to(send_email_handler))
            .route("/create-mailing-list", web::post().to(create_mailing_list))
            .route(
                "/send-to-mailing-list",
                web::post().to(send_to_mailing_list),
            )
    })
    .bind_openssl("0.0.0.0:8443", builder)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use dotenv::dotenv;
    use mockall::mock;
    use mockall::predicate::eq;

    mock! {
        pub DkimService {
            pub async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
        }
    }

    #[async_trait::async_trait]
    impl DkimService for MockDkimService {
        async fn sign_email(
            &self,
            email: &EmailRequest,
        ) -> Result<serde_json::Value, std::io::Error> {
            self.sign_email(email).await
        }
    }

    #[actix_web::test]
    async fn test_send_email() {
        dotenv::from_filename(".env.test").ok();

        let mut mock_dkim_service = MockDkimService::new();
        mock_dkim_service
            .expect_sign_email()
            .with(eq(EmailRequest {
                from: "sender@example.com".to_string(),
                to: "recipient@example.com".to_string(),
                subject: "Test Email".to_string(),
                body: "This is a test email.".to_string(),
            }))
            .times(1)
            .returning(|_| Ok(serde_json::json!({"status": "success", "messageId": "12345"})));

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    Box::new(mock_dkim_service) as Box<dyn DkimService>
                ))
                .route("/send-email", web::post().to(send_email_handler)),
        )
        .await;

        let email_request = EmailRequest {
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test Email".to_string(),
            body: "This is a test email.".to_string(),
        };
        println!("Sending test request to /send-email");

        let req = test::TestRequest::post()
            .uri("/send-email")
            .set_json(&email_request)
            .to_request();
        let resp = test::call_service(&app, req).await;
        println!("Response status: {:?}", resp.status());
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_api_hermes_chat_requires_messages() {
        let app = test::init_service(
            App::new().route("/api/hermes/chat", web::post().to(api_hermes_chat)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/hermes/chat")
            .set_json(serde_json::json!({ "messages": [] }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_hermes_chat_request_accepts_explicit_session_overrides() {
        let parsed: HermesChatProxyRequest = serde_json::from_value(serde_json::json!({
            "messages": [{"role":"user","content":"hello"}],
            "threadId": "thread-123",
            "userId": "admin",
            "sessionId": "mail-thread-explicit",
            "sessionKey": "user-explicit",
            "maxTokens": 1200
        }))
        .expect("HermesChatProxyRequest should deserialize");

        assert_eq!(parsed.thread_id.as_deref(), Some("thread-123"));
        assert_eq!(parsed.user_id.as_deref(), Some("admin"));
        assert_eq!(parsed.session_id.as_deref(), Some("mail-thread-explicit"));
        assert_eq!(parsed.session_key.as_deref(), Some("user-explicit"));
        assert_eq!(parsed.max_tokens, Some(1200));
    }
    #[actix_web::test]
    async fn test_api_hermes_runs_requires_input() {
        let app = test::init_service(
            App::new().route("/api/hermes/runs", web::post().to(api_hermes_runs)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/hermes/runs")
            .set_json(serde_json::json!({}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_hermes_runs_request_accepts_explicit_session_overrides() {
        let parsed: HermesRunsProxyRequest = serde_json::from_value(serde_json::json!({
            "input": [{"role":"user","content":"hello"}],
            "threadId": "thread-123",
            "userId": "admin",
            "sessionId": "mail-thread-explicit",
            "sessionKey": "user-explicit",
            "model": "hermes-agent"
        }))
        .expect("HermesRunsProxyRequest should deserialize");

        assert!(parsed.input.is_some());
        assert_eq!(parsed.thread_id.as_deref(), Some("thread-123"));
        assert_eq!(parsed.user_id.as_deref(), Some("admin"));
        assert_eq!(parsed.session_id.as_deref(), Some("mail-thread-explicit"));
        assert_eq!(parsed.session_key.as_deref(), Some("user-explicit"));
        assert_eq!(parsed.model.as_deref(), Some("hermes-agent"));
    }

    #[test]
    fn test_normalize_hermes_base_url_strips_v1_and_slashes() {
        assert_eq!(
            normalize_hermes_base_url("http://172.16.12.2:8642/v1/"),
            "http://172.16.12.2:8642"
        );
        assert_eq!(
            normalize_hermes_base_url("http://172.16.12.2:8642/v1"),
            "http://172.16.12.2:8642"
        );
        assert_eq!(
            normalize_hermes_base_url("http://172.16.12.2:8642"),
            "http://172.16.12.2:8642"
        );
    }
}

#[async_trait::async_trait]
pub trait DkimService: Send + Sync {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
}

pub struct RealDkimService;

#[async_trait::async_trait]
impl DkimService for RealDkimService {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
        let dkim_service_url = env::var("DKIM_SERVICE_URL").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "DKIM_SERVICE_URL not set")
        })?;
        let client = reqwest::Client::new();

        let response = client
            .post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": email.from,
                "to": email.to,
                "subject": email.subject,
                "text": email.body,
                "html": email.body
            }))
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if status.is_success() {
            serde_json::from_str::<serde_json::Value>(&body)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            let snippet = if body.len() > 1200 {
                &body[..1200]
            } else {
                &body
            };
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("DKIM service HTTP {}: {}", status.as_u16(), snippet),
            ))
        }
    }
}
