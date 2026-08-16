#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_external_sync_start(
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

pub(crate) async fn api_external_sync_run_get(
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

pub(crate) async fn api_external_sync_status(
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

pub(crate) async fn api_external_sync_pause(
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

pub(crate) async fn api_external_sync_resume(
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

pub(crate) async fn api_external_messages_list(
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

pub(crate) async fn api_external_message_action(
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
pub(crate) struct CreateCalendarEventRequest {
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

pub(crate) fn default_event_type_str() -> String {
    "default".to_string()
}
pub(crate) fn default_color_str() -> String {
    "#3788d8".to_string()
}

#[derive(Deserialize)]
pub(crate) struct UpdateCalendarEventRequest {
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
pub(crate) struct CalendarQueryParams {
    #[serde(default)]
    start: Option<String>, // ISO 8601
    #[serde(default)]
    end: Option<String>, // ISO 8601
}

pub(crate) fn parse_iso_to_bson(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

pub(crate) fn get_user_from_headers(req: &actix_web::HttpRequest) -> String {
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

pub(crate) async fn calendar_create_event(
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

pub(crate) async fn calendar_list_events(
    req: actix_web::HttpRequest,
    query: web::Query<CalendarQueryParams>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start_after = query.start.as_ref().and_then(|s| parse_iso_to_bson(s))
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()));
    let start_before = query.end.as_ref().and_then(|s| parse_iso_to_bson(s))
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()));

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

pub(crate) async fn calendar_get_event(
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

pub(crate) async fn calendar_update_event(
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

pub(crate) async fn calendar_delete_event(
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

