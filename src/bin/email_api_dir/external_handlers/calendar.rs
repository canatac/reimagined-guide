#![allow(unused_imports, dead_code)]
use super::super::*;

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

