// Scheduled draft sending: POST /api/v1/drafts/schedule, GET /api/v1/drafts/scheduled,
// DELETE /api/v1/drafts/scheduled/{id}.
// Reuses the existing send_queue collection + send_queue_worker (which already handles
// "scheduled" status with retry/exponential backoff).
#![allow(unused_imports)]
use super::*;

#[derive(Deserialize)]
pub(crate) struct ScheduleDraftRequest {
    pub draft_id: String,
    pub send_at: String,
}

/// POST /api/v1/drafts/schedule — schedule a draft for later sending.
pub(crate) async fn api_drafts_schedule(
    body: web::Json<ScheduleDraftRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);

    let send_at = match chrono::DateTime::parse_from_rfc3339(&body.send_at) {
        Ok(dt) => dt,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid send_at: use ISO 8601 / RFC 3339 format"
            }));
        }
    };
    if send_at.timestamp() <= Utc::now().timestamp() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "send_at must be in the future" }));
    }

    // Fetch the draft
    let drafts_coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("drafts");

    let draft = match drafts_coll
        .find_one(doc! { "user_id": &user_id, "id": &body.draft_id })
        .await
    {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "error": "Draft not found" }));
        }
        Err(e) => {
            eprintln!("api_drafts_schedule draft lookup error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Failed to look up draft" }));
        }
    };

    // Extract email fields from the draft (defensive: drafts are freeform JSON).
    let get_str = |key: &str| -> String {
        draft
            .get_str(key)
            .unwrap_or("")
            .trim()
            .to_string()
    };

    let from = get_str("from");
    let to = get_str("to");
    let cc = get_str("cc");
    let bcc = get_str("bcc");
    let subject = get_str("subject");
    let mail_body = get_str("body");

    if to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Draft has no recipients (to)"
        }));
    }

    // Resolve sender address
    let from = if from.is_empty() {
        from_address_for_user(&user_id)
    } else {
        from
    };

    // Build MIME body (supports multipart if the draft carries attachments).
    let attachments: Vec<ComposeAttachmentInput> = draft
        .get_array("attachments")
        .ok()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_document())
                .filter_map(|d| bson::from_document::<ComposeAttachmentInput>(d.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    let (smtp_body, content_type_header) = match build_body_with_attachments(&mail_body, &attachments) {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "error": e }));
        }
    };

    let id = Uuid::new_v4().to_string();
    let message_id = format!("<{}@{}>", id, domain_from_env());

    let sq_coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match sq_coll
        .insert_one(doc! {
            "id": &id,
            "user_id", &user_id,
            "draft_id": &body.draft_id,
            "from": &from,
            "to": &to,
            "cc": &cc,
            "bcc": &bcc,
            "subject": &subject,
            "body": &smtp_body,
            "content_type": &content_type_header,
            "dkim_signature": "",
            "message_id": &message_id,
            "status": "scheduled",
            "send_after": bson::DateTime::from_millis(send_at.timestamp_millis()),
            "created_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        })
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "scheduled": true,
            "id": id,
            "draftId": &body.draft_id,
            "sendAt": &body.send_at,
        })),
        Err(e) => {
            eprintln!("api_drafts_schedule insert error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

/// GET /api/v1/drafts/scheduled — list pending scheduled sends for the current user.
pub(crate) async fn api_drafts_scheduled_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let sq_coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match sq_coll
        .find(doc! { "user_id": &user_id, "status": "scheduled" })
        .sort(doc! { "send_after": 1 })
        .await
    {
        Ok(cursor) => {
            let mut entries: Vec<serde_json::Value> = Vec::new();
            for mut doc in cursor.try_collect::<Vec<bson::Document>>().await.unwrap_or_default() {
                doc.remove("_id");
                doc.remove("user_id");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(doc)) {
                    entries.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({ "scheduled": entries }))
        }
        Err(e) => {
            eprintln!("api_drafts_scheduled_list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Failed to list scheduled sends" }))
        }
    }
}

/// DELETE /api/v1/drafts/scheduled/{id} — cancel a scheduled send (only while still "scheduled").
pub(crate) async fn api_drafts_scheduled_cancel(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let scheduled_id = path.into_inner();
    let sq_coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match sq_coll
        .update_one(
            doc! {
                "id": &scheduled_id,
                "user_id": &user_id,
                "status": "scheduled",
            },
            doc! { "$set": { "status": "cancelled", "updated_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
        )
        .await
    {
        Ok(r) if r.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "cancelled": true,
            "id": scheduled_id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "cancelled": false,
            "error": "Scheduled send not found or already sent/cancelled",
        })),
        Err(e) => {
            eprintln!("api_drafts_scheduled_cancel error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_draft_request_deserializes() {
        let json = serde_json::json!({
            "draft_id": "draft-123",
            "send_at": "2099-01-01T00:00:00Z"
        });
        let req: ScheduleDraftRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.draft_id, "draft-123");
        assert_eq!(req.send_at, "2099-01-01T00:00:00Z");
    }

    #[test]
    fn schedule_draft_request_missing_fields_error() {
        let json = serde_json::json!({ "draft_id": "draft-123" });
        let result: Result<ScheduleDraftRequest, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn schedule_draft_request_extra_fields_ok() {
        let json = serde_json::json!({
            "draft_id": "draft-123",
            "send_at": "2099-01-01T00:00:00Z",
            "extra": "ignored"
        });
        let req: ScheduleDraftRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.draft_id, "draft-123");
    }

    #[test]
    fn future_timestamp_parses() {
        let ts = "2099-01-01T00:00:00Z";
        let dt = chrono::DateTime::parse_from_rfc3339(ts);
        assert!(dt.is_ok());
        assert!(dt.unwrap().timestamp() > Utc::now().timestamp());
    }

    #[test]
    fn past_timestamp_rejected() {
        let ts = "2020-01-01T00:00:00Z";
        let dt = chrono::DateTime::parse_from_rfc3339(ts).unwrap();
        assert!(dt.timestamp() <= Utc::now().timestamp());
    }

    #[test]
    fn invalid_timestamp_rejected() {
        let ts = "not-a-date";
        let dt = chrono::DateTime::parse_from_rfc3339(ts);
        assert!(dt.is_err());
    }
}
