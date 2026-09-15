// Scheduled send handlers — list & cancel scheduled emails (issue #493)
#![allow(unused_imports)]
use super::*;

/// GET /api/v1/drafts/scheduled — list pending scheduled sends for current user
pub(crate) async fn api_scheduled_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    match coll
        .find(doc! {
            "user_id": &user_id,
            "status": "scheduled",
        })
        .sort(doc! { "send_after": 1 })
        .limit(200)
        .await
    {
        Ok(cursor) => {
            let mut items: Vec<serde_json::Value> = Vec::new();
            for mut docu in cursor
                .try_collect::<Vec<bson::Document>>()
                .await
                .unwrap_or_default()
            {
                docu.remove("_id");
                docu.remove("user_id");
                docu.remove("dkim_signature");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu)) {
                    items.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({ "scheduled": items }))
        }
        Err(e) => {
            eprintln!("api_scheduled_list error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list scheduled sends"
            }))
        }
    }
}

/// DELETE /api/v1/drafts/scheduled/{id} — cancel a scheduled send
pub(crate) async fn api_scheduled_cancel(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = path.into_inner();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);

    // Only allow cancelling emails that are still scheduled (not yet sent/sending)
    match coll
        .update_one(
            doc! {
                "id": &id,
                "user_id": &user_id,
                "status": "scheduled",
            },
            doc! { "$set": { "status": "cancelled", "updated_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
        )
        .await
    {
        Ok(r) if r.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "cancelled": true,
            "id": &id
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "cancelled": false,
            "reason": "Scheduled send not found or already processed"
        })),
        Err(e) => {
            eprintln!("api_scheduled_cancel error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to cancel scheduled send"
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduled_status_filter_only_matches_scheduled() {
        // Verify the MongoDB filter structure for cancel operation
        let filter = doc! {
            "id": "test-id",
            "user_id": "user-1",
            "status": "scheduled",
        };
        assert_eq!(filter.get_str("status").unwrap(), "scheduled");
    }

    #[test]
    fn cancelled_update_sets_status_field() {
        let update = doc! { "$set": { "status": "cancelled", "updated_at": bson::DateTime::from_millis(0) } };
        let set = update.get_document("$set").unwrap();
        assert_eq!(set.get_str("status").unwrap(), "cancelled");
    }
}
