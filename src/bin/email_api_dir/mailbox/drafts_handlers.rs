// Sprint 8: split from mailbox_handlers.rs
#![allow(unused_imports)]
use super::*;


pub(crate) async fn api_drafts_list(
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

pub(crate) async fn api_drafts_upsert(
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

pub(crate) async fn api_drafts_delete(
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

