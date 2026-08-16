#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_admin_change_requests_list(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
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

pub(crate) async fn api_admin_change_request_get(
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
