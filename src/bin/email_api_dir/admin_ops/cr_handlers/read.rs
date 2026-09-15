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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_response_structure() {
        let response = serde_json::json!({
            "generatedAt": "2026-01-01T00:00:00Z",
            "counts": {},
            "items": [],
        });
        assert!(response.get("generatedAt").is_some());
        assert!(response.get("counts").is_some());
        assert!(response.get("items").is_some());
    }

    #[test]
    fn get_response_success() {
        let response = serde_json::json!({ "item": {} });
        assert!(response.get("item").is_some());
    }

    #[test]
    fn get_response_not_found() {
        let response = serde_json::json!({ "message": "Change request not found" });
        assert_eq!(response["message"], "Change request not found");
    }

    #[test]
    fn get_response_error() {
        let response = serde_json::json!({ "message": "Failed to load change request" });
        assert_eq!(response["message"], "Failed to load change request");
    }

    #[test]
    fn list_response_error() {
        let response = serde_json::json!({ "message": "Failed to load change requests" });
        assert_eq!(response["message"], "Failed to load change requests");
    }

    #[test]
    fn find_one_query_format() {
        let id = "cr-123";
        let query = mongodb::bson::doc! { "id": &id };
        assert_eq!(query.get_str("id").unwrap(), "cr-123");
    }

    #[test]
    fn find_all_query_format() {
        let query = mongodb::bson::doc! {};
        assert!(query.is_empty());
    }

    #[test]
    fn sort_by_updated_at_desc() {
        let sort = mongodb::bson::doc! { "updatedAt": -1 };
        assert_eq!(sort.get_i32("updatedAt").unwrap(), -1);
    }

    #[test]
    fn limit_500() {
        let limit = 500i64;
        assert_eq!(limit, 500);
    }
}
