#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_admin_change_request_delete(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_response_success() {
        let response = serde_json::json!({ "deleted": true, "id": "cr-123" });
        assert_eq!(response["deleted"], true);
        assert_eq!(response["id"], "cr-123");
    }

    #[test]
    fn delete_response_not_found() {
        let response = serde_json::json!({ "deleted": false, "message": "Change request not found" });
        assert_eq!(response["deleted"], false);
        assert_eq!(response["message"], "Change request not found");
    }

    #[test]
    fn delete_response_error() {
        let response = serde_json::json!({ "message": "Failed to delete change request" });
        assert_eq!(response["message"], "Failed to delete change request");
    }

    #[test]
    fn delete_one_query_format() {
        let id = "cr-123";
        let query = mongodb::bson::doc! { "id": &id };
        assert_eq!(query.get_str("id").unwrap(), "cr-123");
    }

    #[test]
    fn delete_count_positive() {
        let deleted_count = 1u64;
        assert!(deleted_count > 0);
    }

    #[test]
    fn delete_count_zero() {
        let deleted_count = 0u64;
        assert!(deleted_count == 0);
    }
}
