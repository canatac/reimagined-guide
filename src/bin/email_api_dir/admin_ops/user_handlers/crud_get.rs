#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

pub(crate) async fn api_admin_user_get(
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
