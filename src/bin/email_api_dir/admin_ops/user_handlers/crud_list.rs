#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

pub(crate) async fn api_admin_users_list(
    req: HttpRequest,
    query: web::Query<AdminUsersQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    // Filtre Mongo dérivé des query params. Tous optionnels — sans param,
    // le comportement reste identique à PR3 (find({}) + sort + limit 500).
    let mut filter = mongodb::bson::Document::new();
    if let Some(role) = &query.role {
        let r = role.trim().to_ascii_lowercase();
        if !r.is_empty() {
            filter.insert("role", r);
        }
    }
    if let Some(status) = &query.status {
        let s = status.trim().to_ascii_lowercase();
        if !s.is_empty() {
            filter.insert("status", s);
        }
    }
    if let Some(q) = &query.q {
        let q = q.trim();
        if !q.is_empty() {
            // Recherche naïve: email OU displayName contient q (case-insensitive).
            let re_email = doc! { "email": { "$regex": q, "$options": "i" } };
            let re_dn = doc! { "displayName": { "$regex": q, "$options": "i" } };
            filter.insert("$or", vec![re_email, re_dn]);
        }
    }

    // Pagination: valeurs par défaut équivalentes à l'ancien comportement
    // (page 1, size 500) si absents.
    let size = query.size.unwrap_or(500).clamp(1, 500);
    let page = query.page.unwrap_or(1).max(1);
    let skip = (page - 1) * size;

    // Total pour la pagination (calcul best-effort, 0 en cas d'erreur).
    let total = coll.count_documents(filter.clone()).await.unwrap_or(0);

    match coll
        .find(filter)
        .sort(doc! { "lastActivityAt": -1 })
        .skip(skip)
        .limit(size as i64)
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
                "pagination": {
                    "page": page,
                    "size": size,
                    "total": total,
                },
            }))
        }
        Err(e) => {
            eprintln!("api_admin_users_list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load admin users" }))
        }
    }
}
