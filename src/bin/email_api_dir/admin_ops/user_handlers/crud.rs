#![allow(unused_imports, dead_code)]
use super::super::*;  // inherit all imports from admin_ops/mod.rs

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

pub(crate) async fn api_admin_user_create(
    req: HttpRequest,
    body: web::Json<CreateAdminUserInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let role = body.role.trim().to_ascii_lowercase();
    if !["user", "admin", "support"].contains(&role.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "role must be user|admin|support" }));
    }

    let status = body
        .status
        .as_deref()
        .unwrap_or("active")
        .trim()
        .to_ascii_lowercase();
    if !["active", "restricted"].contains(&status.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "status must be active|restricted" }));
    }

    let id = body
        .id
        .clone()
        .unwrap_or_else(|| format!("u_{}", Uuid::new_v4().simple()));
    let now = now_iso();

    let user = AdminUserRecord {
        id: id.clone(),
        email: body.email.trim().to_string(),
        display_name: body.display_name.clone(),
        role,
        status,
        two_factor_enabled: body.two_factor_enabled.unwrap_or(false),
        last_login_at: None,
        last_activity_at: Some(now.clone()),
        sessions24h: 0,
        actions7d: 0,
        change_requests30d: 0,
        recent_activity: vec![AdminUserActivity {
            at: now.clone(),
            label: "User created".to_string(),
            kind: "admin_action".to_string(),
        }],
        created_at: now.clone(),
        updated_at: now,
        password_hash: None,
        invite_token: None,
        invite_expires_at: None,
        invited_at: None,
        notes: None,
    };

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll.insert_one(&user).await {
        Ok(_) => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.create",
                "admin_user",
                &user.id,
                None,
                Some(serde_json::json!({ "email": user.email, "role": user.role, "status": user.status })),
            )
            .await;
            HttpResponse::Created().json(serde_json::json!({ "user": user }))
        }
        Err(e) => {
            eprintln!("api_admin_user_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create user" }))
        }
    }
}

pub(crate) async fn api_admin_user_patch(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<UpdateAdminUserInput>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    let current = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_user_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    let now = now_iso();
    let mut updated = current.clone();

    if let Some(role) = &body.role {
        let role = role.trim().to_ascii_lowercase();
        if !["user", "admin", "support"].contains(&role.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "role must be user|admin|support" }));
        }
        updated.role = role;
    }

    if let Some(status) = &body.status {
        let status = status.trim().to_ascii_lowercase();
        if !["active", "restricted"].contains(&status.as_str()) {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "status must be active|restricted" }));
        }
        updated.status = status;
    }

    if let Some(email) = &body.email {
        let email = email.trim();
        if email.is_empty() || !email.contains('@') {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "invalid email" }));
        }
        updated.email = email.to_string();
    }
    if let Some(dn) = &body.display_name {
        let dn = dn.trim();
        updated.display_name = if dn.is_empty() {
            None
        } else {
            Some(dn.to_string())
        };
    }
    if let Some(v) = body.two_factor_enabled {
        updated.two_factor_enabled = v;
    }
    if let Some(notes) = &body.notes {
        let notes = notes.trim();
        if notes.len() > 1024 {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "notes too long (max 1024)" }));
        }
        updated.notes = if notes.is_empty() {
            None
        } else {
            Some(notes.to_string())
        };
    }

    updated.updated_at = now.clone();
    updated.last_activity_at = Some(now.clone());
    updated.actions7d += 1;
    let note = body
        .role
        .as_ref()
        .map(|r| format!("Role changed to {}", r))
        .unwrap_or_else(|| "User updated".to_string());
    let mut recent = updated.recent_activity;
    recent.insert(
        0,
        AdminUserActivity {
            at: now,
            label: note,
            kind: "role_change".to_string(),
        },
    );
    recent.truncate(8);
    updated.recent_activity = recent;

    match coll
        .replace_one(doc! { "id": &id }, &updated)
        .upsert(false)
        .await
    {
        Ok(_) => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.patch",
                "admin_user",
                &id,
                None,
                Some(serde_json::json!({
                    "role": updated.role,
                    "status": updated.status,
                    "email": updated.email,
                    "displayName": updated.display_name,
                    "twoFactorEnabled": updated.two_factor_enabled,
                })),
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({ "user": updated }))
        }
        Err(e) => {
            eprintln!("api_admin_user_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update user" }))
        }
    }
}

pub(crate) async fn api_admin_user_delete(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminUserRecord>(ADMIN_USERS_COLL);

    match coll.delete_one(doc! { "id": &id }).await {
        Ok(res) if res.deleted_count > 0 => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.delete",
                "admin_user",
                &id,
                None,
                None,
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({ "deleted": true, "id": id }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "deleted": false, "message": "User not found" })),
        Err(e) => {
            eprintln!("api_admin_user_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete user" }))
        }
    }
}

/// PR1 (RBAC) — GET /api/admin/whoami
///
/// Utilisé par le frontend pour connaître le rôle réel de l'utilisateur
/// courant et adapter l'UI (viewer vs admin). Respecte le feature flag :
/// - RBAC OFF → répond `{ role: "admin", email: "system@...", enforced: false }`
///   (compat rétro : le front continue à voir un admin).
/// - RBAC ON  → nécessite un token valide, renvoie l'identité réelle.
pub(crate) async fn api_admin_whoami(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(user) => HttpResponse::Ok().json(serde_json::json!({
            "userId": user.user_id,
            "email": user.email,
            "role": user.role,
            "enforced": admin_auth::rbac_enabled(),
        })),
        Err(resp) => resp,
    }
}

// ================================================================
// PR3 — Comptes admin réels
// ================================================================

// PR4 — audit trail admin.
