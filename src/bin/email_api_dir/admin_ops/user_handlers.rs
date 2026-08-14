#![allow(unused_imports, dead_code)]
use super::*;  // inherit all imports from mod.rs

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
pub(crate) const ADMIN_AUDIT_COLL: &str = "admin_audit_log";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminAuditEntry {
    id: String,
    at: String,
    actor_id: String,
    actor_email: String,
    action: String,
    target_kind: String,
    target_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    diff: Option<serde_json::Value>,
}

/// Best-effort — n'échoue jamais, log stderr en cas de problème Mongo.
pub(crate) async fn log_admin_action(
    mongo: &mongodb::Client,
    actor: &admin_auth::AuthUser,
    action: &str,
    target_kind: &str,
    target_id: &str,
    note: Option<String>,
    diff: Option<serde_json::Value>,
) {
    let entry = AdminAuditEntry {
        id: Uuid::new_v4().to_string(),
        at: now_iso(),
        actor_id: actor.user_id.clone(),
        actor_email: actor.email.clone(),
        action: action.to_string(),
        target_kind: target_kind.to_string(),
        target_id: target_id.to_string(),
        note,
        diff,
    };
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminAuditEntry>(ADMIN_AUDIT_COLL);
    if let Err(e) = coll.insert_one(&entry).await {
        eprintln!("log_admin_action: insert error: {}", e);
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct AdminAuditQuery {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

/// GET /api/admin/audit-log
pub(crate) async fn api_admin_audit_log(
    req: HttpRequest,
    query: web::Query<AdminAuditQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AdminAuditEntry>(ADMIN_AUDIT_COLL);
    let mut filter = mongodb::bson::Document::new();
    if let Some(t) = &query.target {
        let t = t.trim();
        if !t.is_empty() {
            filter.insert("targetId", t);
        }
    }
    if let Some(a) = &query.actor {
        let a = a.trim();
        if !a.is_empty() {
            filter.insert("actorId", a);
        }
    }
    if let Some(a) = &query.action {
        let a = a.trim();
        if !a.is_empty() {
            filter.insert("action", a);
        }
    }
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    match coll
        .find(filter)
        .sort(doc! { "at": -1 })
        .limit(limit)
        .await
    {
        Ok(cursor) => {
            let entries = cursor
                .try_collect::<Vec<AdminAuditEntry>>()
                .await
                .unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({
                "generatedAt": now_iso(),
                "entries": entries,
            }))
        }
        Err(e) => {
            eprintln!("audit_log query error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load audit log" }))
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResetPasswordInput {
    /// Optionnel — si non fourni, un mot de passe temporaire est généré.
    new_password: Option<String>,
    /// Si true, invalide toutes les sessions existantes en plus.
    #[serde(default)]
    revoke_sessions: bool,
}

/// POST /api/admin/users/{id}/invite
///
/// Génère un token d'invitation (UUID v4, 72h par défaut), le persiste
/// sur l'AdminUserRecord, et déclenche l'envoi d'un mail via le service
/// DKIM interne (best-effort — la réussite du POST ne dépend pas de
/// l'envoi effectif, on trace l'erreur mais on renvoie 200).
pub(crate) async fn api_admin_user_invite(
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

    let mut user = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("invite: find_one error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    let token = Uuid::new_v4().to_string();
    let now = Utc::now();
    let ttl_hours: i64 = env::var("ADMIN_INVITE_TTL_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(72);
    let expires = now + chrono::Duration::hours(ttl_hours);

    user.invite_token = Some(token.clone());
    user.invite_expires_at = Some(expires.to_rfc3339());
    user.invited_at = Some(now.to_rfc3339());
    user.updated_at = now.to_rfc3339();
    let mut recent = user.recent_activity.clone();
    recent.insert(
        0,
        AdminUserActivity {
            at: now.to_rfc3339(),
            label: "Invitation sent".to_string(),
            kind: "admin_action".to_string(),
        },
    );
    recent.truncate(8);
    user.recent_activity = recent;

    if let Err(e) = coll
        .replace_one(doc! { "id": &id }, &user)
        .upsert(false)
        .await
    {
        eprintln!("invite: replace_one error: {}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "message": "Failed to save invite" }));
    }

    // Envoi email best-effort via le service DKIM. On ne bloque pas la
    // réponse HTTP en cas d'erreur de la chaîne d'envoi (le token reste
    // valide et peut être renvoyé manuellement au besoin).
    let dkim_url = env::var("DKIM_SERVICE_URL")
        .unwrap_or_else(|_| "http://dkim-service:3000".to_string());
    let invite_base = env::var("ADMIN_INVITE_BASE_URL")
        .unwrap_or_else(|_| "https://misfits.ai/admin/accept-invite".to_string());
    let sender = env::var("ADMIN_INVITE_FROM")
        .unwrap_or_else(|_| "no-reply@misfits.ai".to_string());
    let accept_url = format!("{}?token={}", invite_base, token);
    let display = user
        .display_name
        .clone()
        .unwrap_or_else(|| user.email.clone());
    let subject = "Invitation à rejoindre la console admin Misfits";
    let html = format!(
        "<p>Bonjour {display},</p>\
         <p>Vous avez été invité(e) à rejoindre la console admin de Misfits Mail.</p>\
         <p>Le lien ci-dessous est valable {ttl_hours}h et à usage unique :</p>\
         <p><a href=\"{accept_url}\">{accept_url}</a></p>\
         <p>Si vous n'attendiez pas cette invitation, ignorez ce message.</p>\
         <p>— L'équipe Misfits</p>",
        display = display,
        ttl_hours = ttl_hours,
        accept_url = accept_url
    );
    let payload = serde_json::json!({
        "from": sender,
        "to": user.email,
        "subject": subject,
        "html": html,
    });
    let mongo_for_send = mongo.clone();
    let email_for_log = user.email.clone();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/generate-dkim", dkim_url.trim_end_matches('/')))
            .json(&payload)
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {}
            Ok(r) => eprintln!("invite: dkim-service {} for {}", r.status(), email_for_log),
            Err(e) => eprintln!("invite: dkim-service unreachable: {}", e),
        }
        let _ = mongo_for_send; // keep clone alive for future extension
    });

    log_admin_action(
        mongo.as_ref(),
        &actor,
        "user.invite",
        "admin_user",
        &id,
        Some(format!("token expires {}", expires.to_rfc3339())),
        None,
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "invited": true,
        "user": user,
        "acceptUrl": accept_url,
        "expiresAt": expires.to_rfc3339(),
    }))
}

/// POST /api/admin/users/{id}/reset-password
///
/// Définit un nouveau mot de passe (bcrypt) sur l'AdminUserRecord.
/// Optionnellement révoque les sessions existantes.
pub(crate) async fn api_admin_user_reset_password(
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<ResetPasswordInput>,
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

    let mut user = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "User not found" }))
        }
        Err(e) => {
            eprintln!("reset_password: find_one error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load user" }));
        }
    };

    // Si aucun mot de passe fourni, on génère un temporaire (16 chars,
    // alphanumérique + 2 symboles insérés à des positions déterministes).
    // Base: 2 UUID hex concaténés (32 chars aléatoires) tronqués à 14,
    // puis '!' et '#' injectés pour satisfaire les politiques classiques.
    let (new_password, generated) = match &body.new_password {
        Some(p) if !p.trim().is_empty() => (p.trim().to_string(), false),
        _ => {
            let a = Uuid::new_v4().simple().to_string();
            let b = Uuid::new_v4().simple().to_string();
            let mixed = format!("{}{}", &a[..7], &b[..7]);
            // Insertion de 2 symboles à positions fixes → 16 chars finaux.
            let temp = format!("{}!{}#", &mixed[..7], &mixed[7..]);
            (temp, true)
        }
    };

    if new_password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "password must be at least 8 chars" }));
    }

    // Conserver la valeur en clair pour la réponse (uniquement dans le cas
    // `generated=true` — pour un mot de passe fourni par l'admin, aucun
    // intérêt à le lui renvoyer).
    let clear_for_response = if generated {
        Some(new_password.clone())
    } else {
        None
    };

    let hash = match web::block(move || bcrypt::hash(&new_password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("reset_password: bcrypt error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to hash password" }));
        }
        Err(e) => {
            eprintln!("reset_password: web::block error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to hash password" }));
        }
    };

    let now = now_iso();
    user.password_hash = Some(hash.clone());
    user.updated_at = now.clone();
    // Consommer un éventuel jeton d'invitation en cours.
    user.invite_token = None;
    user.invite_expires_at = None;
    let mut recent = user.recent_activity.clone();
    recent.insert(
        0,
        AdminUserActivity {
            at: now,
            label: if generated {
                "Password reset (auto-generated)".to_string()
            } else {
                "Password reset".to_string()
            },
            kind: "admin_action".to_string(),
        },
    );
    recent.truncate(8);
    user.recent_activity = recent;

    if let Err(e) = coll
        .replace_one(doc! { "id": &id }, &user)
        .upsert(false)
        .await
    {
        eprintln!("reset_password: replace_one error: {}", e);
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "message": "Failed to update password" }));
    }

    // Propager le hash à la collection `users` (utilisée par
    // `authenticate_user` pour le login classique + IMAP/SMTP). Sans cette
    // synchro, l'admin définit un nouveau mot de passe côté `admin_users`
    // mais l'utilisateur reste incapable de se connecter.
    // Le match se fait sur `username = email` (convention Misfits Mail).
    let users_coll = mongo
        .database(&mongo_db_name())
        .collection::<mongodb::bson::Document>("users");
    if let Err(e) = users_coll
        .update_one(
            doc! { "username": &user.email },
            doc! { "$set": { "password": &hash } },
        )
        .await
    {
        // Non-bloquant: on log mais on renvoie succès. Le hash reste
        // désynchronisé si `users` ne contient pas encore ce username —
        // c'est le cas si le compte a été créé UNIQUEMENT côté admin.
        eprintln!("reset_password: users sync warning: {}", e);
    }

    // Révocation des sessions optionnelle.
    if body.revoke_sessions {
        let sessions = mongo
            .database(&mongo_db_name())
            .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
        if let Err(e) = sessions.delete_many(doc! { "user_id": &id }).await {
            eprintln!("reset_password: revoke sessions error: {}", e);
        }
    }

    log_admin_action(
        mongo.as_ref(),
        &actor,
        "user.reset_password",
        "admin_user",
        &id,
        Some(if generated { "auto-generated".to_string() } else { "manual".to_string() }),
        None,
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "reset": true,
        "user": user,
        "generated": generated,
        // Mot de passe en clair — présent UNIQUEMENT si `generated=true`.
        // L'admin doit le communiquer au propriétaire hors-bande puis
        // exiger un changement à la prochaine connexion.
        "password": clear_for_response,
    }))
}

/// POST /api/admin/users/{id}/revoke-sessions
pub(crate) async fn api_admin_user_revoke_sessions(
    req: HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let actor = match admin_auth::require_admin(&req, &mongo, &mongo_db_name()).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };
    let id = path.into_inner();
    let sessions = mongo
        .database(&mongo_db_name())
        .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
    match sessions.delete_many(doc! { "user_id": &id }).await {
        Ok(res) => {
            log_admin_action(
                mongo.as_ref(),
                &actor,
                "user.revoke_sessions",
                "admin_user",
                &id,
                Some(format!("deleted {} sessions", res.deleted_count)),
                None,
            )
            .await;
            HttpResponse::Ok().json(serde_json::json!({
                "revoked": true,
                "deletedCount": res.deleted_count,
            }))
        }
        Err(e) => {
            eprintln!("revoke_sessions: error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to revoke sessions" }))
        }
    }
}

