// admin_ops_handlers.rs — extracted from email_api_dir/main.rs Sprint 2
// Handlers: api_admin_users_list, api_admin_user_*, api_admin_whoami,
//           api_admin_audit_log, api_admin_change_requests_*, log_admin_action,
//           api_admin_deliverability_*, api_admin_security_posture,
//           api_admin_observability_overview, ai-activity, change-request workflow

use super::*;

pub(crate) const ADMIN_USERS_COLL: &str = "admin_users";
pub(crate) const ADMIN_CHANGE_REQUESTS_COLL: &str = "admin_change_requests";

pub(crate) fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub(crate) fn admin_workflow_order() -> Vec<&'static str> {
    vec![
        "submitted",
        "triaged",
        "planned",
        "in_progress",
        "qa",
        "released",
    ]
}

pub(crate) fn compute_priority(urgency: &str, impact: &str) -> String {
    if urgency == "high" && impact == "high" {
        "P0".to_string()
    } else if urgency == "high" || impact == "high" {
        "P1".to_string()
    } else {
        "P2".to_string()
    }
}

pub(crate) fn build_initial_stages() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage {
            key: "discovery".to_string(),
            label: "Discovery produit".to_string(),
            owner: "product".to_string(),
            status: "active".to_string(),
            checklist: vec![
                "Clarifier le problème utilisateur".to_string(),
                "Mesurer impact business/ops".to_string(),
                "Valider la portée UX + Backend".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "spec".to_string(),
            label: "Spécification".to_string(),
            owner: "backend".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Définir contrat API + payload".to_string(),
                "Définir telemetry & changelog".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "build".to_string(),
            label: "Implémentation".to_string(),
            owner: "frontend".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Implémenter UI/UX".to_string(),
                "Implémenter endpoint backend".to_string(),
                "Ajouter tests critiques".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "qa".to_string(),
            label: "Validation".to_string(),
            owner: "qa".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Typecheck + lint + tests".to_string(),
                "Validation de non-régression admin".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "release".to_string(),
            label: "Rollout".to_string(),
            owner: "ops".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Publier changelog".to_string(),
                "Surveiller métriques post-release".to_string(),
                "Préparer rollback playbook".to_string(),
            ],
            done_at: None,
        },
    ]
}

pub(crate) fn build_acceptance_criteria(scope: &str) -> Vec<String> {
    let mut base = vec![
        "Le flux admin expose un état lisible de la demande".to_string(),
        "Le backend retourne un état workflow déterministe".to_string(),
        "Le changement apparaît dans le flux changelog une fois released".to_string(),
    ];

    if scope == "ux" || scope == "fullstack" {
        base.push("Parcours UX sans ambiguïté: soumission -> triage -> release".to_string());
    }
    if scope == "backend" || scope == "fullstack" {
        base.push("Contrat API versionné et validé sur payloads invalides".to_string());
    }
    if scope == "security" {
        base.push("Audit trail incluant owner, horodatage et note de transition".to_string());
    }

    base
}

pub(crate) fn advance_workflow(stages: &[WorkflowStage]) -> Vec<WorkflowStage> {
    let now = now_iso();
    let current_idx = stages.iter().position(|s| s.status == "active");
    if current_idx.is_none() {
        return stages.to_vec();
    }
    let current_idx = current_idx.unwrap();
    stages
        .iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == current_idx {
                let mut done = stage.clone();
                done.status = "done".to_string();
                done.done_at = Some(now.clone());
                done
            } else if idx == current_idx + 1 {
                let mut active = stage.clone();
                active.status = "active".to_string();
                active
            } else {
                stage.clone()
            }
        })
        .collect()
}

pub(crate) fn status_counts(items: &[ChangeRequestItem]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for status in [
        "submitted",
        "triaged",
        "planned",
        "in_progress",
        "qa",
        "released",
        "rejected",
    ] {
        map.insert(status.to_string(), serde_json::Value::from(0));
    }
    for item in items {
        if let Some(v) = map.get_mut(&item.status) {
            let next = v.as_i64().unwrap_or(0) + 1;
            *v = serde_json::Value::from(next);
        }
    }
    serde_json::Value::Object(map)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateAdminUserInput {
    id: Option<String>,
    email: String,
    display_name: Option<String>,
    role: String,
    status: Option<String>,
    two_factor_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateAdminUserInput {
    role: Option<String>,
    status: Option<String>,
    // PR3 — champs additionnels supportés par PATCH
    email: Option<String>,
    display_name: Option<String>,
    two_factor_enabled: Option<bool>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateChangeRequestInputApi {
    title: String,
    problem: String,
    desired_outcome: String,
    scope: String,
    urgency: String,
    impact: String,
    requested_by: String,
    linked_repo: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PatchChangeRequestInputApi {
    action: Option<String>,
    note: Option<String>,
    actor: Option<String>,
    title: Option<String>,
    problem: Option<String>,
    desired_outcome: Option<String>,
    status: Option<String>,
    execution_run_id: Option<String>,
    execution_error: Option<String>,
}

/// PR4 — query params optionnels : ?q=&role=&status=&page=&size=
#[derive(Debug, Deserialize)]
pub(crate) struct AdminUsersQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
}

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

    // Si aucun mot de passe fourni, on génère un temporaire.
    let (new_password, generated) = match &body.new_password {
        Some(p) if !p.trim().is_empty() => (p.trim().to_string(), false),
        _ => {
            let random = Uuid::new_v4().simple().to_string();
            (random[..12].to_string(), true)
        }
    };

    if new_password.len() < 8 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "password must be at least 8 chars" }));
    }

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
    user.password_hash = Some(hash);
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

    // Révocation des sessions optionnelle.
    if body.revoke_sessions {
        let sessions = mongo
            .database(&mongo_db_name())
            .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
        if let Err(e) = sessions.delete_many(doc! { "userId": &id }).await {
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
        "generatedPassword": if generated { serde_json::Value::Bool(true) } else { serde_json::Value::Null },
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
    match sessions.delete_many(doc! { "userId": &id }).await {
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

pub(crate) async fn api_admin_change_request_create(
    body: web::Json<CreateChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let scope = body.scope.trim().to_ascii_lowercase();
    let urgency = body.urgency.trim().to_ascii_lowercase();
    let impact = body.impact.trim().to_ascii_lowercase();
    let linked_repo = body.linked_repo.trim().to_ascii_lowercase();

    if !["ux", "backend", "fullstack", "security"].contains(&scope.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "scope must be ux|backend|fullstack|security" }));
    }
    if !["low", "medium", "high"].contains(&urgency.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "urgency must be low|medium|high" }));
    }
    if !["small", "medium", "high"].contains(&impact.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "impact must be small|medium|high" }));
    }
    if !["misfits-web", "reimagined-guide", "cross-repo"].contains(&linked_repo.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "linkedRepo must be misfits-web|reimagined-guide|cross-repo" }));
    }

    let now = now_iso();
    let submitter = body.requested_by.trim().to_string();
    let item = ChangeRequestItem {
        id: format!("cr_{}", Uuid::new_v4().simple()),
        title: body.title.trim().to_string(),
        problem: body.problem.trim().to_string(),
        desired_outcome: body.desired_outcome.trim().to_string(),
        scope: scope.clone(),
        priority: compute_priority(&urgency, &impact),
        status: "submitted".to_string(),
        requested_by: submitter.clone(),
        linked_repo,
        created_at: now.clone(),
        updated_at: now.clone(),
        taken_in_charge_at: None,
        taken_in_charge_by: None,
        target_release_window: if urgency == "high" {
            "next-24h".to_string()
        } else if urgency == "medium" {
            "next-72h".to_string()
        } else {
            "next-sprint".to_string()
        },
        acceptance_criteria: build_acceptance_criteria(&scope),
        workflow: build_initial_stages(),
        workflow_events: vec![WorkflowEvent {
            at: now,
            actor: submitter,
            action: "submitted".to_string(),
            from_status: "submitted".to_string(),
            to_status: "submitted".to_string(),
            note: Some("Change request créée".to_string()),
        }],
        execution_state: "idle".to_string(),
        execution_run_id: None,
        execution_started_at: None,
        execution_last_heartbeat_at: None,
        execution_finished_at: None,
        execution_last_error: None,
        changelog_entry: None,
    };

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.insert_one(&item).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create change request" }))
        }
    }
}

pub(crate) async fn api_admin_change_request_patch(
    path: web::Path<String>,
    body: web::Json<PatchChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    let mut item = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "Change request not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_change_request_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change request" }));
        }
    };

    if let Some(action) = &body.action {
        let action = action.trim().to_ascii_lowercase();
        let actor = body
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        let previous_status = item.status.clone();
        let mut transition_note = body.note.clone();

        if action == "reject" {
            item.status = "rejected".to_string();
            item.workflow = item
                .workflow
                .iter()
                .map(|stage| {
                    if stage.status == "active" {
                        let mut s = stage.clone();
                        s.status = "done".to_string();
                        s.done_at = Some(now_iso());
                        s
                    } else {
                        stage.clone()
                    }
                })
                .collect();
            item.execution_state = "idle".to_string();
            item.execution_run_id = None;
            item.execution_started_at = None;
            item.execution_last_heartbeat_at = None;
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = None;
        } else if action == "advance" {
            let order = admin_workflow_order();
            let idx = order.iter().position(|x| *x == item.status).unwrap_or(0);
            if idx < order.len() - 1 {
                item.status = order[idx + 1].to_string();
                item.workflow = advance_workflow(&item.workflow);
                if item.status == "in_progress" && item.execution_state == "idle" {
                    item.execution_state = "queued".to_string();
                    item.execution_last_error = None;
                    item.execution_finished_at = None;
                    if transition_note.is_none() {
                        transition_note = Some(
                            "Workflow in_progress atteint; en attente d’un run technique backend explicite".to_string(),
                        );
                    }
                }
                if item.status == "released" {
                    item.execution_state = "success".to_string();
                    item.execution_finished_at = Some(now_iso());
                    item.execution_last_error = None;
                    item.changelog_entry = Some(serde_json::json!({
                        "title": item.title,
                        "summary": body.note.clone().unwrap_or_else(|| item.desired_outcome.clone()),
                        "releasedAt": now_iso(),
                    }));
                }
            }
        } else if action == "execution_queue" {
            item.execution_state = "queued".to_string();
            item.execution_finished_at = None;
            item.execution_last_error = None;
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_start" {
            let now = now_iso();
            item.execution_state = "running".to_string();
            item.execution_started_at = Some(
                item.execution_started_at
                    .clone()
                    .unwrap_or_else(|| now.clone()),
            );
            item.execution_last_heartbeat_at = Some(now.clone());
            item.execution_finished_at = None;
            item.execution_last_error = None;
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_heartbeat" {
            item.execution_state = "running".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            if item.execution_started_at.is_none() {
                item.execution_started_at = Some(now_iso());
            }
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_fail" {
            item.execution_state = "failed".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = body
                .execution_error
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| transition_note.clone())
                .or(Some("Execution failed".to_string()));
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_success" {
            item.execution_state = "success".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = None;
            if let Some(run_id) = body
                .execution_run_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                item.execution_run_id = Some(run_id.to_string());
            }
        } else if action == "execution_reset" {
            item.execution_state = "idle".to_string();
            item.execution_run_id = None;
            item.execution_started_at = None;
            item.execution_last_heartbeat_at = None;
            item.execution_finished_at = None;
            item.execution_last_error = None;
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "message": "action must be advance|reject|execution_queue|execution_start|execution_heartbeat|execution_fail|execution_success|execution_reset" }));
        }

        if item.taken_in_charge_at.is_none()
            && previous_status == "submitted"
            && item.status != "submitted"
        {
            let intake_at = now_iso();
            item.taken_in_charge_at = Some(intake_at.clone());
            item.taken_in_charge_by = Some(actor.clone());
            if transition_note.is_none() {
                transition_note = Some("Prise en charge initiale".to_string());
            }
        }

        item.workflow_events.push(WorkflowEvent {
            at: now_iso(),
            actor,
            action,
            from_status: previous_status,
            to_status: item.status.clone(),
            note: transition_note,
        });
    }

    if let Some(title) = &body.title {
        item.title = title.trim().to_string();
    }
    if let Some(problem) = &body.problem {
        item.problem = problem.trim().to_string();
    }
    if let Some(desired) = &body.desired_outcome {
        item.desired_outcome = desired.trim().to_string();
    }
    if let Some(status) = &body.status {
        let status = status.trim().to_ascii_lowercase();
        if [
            "submitted",
            "triaged",
            "planned",
            "in_progress",
            "qa",
            "released",
            "rejected",
        ]
        .contains(&status.as_str())
        {
            item.status = status;
        }
    }

    item.updated_at = now_iso();

    match coll
        .replace_one(doc! { "id": &id }, &item)
        .upsert(false)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update change request" }))
        }
    }
}

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

// --- AI settings (Phase B1, issue #173) ----------------------------------------

pub(crate) const AI_SETTINGS_ID: &str = "global";
pub(crate) const DEFAULT_AI_MODEL: &str = "qwen/qwen3.7-flash";

pub(crate) fn default_ai_feature_models() -> HashMap<String, String> {
    let mut m = HashMap::new();
    for key in [
        "compose",
        "translate",
        "triage",
        "security",
        "rewrite",
        "subject",
        "complete",
    ] {
        m.insert(key.to_string(), DEFAULT_AI_MODEL.to_string());
    }
    m
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AiSettingsDoc {
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "defaultModel", alias = "default_model")]
    default_model: String,
    features: HashMap<String, String>,
    #[serde(rename = "updatedAt", alias = "updated_at", default)]
    updated_at: Option<String>,
}

impl AiSettingsDoc {
    fn defaults() -> Self {
        Self {
            id: AI_SETTINGS_ID.to_string(),
            default_model: DEFAULT_AI_MODEL.to_string(),
            features: default_ai_feature_models(),
            updated_at: Some(Utc::now().to_rfc3339()),
        }
    }

    fn merge_with_defaults(mut self) -> Self {
        let defaults = default_ai_feature_models();
        for (k, v) in defaults {
            self.features.entry(k).or_insert(v);
        }
        if self.default_model.trim().is_empty() {
            self.default_model = DEFAULT_AI_MODEL.to_string();
        }
        self
    }

    fn to_public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "defaultModel": self.default_model,
            "features": self.features,
            "updatedAt": self.updated_at,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct AiSettingsUpdate {
    #[serde(rename = "defaultModel", alias = "default_model", default)]
    default_model: Option<String>,
    #[serde(default)]
    features: Option<HashMap<String, String>>,
}

pub(crate) fn mongo_db_name() -> String {
    env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

pub(crate) async fn load_ai_settings(client: &mongodb::Client) -> AiSettingsDoc {
    let coll = client
        .database(&mongo_db_name())
        .collection::<AiSettingsDoc>("ai_settings");
    match coll.find_one(doc! { "_id": AI_SETTINGS_ID }).await {
        Ok(Some(doc)) => doc.merge_with_defaults(),
        _ => AiSettingsDoc::defaults(),
    }
}

pub(crate) async fn api_get_ai_settings(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
    let settings = load_ai_settings(mongo.get_ref()).await;
    HttpResponse::Ok().json(settings.to_public_json())
}

pub(crate) async fn api_put_ai_settings(
    body: web::Json<AiSettingsUpdate>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let mut current = load_ai_settings(mongo.get_ref()).await;
    if let Some(model) = body.default_model.as_ref() {
        let m = model.trim();
        if !m.is_empty() {
            current.default_model = m.to_string();
        }
    }
    if let Some(features) = body.features.as_ref() {
        for (k, v) in features {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() && !val.is_empty() {
                current.features.insert(key.to_string(), val.to_string());
            }
        }
    }
    current = current.merge_with_defaults();
    current.updated_at = Some(Utc::now().to_rfc3339());

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AiSettingsDoc>("ai_settings");
    // mongodb 3.x: upsert via ReplaceOptions builder chain
    match coll
        .replace_one(doc! { "_id": AI_SETTINGS_ID }, current.clone())
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(current.to_public_json()),
        Err(e) => {
            eprintln!("ai_settings upsert failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to save AI settings",
            }))
        }
    }
}

pub(crate) async fn api_templates() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"templates": []}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HermesChatProxyRequest {
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
    #[serde(default)]
    temperature: Option<f32>,
    #[serde(default)]
    max_tokens: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HermesRunsProxyRequest {
    #[serde(default)]
    input: Option<serde_json::Value>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    session_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HermesRunsListQuery {
    #[serde(default)]
    limit: Option<u32>,
}

pub(crate) fn normalize_hermes_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some(without_v1) = trimmed.strip_suffix("/v1") {
        without_v1.to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn resolve_hermes_base_url() -> String {
    let base =
        env::var("HERMES_BASE_URL").unwrap_or_else(|_| "http://172.16.12.2:8642".to_string());
    normalize_hermes_base_url(&base)
}

pub(crate) async fn api_hermes_chat(
    req: HttpRequest,
    body: web::Json<HermesChatProxyRequest>,
) -> impl Responder {
    if body.messages.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "messages is required"
        }));
    }

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/chat/completions", base);
    let model = body
        .model
        .clone()
        .unwrap_or_else(|| env::var("HERMES_MODEL").unwrap_or_else(|_| "hermes-agent".to_string()));

    let thread_id = body
        .thread_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let fallback_user_id = resolve_user_id(&req);
    let user_id = body
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_user_id);

    let session_id = body
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("mail-thread-{}", thread_id));

    let session_key = body
        .session_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("user-{}", user_id));

    let mut payload = serde_json::json!({
        "model": model,
        "messages": body.messages,
    });

    if let Some(temp) = body.temperature {
        payload["temperature"] = serde_json::json!(temp);
    }
    if let Some(max_tokens) = body.max_tokens {
        payload["max_tokens"] = serde_json::json!(max_tokens);
    }

    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id)
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

pub(crate) async fn api_hermes_runs_list(query: web::Query<HermesRunsListQuery>) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let limit = query.limit.unwrap_or(40).clamp(10, 200);
    let url = format!("{}/v1/runs?limit={}", base, limit);
    let client = reqwest::Client::new();
    let response = match client.get(url).bearer_auth(api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

pub(crate) async fn api_hermes_runs(
    req: HttpRequest,
    body: web::Json<HermesRunsProxyRequest>,
) -> impl Responder {
    let input = match body.input.clone().filter(|v| !v.is_null()) {
        Some(v) => v,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "input is required"
            }))
        }
    };

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs", base);
    let model = body
        .model
        .clone()
        .unwrap_or_else(|| env::var("HERMES_MODEL").unwrap_or_else(|_| "hermes-agent".to_string()));

    let thread_id = body
        .thread_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let fallback_user_id = resolve_user_id(&req);
    let user_id = body
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_user_id);

    let session_id = body
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("mail-thread-{}", thread_id));

    let session_key = body
        .session_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("user-{}", user_id));

    let payload = serde_json::json!({
        "model": model,
        "input": input,
    });

    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id)
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

#[derive(Deserialize)]
pub(crate) struct HermesRunPath {
    run_id: String,
}

pub(crate) async fn api_hermes_run_status(path: web::Path<HermesRunPath>) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs/{}", base, path.run_id);
    let client = reqwest::Client::new();
    let response = match client.get(url).bearer_auth(api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

pub(crate) async fn api_hermes_run_events(path: web::Path<HermesRunPath>, req: HttpRequest) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let url = format!("{}/v1/runs/{}/events{}", base, path.run_id, query_suffix);

    let client = reqwest::Client::new();
    let upstream = match client
        .get(url)
        .bearer_auth(api_key)
        .header("Accept", "text/event-stream")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = upstream.status();
    if !status.is_success() {
        let body_json = match upstream.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(_) => serde_json::json!({ "error": "Hermes upstream error" }),
        };
        return HttpResponse::build(
            actix_web::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
        )
        .json(body_json);
    }

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let bytes_stream = upstream
        .bytes_stream()
        .map_err(actix_web::error::ErrorBadGateway);

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .content_type(content_type)
    .insert_header(("Cache-Control", "no-cache"))
    .insert_header(("X-Accel-Buffering", "no"))
    .streaming(bytes_stream)
}

// --- Calendar types ---

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExternalMessagesQuery {
    account_id: String,
    folder: Option<String>,
    page: Option<u64>,
    page_size: Option<u64>,
}

pub(crate) async fn api_openapi_json() -> impl Responder {
    static SPEC_JSON: &str = r#"{
        "openapi": "3.0.3",
        "info": {
            "title": "Email API",
            "version": "1.0.0",
            "description": "Backend API for the mail server"
        },
        "paths": {
            "/api/auth/login": { "post": { "tags": ["Auth"], "summary": "Login", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/register": { "post": { "tags": ["Auth"], "summary": "Register", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/logout": { "post": { "tags": ["Auth"], "summary": "Logout", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/refresh": { "post": { "tags": ["Auth"], "summary": "Refresh token", "responses": { "200": { "description": "OK" } } } },
            "/api/user/locale": { "patch": { "tags": ["Auth"], "summary": "Update user locale", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/oauth/{provider}": { "get": { "tags": ["Auth"], "summary": "Start OAuth flow", "parameters": [{ "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "302": { "description": "Redirect" } } } },
            "/api/auth/oauth/{provider}/callback": { "get": { "tags": ["Auth"], "summary": "OAuth callback", "parameters": [{ "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "302": { "description": "Redirect" } } } },
            "/api/emails": { "get": { "tags": ["Emails"], "summary": "List emails", "responses": { "200": { "description": "OK" } } } },
            "/api/emails/{id}": {
                "get": { "tags": ["Emails"], "summary": "Get email by ID", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/emails/{id}/action": {
                "post": { "tags": ["Emails"], "summary": "Perform action on email (move, delete, read, unread, star, unstar)", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/tags": { "get": { "tags": ["Emails"], "summary": "List tags", "responses": { "200": { "description": "OK" } } } },
            "/api/send": { "post": { "tags": ["Send"], "summary": "Send an email", "responses": { "200": { "description": "OK" } } } },
            "/api/send/{id}/status": { "get": { "tags": ["Send"], "summary": "Get send status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/drafts": {
                "get": { "tags": ["Drafts"], "summary": "List drafts", "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["Drafts"], "summary": "Create or update draft", "responses": { "200": { "description": "OK" } } }
            },
            "/api/drafts/{id}": { "delete": { "tags": ["Drafts"], "summary": "Delete draft", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/templates": { "get": { "tags": ["Templates"], "summary": "List templates", "responses": { "200": { "description": "OK" } } } },
            "/api/settings/ai": {
                "get": { "tags": ["AI"], "summary": "Get AI settings", "responses": { "200": { "description": "OK" } } },
                "put": { "tags": ["AI"], "summary": "Update AI settings", "responses": { "200": { "description": "OK" } } }
            },
            "/api/hermes/chat": { "post": { "tags": ["Hermes"], "summary": "Chat completions proxy", "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs": { "post": { "tags": ["Hermes"], "summary": "Create run", "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs/{run_id}": { "get": { "tags": ["Hermes"], "summary": "Get run status", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs/{run_id}/events": { "get": { "tags": ["Hermes"], "summary": "Stream run events (SSE)", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "SSE stream" } } } },
            "/api/calendar/events": {
                "get": { "tags": ["Calendar"], "summary": "List calendar events", "parameters": [{ "name": "start", "in": "query", "schema": { "type": "string", "format": "date-time" } }, { "name": "end", "in": "query", "schema": { "type": "string", "format": "date-time" } }], "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["Calendar"], "summary": "Create calendar event", "responses": { "201": { "description": "Created" } } }
            },
            "/api/calendar/events/{id}": {
                "get": { "tags": ["Calendar"], "summary": "Get calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "put": { "tags": ["Calendar"], "summary": "Update calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "tags": ["Calendar"], "summary": "Delete calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/events": { "get": { "tags": ["Events"], "summary": "List events", "responses": { "200": { "description": "OK" } } } },
            "/api/events/stream": { "get": { "tags": ["Events"], "summary": "SSE event stream", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/monitoring/summary": { "get": { "tags": ["Monitoring"], "summary": "SMTP monitoring summary", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/events": { "get": { "tags": ["Monitoring"], "summary": "SMTP monitoring events", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/messages/{message_id}/trace": { "get": { "tags": ["Monitoring"], "summary": "Message delivery trace", "parameters": [{ "name": "message_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/bounces": { "get": { "tags": ["Monitoring"], "summary": "Bounce list", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/providers/top": { "get": { "tags": ["Monitoring"], "summary": "Top providers", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/live": { "get": { "tags": ["Monitoring"], "summary": "Live SMTP events (SSE)", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/monitoring/alerts/active": { "get": { "tags": ["Monitoring"], "summary": "Active monitoring alerts", "responses": { "200": { "description": "OK" } } } },
            "/api/security/alerts/active": { "get": { "tags": ["Security"], "summary": "Active security alerts", "responses": { "200": { "description": "OK" } } } },
            "/api/security/incidents": { "get": { "tags": ["Security"], "summary": "Security incidents", "responses": { "200": { "description": "OK" } } } },
            "/api/security/live": { "get": { "tags": ["Security"], "summary": "Live security events (SSE)", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/security/tenant/{id}/status": { "get": { "tags": ["Security"], "summary": "Tenant security status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/security/remediation/{alert_id}/rollback": { "post": { "tags": ["Security"], "summary": "Rollback remediation", "parameters": [{ "name": "alert_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts": {
                "get": { "tags": ["External IMAP"], "summary": "List external accounts", "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["External IMAP"], "summary": "Create external account", "responses": { "200": { "description": "OK" } } }
            },
            "/api/external-accounts/{id}": {
                "get": { "tags": ["External IMAP"], "summary": "Get external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "patch": { "tags": ["External IMAP"], "summary": "Update external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "tags": ["External IMAP"], "summary": "Delete external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/external-accounts/{id}/test": { "post": { "tags": ["External IMAP"], "summary": "Test IMAP connection", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders": { "get": { "tags": ["External IMAP"], "summary": "List folders", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders/discover": { "post": { "tags": ["External IMAP"], "summary": "Discover folders", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders/{folder_id}/mapping": { "put": { "tags": ["External IMAP"], "summary": "Set folder mapping", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }, { "name": "folder_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync": { "post": { "tags": ["External IMAP"], "summary": "Start sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/status": { "get": { "tags": ["External IMAP"], "summary": "Get sync status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/pause": { "post": { "tags": ["External IMAP"], "summary": "Pause sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/resume": { "post": { "tags": ["External IMAP"], "summary": "Resume sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-sync-runs/{run_id}": { "get": { "tags": ["External IMAP"], "summary": "Get sync run", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-messages": { "get": { "tags": ["External IMAP"], "summary": "List external messages", "parameters": [{ "name": "account_id", "in": "query", "required": true, "schema": { "type": "string" } }, { "name": "folder", "in": "query", "schema": { "type": "string" } }, { "name": "page", "in": "query", "schema": { "type": "integer" } }, { "name": "page_size", "in": "query", "schema": { "type": "integer" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-messages/{id}/action": { "post": { "tags": ["External IMAP"], "summary": "Apply action on external message", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } }
        }
    }"#;
    let spec: serde_json::Value = serde_json::from_str(SPEC_JSON).unwrap_or_default();
    HttpResponse::Ok().json(spec)
}

pub(crate) async fn api_swagger_ui() -> impl Responder {
    let html = r##"<!DOCTYPE html>
<html>
<head>
  <title>Email API — Swagger UI</title>
  <meta charset="utf-8"/>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger-ui", presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset] });
</script>
</body>
</html>"##;
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

pub(crate) async fn api_external_openapi() -> impl Responder {
    static OPENAPI_YAML: &str = include_str!("../../ops/openapi/external-imap-v1.yaml");
    HttpResponse::Ok()
        .content_type("application/yaml; charset=utf-8")
        .body(OPENAPI_YAML)
}

pub(crate) async fn api_external_accounts_list(
    req: HttpRequest,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    match svc.list_accounts(&user_id).await {
        Ok(accounts) => HttpResponse::Ok().json(serde_json::json!({ "accounts": accounts })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNTS_LIST_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_accounts_create(
    req: HttpRequest,
    payload: web::Json<CreateExternalAccountInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    match svc.create_account(&user_id, payload.into_inner()).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_CREATE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_get(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.get_account(&user_id, &account_id).await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_patch(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<UpdateExternalAccountInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc
        .update_account(&user_id, &account_id, payload.into_inner())
        .await
    {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_UPDATE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_delete(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.delete_account(&user_id, &account_id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({ "deleted": true })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_DELETE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_test(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    match svc.imap_test(&account).await {
        Ok(result) => {
            if result.ok {
                HttpResponse::Ok().json(result)
            } else {
                HttpResponse::UnprocessableEntity().json(serde_json::json!({
                    "ok": false,
                    "error": {"code": "IMAP_AUTH_FAILED", "message": result.message},
                    "capabilities": result.capabilities,
                    "greeting": result.greeting,
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(
            serde_json::json!({"error": {"code": "IMAP_TEST_FAILED", "message": e.to_string()}}),
        ),
    }
}

pub(crate) async fn api_external_folders_list(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.list_folders(&user_id, &account_id).await {
        Ok(folders) => HttpResponse::Ok().json(serde_json::json!({ "folders": folders })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDERS_LIST_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_folders_discover(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    match svc.discover_folders(&user_id, &account).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDERS_DISCOVER_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_folder_mapping_put(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    payload: web::Json<ExternalFolderMappingInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let (account_id, folder_id) = path.into_inner();
    match svc
        .upsert_folder_mapping(&user_id, &account_id, &folder_id, &payload.local_role)
        .await
    {
        Ok(Some(folder)) => HttpResponse::Ok().json(folder),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDER_NOT_FOUND", "message": "Folder not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDER_MAPPING_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_start(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<StartSyncInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    let run = match svc.start_sync_run(&user_id, &account_id, &payload).await {
        Ok(run) => run,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_START_FAILED", "message": e.to_string()}})),
    };

    match svc.run_sync_now(&user_id, &account, &run).await {
        Ok(stats) => {
            let updated = svc
                .complete_sync_run(&user_id, &run.id, "success", stats, None)
                .await
                .ok()
                .flatten();
            HttpResponse::Ok()
                .json(serde_json::json!({ "runId": run.id, "status": "success", "run": updated }))
        }
        Err(e) => {
            let _ = svc
                .complete_sync_run(
                    &user_id,
                    &run.id,
                    "failed",
                    simple_smtp_server::external_imap::SyncExecutionResult {
                        fetched: 0,
                        updated: 0,
                        deleted: 0,
                        discovered_folders: 0,
                    },
                    Some(e.to_string()),
                )
                .await;
            HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_EXECUTION_FAILED", "message": e.to_string()}, "runId": run.id}))
        }
    }
}

pub(crate) async fn api_external_sync_run_get(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let run_id = path.into_inner();
    match svc.get_sync_run(&user_id, &run_id).await {
        Ok(Some(run)) => HttpResponse::Ok().json(run),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RUN_NOT_FOUND", "message": "Sync run not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RUN_FETCH_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_status(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.get_sync_status(&user_id, &account_id).await {
        Ok(Some(run)) => HttpResponse::Ok().json(run),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({"status": "idle"})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_STATUS_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_pause(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.set_account_status(&user_id, &account_id, "paused").await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_PAUSE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_resume(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.set_account_status(&user_id, &account_id, "active").await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RESUME_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_messages_list(
    req: HttpRequest,
    query: web::Query<ExternalMessagesQuery>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    match svc
        .list_messages(
            &user_id,
            &query.account_id,
            query.folder.as_deref(),
            page,
            page_size,
        )
        .await
    {
        Ok(messages) => HttpResponse::Ok().json(serde_json::json!({ "messages": messages, "page": page, "pageSize": page_size })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGES_LIST_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_message_action(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<ExternalMessageActionInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let message_id = path.into_inner();
    match svc
        .apply_message_action(&user_id, &message_id, &payload)
        .await
    {
        Ok(Some(message)) => HttpResponse::Ok().json(message),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGE_NOT_FOUND", "message": "Message not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGE_ACTION_FAILED", "message": e.to_string()}})),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateCalendarEventRequest {
    title: String,
    #[serde(default)]
    description: String,
    start: String, // ISO 8601
    end: String,   // ISO 8601
    #[serde(default = "default_event_type_str")]
    event_type: String,
    #[serde(default = "default_color_str")]
    color: String,
    #[serde(default)]
    location: String,
}

pub(crate) fn default_event_type_str() -> String {
    "default".to_string()
}
pub(crate) fn default_color_str() -> String {
    "#3788d8".to_string()
}

#[derive(Deserialize)]
pub(crate) struct UpdateCalendarEventRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    location: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CalendarQueryParams {
    #[serde(default)]
    start: Option<String>, // ISO 8601
    #[serde(default)]
    end: Option<String>, // ISO 8601
}

pub(crate) fn parse_iso_to_bson(s: &str) -> Option<bson::DateTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()))
}

pub(crate) fn get_user_from_headers(req: &actix_web::HttpRequest) -> String {
    // Try x-user-email header, fallback to query param, fallback to env SMTP_USERNAME
    if let Some(email) = req
        .headers()
        .get("x-user-email")
        .and_then(|v| v.to_str().ok())
    {
        return email.to_string();
    }
    // Fallback: use SMTP_USERNAME env var
    env::var("SMTP_USERNAME").unwrap_or_else(|_| "admin@misfits.ai".to_string())
}

// --- Calendar handlers ---

pub(crate) async fn calendar_create_event(
    req_body: web::Json<CreateCalendarEventRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start = match parse_iso_to_bson(&req_body.start) {
        Some(dt) => dt,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid start date format, use ISO 8601"}))
        }
    };
    let end = match parse_iso_to_bson(&req_body.end) {
        Some(dt) => dt,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid end date format, use ISO 8601"}))
        }
    };

    let mut event = CalendarEvent::new(&user, &req_body.title, start, end);
    event.description = req_body.description.clone();
    event.event_type = req_body.event_type.clone();
    event.color = req_body.color.clone();
    event.location = req_body.location.clone();

    match logic.create_calendar_event(&event).await {
        Ok(_) => HttpResponse::Created().json(&event),
        Err(e) => {
            eprintln!("Calendar create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to create event"}))
        }
    }
}

pub(crate) async fn calendar_list_events(
    req: actix_web::HttpRequest,
    query: web::Query<CalendarQueryParams>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start_after = query.start.as_ref().and_then(|s| parse_iso_to_bson(s));
    let start_before = query.end.as_ref().and_then(|s| parse_iso_to_bson(s));

    match logic
        .get_calendar_events(&user, start_after, start_before)
        .await
    {
        Ok(events) => {
            HttpResponse::Ok().json(serde_json::json!({"events": events, "total": events.len()}))
        }
        Err(e) => {
            eprintln!("Calendar list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to list events"}))
        }
    }
}

pub(crate) async fn calendar_get_event(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    match logic.get_calendar_event(&user, &event_id).await {
        Ok(Some(event)) => HttpResponse::Ok().json(&event),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Event not found"})),
        Err(e) => {
            eprintln!("Calendar get error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to get event"}))
        }
    }
}

pub(crate) async fn calendar_update_event(
    req_body: web::Json<UpdateCalendarEventRequest>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    let mut update = bson::Document::new();
    if let Some(title) = &req_body.title {
        update.insert("title", title.clone());
    }
    if let Some(desc) = &req_body.description {
        update.insert("description", desc.clone());
    }
    if let Some(start) = &req_body.start {
        match parse_iso_to_bson(start) {
            Some(dt) => {
                update.insert("start", dt);
            }
            None => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Invalid start date format"}))
            }
        }
    }
    if let Some(end) = &req_body.end {
        match parse_iso_to_bson(end) {
            Some(dt) => {
                update.insert("end", dt);
            }
            None => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Invalid end date format"}))
            }
        }
    }
    if let Some(et) = &req_body.event_type {
        update.insert("event_type", et.clone());
    }
    if let Some(color) = &req_body.color {
        update.insert("color", color.clone());
    }
    if let Some(loc) = &req_body.location {
        update.insert("location", loc.clone());
    }

    if update.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "No fields to update"}));
    }

    match logic.update_calendar_event(&user, &event_id, update).await {
        Ok(Some(event)) => HttpResponse::Ok().json(&event),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Event not found"})),
        Err(e) => {
            eprintln!("Calendar update error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to update event"}))
        }
    }
}

pub(crate) async fn calendar_delete_event(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    match logic.delete_calendar_event(&user, &event_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Err(e) => {
            eprintln!("Calendar delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to delete event"}))
        }
    }
}

// ─── Admin misc (security_posture, deliverability, observability) ──────────

