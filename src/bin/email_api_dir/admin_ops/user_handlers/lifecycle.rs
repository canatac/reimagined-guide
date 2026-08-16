#![allow(unused_imports, dead_code)]
use super::super::*; // inherit all imports from admin_ops/mod.rs
use super::audit::log_admin_action;

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
