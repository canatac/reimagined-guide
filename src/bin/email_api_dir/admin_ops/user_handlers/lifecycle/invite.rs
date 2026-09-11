#![allow(unused_imports, dead_code)]
use super::super::super::*;
use super::super::audit::log_admin_action;

/// Generates a unique invite token.
pub(crate) fn generate_invite_token() -> String {
    Uuid::new_v4().to_string()
}

/// Calculates the expiration time for an invite.
pub(crate) fn calculate_invite_expiration(ttl_hours: i64) -> chrono::DateTime<chrono::Utc> {
    Utc::now() + chrono::Duration::hours(ttl_hours)
}

/// Builds the accept URL for an invite.
pub(crate) fn build_accept_url(invite_base: &str, token: &str) -> String {
    format!("{}?token={}", invite_base, token)
}

/// Truncates recent activity to the last N entries.
pub(crate) fn truncate_recent_activity(activity: &mut Vec<AdminUserActivity>, max_entries: usize) {
    activity.truncate(max_entries);
}

/// POST /api/admin/users/{id}/invite
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

    let token = generate_invite_token();
    let now = Utc::now();
    let ttl_hours: i64 = env::var("ADMIN_INVITE_TTL_HOURS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(72);
    let expires = calculate_invite_expiration(ttl_hours);

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
    truncate_recent_activity(&mut recent, 8);
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

    let dkim_url = env::var("DKIM_SERVICE_URL")
        .unwrap_or_else(|_| "http://dkim-service:3000".to_string());
    let invite_base = env::var("ADMIN_INVITE_BASE_URL")
        .unwrap_or_else(|_| "https://misfits.ai/admin/accept-invite".to_string());
    let sender = env::var("ADMIN_INVITE_FROM")
        .unwrap_or_else(|_| "no-reply@misfits.ai".to_string());
    let accept_url = build_accept_url(&invite_base, &token);
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
        let _ = mongo_for_send;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_invite_token_is_unique() {
        let token1 = generate_invite_token();
        let token2 = generate_invite_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn generate_invite_token_is_uuid_format() {
        let token = generate_invite_token();
        assert!(Uuid::parse_str(&token).is_ok());
    }

    #[test]
    fn calculate_invite_expiration_default_ttl() {
        let expiration = calculate_invite_expiration(72);
        let now = Utc::now();
        let expected = now + chrono::Duration::hours(72);
        // Allow 1 second tolerance for test execution time
        let diff = (expiration - expected).num_seconds().abs();
        assert!(diff <= 1);
    }

    #[test]
    fn calculate_invite_expiration_custom_ttl() {
        let expiration = calculate_invite_expiration(24);
        let now = Utc::now();
        let expected = now + chrono::Duration::hours(24);
        let diff = (expiration - expected).num_seconds().abs();
        assert!(diff <= 1);
    }

    #[test]
    fn build_accept_url_with_token() {
        let url = build_accept_url("https://misfits.ai/admin/accept-invite", "token123");
        assert_eq!(url, "https://misfits.ai/admin/accept-invite?token=token123");
    }

    #[test]
    fn build_accept_url_with_empty_token() {
        let url = build_accept_url("https://example.com/invite", "");
        assert_eq!(url, "https://example.com/invite?token=");
    }

    #[test]
    fn truncate_recent_activity_to_8() {
        let mut activity: Vec<AdminUserActivity> = (0..10)
            .map(|i| AdminUserActivity {
                at: format!("2026-01-0{}T00:00:00Z", i),
                label: format!("Activity {}", i),
                kind: "test".to_string(),
            })
            .collect();
        truncate_recent_activity(&mut activity, 8);
        assert_eq!(activity.len(), 8);
    }

    #[test]
    fn truncate_recent_activity_under_limit() {
        let mut activity: Vec<AdminUserActivity> = (0..5)
            .map(|i| AdminUserActivity {
                at: format!("2026-01-0{}T00:00:00Z", i),
                label: format!("Activity {}", i),
                kind: "test".to_string(),
            })
            .collect();
        truncate_recent_activity(&mut activity, 8);
        assert_eq!(activity.len(), 5);
    }

    #[test]
    fn truncate_recent_activity_empty() {
        let mut activity: Vec<AdminUserActivity> = vec![];
        truncate_recent_activity(&mut activity, 8);
        assert!(activity.is_empty());
    }
}
