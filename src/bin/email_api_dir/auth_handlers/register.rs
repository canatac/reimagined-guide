// register.rs — auth_register handler.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::login::make_session;
use super::session::RegisterRequest;

pub(crate) async fn auth_register(
    req: web::Json<RegisterRequest>,
    req_http: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let locale = i18n::resolve_locale(&get_accept_language(&req_http), None);
    if !req.condition_accepted {
        return HttpResponse::BadRequest().json(serde_json::json!({ "code": "CONDITIONS_NOT_ACCEPTED", "message": i18n::t(&locale, "error-conditions-required", &[]) }));
    }
    if req.password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({ "code": "INVALID_PASSWORD", "message": i18n::t(&locale, "error-password-too-short", &[]) }));
    }
    let local_part = match build_misfits_local(&req.first_name, &req.last_name) {
        Some(l) => l,
        None => return HttpResponse::BadRequest().json(serde_json::json!({ "code": "MISSING_IDENTITY", "message": i18n::t(&locale, "error-name-required", &[]) })),
    };
    let primary_email = format!("{}@misfits.ai", local_part);
    let alias_email: Option<String> = req.alias.as_deref().map(str::trim).filter(|s| !s.is_empty())
        .map(|a| normalize_segment(a)).filter(|n| !n.is_empty() && *n != local_part)
        .map(|n| format!("{}@misfits.ai", n));
    let display_name = {
        let first = req.first_name.trim();
        let last = req.last_name.trim();
        if first.is_empty() && last.is_empty() { local_part.clone() } else { format!("{} {}", first, last).trim().to_string() }
    };
    let password = req.password.clone();
    let password_hash = match web::block(move || bcrypt::hash(&password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => { eprintln!("bcrypt error: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": i18n::t(&locale, "error-account-creation-failed", &[]) })); }
        Err(e) => { eprintln!("bcrypt task error: {}", e); return HttpResponse::InternalServerError().json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": i18n::t(&locale, "error-account-creation-failed", &[]) })); }
    };
    match logic.create_user(&primary_email, &password_hash, "inbox").await {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("E11000") || msg.contains("duplicate key") {
                return HttpResponse::Conflict().json(serde_json::json!({ "code": "EMAIL_TAKEN", "message": i18n::t(&locale, "error-email-taken", &[("email", &primary_email)]) }));
            }
            eprintln!("Register error ({}): {}", primary_email, e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "code": "INTERNAL_ERROR", "message": i18n::t(&locale, "error-account-creation-failed", &[]) }));
        }
    }
    if let Some(ref alias) = alias_email {
        if let Err(e) = logic.create_alias(alias, &primary_email).await {
            eprintln!("Alias creation error ({} → {}): {}", alias, primary_email, e);
        }
    }
    let welcome_subject = i18n::t(&locale, "email-welcome-subject", &[]);
    let welcome_body = welcome_email_html(&locale, &display_name, &primary_email, alias_email.as_deref());
    let welcome = Email {
        id: Uuid::new_v4().to_string(),
        from: "noreply@misfits.ai".to_string(),
        to: primary_email.clone(),
        subject: welcome_subject,
        body: welcome_body,
        headers: vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())],
        flags: vec![],
        sequence_number: 1,
        uid: 1,
        internal_date: Utc::now(),
        dkim_signature: None,
    };
    if let Err(e) = logic.deliver_to_inbox(&local_part, &welcome).await {
        eprintln!("Welcome email delivery error ({}): {}", primary_email, e);
    } else {
        emit_event(&bus, &mongo, MailEvent {
            id: Uuid::new_v4().to_string(), kind: MailEventKind::Received,
            user_id: local_part.clone(), email_id: welcome.id.clone(),
            subject: welcome.subject.clone(), from: welcome.from.clone(),
            to: welcome.to.clone(), timestamp: Utc::now().to_rfc3339(),
        }).await;
    }
    let session = make_session(&primary_email, &display_name);
    HttpResponse::Created()
        .insert_header(("Content-Language", locale.as_str()))
        .json(serde_json::json!({ "email": primary_email, "alias": alias_email, "session": session.session, "locale": locale }))
}
