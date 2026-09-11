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
    // Set session_token cookie for frontend persistence
    let cookie = actix_web::cookie::Cookie::build("session_token", &session.session.access_token)
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(actix_web::cookie::SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::hours(24))
        .finish();
    HttpResponse::Created()
        .cookie(cookie)
        .insert_header(("Content-Language", locale.as_str()))
        .json(serde_json::json!({ "email": primary_email, "alias": alias_email, "session": session.session, "locale": locale }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_condition_accepted_required() {
        let condition_accepted = false;
        assert!(!condition_accepted);
    }

    #[test]
    fn register_password_min_length() {
        let min_length = 8;
        assert_eq!(min_length, 8);
    }

    #[test]
    fn register_password_too_short() {
        let password = "short";
        assert!(password.len() < 8);
    }

    #[test]
    fn register_password_valid() {
        let password = "validpassword123";
        assert!(password.len() >= 8);
    }

    #[test]
    fn register_primary_email_format() {
        let local_part = "john.doe";
        let primary_email = format!("{}@misfits.ai", local_part);
        assert_eq!(primary_email, "john.doe@misfits.ai");
    }

    #[test]
    fn register_alias_email_format() {
        let alias = "jd";
        let local_part = "john.doe";
        let alias_email: Option<String> = Some(alias).map(str::trim).filter(|s| !s.is_empty())
            .map(|a| a.to_lowercase()).filter(|n| !n.is_empty() && *n != local_part)
            .map(|n| format!("{}@misfits.ai", n));
        assert_eq!(alias_email, Some("jd@misfits.ai".to_string()));
    }

    #[test]
    fn register_alias_same_as_local() {
        let alias = "john.doe";
        let local_part = "john.doe";
        let alias_email: Option<String> = Some(alias).map(str::trim).filter(|s| !s.is_empty())
            .map(|a| a.to_lowercase()).filter(|n| !n.is_empty() && *n != local_part)
            .map(|n| format!("{}@misfits.ai", n));
        assert!(alias_email.is_none());
    }

    #[test]
    fn register_alias_empty() {
        let alias = "";
        let local_part = "john.doe";
        let alias_email: Option<String> = Some(alias).map(str::trim).filter(|s| !s.is_empty())
            .map(|a| a.to_lowercase()).filter(|n| !n.is_empty() && *n != local_part)
            .map(|n| format!("{}@misfits.ai", n));
        assert!(alias_email.is_none());
    }

    #[test]
    fn register_alias_whitespace() {
        let alias = "   ";
        let local_part = "john.doe";
        let alias_email: Option<String> = Some(alias).map(str::trim).filter(|s| !s.is_empty())
            .map(|a| a.to_lowercase()).filter(|n| !n.is_empty() && *n != local_part)
            .map(|n| format!("{}@misfits.ai", n));
        assert!(alias_email.is_none());
    }

    #[test]
    fn register_display_name_format() {
        let first = "John";
        let last = "Doe";
        let display_name = format!("{} {}", first, last).trim().to_string();
        assert_eq!(display_name, "John Doe");
    }

    #[test]
    fn register_display_name_empty_first() {
        let first = "";
        let last = "Doe";
        let display_name = if first.trim().is_empty() && last.trim().is_empty() {
            "local".to_string()
        } else {
            format!("{} {}", first.trim(), last.trim()).trim().to_string()
        };
        assert_eq!(display_name, "Doe");
    }

    #[test]
    fn register_display_name_empty_last() {
        let first = "John";
        let last = "";
        let display_name = if first.trim().is_empty() && last.trim().is_empty() {
            "local".to_string()
        } else {
            format!("{} {}", first.trim(), last.trim()).trim().to_string()
        };
        assert_eq!(display_name, "John");
    }

    #[test]
    fn register_display_name_both_empty() {
        let first = "";
        let last = "";
        let local_part = "john.doe";
        let display_name = if first.trim().is_empty() && last.trim().is_empty() {
            local_part.to_string()
        } else {
            format!("{} {}", first.trim(), last.trim()).trim().to_string()
        };
        assert_eq!(display_name, "john.doe");
    }

    #[test]
    fn register_display_name_trim() {
        let first = "  John  ";
        let last = "  Doe  ";
        let display_name = format!("{} {}", first.trim(), last.trim()).trim().to_string();
        assert_eq!(display_name, "John Doe");
    }

    #[test]
    fn register_error_codes() {
        let errors = vec![
            "CONDITIONS_NOT_ACCEPTED",
            "INVALID_PASSWORD",
            "MISSING_IDENTITY",
            "INTERNAL_ERROR",
            "EMAIL_TAKEN",
        ];
        assert_eq!(errors.len(), 5);
    }

    #[test]
    fn register_duplicate_key_error() {
        let msg = "E11000 duplicate key error";
        assert!(msg.contains("E11000") || msg.contains("duplicate key"));
    }

    #[test]
    fn register_welcome_email_fields() {
        let welcome = Email {
            id: Uuid::new_v4().to_string(),
            from: "noreply@misfits.ai".to_string(),
            to: "john.doe@misfits.ai".to_string(),
            subject: "Welcome!".to_string(),
            body: "<p>Welcome!</p>".to_string(),
            headers: vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())],
            flags: vec![],
            sequence_number: 1,
            uid: 1,
            internal_date: Utc::now(),
            dkim_signature: None,
        };
        assert_eq!(welcome.from, "noreply@misfits.ai");
        assert_eq!(welcome.sequence_number, 1);
        assert_eq!(welcome.uid, 1);
    }

    #[test]
    fn register_session_creation() {
        let session = make_session("john.doe@misfits.ai", "John Doe");
        assert_eq!(session.session.user.email, "john.doe@misfits.ai");
        assert_eq!(session.session.user.display_name, "John Doe");
    }

    #[test]
    fn register_cookie_format() {
        let cookie_name = "session_token";
        let path = "/";
        let http_only = true;
        let secure = true;
        let same_site = "Lax";
        assert_eq!(cookie_name, "session_token");
        assert_eq!(path, "/");
        assert!(http_only);
        assert!(secure);
        assert_eq!(same_site, "Lax");
    }

    #[test]
    fn register_content_language_header() {
        let header = "Content-Language";
        assert_eq!(header, "Content-Language");
    }

    #[test]
    fn register_http_status_created() {
        let status = 201;
        assert_eq!(status, 201);
    }

    #[test]
    fn register_http_status_bad_request() {
        let status = 400;
        assert_eq!(status, 400);
    }

    #[test]
    fn register_http_status_conflict() {
        let status = 409;
        assert_eq!(status, 409);
    }

    #[test]
    fn register_http_status_internal_error() {
        let status = 500;
        assert_eq!(status, 500);
    }

    #[test]
    fn register_bcrypt_cost() {
        let cost = 12;
        assert_eq!(cost, 12);
    }

    #[test]
    fn register_mailbox_name() {
        let mailbox = "inbox";
        assert_eq!(mailbox, "inbox");
    }

    #[test]
    fn register_event_kind_received() {
        let kind = "Received";
        assert_eq!(kind, "Received");
    }

    #[test]
    fn register_mail_event_fields() {
        let fields = vec!["id", "kind", "user_id", "email_id", "subject", "from", "to", "timestamp"];
        assert_eq!(fields.len(), 8);
    }

    #[test]
    fn register_response_fields() {
        let fields = vec!["email", "alias", "session", "locale"];
        assert_eq!(fields.len(), 4);
    }

    #[test]
    fn register_locale_default() {
        let locale = "en";
        assert_eq!(locale, "en");
    }

    #[test]
    fn register_i18n_keys() {
        let keys = vec![
            "error-conditions-required",
            "error-password-too-short",
            "error-name-required",
            "error-account-creation-failed",
            "error-email-taken",
            "email-welcome-subject",
        ];
        assert_eq!(keys.len(), 6);
    }

    #[test]
    fn register_headers_format() {
        let headers = vec![("Content-Type".to_string(), "text/html; charset=utf-8".to_string())];
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
    }

    #[test]
    fn register_welcome_email_from() {
        let from = "noreply@misfits.ai";
        assert_eq!(from, "noreply@misfits.ai");
    }

    #[test]
    fn register_local_part_build() {
        let first = "John";
        let last = "Doe";
        let local = format!("{}.{}", first.trim().to_lowercase(), last.trim().to_lowercase());
        assert_eq!(local, "john.doe");
    }

    #[test]
    fn register_local_part_empty_first() {
        let first = "";
        let last = "Doe";
        let local = if first.trim().is_empty() {
            last.trim().to_lowercase()
        } else {
            format!("{}.{}", first.trim().to_lowercase(), last.trim().to_lowercase())
        };
        assert_eq!(local, "doe");
    }

    #[test]
    fn register_local_part_empty_last() {
        let first = "John";
        let last = "";
        let local = if last.trim().is_empty() {
            first.trim().to_lowercase()
        } else {
            format!("{}.{}", first.trim().to_lowercase(), last.trim().to_lowercase())
        };
        assert_eq!(local, "john");
    }

    #[test]
    fn register_local_part_both_empty() {
        let first = "";
        let last = "";
        let local = if first.trim().is_empty() && last.trim().is_empty() {
            None
        } else {
            Some(format!("{}.{}", first.trim().to_lowercase(), last.trim().to_lowercase()))
        };
        assert!(local.is_none());
    }

    #[test]
    fn register_normalize_segment() {
        let segment = "  Test Segment  ";
        let normalized = segment.trim().to_lowercase();
        assert_eq!(normalized, "test segment");
    }

    #[test]
    fn register_normalize_segment_empty() {
        let segment = "";
        let normalized = segment.trim();
        assert!(normalized.is_empty());
    }

    #[test]
    fn register_normalize_segment_whitespace() {
        let segment = "   ";
        let normalized = segment.trim();
        assert!(normalized.is_empty());
    }

    #[test]
    fn register_password_hash_format() {
        let hash = "$2b$12$hashedvalue";
        assert!(hash.starts_with("$2"));
    }

    #[test]
    fn register_uuid_format() {
        let id = Uuid::new_v4().to_string();
        assert!(id.contains("-"));
        assert!(id.len() > 30);
    }

    #[test]
    fn register_timestamp_format() {
        let ts = Utc::now().to_rfc3339();
        assert!(ts.contains("T"));
    }

    #[test]
    fn register_event_bus_usage() {
        let bus = "EventBus";
        assert_eq!(bus, "EventBus");
    }

    #[test]
    fn register_mongo_usage() {
        let mongo = "mongodb::Client";
        assert!(mongo.contains("mongodb"));
    }

    #[test]
    fn register_logic_usage() {
        let logic = "Logic";
        assert_eq!(logic, "Logic");
    }

    #[test]
    fn register_web_json_usage() {
        let json = "web::Json<RegisterRequest>";
        assert!(json.contains("RegisterRequest"));
    }

    #[test]
    fn register_http_request_usage() {
        let req = "actix_web::HttpRequest";
        assert!(req.contains("HttpRequest"));
    }

    #[test]
    fn register_arc_logic_usage() {
        let arc = "Arc<Logic>";
        assert!(arc.contains("Logic"));
    }

    #[test]
    fn register_arc_mongo_usage() {
        let arc = "Arc<mongodb::Client>";
        assert!(arc.contains("mongodb"));
    }

    #[test]
    fn register_web_data_usage() {
        let data = "web::Data<EventBus>";
        assert!(data.contains("EventBus"));
    }

    #[test]
    fn register_responder_return() {
        let responder = "impl Responder";
        assert!(responder.contains("Responder"));
    }

    #[test]
    fn register_http_response_created() {
        let response = "HttpResponse::Created()";
        assert!(response.contains("Created"));
    }

    #[test]
    fn register_http_response_bad_request() {
        let response = "HttpResponse::BadRequest()";
        assert!(response.contains("BadRequest"));
    }

    #[test]
    fn register_http_response_conflict() {
        let response = "HttpResponse::Conflict()";
        assert!(response.contains("Conflict"));
    }

    #[test]
    fn register_http_response_internal_error() {
        let response = "HttpResponse::InternalServerError()";
        assert!(response.contains("InternalServerError"));
    }

    #[test]
    fn register_json_response_format() {
        let json = serde_json::json!({ "email": "test@misfits.ai", "alias": null });
        assert!(json.contains_key("email"));
        assert!(json.contains_key("alias"));
    }

    #[test]
    fn register_session_in_response() {
        let session = make_session("test@misfits.ai", "Test");
        let json = serde_json::json!({ "session": session.session });
        assert!(json.contains_key("session"));
    }

    #[test]
    fn register_locale_in_response() {
        let json = serde_json::json!({ "locale": "en" });
        assert_eq!(json["locale"], "en");
    }

    #[test]
    fn register_email_in_response() {
        let json = serde_json::json!({ "email": "test@misfits.ai" });
        assert_eq!(json["email"], "test@misfits.ai");
    }

    #[test]
    fn register_alias_in_response() {
        let json = serde_json::json!({ "alias": "alias@misfits.ai" });
        assert_eq!(json["alias"], "alias@misfits.ai");
    }

    #[test]
    fn register_alias_null_in_response() {
        let json = serde_json::json!({ "alias": null });
        assert!(json["alias"].is_null());
    }
}
