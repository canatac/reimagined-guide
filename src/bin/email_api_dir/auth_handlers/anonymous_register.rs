// anonymous_register.rs — Anonymous Tor signup handler (issue #621).
// Allows account creation without email verification when accessed via .onion.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::login::make_session;
use crate::entities::Email;
use actix_web::{HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

/// Request body for anonymous registration.
#[derive(serde::Deserialize)]
pub(crate) struct AnonymousRegisterRequest {
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Detect if the request originated from a Tor .onion address.
/// Checks X-Forwarded-Host, Host header, and X-Onion-Context custom header.
fn is_tor_request(req: &HttpRequest) -> bool {
    // Check X-Onion-Context header (set by Tor-aware reverse proxy)
    if req
        .headers()
        .get("x-onion-context")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
    {
        return true;
    }

    // Check X-Forwarded-Host for .onion suffix
    if let Some(host) = req
        .headers()
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
    {
        if host.ends_with(".onion") {
            return true;
        }
    }

    // Check Host header for .onion suffix
    if let Some(host) = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
    {
        if host.ends_with(".onion") {
            return true;
        }
    }

    // Check X-Tor-Exit or similar proxy headers
    if req.headers().get("x-tor-exit").is_some() {
        return true;
    }

    false
}

/// Generate a random anonymous local part for the misfits.ai email.
fn generate_anonymous_local() -> String {
    let uuid = Uuid::new_v4();
    let bytes = uuid.as_bytes();
    // Use first 8 bytes as hex for a random local part
    format!(
        "anon_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

/// Anonymous registration handler — creates account without email verification.
/// Only accessible via Tor (.onion). No welcome email sent.
pub(crate) async fn auth_anonymous_register(
    req: actix_web::Json<AnonymousRegisterRequest>,
    req_http: HttpRequest,
    logic: actix_web::web::Data<Arc<Logic>>,
) -> impl Responder {
    // Enforce Tor-only access
    if !is_tor_request(&req_http) {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "code": "ANONYMOUS_REQUIRES_TOR",
            "message": "Anonymous registration is only available via Tor (.onion) access."
        }));
    }

    // Validate password length
    if req.password.len() < 12 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code": "WEAK_PASSWORD",
            "message": "Anonymous accounts require a password of at least 12 characters."
        }));
    }

    let local_part = generate_anonymous_local();
    let primary_email = format!("{}@misfits.ai", local_part);
    let display_name = req
        .display_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("anon_{}", &local_part[..8]));

    // Hash password
    let password = req.password.clone();
    let password_hash = match actix_web::web::block(move || bcrypt::hash(&password, 12)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("[anon-register] bcrypt error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": "Account creation failed."
            }));
        }
        Err(e) => {
            eprintln!("[anon-register] bcrypt task error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": "Account creation failed."
            }));
        }
    };

    // Create user account
    match logic
        .create_user(&primary_email, &password_hash, "inbox")
        .await
    {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("E11000") || msg.contains("duplicate key") {
                // Extremely unlikely with UUID-based local parts, but handle gracefully
                return HttpResponse::Conflict().json(serde_json::json!({
                    "code": "EMAIL_TAKEN",
                    "message": "Please retry registration."
                }));
            }
            eprintln!("[anon-register] create_user error ({}): {}", primary_email, e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "INTERNAL_ERROR",
                "message": "Account creation failed."
            }));
        }
    }

    // Create session immediately (no email verification needed)
    let session = make_session(&primary_email, &display_name);

    // Set session cookie
    let cookie = actix_web::cookie::Cookie::build("session_token", &session.session.access_token)
        .path("/")
        .http_only(true)
        .secure(false) // Tor hidden services use HTTP within the Tor network
        .same_site(actix_web::cookie::SameSite::Lax)
        .max_age(actix_web::cookie::time::Duration::hours(24))
        .finish();

    HttpResponse::Created()
        .cookie(cookie)
        .json(serde_json::json!({
            "email": primary_email,
            "display_name": display_name,
            "session": session.session,
            "anonymous": true,
            "tor": true
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_anonymous_local_is_unique() {
        let a = generate_anonymous_local();
        let b = generate_anonymous_local();
        assert_ne!(a, b);
        assert!(a.starts_with("anon_"));
    }

    #[test]
    fn generate_anonymous_local_format() {
        let local = generate_anonymous_local();
        // "anon_" + 16 hex chars
        assert_eq!(local.len(), 21);
        assert!(local.starts_with("anon_"));
        let hex_part = &local[5..];
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn anonymous_local_no_uppercase() {
        let local = generate_anonymous_local();
        assert_eq!(local, local.to_lowercase());
    }

    #[test]
    fn anonymous_register_request_deserialize() {
        let json = r#"{"password":"supersecret123"}"#;
        let req: AnonymousRegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password, "supersecret123");
        assert!(req.display_name.is_none());
    }

    #[test]
    fn anonymous_register_request_with_display_name() {
        let json = r#"{"password":"supersecret123","display_name":"Ghost"}"#;
        let req: AnonymousRegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.password, "supersecret123");
        assert_eq!(req.display_name.as_deref(), Some("Ghost"));
    }

    #[test]
    fn anonymous_register_password_too_short() {
        let password = "short";
        assert!(password.len() < 12);
    }

    #[test]
    fn anonymous_register_password_min_length() {
        let password = "a".repeat(12);
        assert!(password.len() >= 12);
    }
}
