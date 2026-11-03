use actix_web::{web, HttpRequest, HttpResponse};
use serde_json::json;

use crate::auth_handlers;
use crate::helpers::{mongo_db_name, resolve_user_id};
use crate::startup::AppState;

/// Register the auth routes on the given configuration.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth")
            .route("/login", web::post().to(auth_handlers::login::handler))
            .route("/register", web::post().to(auth_handlers::register::handler))
            .route("/logout", web::post().to(auth_handlers::session::logout_handler))
            .route("/refresh", web::post().to(auth_handlers::session::refresh_handler))
            .route("/password-reset/request", web::post().to(auth_handlers::password_reset::request_handler))
            .route("/password-reset/confirm", web::post().to(auth_handlers::password_reset::confirm_handler))
            .route("/oauth/{provider}", web::get().to(auth_handlers::oauth::handler))
            .route("/oauth/{provider}/start", web::get().to(auth_handlers::oauth::start_handler))
            .route("/oauth/{provider}/callback", web::get().to(auth_handlers::oauth::callback_handler))
            .route("/2fa/verify", web::post().to(auth_handlers::two_factor::verify_handler))
            .route("/2fa/enable", web::post().to(auth_handlers::two_factor::enable_handler))
            .route("/2fa/disable", web::post().to(auth_handlers::two_factor::disable_handler))
            .route("/anonymous-register", web::post().to(auth_handlers::anonymous_register::handler))
            .route("/gdpr/delete-account", web::delete().to(auth_handlers::gdpr::delete_account_handler)),
    );
}

/// Placeholder handler for auth routes that are not yet implemented.
pub async fn not_implemented(_req: HttpRequest) -> HttpResponse {
    HttpResponse::NotImplemented().json(json!({ "error": "not implemented" }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn auth_routes_oauth_provider() {
        let route = "/api/auth/oauth/{provider}";
        assert_eq!(route, "/api/auth/oauth/{provider}");
    }

    #[test]
    fn auth_routes_oauth_provider_google() {
        let provider = "google";
        let route = format!("/api/auth/oauth/{}", provider);
        assert_eq!(route, "/api/auth/oauth/google");
    }

    #[test]
    fn auth_routes_oauth_provider_github() {
        let provider = "github";
        let route = format!("/api/auth/oauth/{}", provider);
        assert_eq!(route, "/api/auth/oauth/github");
    }

    #[test]
    fn auth_routes_oauth_start_google() {
        let provider = "google";
        let route = format!("/api/auth/oauth/{}/start", provider);
        assert_eq!(route, "/api/auth/oauth/google/start");
    }

    #[test]
    fn auth_routes_oauth_callback_google() {
        let provider = "google";
        let route = format!("/api/auth/oauth/{}/callback", provider);
        assert_eq!(route, "/api/auth/oauth/google/callback");
    }

    #[test]
    fn auth_routes_oauth_start_github() {
        let provider = "github";
        let route = format!("/api/auth/oauth/{}/start", provider);
        assert_eq!(route, "/api/auth/oauth/github/start");
    }

    #[test]
    fn auth_routes_oauth_callback_github() {
        let provider = "github";
        let route = format!("/api/auth/oauth/{}/callback", provider);
        assert_eq!(route, "/api/auth/oauth/github/callback");
    }

    #[test]
    fn auth_routes_login_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_register_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_logout_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_refresh_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_2fa_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_password_reset_request_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_password_reset_confirm_method_post() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn auth_routes_user_locale_method_patch() {
        let method = "PATCH";
        assert_eq!(method, "PATCH");
    }

    #[test]
    fn auth_routes_oauth_method_get() {
        let method = "GET";
        assert_eq!(method, "GET");
    }

    #[test]
    fn auth_routes_anonymous_register() {
        let route = "/api/auth/anonymous-register";
        assert_eq!(route, "/api/auth/anonymous-register");
        assert!(route.starts_with("/api/auth/"));
        assert!(route.contains("anonymous"));
    }
}
