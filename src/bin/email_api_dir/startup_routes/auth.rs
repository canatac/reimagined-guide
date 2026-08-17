//! Auth & user session routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/auth/login", web::post().to(auth_login))
        .route("/api/auth/register", web::post().to(auth_register))
        .route("/api/auth/logout", web::post().to(auth_logout))
        .route("/api/auth/refresh", web::post().to(auth_refresh))
        .route("/api/auth/2fa/verify", web::post().to(api_2fa_verify))
        .route(
            "/api/auth/password-reset/request",
            web::post().to(api_password_reset_request),
        )
        .route(
            "/api/auth/password-reset/confirm",
            web::post().to(api_password_reset_confirm),
        )
        .route("/api/user/locale", web::patch().to(api_patch_user_locale))
        .route(
            "/api/auth/oauth/{provider}",
            web::get().to(auth_oauth_start),
        )
        .route(
            "/api/auth/oauth/{provider}/start",
            web::get().to(auth_oauth_start),
        )
        .route(
            "/api/auth/oauth/{provider}/callback",
            web::get().to(auth_oauth_callback),
        );
}
