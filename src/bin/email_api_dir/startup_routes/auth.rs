//! Authentication routes.

use actix_web::web;

use super::super::*;

pub(crate) fn register_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/auth/login", web::post().to(api_auth_login))
        .route("/api/auth/logout", web::post().to(api_auth_logout))
        .route("/api/auth/register", web::post().to(api_auth_register))
        .route("/api/auth/session", web::get().to(api_auth_session))
        .route("/api/auth/password-reset", web::post().to(api_auth_password_reset))
        .route("/api/auth/totp/setup", web::post().to(api_auth_totp_setup))
        .route("/api/auth/totp/verify", web::post().to(api_auth_totp_verify))
        .route("/api/auth/2fa/enable", web::post().to(api_auth_2fa_enable))
        .route("/api/auth/2fa/disable", web::post().to(api_auth_2fa_disable))
        .route("/api/auth/anonymous-register", web::post().to(api_auth_anonymous_register))
        .route("/api/account", web::delete().to(api_gdpr_delete_account));
}
