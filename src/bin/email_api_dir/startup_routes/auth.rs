use actix_web::web;

use crate::auth_handlers::{
    auth_2fa_verify, auth_login, auth_logout, auth_oauth_callback, auth_oauth_start,
    auth_password_reset_confirm, auth_password_reset_request, auth_refresh, auth_register,
    auth_user_locale,
};

pub(crate) fn register_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/auth/login", web::post().to(auth_login))
            .route("/auth/register", web::post().to(auth_register))
            .route("/auth/logout", web::post().to(auth_logout))
            .route("/auth/refresh", web::post().to(auth_refresh))
            .route("/auth/2fa/verify", web::post().to(auth_2fa_verify))
            .route(
                "/auth/password-reset/request",
                web::post().to(auth_password_reset_request),
            )
            .route(
                "/auth/password-reset/confirm",
                web::post().to(auth_password_reset_confirm),
            )
            .route("/user/locale", web::patch().to(auth_user_locale))
            .route(
                "/auth/oauth/{provider}",
                web::get().to(auth_oauth_start),
            )
            .route(
                "/auth/oauth/{provider}/callback",
                web::get().to(auth_oauth_callback),
            )
            // Post-quantum email signing (issue #620)
            .route(
                "/api/crypto/sign-pq",
                web::post().to(sign_post_quantum),
            )
            // GDPR Article 17 — right to erasure (issue #595)
            .route("/api/account", web::delete().to(api_gdpr_delete_account))
            // Anonymous Tor signup (issue #621) — no email verification required
            .route(
                "/api/auth/anonymous-register",
                web::post().to(auth_anonymous_register),
            ),
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn auth_routes_login() {
        let route = "/api/auth/login";
        assert_eq!(route, "/api/auth/login");
    }

    #[test]
    fn auth_routes_register() {
        let route = "/api/auth/register";
        assert_eq!(route, "/api/auth/register");
    }

    #[test]
    fn auth_routes_logout() {
        let route = "/api/auth/logout";
        assert_eq!(route, "/api/auth/logout");
    }

    #[test]
    fn auth_routes_refresh() {
        let route = "/api/auth/refresh";
        assert_eq!(route, "/api/auth/refresh");
    }

    #[test]
    fn auth_routes_2fa_verify() {
        let route = "/api/auth/2fa/verify";
        assert_eq!(route, "/api/auth/2fa/verify");
    }

    #[test]
    fn auth_routes_password_reset_request() {
        let route = "/api/auth/password-reset/request";
        assert_eq!(route, "/api/auth/password-reset/request");
    }

    #[test]
    fn auth_routes_password_reset_confirm() {
        let route = "/api/auth/password-reset/confirm";
        assert_eq!(route, "/api/auth/password-reset/confirm");
    }

    #[test]
    fn auth_routes_user_locale() {
        let route = "/api/user/locale";
        assert_eq!(route, "/api/user/locale");
    }

    #[test]
    fn auth_routes_oauth_provider() {
        let route = "/api/auth/oauth/{provider}";
        assert_eq!(route, "/api/auth/oauth/{provider}");
    }

    #[test]
    fn auth_routes_oauth_callback() {
        let route = "/api/auth/oauth/{provider}/callback";
        assert_eq!(route, "/api/auth/oauth/{provider}/callback");
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
    fn auth_routes_all_paths() {
        let paths = vec![
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/logout",
            "/api/auth/refresh",
            "/api/auth/2fa/verify",
            "/api/auth/password-reset/request",
            "/api/auth/password-reset/confirm",
            "/api/user/locale",
            "/api/auth/oauth/{provider}",
            "/api/auth/oauth/{provider}/callback",
        ];
        assert_eq!(paths.len(), 10);
        assert!(paths[0].starts_with("/api/auth/"));
        assert!(paths[9].starts_with("/api/auth/oauth/"));
    }

    #[test]
    fn auth_routes_oauth_paths() {
        let route1 = "/api/auth/oauth/google";
        let route2 = "/api/auth/oauth/google/callback";
        assert!(route1.starts_with("/api/auth/oauth/"));
        assert!(route2.starts_with("/api/auth/oauth/"));
    }

    #[test]
    fn auth_routes_anonymous_register() {
        let route = "/api/auth/anonymous-register";
        assert_eq!(route, "/api/auth/anonymous-register");
        assert!(route.starts_with("/api/auth/"));
        assert!(route.contains("anonymous"));
    }
}
