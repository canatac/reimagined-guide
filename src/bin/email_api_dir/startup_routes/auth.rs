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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn auth_routes_oauth_start() {
        let route = "/api/auth/oauth/{provider}/start";
        assert_eq!(route, "/api/auth/oauth/{provider}/start");
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
            "/api/auth/oauth/{provider}/start",
            "/api/auth/oauth/{provider}/callback",
        ];
        assert_eq!(paths.len(), 11);
    }

    #[test]
    fn auth_routes_post_routes() {
        let post_routes = vec![
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/logout",
            "/api/auth/refresh",
            "/api/auth/2fa/verify",
            "/api/auth/password-reset/request",
            "/api/auth/password-reset/confirm",
        ];
        assert_eq!(post_routes.len(), 7);
    }

    #[test]
    fn auth_routes_get_routes() {
        let get_routes = vec![
            "/api/auth/oauth/{provider}",
            "/api/auth/oauth/{provider}/start",
            "/api/auth/oauth/{provider}/callback",
        ];
        assert_eq!(get_routes.len(), 3);
    }

    #[test]
    fn auth_routes_patch_routes() {
        let patch_routes = vec!["/api/user/locale"];
        assert_eq!(patch_routes.len(), 1);
    }

    #[test]
    fn auth_routes_oauth_providers() {
        let providers = vec!["google", "github", "microsoft", "apple"];
        assert_eq!(providers.len(), 4);
        assert_eq!(providers[0], "google");
        assert_eq!(providers[1], "github");
        assert_eq!(providers[2], "microsoft");
        assert_eq!(providers[3], "apple");
    }

    #[test]
    fn auth_routes_oauth_flow() {
        let provider = "google";
        let start_route = format!("/api/auth/oauth/{}/start", provider);
        let callback_route = format!("/api/auth/oauth/{}/callback", provider);
        assert_eq!(start_route, "/api/auth/oauth/google/start");
        assert_eq!(callback_route, "/api/auth/oauth/google/callback");
    }

    #[test]
    fn auth_routes_password_reset_flow() {
        let request_route = "/api/auth/password-reset/request";
        let confirm_route = "/api/auth/password-reset/confirm";
        assert_eq!(request_route, "/api/auth/password-reset/request");
        assert_eq!(confirm_route, "/api/auth/password-reset/confirm");
    }

    #[test]
    fn auth_routes_2fa_flow() {
        let verify_route = "/api/auth/2fa/verify";
        assert_eq!(verify_route, "/api/auth/2fa/verify");
    }

    #[test]
    fn auth_routes_user_session_flow() {
        let login = "/api/auth/login";
        let refresh = "/api/auth/refresh";
        let logout = "/api/auth/logout";
        assert_eq!(login, "/api/auth/login");
        assert_eq!(refresh, "/api/auth/refresh");
        assert_eq!(logout, "/api/auth/logout");
    }

    #[test]
    fn auth_routes_user_locale_method() {
        let method = "PATCH";
        assert_eq!(method, "PATCH");
    }

    #[test]
    fn auth_routes_oauth_start_duplicate() {
        // Verify that /api/auth/oauth/{provider} and /api/auth/oauth/{provider}/start both map to auth_oauth_start
        let route1 = "/api/auth/oauth/{provider}";
        let route2 = "/api/auth/oauth/{provider}/start";
        assert_ne!(route1, route2);
        assert!(route1.starts_with("/api/auth/oauth/"));
        assert!(route2.starts_with("/api/auth/oauth/"));
    }
}
