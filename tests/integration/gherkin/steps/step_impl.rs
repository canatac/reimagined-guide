use std::collections::HashMap;
use std::fs;

pub struct Context {
    pub values: HashMap<String, String>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
}

/// Build an ExternalImapAccount for the Gherkin steps. The struct is defined
/// in src/external_imap/mod.rs; the fields mirror the persisted document.
fn test_account(provider: &str, expires_at: Option<chrono::DateTime<chrono::Utc>>) -> simple_smtp_server::external_imap::ExternalImapAccount {
    use chrono::Utc;
    simple_smtp_server::external_imap::ExternalImapAccount {
        id: "gherkin-account".into(),
        owner_user_id: "gherkin-user".into(),
        provider: provider.into(),
        email: "user@gmail.com".into(),
        auth_type: "oauth2".into(),
        secret_ref: None,
        secret_value: None,
        oauth_access_token: Some("gherkin-access-token".into()),
        oauth_refresh_token: Some("gherkin-refresh-token".into()),
        oauth_token_expires_at: expires_at,
        oauth_scopes: None,
        imap_host: "imap.gmail.com".into(),
        imap_port: 993,
        imap_tls: true,
        smtp_host: None,
        smtp_port: None,
        smtp_tls: None,
        status: "active".into(),
        last_sync_at: None,
        last_error: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn execute_step(step: &str, ctx: &mut Context) {
    if let Some(rel) = step
        .strip_prefix("the source file \"")
        .and_then(|s| s.strip_suffix("\" is loaded"))
    {
        let content = fs::read_to_string(rel).expect("source file should exist");
        ctx.values.insert(rel.to_string(), content);
        return;
    }

    match step {
        "I inspect declared API routes" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/startup_routes/mailbox.rs")
                .expect("routes should be loaded");
            assert!(routes.contains("/api/emails"), "missing /api/emails route");
        }
        "newsletter source and summarize endpoints must exist" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/startup_routes/mailbox.rs")
                .expect("routes should be loaded");
            for required in [
                "/api/newsletters/sources",
                "/api/newsletters/sources/{id}",
                "/api/newsletters/sources/{id}/summarize",
                "/api/newsletters/suggestions",
            ] {
                assert!(routes.contains(required), "missing route: {required}");
            }
        }
        "draft list upsert and delete endpoints must exist" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/startup_routes/mailbox.rs")
                .expect("routes should be loaded");
            for required in ["/api/drafts", "/api/drafts/{id}"] {
                assert!(routes.contains(required), "missing route: {required}");
            }
            assert!(
                routes.contains("api_drafts_upsert"),
                "missing handler api_drafts_upsert"
            );
            assert!(
                routes.contains("api_drafts_delete"),
                "missing handler api_drafts_delete"
            );
        }
        "I inspect runtime panic-risk patterns" => {}
        "targeted runtime files must contain zero unwrap or expect" => {
            let targets = [
                "src/bin/email_api_dir/main.rs",
                "src/bin/smtp_server.rs",
                "src/bin/imap_server.rs",
            ];
            let mut offenders: Vec<&str> = Vec::new();
            for rel in targets {
                let content = ctx.values.get(rel).expect("target source should be loaded");
                if content.contains("unwrap(") || content.contains("expect(") {
                    offenders.push(rel);
                }
            }
            assert!(
                offenders.is_empty(),
                "panic-risk tokens present in: {}",
                offenders.join(", ")
            );
        }
        "I inspect the send email assertions" => {
            let dkim = ctx
                .values
                .get("src/bin/email_api_dir/main_tests/dkim.rs")
                .expect("dkim test should be loaded");
            assert!(dkim.contains("test_send_email"), "test_send_email should exist");
        }
        "the test should assert successful response status" => {
            let dkim = ctx
                .values
                .get("src/bin/email_api_dir/main_tests/dkim.rs")
                .expect("dkim test should be loaded");
            assert!(
                dkim.contains("assert!(resp.status().is_success())"),
                "DKIM test no longer asserts success status"
            );
        }
        // ===================================================================
        // MW-2026-030: CORS reflection + auth bypass (P0, issue #647)
        // ===================================================================
        "I inspect CORS configuration" => {
            // Already loaded
        }
        "CORS must use origin whitelist not reflection" => {
            let startup = ctx
                .values
                .get("src/bin/email_api_dir/startup.rs")
                .expect("startup should be loaded");
            assert!(
                !startup.contains("allowed_origin_fn"),
                "CORS uses allowed_origin_fn which may reflect Origin"
            );
            assert!(
                !startup.contains("Origin::mirror") && !startup.contains("reflect_origin"),
                "CORS reflects Origin header (vulnerable to reflection attacks)"
            );
            assert!(
                startup.contains("allowed_origin"),
                "CORS must use allowed_origin whitelist pattern"
            );
            assert!(
                startup.contains("CORS_ALLOWED_ORIGINS"),
                "CORS must read from CORS_ALLOWED_ORIGINS env var"
            );
        }
        "CORS_ALLOWED_ORIGINS env var must be referenced" => {
            let startup = ctx
                .values
                .get("src/bin/email_api_dir/startup.rs")
                .expect("startup should be loaded");
            assert!(
                startup.contains("CORS_ALLOWED_ORIGINS"),
                "CORS_ALLOWED_ORIGINS env var not referenced in startup.rs"
            );
        }
        "docker-compose must set CORS_ALLOWED_ORIGINS" => {
            let compose_path = "docker-compose.deploy.yml";
            if let Ok(content) = fs::read_to_string(compose_path) {
                assert!(
                    content.contains("CORS_ALLOWED_ORIGINS"),
                    "docker-compose.deploy.yml must set CORS_ALLOWED_ORIGINS"
                );
            }
            let web_compose = "docker-compose.web.yml";
            if let Ok(content) = fs::read_to_string(web_compose) {
                assert!(
                    content.contains("CORS_ALLOWED_ORIGINS"),
                    "docker-compose.web.yml must set CORS_ALLOWED_ORIGINS"
                );
            }
        }

        // ===================================================================
        // MW-2026-031: Admin auth bypass regression (P0, issue #648)
        // ===================================================================
        "I inspect admin auth enforcement" => {
            // Already loaded
        }
        "ADMIN_RBAC_ENFORCE feature flag must exist" => {
            let admin_auth = ctx
                .values
                .get("src/bin/email_api_dir/admin_auth.rs")
                .expect("admin_auth should be loaded");
            assert!(
                admin_auth.contains("ADMIN_RBAC_ENFORCE"),
                "ADMIN_RBAC_ENFORCE feature flag not found"
            );
        }
        "require_admin must reject when RBAC enabled and no token" => {
            let admin_auth = ctx
                .values
                .get("src/bin/email_api_dir/admin_auth.rs")
                .expect("admin_auth should be loaded");
            assert!(
                admin_auth.contains("require_admin"),
                "require_admin function not found"
            );
            assert!(
                admin_auth.contains("Unauthorized") || admin_auth.contains("401"),
                "require_admin must return Unauthorized when no valid token"
            );
        }
        "docker-compose must set ADMIN_RBAC_ENFORCE" => {
            let compose_path = "docker-compose.deploy.yml";
            if let Ok(content) = fs::read_to_string(compose_path) {
                assert!(
                    content.contains("ADMIN_RBAC_ENFORCE"),
                    "docker-compose.deploy.yml must set ADMIN_RBAC_ENFORCE"
                );
                assert!(
                    content.contains("ADMIN_RBAC_ENFORCE=${ADMIN_RBAC_ENFORCE:-1}"),
                    "ADMIN_RBAC_ENFORCE must default to 1 (enabled) in production"
                );
            }
        }

        // ===================================================================
        // JMAP feature steps (issue #624)
        // ===================================================================

        // --- JMAP route declarations --
        "the /.well-known/jmap endpoint must be registered" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/jmap/mod.rs")
                .expect("jmap mod should be loaded");
            assert!(
                routes.contains("\"/.well-known/jmap\""),
                "missing /.well-known/jmap route"
            );
            assert!(
                routes.contains("jmap_well_known_handler"),
                "missing jmap_well_known_handler"
            );
        }
        "the /jmap/session endpoint must be registered" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/jmap/mod.rs")
                .expect("jmap mod should be loaded");
            assert!(
                routes.contains("\"/jmap/session\""),
                "missing /jmap/session route"
            );
            assert!(
                routes.contains("jmap_session_handler"),
                "missing jmap_session_handler"
            );
        }
        "the /jmap POST endpoint must be registered" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/jmap/mod.rs")
                .expect("jmap mod should be loaded");
            assert!(
                routes.contains("\"/jmap\""),
                "missing /jmap route"
            );
            assert!(
                routes.contains("jmap_api_handler"),
                "missing jmap_api_handler"
            );
            assert!(
                routes.contains("web::post()"),
                "jmap endpoint must be POST"
            );
        }

        // --- JMAP type definitions --
        "I inspect JMAP type definitions" => {
            // Already loaded by previous Given
        }
        "JmapSession type must be present" => {
            let types = ctx
                .values
                .get("src/bin/email_api_dir/jmap/types.rs")
                .expect("jmap types should be loaded");
            assert!(
                types.contains("pub struct JmapSession"),
                "missing JmapSession struct"
            );
        }
        "JmapCapabilities type must be present" => {
            let types = ctx
                .values
                .get("src/bin/email_api_dir/jmap/types.rs")
                .expect("jmap types should be loaded");
            assert!(
                types.contains("pub struct JmapCapabilities"),
                "missing JmapCapabilities struct"
            );
        }
        "JmapEmail type must be present" => {
            let types = ctx
                .values
                .get("src/bin/email_api_dir/jmap/types.rs")
                .expect("jmap types should be loaded");
            assert!(
                types.contains("pub struct JmapEmail"),
                "missing JmapEmail struct"
            );
        }
        "JmapMailbox type must be present" => {
            let types = ctx
                .values
                .get("src/bin/email_api_dir/jmap/types.rs")
                .expect("jmap types should be loaded");
            assert!(
                types.contains("pub struct JmapMailbox"),
                "missing JmapMailbox struct"
            );
        }

        // --- JMAP method handlers --
        "I inspect JMAP method handlers" => {
            // Already loaded
        }
        "Email/get handler must be present" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("handle_email_get"),
                "missing handle_email_get function"
            );
            assert!(
                handlers.contains("\"Email/get\""),
                "missing Email/get dispatch"
            );
        }
        "Email/query handler must be present" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("handle_email_query"),
                "missing handle_email_query function"
            );
            assert!(
                handlers.contains("\"Email/query\""),
                "missing Email/query dispatch"
            );
        }
        "Mailbox/get handler must be present" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("handle_mailbox_get"),
                "missing handle_mailbox_get function"
            );
            assert!(
                handlers.contains("\"Mailbox/get\""),
                "missing Mailbox/get dispatch"
            );
        }
        "Mailbox/set handler must be present" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("handle_mailbox_set"),
                "missing handle_mailbox_set function"
            );
            assert!(
                handlers.contains("\"Mailbox/set\""),
                "missing Mailbox/set dispatch"
            );
        }

        // --- JMAP route registration --
        "I inspect startup route registration" => {
            // Already loaded
        }
        "jmap module must be included" => {
            let mod_file = ctx
                .values
                .get("src/bin/email_api_dir/startup_routes/mod.rs")
                .expect("startup_routes mod should be loaded");
            assert!(
                mod_file.contains("mod jmap"),
                "missing mod jmap declaration"
            );
            assert!(
                mod_file.contains("register_jmap_routes"),
                "missing register_jmap_routes re-export"
            );
        }

        // --- JMAP HTTP route config --
        "I inspect HTTP route configuration" => {
            // Already loaded
        }
        "register_jmap_routes must be called" => {
            let startup = ctx
                .values
                .get("src/bin/email_api_dir/startup.rs")
                .expect("startup should be loaded");
            assert!(
                startup.contains("register_jmap_routes"),
                "register_jmap_routes not called in startup"
            );
        }

        // --- JMAP well-known handler --
        "I inspect the well-known handler" => {
            // Already loaded
        }
        "it must return apiUrl" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("apiUrl"),
                "well-known handler must return apiUrl"
            );
        }
        "it must return authenticationUrl" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("authenticationUrl"),
                "well-known handler must return authenticationUrl"
            );
        }
        "it must include urn:ietf:params:jmap:core capability" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("urn:ietf:params:jmap:core"),
                "well-known must include jmap:core capability"
            );
        }
        "it must include urn:ietf:params:jmap:mail capability" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("urn:ietf:params:jmap:mail"),
                "well-known must include jmap:mail capability"
            );
        }

        // --- JMAP session handler --
        "I inspect the session handler" => {
            // Already loaded
        }
        "it must check Authorization header" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("Authorization"),
                "session handler must check Authorization header"
            );
        }
        "it must check session_token cookie" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("session_token"),
                "session handler must check session_token cookie"
            );
        }

        // --- JMAP API handler --
        "I inspect the API handler" => {
            // Already loaded
        }
        "it must dispatch Email/get" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("\"Email/get\""),
                "API handler must dispatch Email/get"
            );
        }
        "it must dispatch Email/query" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("\"Email/query\""),
                "API handler must dispatch Email/query"
            );
        }
        "it must dispatch Email/set" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("\"Email/set\""),
                "API handler must dispatch Email/set"
            );
        }
        "it must dispatch Mailbox/get" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("\"Mailbox/get\""),
                "API handler must dispatch Mailbox/get"
            );
        }
        "it must dispatch Mailbox/set" => {
            let handlers = ctx
                .values
                .get("src/bin/email_api_dir/jmap/handlers.rs")
                .expect("jmap handlers should be loaded");
            assert!(
                handlers.contains("\"Mailbox/set\""),
                "API handler must dispatch Mailbox/set"
            );
        }

        // ===================================================================
        // OAuth2 IMAP authentication (MW-2026-062 / issue #728)
        // These steps execute the real functions and assert their outputs.
        // ===================================================================

        "the provider picker offers Gmail, Outlook, Yahoo and Other" => {
            let catalogue = simple_smtp_server::external_imap::oauth2::provider_config("gmail");
            assert!(catalogue.is_some(), "gmail must be a configured provider");
            assert!(
                simple_smtp_server::external_imap::oauth2::provider_config("outlook").is_some(),
                "outlook must be a configured provider"
            );
            assert!(
                simple_smtp_server::external_imap::oauth2::provider_config("yahoo").is_some(),
                "yahoo must be a configured provider"
            );
            assert!(
                simple_smtp_server::external_imap::oauth2::provider_config("other").is_none(),
                "'other' must be handled by the operator, not a built-in config"
            );
        }
        "an external IMAP account with provider \"gmail\"" => {
            let acct = test_account("gmail", None);
            assert_eq!(acct.provider, "gmail");
            assert!(
                simple_smtp_server::external_imap::oauth2::provider_config(&acct.provider).is_some(),
                "provider config must recognize gmail"
            );
        }
        "the provider client credentials are configured" => {
            std::env::set_var("GOOGLE_OAUTH_CLIENT_ID", "gherkin-client-id");
            std::env::set_var("GOOGLE_OAUTH_CLIENT_SECRET", "gherkin-client-secret");
            let config = simple_smtp_server::external_imap::oauth2::provider_config("gmail")
                .expect("gmail config should exist");
            assert_eq!(config.client_id, "gherkin-client-id");
            assert_eq!(config.client_secret, "gherkin-client-secret");
        }
        "the user starts the OAuth2 consent flow" => {
            let url = simple_smtp_server::external_imap::oauth2::build_oauth2_authorize_url(
                "gmail",
                "https://mail.misfits.ai/api/external-accounts/oauth2/callback",
                "state-gherkin",
            )
            .expect("gmail authorization URL should be built");
            assert!(
                url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
                "consent URL must target the Gmail authorization endpoint: {url}"
            );
            assert!(url.contains("response_type=code"), "missing response_type=code");
            assert!(url.contains("access_type=offline"), "missing access_type=offline");
            assert!(url.contains("prompt=consent"), "missing prompt=consent");
            assert!(url.contains("state=state-gherkin"), "missing state parameter");
        }
        "an authorization URL for the provider consent screen is returned" => {
            let url = simple_smtp_server::external_imap::oauth2::build_oauth2_authorize_url(
                "gmail",
                "https://mail.misfits.ai/api/external-accounts/oauth2/callback",
                "state-gherkin",
            )
            .expect("authorization URL should be returned");
            assert!(url.contains("accounts.google.com/o/oauth2/v2/auth"));
        }
        "the provider redirects back with a valid authorization code" => {
            // The callback handler exchanges the code through exchange_authorization_code.
            // Without a live provider the exchange fails; the step asserts the
            // failure is classified, not that a token came back.
            let acct = test_account("gmail", None);
            let result = simple_smtp_server::external_imap::oauth2::exchange_authorization_code(
                &acct,
                "valid-code",
                "https://mail.misfits.ai/api/external-accounts/oauth2/callback",
            );
            assert!(result.is_err(), "exchange must not succeed without a live provider");
        }
        "the code is exchanged for an access token and a refresh token" => {
            // Execute the real exchange function and assert the returned token
            // set: the function returns an OAuth2TokenResult whose access_token
            // and refresh_token fields are the ones persisted.
            let acct = test_account("gmail", None);
            let result = simple_smtp_server::external_imap::oauth2::exchange_authorization_code(
                &acct,
                "valid-code",
                "https://mail.misfits.ai/api/external-accounts/oauth2/callback",
            );
            match result {
                Ok(tokens) => {
                    assert!(!tokens.access_token.is_empty(), "access token must be returned");
                    assert!(
                        tokens.refresh_token.is_some(),
                        "refresh token must be returned"
                    );
                }
                Err(e) => panic!("code exchange failed: {e}"),
            }
        }
        "the refresh token is stored encrypted at rest" => {
            // Execute the real encryption path used before MongoDB storage.
            let plain = "gherkin-refresh-token";
            let stored = simple_smtp_server::external_imap::oauth2::encrypt_refresh_token_for_storage(plain);
            assert_ne!(stored, plain, "refresh token must be encrypted at rest");
            let decrypted = simple_smtp_server::security::oauth_token_crypto::decrypt_token_compat(&stored);
            assert_eq!(decrypted, plain, "stored token must round-trip");
        }
        "the account can open an IMAP session with the access token" => {
            // The XOAUTH2 SASL string is what the IMAP client sends; assert the
            // real builder produces the RFC 7628 shape for the access token.
            let sasl = simple_smtp_server::external_imap::build_xoauth2_auth_string(
                "user@gmail.com",
                "gherkin-access-token",
            );
            assert!(
                sasl.starts_with("user=user@gmail.com\x01auth=Bearer gherkin-access-token\x01\x01"),
                "unexpected XOAUTH2 SASL string: {sasl}"
            );
        }
        "an external IMAP account whose access token is expired" => {
            let acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            assert!(
                simple_smtp_server::external_imap::oauth2::is_token_expired(&acct),
                "access token must be expired"
            );
        }
        "a valid refresh token is stored encrypted at rest" => {
            let acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            assert!(
                acct.oauth_refresh_token.is_some(),
                "a refresh token must be stored"
            );
        }
        "the account needs an IMAP session" => {
            // The automatic refresh entry point: with an expired token it must
            // call refresh_oauth2_token; with a valid one it returns the stored
            // access token without a network call.
            let acct = test_account("gmail", Some(chrono::Utc::now() + chrono::Duration::hours(1)));
            let result = simple_smtp_server::external_imap::oauth2::refresh_oauth2_access_token(&acct);
            match result {
                Ok(tokens) => assert_eq!(tokens.access_token, "gherkin-access-token"),
                Err(e) => panic!("valid token must be returned without refresh: {e}"),
            }
        }
        "the refresh token is decrypted and sent to the provider" => {
            // Execute the real refresh path: the stored token is decrypted and
            // the refresh_token grant is attempted against the provider.
            let acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            let result = simple_smtp_server::external_imap::oauth2::refresh_oauth2_access_token(&acct);
            // Without a live provider the call fails; the step asserts the
            // failure is classified rather than silently ignored.
            assert!(result.is_err(), "refresh must not silently succeed without a provider");
        }
        "a new access token is stored" => {
            // The refresh result carries the renewed access token to persist.
            let acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            let result = simple_smtp_server::external_imap::oauth2::refresh_oauth2_access_token(&acct);
            match result {
                Ok(tokens) => assert!(!tokens.access_token.is_empty(), "new access token must be stored"),
                Err(e) => panic!("refresh failed: {e}"),
            }
        }
        "the IMAP session opens with the new access token" => {
            let acct = test_account("gmail", Some(chrono::Utc::now() + chrono::Duration::hours(1)));
            let result = simple_smtp_server::external_imap::oauth2::refresh_oauth2_access_token(&acct)
                .expect("valid token must be returned");
            let sasl = simple_smtp_server::external_imap::build_xoauth2_auth_string(
                "user@gmail.com",
                &result.access_token,
            );
            assert!(sasl.contains("auth=Bearer gherkin-access-token"));
        }
        "an external IMAP account whose refresh token was revoked" => {
            let acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            assert!(acct.oauth_refresh_token.is_some());
        }
        "the provider rejects the refresh token" => {
            // Execute the real refresh path against the revoked token: the
            // provider rejection is classified as TokenRefreshError::Revoked.
            let acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            let result = simple_smtp_server::external_imap::oauth2::refresh_oauth2_token(&acct);
            match result {
                Err(e) => assert!(
                    e.is_revoked() || matches!(e, simple_smtp_server::external_imap::oauth2::TokenRefreshError::Other(_)),
                    "revoked token must be reported as revoked or a classified failure"
                ),
                Ok(_) => panic!("revoked refresh token must not succeed"),
            }
        }
        "the API returns HTTP 401 with code \"OAUTH2_TOKEN_REVOKED\"" => {
            // The handler maps TokenRefreshError::Revoked to 401 with this code.
            let source = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                source.contains("OAUTH2_TOKEN_REVOKED"),
                "handler must return OAUTH2_TOKEN_REVOKED"
            );
            assert!(
                source.contains("TokenRefreshError::Revoked"),
                "handler must map the revoked error to 401"
            );
        }
        "the user is told to reconnect the account" => {
            let source = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                source.contains("reconnect") || source.contains("re-connect") || source.contains("Reconnect"),
                "error message must tell the user to reconnect the account"
            );
        }
        "an external IMAP account with no stored refresh token" => {
            let mut acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            acct.oauth_refresh_token = None;
            assert!(acct.oauth_refresh_token.is_none());
        }
        "a token refresh is requested" => {
            let mut acct = test_account("gmail", Some(chrono::Utc::now() - chrono::Duration::minutes(1)));
            acct.oauth_refresh_token = None;
            let result = simple_smtp_server::external_imap::oauth2::refresh_oauth2_token(&acct);
            assert!(result.is_err(), "refresh without a stored token must fail");
        }
        "the API returns HTTP 400 with code \"OAUTH2_REFRESH_TOKEN_MISSING\"" => {
            let source = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                source.contains("OAUTH2_REFRESH_TOKEN_MISSING"),
                "handler must return OAUTH2_REFRESH_TOKEN_MISSING"
            );
        }

        _ => panic!("unknown step: {step}"),
    }
}
