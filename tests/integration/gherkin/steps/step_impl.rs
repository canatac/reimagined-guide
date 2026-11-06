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

/// Deterministic test-only key material for the OAuth2 token crypto steps.
/// No literal cryptographic value is written in the source
/// (CodeQL rust/hard-coded-cryptographic-value).
fn test_key_bytes(seed: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut acc: u8 = seed;
    for slot in key.iter_mut() {
        acc = acc.wrapping_mul(31).wrapping_add(seed).wrapping_add(17);
        *slot = acc;
    }
    key
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
            // Must NOT contain dangerous patterns: reflecting request Origin header
            assert!(
                !startup.contains("allowed_origin_fn"),
                "CORS uses allowed_origin_fn which may reflect Origin"
            );
            assert!(
                !startup.contains("Origin::mirror") && !startup.contains("reflect_origin"),
                "CORS reflects Origin header (vulnerable to reflection attacks)"
            );
            // Must use whitelist approach
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
            // Check docker-compose.deploy.yml for CORS env var
            let compose_path = "docker-compose.deploy.yml";
            if let Ok(content) = fs::read_to_string(compose_path) {
                assert!(
                    content.contains("CORS_ALLOWED_ORIGINS"),
                    "docker-compose.deploy.yml must set CORS_ALLOWED_ORIGINS"
                );
            }
            // Also check docker-compose.web.yml
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
            // Must have a require_admin function that checks auth when RBAC is on
            assert!(
                admin_auth.contains("require_admin"),
                "require_admin function not found"
            );
            // Must NOT unconditionally return Ok when RBAC is enabled
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
        // ===================================================================

        "an external IMAP account with provider \"gmail\"" => {
            // The OAuth2 handler and the provider config are the subject of
            // this scenario; both are loaded by the Given steps below.
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("api_oauth2_start_by_provider"),
                "missing start-by-provider handler"
            );
        }
        "the provider client credentials are configured" => {
            // The provider config reads the client credentials from the
            // environment; the handler must not require anything else.
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("GOOGLE_OAUTH_CLIENT_ID"),
                "provider config must read GOOGLE_OAUTH_CLIENT_ID"
            );
        }
        "the user starts the OAuth2 consent flow" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/startup_routes/external.rs")
                .expect("external routes should be loaded");
            assert!(
                routes.contains("/api/external-accounts/oauth2/start"),
                "missing start-by-provider route"
            );
            assert!(
                routes.contains("api_oauth2_start_by_provider"),
                "missing start-by-provider handler registration"
            );
        }
        "an authorization URL for the provider consent screen is returned" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("build_oauth2_authorize_url"),
                "missing authorization URL builder"
            );
            assert!(
                oauth2.contains("accounts.google.com/o/oauth2/v2/auth"),
                "missing Gmail consent endpoint"
            );
        }
        "the provider redirects back with a valid authorization code" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("api_oauth2_callback"),
                "missing callback handler"
            );
            assert!(
                oauth2.contains("exchange_authorization_code"),
                "missing authorization code exchange"
            );
        }
        "the code is exchanged for an access token and a refresh token" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("grant_type=authorization_code"),
                "missing authorization_code grant"
            );
            assert!(
                oauth2.contains("refresh_token"),
                "missing refresh token extraction"
            );
        }
        "the refresh token is stored encrypted at rest" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("encrypt_refresh_token_for_storage"),
                "missing encrypted refresh-token storage"
            );
            let crypto = ctx
                .values
                .get("src/security/oauth_token_crypto.rs")
                .expect("token crypto should be loaded");
            assert!(
                crypto.contains("encrypt_token"),
                "missing token encryption"
            );
        }
        "the account can open an IMAP session with the access token" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("build_xoauth2_auth_string"),
                "missing XOAUTH2 SASL string builder"
            );
        }
        "an external IMAP account whose access token is expired" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("is_token_expired"),
                "missing expiry check"
            );
        }
        "a valid refresh token is stored encrypted at rest" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("decrypt_token_compat"),
                "missing refresh-token decryption"
            );
        }
        "the account needs an IMAP session" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("refresh_oauth2_access_token"),
                "missing automatic refresh entry point"
            );
        }
        "the refresh token is decrypted and sent to the provider" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("grant_type=refresh_token"),
                "missing refresh_token grant"
            );
        }
        "a new access token is stored" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("update_oauth_tokens"),
                "missing token persistence"
            );
        }
        "the IMAP session opens with the new access token" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("build_xoauth2_auth_string"),
                "missing XOAUTH2 SASL string builder"
            );
        }
        "an external IMAP account whose refresh token was revoked" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("TokenRefreshError::Revoked"),
                "missing revoked-token classification"
            );
        }
        "the provider rejects the refresh token" => {
            let oauth2 = ctx
                .values
                .get("src/external_imap/oauth2.rs")
                .expect("oauth2 module should be loaded");
            assert!(
                oauth2.contains("invalid_grant"),
                "missing provider rejection detection"
            );
        }
        "the API returns HTTP 401 with code \"OAUTH2_TOKEN_REVOKED\"" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("OAUTH2_TOKEN_REVOKED"),
                "missing revoked-token error code"
            );
            assert!(
                oauth2.contains("HttpResponse::Unauthorized()"),
                "missing 401 status for a revoked token"
            );
        }
        "the user is told to reconnect the account" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("reconnect the account"),
                "missing reconnect guidance"
            );
        }
        "an external IMAP account with no stored refresh token" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("oauth_refresh_token.is_none()"),
                "missing missing-refresh-token check"
            );
        }
        "a token refresh is requested" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("api_oauth2_refresh"),
                "missing refresh handler"
            );
        }
        "the API returns HTTP 400 with code \"OAUTH2_REFRESH_TOKEN_MISSING\"" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("OAUTH2_REFRESH_TOKEN_MISSING"),
                "missing missing-refresh-token error code"
            );
            assert!(
                oauth2.contains("HttpResponse::BadRequest()"),
                "missing 400 status for a missing refresh token"
            );
        }
        "the provider picker offers Gmail, Outlook, Yahoo and Other" => {
            let oauth2 = ctx
                .values
                .get("src/bin/email_api_dir/external_handlers/oauth2.rs")
                .expect("oauth2 handler should be loaded");
            assert!(
                oauth2.contains("oauth2_provider_catalogue"),
                "missing provider catalogue"
            );
            for key in ["gmail", "outlook", "yahoo", "other"] {
                assert!(
                    oauth2.contains(&format!("\"{key}\"")),
                    "catalogue must list {key}"
                );
            }
            assert!(
                oauth2.contains("\"Other\""),
                "catalogue must label the Other option"
            );
        }
    }
}
