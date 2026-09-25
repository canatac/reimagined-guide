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
        // MW-2026-022: IMAP external account sync feeds unified inbox (issue #626)
        // ===================================================================
        "I inspect the unified inbox contract" => {}
        "unified inbox must merge native and external account emails" => {
            let unified = ctx
                .values
                .get("src/bin/email_api_dir/mailbox/unified_handlers.rs")
                .expect("unified_handlers should be loaded");
            assert!(
                unified.contains("native_to_unified"),
                "missing native_to_unified converter"
            );
            assert!(
                unified.contains("external_to_unified"),
                "missing external_to_unified converter"
            );
            assert!(
                unified.contains("sort_unified_by_date"),
                "missing unified sort"
            );
        }
        "periodic sync worker must be present for external accounts" => {
            let sync = ctx
                .values
                .get("src/external_imap/periodic_sync.rs")
                .expect("periodic_sync should be loaded");
            assert!(
                sync.contains("start_periodic_sync"),
                "missing start_periodic_sync function"
            );
            assert!(
                sync.contains("run_sync_now"),
                "missing run_sync_now call in periodic worker"
            );
        }
        "unified inbox route must expose external account messages" => {
            let routes = ctx
                .values
                .get("src/bin/email_api_dir/startup_routes/mailbox.rs")
                .expect("routes should be loaded");
            assert!(
                routes.contains("/api/emails/unified"),
                "missing /api/emails/unified route"
            );
        }
        "external messages must carry account_type and account_email metadata" => {
            let unified = ctx
                .values
                .get("src/bin/email_api_dir/mailbox/unified_handlers.rs")
                .expect("unified_handlers should be loaded");
            assert!(
                unified.contains("account_type"),
                "missing account_type field in unified DTO"
            );
            assert!(
                unified.contains("account_email"),
                "missing account_email field in unified DTO"
            );
            assert!(
                unified.contains("\"external\""),
                "missing external account type tag"
            );
        }
        _ => panic!("No step definition for: {step}"),
    }
}
