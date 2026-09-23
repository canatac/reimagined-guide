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
        // MW-2026-022: IMAP external account sync feeds unified inbox
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
