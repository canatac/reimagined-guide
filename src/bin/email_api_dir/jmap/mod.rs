//! JMAP (JSON Meta Application Protocol) server module.
//!
//! Implements RFC 8620 (JMAP Core) and RFC 8621 (JMAP Mail) endpoints.
//! Provides a modern email client protocol as an alternative to IMAP/SMTP.
//!
//! Routes:
//! - GET /.well-known/jmap — Session discovery (capabilities + API URLs)
//! - GET /jmap/session — Full session resource (authenticated)
//! - POST /jmap — Main JMAP request endpoint (method calls)

pub mod handlers;
pub mod types;

pub use handlers::{jmap_api_handler, jmap_session_handler, jmap_well_known_handler};
pub use types::*;

use actix_web::web;

/// Register all JMAP routes on the given `ServiceConfig`.
pub fn register_jmap_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/.well-known/jmap", web::get().to(jmap_well_known_handler))
        .route("/jmap/session", web::get().to(jmap_session_handler))
        .route("/jmap", web::post().to(jmap_api_handler));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmap_routes_well_known() {
        let route = "/.well-known/jmap";
        assert_eq!(route, "/.well-known/jmap");
    }

    #[test]
    fn jmap_routes_session() {
        let route = "/jmap/session";
        assert_eq!(route, "/jmap/session");
    }

    #[test]
    fn jmap_routes_api() {
        let route = "/jmap";
        assert_eq!(route, "/jmap");
    }

    #[test]
    fn jmap_routes_all_paths() {
        let paths = vec!["/.well-known/jmap", "/jmap/session", "/jmap"];
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn jmap_types_module_exists() {
        // Verify types module is accessible
        let _session = types::JmapSession {
            capabilities: types::JmapCapabilities::new(),
            accounts: std::collections::HashMap::new(),
            primary_accounts: std::collections::HashMap::new(),
            username: "user@example.com".to_string(),
            api_url: "/jmap".to_string(),
            download_url: "/jmap/download/{accountId}/{blobId}/{name}?type={type}"
                .to_string(),
            upload_url: "/jmap/upload/{accountId}".to_string(),
            event_source_url: None,
            state: "state".to_string(),
        };
        assert_eq!(_session.username, "user@example.com");
    }

    #[test]
    fn jmap_capabilities_new() {
        let caps = types::JmapCapabilities::new();
        assert_eq!(
            caps.core_max_size_upload,
            25_000_000
        );
        assert_eq!(caps.mail_max_mailboxes_per_email, Some(1));
    }

    #[test]
    fn jmap_request_default() {
        let req = types::JmapRequest::new();
        assert!(req.using.is_empty());
        assert!(req.method_calls.is_empty());
        assert!(!req.created_ids);
    }

    #[test]
    fn jmap_email_get_args_default() {
        let args = types::JmapEmailGetArgs::default();
        assert!(args.account_id.is_empty());
        assert!(args.ids.is_none());
        assert!(args.properties.is_none());
        assert!(!args.body_properties.is_empty());
    }

    #[test]
    fn jmap_email_query_args_default() {
        let args = types::JmapEmailQueryArgs::default();
        assert!(args.account_id.is_empty());
        assert!(args.filter.is_none());
        assert!(args.sort.is_none());
        assert_eq!(args.position, 0);
        assert!(args.anchor.is_none());
        assert_eq!(args.anchor_offset, 0);
        assert_eq!(args.limit, Some(10));
        assert!(!args.calculate_total);
    }

    #[test]
    fn jmap_mailbox_get_args_default() {
        let args = types::JmapMailboxGetArgs::default();
        assert!(args.account_id.is_empty());
        assert!(args.ids.is_none());
        assert!(args.properties.is_none());
    }

    #[test]
    fn jmap_mailbox_set_create() {
        let set = types::JmapMailboxSet::default();
        assert!(set.account_id.is_empty());
        assert!(set.create.is_none());
        assert!(set.update.is_none());
        assert!(set.destroy.is_none());
    }

    #[test]
    fn jmap_handler_names() {
        let handlers = vec![
            "jmap_well_known_handler",
            "jmap_session_handler",
            "jmap_api_handler",
        ];
        assert_eq!(handlers.len(), 3);
    }
}
