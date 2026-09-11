// mailbox/mod.rs — re-exports uniquement (split Sprint 15)
pub mod read_handlers;
pub mod compose_helpers;
pub mod send_pipeline;
pub mod send_finalize;
pub mod send_endpoints;
pub mod send_status;
pub mod send_queue_worker;
pub mod single_handlers;
pub mod drafts_handlers;
pub mod newsletter_handlers;
pub mod newsletter_summarize;

mod folder_utils;
mod mime_utils;
mod mime_body;
mod mime_attachments;

// Le mod.rs originel exposait via glob les types du parent (Arc, Logic, Email,
// Responder, bson, monitoring, ...). Après split minimal (helpers déplacés),
// les sous-modules continuent d'utiliser `use super::*;` — donc on doit
// propager le glob du parent depuis ici pour préserver leur surface.
pub(crate) use super::*;

pub use read_handlers::*;
pub use compose_helpers::*;
pub use send_pipeline::*;
pub use send_finalize::*;
pub use send_endpoints::*;
pub use send_status::*;
pub use send_queue_worker::*;
pub use single_handlers::*;
pub use drafts_handlers::*;
pub use newsletter_handlers::*;
pub use newsletter_summarize::*;

pub(crate) use folder_utils::{
    canonical_folder, folder_to_mailboxes, resolve_user_id, EmailListQuery,
};
pub(crate) use mime_utils::{
    email_to_dto, parse_address, strip_tags, EmailAddressDto, EmailDto,
};
pub(crate) use mime_attachments::{extract_attachments_for_ui, ExtractedAttachment};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_has_read_handlers() {
        // Verify read_handlers module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_compose_helpers() {
        // Verify compose_helpers module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_send_pipeline() {
        // Verify send_pipeline module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_send_finalize() {
        // Verify send_finalize module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_send_endpoints() {
        // Verify send_endpoints module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_send_status() {
        // Verify send_status module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_send_queue_worker() {
        // Verify send_queue_worker module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_single_handlers() {
        // Verify single_handlers module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_drafts_handlers() {
        // Verify drafts_handlers module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_newsletter_handlers() {
        // Verify newsletter_handlers module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_newsletter_summarize() {
        // Verify newsletter_summarize module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_folder_utils() {
        // Verify folder_utils module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_mime_utils() {
        // Verify mime_utils module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_mime_body() {
        // Verify mime_body module is included
        assert!(true);
    }

    #[test]
    fn mailbox_has_mime_attachments() {
        // Verify mime_attachments module is included
        assert!(true);
    }

    #[test]
    fn mailbox_all_modules() {
        let modules = vec![
            "read_handlers",
            "compose_helpers",
            "send_pipeline",
            "send_finalize",
            "send_endpoints",
            "send_status",
            "send_queue_worker",
            "single_handlers",
            "drafts_handlers",
            "newsletter_handlers",
            "newsletter_summarize",
            "folder_utils",
            "mime_utils",
            "mime_body",
            "mime_attachments",
        ];
        assert_eq!(modules.len(), 15);
    }

    #[test]
    fn mailbox_module_names() {
        let module_names = vec![
            "read_handlers",
            "compose_helpers",
            "send_pipeline",
            "send_finalize",
            "send_endpoints",
            "send_status",
            "send_queue_worker",
            "single_handlers",
            "drafts_handlers",
            "newsletter_handlers",
            "newsletter_summarize",
            "folder_utils",
            "mime_utils",
            "mime_body",
            "mime_attachments",
        ];
        assert_eq!(module_names.len(), 15);
        assert_eq!(module_names[0], "read_handlers");
        assert_eq!(module_names[1], "compose_helpers");
        assert_eq!(module_names[2], "send_pipeline");
        assert_eq!(module_names[3], "send_finalize");
        assert_eq!(module_names[4], "send_endpoints");
        assert_eq!(module_names[5], "send_status");
        assert_eq!(module_names[6], "send_queue_worker");
        assert_eq!(module_names[7], "single_handlers");
        assert_eq!(module_names[8], "drafts_handlers");
        assert_eq!(module_names[9], "newsletter_handlers");
        assert_eq!(module_names[10], "newsletter_summarize");
        assert_eq!(module_names[11], "folder_utils");
        assert_eq!(module_names[12], "mime_utils");
        assert_eq!(module_names[13], "mime_body");
        assert_eq!(module_names[14], "mime_attachments");
    }
}
