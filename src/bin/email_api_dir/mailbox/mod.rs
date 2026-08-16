// mailbox/mod.rs — re-exports uniquement (split Sprint 15)
pub mod read_handlers;
pub mod send_pipeline;
pub mod send_endpoints;
pub mod send_queue_worker;
pub mod single_handlers;
pub mod drafts_handlers;

mod folder_utils;
mod mime_utils;

// Le mod.rs originel exposait via glob les types du parent (Arc, Logic, Email,
// Responder, bson, monitoring, ...). Après split minimal (helpers déplacés),
// les sous-modules continuent d'utiliser `use super::*;` — donc on doit
// propager le glob du parent depuis ici pour préserver leur surface.
pub(crate) use super::*;

pub use read_handlers::*;
pub use send_pipeline::*;
pub use send_endpoints::*;
pub use send_queue_worker::*;
pub use single_handlers::*;
pub use drafts_handlers::*;

pub(crate) use folder_utils::{
    canonical_folder, folder_to_mailboxes, resolve_user_id, EmailListQuery,
};
pub(crate) use mime_utils::{
    email_to_dto, extract_attachments_for_ui, parse_address, strip_tags, EmailAddressDto, EmailDto,
    ExtractedAttachment,
};
