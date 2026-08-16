// mailbox/mod.rs — re-exports uniquement (split Sprint 15)
pub mod read_handlers;
pub mod send_handlers;
pub mod send_queue_worker;
pub mod single_handlers;
pub mod drafts_handlers;

mod folder_utils;
mod mime_utils;

pub use read_handlers::*;
pub use send_handlers::*;
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
