//! HTTP route registration helpers extracted from startup.rs.
//!
//! Split into submodules for LOC budget. No behaviour change.

mod admin;
mod auth;
mod diag;
mod docs;
mod external;
mod mailbox;

pub(crate) use admin::register_admin_routes;
pub(crate) use auth::register_auth_routes;
pub(crate) use diag::register_diag_routes;
pub(crate) use docs::register_docs_routes;
pub(crate) use external::register_external_routes;
pub(crate) use mailbox::register_mailbox_routes;
