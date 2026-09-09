//! HTTP route registration helpers extracted from startup.rs.
//!
//! Split into submodules for LOC budget. No behaviour change.

mod admin;
mod auth;
mod dashboard;
mod dmarc;
mod diag;
mod docs;
mod external;
mod mailbox;
mod prometheus;
mod webhook;
mod incoming_webhook;

pub(crate) use admin::register_admin_routes;
pub(crate) use auth::register_auth_routes;
pub(crate) use dashboard::register_dashboard_routes;
pub(crate) use dmarc::register_dmarc_routes;
pub(crate) use diag::register_diag_routes;
pub(crate) use docs::register_docs_routes;
pub(crate) use external::register_external_routes;
pub(crate) use mailbox::register_mailbox_routes;
pub(crate) use prometheus::register_prometheus_routes;
pub(crate) use webhook::register_webhook_routes;
pub(crate) use incoming_webhook::register_incoming_webhook_routes;
