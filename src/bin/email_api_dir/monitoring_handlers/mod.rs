// monitoring_handlers — split into submodules in cycle 26 (LOC reduction)
// Public API preserved via `pub use` re-exports; parent uses `pub use monitoring_handlers::*`.

mod monitoring;
mod mta_sts;
mod prometheus;
mod dashboard;
mod security;
mod shared;
pub(crate) mod webhook;
pub(crate) mod webhook_incoming;
pub(crate) mod mongo_health;

pub(crate) use monitoring::*;
pub(crate) use mta_sts::*;
pub(crate) use prometheus::*;
pub(crate) use dashboard::*;
pub(crate) use security::*;
pub(crate) use webhook::*;
pub(crate) use mongo_health::*;
#[allow(unused_imports)]
pub(crate) use shared::*;
