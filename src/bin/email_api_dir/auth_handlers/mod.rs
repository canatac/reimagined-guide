// mod.rs — auth_handlers split : session (core), oauth, totp/2FA.
// Re-exports globaux pour préserver l'API `super::auth_handlers::*` utilisée par main.rs.
#![allow(unused_imports)]

pub(crate) mod session;
pub(crate) mod oauth;
pub(crate) mod totp;

pub(crate) use session::*;
pub(crate) use oauth::*;
pub(crate) use totp::*;
