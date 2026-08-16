// mod.rs — auth_handlers split : session (types+stubs), login, register, password_reset, oauth, totp/2FA.
// Re-exports globaux pour préserver l'API `super::auth_handlers::*` utilisée par main.rs.
#![allow(unused_imports)]

pub(crate) mod session;
pub(crate) mod login;
pub(crate) mod register;
pub(crate) mod password_reset;
pub(crate) mod oauth;
pub(crate) mod totp;

pub(crate) use session::*;
pub(crate) use login::*;
pub(crate) use register::*;
pub(crate) use password_reset::*;
pub(crate) use oauth::*;
pub(crate) use totp::*;
