//! Authentication handlers.

pub(crate) mod anonymous_register;
pub(crate) mod gdpr;
pub(crate) mod login;
pub(crate) mod oauth;
pub(crate) mod password_reset;
pub(crate) mod register;
pub(crate) mod session;
pub(crate) mod totp;
pub(crate) mod two_factor;

pub(crate) use anonymous_register::api_auth_anonymous_register;
pub(crate) use gdpr::api_gdpr_delete_account;
pub(crate) use login::api_auth_login;
pub(crate) use oauth::*;
pub(crate) use password_reset::api_auth_password_reset;
pub(crate) use register::api_auth_register;
pub(crate) use session::api_auth_session;
pub(crate) use totp::{api_auth_totp_setup, api_auth_totp_verify};
pub(crate) use two_factor::{api_auth_2fa_disable, api_auth_2fa_enable};
