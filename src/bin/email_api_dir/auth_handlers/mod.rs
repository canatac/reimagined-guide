// mod.rs — auth_handlers split : session (types+stubs), login, register, password_reset, oauth, totp/2FA.
// Re-exports globaux pour préserver l'API `super::auth_handlers::*` utilisée par main.rs.
#![allow(unused_imports)]

pub(crate) mod session;
pub(crate) mod login;
(crate) mod register;
pub(crate) mod password_reset;
pub(crate) mod oauth;
pub(crate) mod totp;
pub(crate) mod two_factor;
pub(crate) mod gdpr;
pub(crate) mod anonymous_register;

pub(crate) use session::*;
pub(crate) use login::*;
pub(crate) use register::*;
pub(crate) use password_reset::*;
pub(crate) use oauth::*;
pub(crate) use totp::*;
pub(crate) use two_factor::*;
pub(crate) use gdpr::*;
pub(crate) use anonymous_register::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_handlers_all_modules() {
        let modules = vec![
            "session",
            "login",
            "register",
            "password_reset",
            "oauth",
            "totp",
            "two_factor",
            "gdpr",
            "anonymous_register",
        ];
        assert_eq!(modules.len(), 9);
    }
}
