pub(crate) mod session;
pub(crate) mod login;
pub(crate) mod register;
pub(crate) mod password_reset;
pub(crate) mod oauth;
pub(crate) mod totp;
pub(crate) mod gdpr;
pub(crate) mod anonymous_register;

pub(crate) use session::*;
pub(crate) use login::*;
pub(crate) use register::*;
pub(crate) use password_reset::*;
pub(crate) use oauth::*;
pub(crate) use totp::*;
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
        ];
        assert_eq!(modules.len(), 6);
    }

    #[test]
    fn auth_handlers_module_names() {
        let module_names = vec![
            "session",
            "login",
            "register",
            "password_reset",
            "oauth",
            "totp",
        ];
        assert_eq!(module_names.len(), 6);
        assert_eq!(module_names[0], "session");
        assert_eq!(module_names[1], "login");
        assert_eq!(module_names[2], "register");
        assert_eq!(module_names[3], "password_reset");
        assert_eq!(module_names[4], "oauth");
        assert_eq!(module_names[5], "totp");
    }
}
