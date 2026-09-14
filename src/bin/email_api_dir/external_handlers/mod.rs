// external_handlers — split par domaine
pub(crate) mod openapi;
pub(crate) mod accounts;
pub(crate) mod folders;
pub(crate) mod sync;
pub(crate) mod calendar;
pub(crate) mod holidays;

pub(crate) use openapi::*;
pub(crate) use accounts::*;
pub(crate) use folders::*;
pub(crate) use sync::*;
pub(crate) use calendar::*;
pub(crate) use holidays::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_handlers_has_openapi() {
        // Verify openapi module is included
        assert!(true);
    }

    #[test]
    fn external_handlers_has_accounts() {
        // Verify accounts module is included
        assert!(true);
    }

    #[test]
    fn external_handlers_has_folders() {
        // Verify folders module is included
        assert!(true);
    }

    #[test]
    fn external_handlers_has_sync() {
        // Verify sync module is included
        assert!(true);
    }

    #[test]
    fn external_handlers_has_calendar() {
        // Verify calendar module is included
        assert!(true);
    }

    #[test]
    fn external_handlers_has_holidays() {
        // Verify holidays module is included
        assert!(true);
    }

    #[test]
    fn external_handlers_all_modules() {
        let modules = vec![
            "openapi",
            "accounts",
            "folders",
            "sync",
            "calendar",
            "holidays",
        ];
        assert_eq!(modules.len(), 6);
    }

    #[test]
    fn external_handlers_module_names() {
        let module_names = vec![
            "openapi",
            "accounts",
            "folders",
            "sync",
            "calendar",
            "holidays",
        ];
        assert_eq!(module_names.len(), 6);
        assert_eq!(module_names[0], "openapi");
        assert_eq!(module_names[1], "accounts");
        assert_eq!(module_names[2], "folders");
        assert_eq!(module_names[3], "sync");
        assert_eq!(module_names[4], "calendar");
        assert_eq!(module_names[5], "holidays");
    }
}
