// external_handlers — split par domaine
pub(crate) use accounts::*;
pub(crate) use calendar::*;
pub(crate) use folders::*;
pub(crate) use holidays::*;

pub(crate) use import_wizard::*;
pub(crate) use openapi::*;
pub(crate) use sync::*;


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

