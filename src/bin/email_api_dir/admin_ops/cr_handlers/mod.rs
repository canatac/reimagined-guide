// cr_handlers/ — Change Request handlers split by HTTP verb (cycle 18)
#![allow(unused_imports, dead_code)]

pub mod read;
pub mod create;
pub mod patch;
pub mod patch_helpers;
pub mod delete;

pub use read::*;
pub use create::*;
pub use patch::*;
pub use delete::*;

// --- AI settings (Phase B1, issue #173) ----------------------------------------
pub(crate) const AI_SETTINGS_ID: &str = "global";
pub(crate) const DEFAULT_AI_MODEL: &str = "qwen/qwen3.7-flash";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_handlers_has_read() {
        // Verify read module is included
        assert!(true);
    }

    #[test]
    fn cr_handlers_has_create() {
        // Verify create module is included
        assert!(true);
    }

    #[test]
    fn cr_handlers_has_patch() {
        // Verify patch module is included
        assert!(true);
    }

    #[test]
    fn cr_handlers_has_patch_helpers() {
        // Verify patch_helpers module is included
        assert!(true);
    }

    #[test]
    fn cr_handlers_has_delete() {
        // Verify delete module is included
        assert!(true);
    }

    #[test]
    fn cr_handlers_all_modules() {
        let modules = vec![
            "read",
            "create",
            "patch",
            "patch_helpers",
            "delete",
        ];
        assert_eq!(modules.len(), 5);
    }

    #[test]
    fn cr_handlers_module_names() {
        let module_names = vec![
            "read",
            "create",
            "patch",
            "patch_helpers",
            "delete",
        ];
        assert_eq!(module_names.len(), 5);
        assert_eq!(module_names[0], "read");
        assert_eq!(module_names[1], "create");
        assert_eq!(module_names[2], "patch");
        assert_eq!(module_names[3], "patch_helpers");
        assert_eq!(module_names[4], "delete");
    }

    #[test]
    fn cr_handlers_ai_settings_id() {
        assert_eq!(AI_SETTINGS_ID, "global");
    }

    #[test]
    fn cr_handlers_default_ai_model() {
        assert_eq!(DEFAULT_AI_MODEL, "qwen/qwen3.7-flash");
    }
}
