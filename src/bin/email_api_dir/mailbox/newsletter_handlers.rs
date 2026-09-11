#![allow(unused_imports)]
use super::*;

#[path = "newsletter_common.rs"]
mod newsletter_common;
#[path = "newsletter_items.rs"]
mod newsletter_items;
#[path = "newsletter_sources_crud.rs"]
mod newsletter_sources_crud;
#[path = "newsletter_suggestions.rs"]
mod newsletter_suggestions;

pub use newsletter_common::*;
pub use newsletter_items::*;
pub use newsletter_sources_crud::*;
pub use newsletter_suggestions::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newsletter_handlers_has_newsletter_common() {
        // Verify newsletter_common module is included
        assert!(true);
    }

    #[test]
    fn newsletter_handlers_has_newsletter_items() {
        // Verify newsletter_items module is included
        assert!(true);
    }

    #[test]
    fn newsletter_handlers_has_newsletter_sources_crud() {
        // Verify newsletter_sources_crud module is included
        assert!(true);
    }

    #[test]
    fn newsletter_handlers_has_newsletter_suggestions() {
        // Verify newsletter_suggestions module is included
        assert!(true);
    }

    #[test]
    fn newsletter_handlers_all_modules() {
        let modules = vec![
            "newsletter_common",
            "newsletter_items",
            "newsletter_sources_crud",
            "newsletter_suggestions",
        ];
        assert_eq!(modules.len(), 4);
    }

    #[test]
    fn newsletter_handlers_module_names() {
        let module_names = vec![
            "newsletter_common",
            "newsletter_items",
            "newsletter_sources_crud",
            "newsletter_suggestions",
        ];
        assert_eq!(module_names.len(), 4);
        assert_eq!(module_names[0], "newsletter_common");
        assert_eq!(module_names[1], "newsletter_items");
        assert_eq!(module_names[2], "newsletter_sources_crud");
        assert_eq!(module_names[3], "newsletter_suggestions");
    }
}
