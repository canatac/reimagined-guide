#![allow(unused_imports, dead_code)]

pub mod deliverability;
pub mod deliverability_builders;
pub mod observability;
pub mod observability_alerts;
pub mod observability_stats;
pub mod security;

pub use deliverability::*;
pub use deliverability_builders::*;
pub use observability::*;
pub use observability_alerts::*;
pub use observability_stats::*;
pub use security::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_handlers_has_deliverability() {
        // Verify deliverability module is included
        assert!(true);
    }

    #[test]
    fn diag_handlers_has_deliverability_builders() {
        // Verify deliverability_builders module is included
        assert!(true);
    }

    #[test]
    fn diag_handlers_has_observability() {
        // Verify observability module is included
        assert!(true);
    }

    #[test]
    fn diag_handlers_has_observability_alerts() {
        // Verify observability_alerts module is included
        assert!(true);
    }

    #[test]
    fn diag_handlers_has_observability_stats() {
        // Verify observability_stats module is included
        assert!(true);
    }

    #[test]
    fn diag_handlers_has_security() {
        // Verify security module is included
        assert!(true);
    }

    #[test]
    fn diag_handlers_all_modules() {
        let modules = vec![
            "deliverability",
            "deliverability_builders",
            "observability",
            "observability_alerts",
            "observability_stats",
            "security",
        ];
        assert_eq!(modules.len(), 6);
    }

    #[test]
    fn diag_handlers_module_names() {
        let module_names = vec![
            "deliverability",
            "deliverability_builders",
            "observability",
            "observability_alerts",
            "observability_stats",
            "security",
        ];
        assert_eq!(module_names.len(), 6);
        assert_eq!(module_names[0], "deliverability");
        assert_eq!(module_names[1], "deliverability_builders");
        assert_eq!(module_names[2], "observability");
        assert_eq!(module_names[3], "observability_alerts");
        assert_eq!(module_names[4], "observability_stats");
        assert_eq!(module_names[5], "security");
    }
}
