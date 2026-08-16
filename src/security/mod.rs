//! Security subsystem: alert bus, unified alert model, auth events, rules.
//!
//! Split into focused submodules (cycle 33 LOC pass):
//! - [`bus`]      – broadcast channel + env flags.
//! - [`alert`]    – `SecurityAlert` model + builder.
//! - [`auth_event`] – auth event log records.

pub mod alert;
pub mod audit;
pub mod auth_event;
pub mod bus;
pub mod remediation;
pub mod rules;

// Public re-exports for backwards compatibility.
pub use alert::{
    AlertStatus, RemediationAction, RemediationLevel, RemediationMode, SecurityAlert,
    SecuritySeverity,
};
pub use auth_event::{log_auth_event, AuthEvent, AuthEventKind};
pub use bus::{emit_alert, enforce_mode, get_bus, init_bus, security_enabled};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_construction() {
        let alert = SecurityAlert::new(
            "ABUSE_VOLUME_SPIKE",
            "Volume sortant anormal",
            SecuritySeverity::Critical,
            RemediationLevel::THROTTLE,
        )
        .with_tenant("tenant-42")
        .with_signal(serde_json::json!({ "ratio": 30.0, "threshold": 10.0 }))
        .with_duration(3600);

        assert_eq!(alert.rule_id, "ABUSE_VOLUME_SPIKE");
        assert_eq!(alert.remediation_level, 2);
        assert_eq!(alert.action_duration_s, Some(3600));
        assert_eq!(alert.tenant_id, Some("tenant-42".to_string()));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(SecuritySeverity::Critical.numeric() > SecuritySeverity::High.numeric());
        assert!(SecuritySeverity::High.numeric() > SecuritySeverity::Medium.numeric());
    }

    #[test]
    fn test_observe_mode_default() {
        std::env::remove_var("SECURITY_ENFORCE_MODE");
        let alert = SecurityAlert::new(
            "TEST",
            "Test",
            SecuritySeverity::Low,
            RemediationLevel::ALERT,
        );
        assert_eq!(alert.mode, RemediationMode::Observe);
    }
}
