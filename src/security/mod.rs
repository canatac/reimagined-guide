pub mod audit;
pub mod remediation;
pub mod rules;
pub mod types;
pub use types::*;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::sync::broadcast;
use uuid::Uuid;

static ALERT_TX: OnceLock<broadcast::Sender<SecurityAlert>> = OnceLock::new();

pub fn init_bus() -> &'static broadcast::Sender<SecurityAlert> {
    ALERT_TX.get_or_init(|| {
        let (tx, _) = broadcast::channel(1024);
        tx
    })
}

pub fn get_bus() -> Option<&'static broadcast::Sender<SecurityAlert>> {
    ALERT_TX.get()
}

pub fn emit_alert(alert: SecurityAlert) {
    if let Some(tx) = ALERT_TX.get() {
        let _ = tx.send(alert.clone());
    }
}

pub fn security_enabled() -> bool {
    std::env::var("SECURITY_MONITORING_ENABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

/// Returns false → observe only; true → auto-remediation active.
pub fn enforce_mode() -> bool {
    std::env::var("SECURITY_ENFORCE_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Event model
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
