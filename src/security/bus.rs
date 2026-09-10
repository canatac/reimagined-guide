//! Security event broadcast bus + env-driven mode flags.

use std::sync::OnceLock;
use tokio::sync::broadcast;

use crate::security::alert::SecurityAlert;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_enabled_default_false() {
        std::env::remove_var("SECURITY_MONITORING_ENABLED");
        assert!(!security_enabled());
    }

    #[test]
    fn security_enabled_with_true() {
        std::env::set_var("SECURITY_MONITORING_ENABLED", "true");
        assert!(security_enabled());
        std::env::remove_var("SECURITY_MONITORING_ENABLED");
    }

    #[test]
    fn security_enabled_with_one() {
        std::env::set_var("SECURITY_MONITORING_ENABLED", "1");
        assert!(security_enabled());
        std::env::remove_var("SECURITY_MONITORING_ENABLED");
    }

    #[test]
    fn enforce_mode_default_false() {
        std::env::remove_var("SECURITY_ENFORCE_MODE");
        assert!(!enforce_mode());
    }

    #[test]
    fn enforce_mode_with_true() {
        std::env::set_var("SECURITY_ENFORCE_MODE", "true");
        assert!(enforce_mode());
        std::env::remove_var("SECURITY_ENFORCE_MODE");
    }

    #[test]
    fn enforce_mode_with_one() {
        std::env::set_var("SECURITY_ENFORCE_MODE", "1");
        assert!(enforce_mode());
        std::env::remove_var("SECURITY_ENFORCE_MODE");
    }

    #[test]
    fn init_bus_creates_channel() {
        let bus = init_bus();
        // Verify it can send without panic (channel capacity 1024)
        // Just verify it doesn't panic
        drop(bus);
    }
}
