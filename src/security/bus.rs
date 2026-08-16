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
