//! Core security alert data model + builder.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::security::bus::enforce_mode;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SecuritySeverity {
    pub fn numeric(&self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }
}

/// Graduated remediation level (1 = alert only, 4 = block + human challenge).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationLevel(pub u8);

impl RemediationLevel {
    pub const ALERT: Self = Self(1);
    pub const THROTTLE: Self = Self(2);
    pub const QUARANTINE: Self = Self(3);
    pub const BLOCK: Self = Self(4);
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    Alert,
    Throttle,
    Quarantine,
    Block,
    HumanChallenge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationMode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Resolved,
    RolledBack,
}

/// Unified security event persisted in `security_alerts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub ts: String,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_version: String,
    pub severity: SecuritySeverity,
    /// 0.0–1.0 detection confidence.
    pub confidence: f32,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
    /// Machine-readable signal data (ratios, counts, thresholds).
    pub signal: serde_json::Value,
    pub mode: RemediationMode,
    pub action: RemediationAction,
    /// Max duration of the auto-remediation action in seconds.
    pub action_duration_s: Option<u64>,
    pub remediation_level: u8,
    pub rolled_back: bool,
    /// SHA-256 of the alert payload (for audit trail integrity).
    pub audit_hash: Option<String>,
    /// Free-form context (MX host, recipient domain, etc.).
    pub context: serde_json::Value,
    pub status: AlertStatus,
}

impl SecurityAlert {
    pub fn new(
        rule_id: &str,
        rule_name: &str,
        severity: SecuritySeverity,
        level: RemediationLevel,
    ) -> Self {
        let action = match level.0 {
            1 => RemediationAction::Alert,
            2 => RemediationAction::Throttle,
            3 => RemediationAction::Quarantine,
            _ => RemediationAction::Block,
        };
        let mode = if enforce_mode() {
            RemediationMode::Enforce
        } else {
            RemediationMode::Observe
        };
        SecurityAlert {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            rule_version: "1.0".to_string(),
            severity,
            confidence: 1.0,
            tenant_id: None,
            user_id: None,
            ip: None,
            country: None,
            asn: None,
            signal: serde_json::Value::Null,
            mode,
            action,
            action_duration_s: None,
            remediation_level: level.0,
            rolled_back: false,
            audit_hash: None,
            context: serde_json::Value::Null,
            status: AlertStatus::Active,
        }
    }

    pub fn with_tenant(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    pub fn with_signal(mut self, signal: serde_json::Value) -> Self {
        self.signal = signal;
        self
    }

    pub fn with_context(mut self, ctx: serde_json::Value) -> Self {
        self.context = ctx;
        self
    }

    pub fn with_duration(mut self, secs: u64) -> Self {
        self.action_duration_s = Some(secs);
        self
    }

    pub fn stamp_audit_hash(&mut self) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        self.id.hash(&mut h);
        self.ts.hash(&mut h);
        self.rule_id.hash(&mut h);
        self.audit_hash = Some(format!("hash:{:x}", h.finish()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_new_sets_default_fields() {
        let alert = SecurityAlert::new(
            "ABUSE_VOLUME_SPIKE",
            "Volume sortant anormal",
            SecuritySeverity::Critical,
            RemediationLevel::THROTTLE,
        );
        assert_eq!(alert.rule_id, "ABUSE_VOLUME_SPIKE");
        assert_eq!(alert.rule_name, "Volume sortant anormal");
        assert_eq!(alert.severity, SecuritySeverity::Critical);
        assert_eq!(alert.remediation_level, 2);
        assert_eq!(alert.action, RemediationAction::Throttle);
        assert_eq!(alert.status, AlertStatus::Active);
        assert!(!alert.rolled_back);
        assert!(alert.audit_hash.is_none());
    }

    #[test]
    fn alert_builder_with_tenant() {
        let alert = SecurityAlert::new("TEST", "Test", SecuritySeverity::Low, RemediationLevel::ALERT)
            .with_tenant("tenant-42");
        assert_eq!(alert.tenant_id, Some("tenant-42".to_string()));
    }

    #[test]
    fn alert_builder_with_signal() {
        let alert = SecurityAlert::new("TEST", "Test", SecuritySeverity::Low, RemediationLevel::ALERT)
            .with_signal(serde_json::json!({ "ratio": 30.0 }));
        assert_eq!(alert.signal["ratio"], 30.0);
    }

    #[test]
    fn alert_builder_with_duration() {
        let alert = SecurityAlert::new("TEST", "Test", SecuritySeverity::Low, RemediationLevel::ALERT)
            .with_duration(3600);
        assert_eq!(alert.action_duration_s, Some(3600));
    }

    #[test]
    fn alert_stamp_audit_hash_produces_hash() {
        let mut alert = SecurityAlert::new("TEST", "Test", SecuritySeverity::Low, RemediationLevel::ALERT);
        alert.stamp_audit_hash();
        assert!(alert.audit_hash.is_some());
        assert!(alert.audit_hash.as_ref().unwrap().starts_with("hash:"));
    }

    #[test]
    fn alert_serialization_roundtrip() {
        let alert = SecurityAlert::new("TEST", "Test", SecuritySeverity::High, RemediationLevel::QUARANTINE);
        let json = serde_json::to_value(&alert).unwrap();
        assert_eq!(json["rule_id"], "TEST");
        assert_eq!(json["severity"], "high");
        assert_eq!(json["remediation_level"], 3);
    }

    #[test]
    fn remediation_level_constants() {
        assert_eq!(RemediationLevel::ALERT.0, 1);
        assert_eq!(RemediationLevel::THROTTLE.0, 2);
        assert_eq!(RemediationLevel::QUARANTINE.0, 3);
        assert_eq!(RemediationLevel::BLOCK.0, 4);
    }

    #[test]
    fn severity_numeric_ordering() {
        assert!(SecuritySeverity::Critical.numeric() > SecuritySeverity::High.numeric());
        assert!(SecuritySeverity::High.numeric() > SecuritySeverity::Medium.numeric());
        assert!(SecuritySeverity::Medium.numeric() > SecuritySeverity::Low.numeric());
        assert!(SecuritySeverity::Low.numeric() > SecuritySeverity::Info.numeric());
    }
}
