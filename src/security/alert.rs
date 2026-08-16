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
