//! Queue buildup / deferred accumulation.

use mongodb::bson::doc;
use serde_json::json;

use crate::security::{RemediationLevel, SecurityAlert, SecuritySeverity};
use crate::security::rules::helpers::{count, env_u64, since, RuleContext};

pub async fn rule_queue_buildup(ctx: &RuleContext<'_>) -> Vec<SecurityAlert> {
    let threshold = env_u64("SEC_QUEUE_DEFERRED_THRESHOLD", 100);
    let s_30m = since(30);
    let s_1h = since(60);

    let deferred_30m = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_30m }, "status": "deferred" },
    )
    .await;
    let deferred_prev_30m = count(
        ctx.client,
        "smtp_events",
        doc! { "ts": { "$gte": &s_1h, "$lt": &s_30m }, "status": "deferred" },
    )
    .await;

    if deferred_30m < threshold {
        return vec![];
    }

    let growing = deferred_30m > deferred_prev_30m;
    let level = if growing {
        RemediationLevel::THROTTLE
    } else {
        RemediationLevel::ALERT
    };

    let mut alert = SecurityAlert::new(
        "QUEUE_BUILDUP",
        "Accumulation anormale de queue + retries",
        SecuritySeverity::Medium,
        level,
    )
    .with_signal(json!({
        "deferred_last_30m": deferred_30m,
        "deferred_prev_30m": deferred_prev_30m,
        "growing": growing,
        "threshold": threshold,
    }));

    if let Some(ref tid) = ctx.tenant_id {
        alert = alert.with_tenant(tid);
    }
    alert.stamp_audit_hash();
    vec![alert]
}
