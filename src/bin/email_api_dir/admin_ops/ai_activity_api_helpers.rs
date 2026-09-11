use super::*;

pub(super) struct RunFacts {
    pub(super) status: String,
    pub(super) model: String,
    pub(super) feature: String,
    pub(super) user_id: Option<String>,
    pub(super) session_id: Option<String>,
    pub(super) day_bucket: String,
    pub(super) prompt_tokens: i64,
    pub(super) completion_tokens: i64,
    pub(super) total_tokens: i64,
    pub(super) latency_ms: i64,
}

pub(super) fn extract_run_facts(run: &serde_json::Value) -> RunFacts {
    let status = str_field_or(run, "status", None, "unknown").to_ascii_lowercase();
    let model = str_field_or(run, "model", None, "unknown").trim().to_string();
    let feature = str_field_or(run, "feature", None, "unknown").trim().to_string();
    let user_id = opt_str_field(run, "user_id", Some("userId"));
    let session_id = opt_str_field(run, "session_id", Some("sessionId"));
    let day_bucket = day_bucket_for_run(run);

    let usage = run.get("usage").unwrap_or(&serde_json::Value::Null);
    let prompt_tokens = as_i64(usage.get("prompt_tokens").or_else(|| usage.get("promptTokens")));
    let completion_tokens =
        as_i64(usage.get("completion_tokens").or_else(|| usage.get("completionTokens")));
    let explicit_total = as_i64(usage.get("total_tokens").or_else(|| usage.get("totalTokens")));
    let total_tokens = if explicit_total > 0 {
        explicit_total
    } else {
        prompt_tokens + completion_tokens
    };

    let latency_ms = as_i64(run.get("latency_ms").or_else(|| run.get("latencyMs")));

    RunFacts {
        status,
        model,
        feature,
        user_id,
        session_id,
        day_bucket,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        latency_ms,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn update_global_counters(
    completed_runs: &mut i64,
    failed_runs: &mut i64,
    prompt_tokens: &mut i64,
    completion_tokens: &mut i64,
    total_tokens: &mut i64,
    latencies: &mut Vec<i64>,
    facts: &RunFacts,
) {
    *prompt_tokens += facts.prompt_tokens;
    *completion_tokens += facts.completion_tokens;
    *total_tokens += facts.total_tokens;

    if is_completed_status(&facts.status) {
        *completed_runs += 1;
    }
    if is_failed_status(&facts.status) {
        *failed_runs += 1;
    }
    if facts.latency_ms > 0 {
        latencies.push(facts.latency_ms);
    }
}

pub(super) fn update_pricing_counters(
    total_cost_usd: &mut f64,
    priced_runs: &mut i64,
    unpriced_runs: &mut i64,
    run_cost: f64,
) {
    *total_cost_usd += run_cost;
    if run_cost > 0.0 {
        *priced_runs += 1;
    } else {
        *unpriced_runs += 1;
    }
}

pub(super) fn apply_bucket_for_run(bucket: &mut Bucket, facts: &RunFacts, run_cost: f64) {
    bucket.runs += 1;
    bucket.prompt_tokens += facts.prompt_tokens;
    bucket.completion_tokens += facts.completion_tokens;
    bucket.total_tokens += facts.total_tokens;
    bucket.total_cost_usd += run_cost;
    if is_completed_status(&facts.status) {
        bucket.completed_runs += 1;
    }
    if is_failed_status(&facts.status) {
        bucket.failed_runs += 1;
    }
}

pub(super) fn estimate_run_cost(
    prompt_tokens: i64,
    completion_tokens: i64,
    pricing_rate: PricingRate,
) -> f64 {
    let input_cost = ((prompt_tokens as f64) / 1_000_000.0) * pricing_rate.input_per_1m_usd;
    let output_cost = ((completion_tokens as f64) / 1_000_000.0) * pricing_rate.output_per_1m_usd;
    round6(input_cost + output_cost)
}

pub(super) fn build_normalized_run(
    run: &serde_json::Value,
    facts: &RunFacts,
    run_cost: f64,
    pricing_applied: &'static str,
) -> serde_json::Value {
    serde_json::json!({
        "id": run.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
        "status": facts.status,
        "model": facts.model,
        "feature": facts.feature,
        "startedAt": run
            .get("started_at")
            .and_then(|v| v.as_str())
            .or_else(|| run.get("startedAt").and_then(|v| v.as_str())),
        "completedAt": run
            .get("completed_at")
            .and_then(|v| v.as_str())
            .or_else(|| run.get("completedAt").and_then(|v| v.as_str())),
        "latencyMs": if facts.latency_ms > 0 {
            Some(facts.latency_ms)
        } else {
            None::<i64>
        },
        "promptTokens": facts.prompt_tokens,
        "completionTokens": facts.completion_tokens,
        "totalTokens": facts.total_tokens,
        "estimatedCostUsd": run_cost,
        "pricingApplied": pricing_applied,
        "sessionId": facts.session_id,
        "userId": facts.user_id,
        "error": run
            .get("last_error")
            .and_then(|v| v.as_str())
            .or_else(|| run.get("error").and_then(|v| v.as_str())),
    })
}

fn str_field_or(run: &serde_json::Value, primary: &str, alias: Option<&str>, default: &str) -> String {
    run.get(primary)
        .and_then(|v| v.as_str())
        .or_else(|| alias.and_then(|k| run.get(k)).and_then(|v| v.as_str()))
        .unwrap_or(default)
        .to_string()
}

fn opt_str_field(run: &serde_json::Value, primary: &str, alias: Option<&str>) -> Option<String> {
    run.get(primary)
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
        .or_else(|| {
            alias
                .and_then(|k| run.get(k))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        })
}

fn day_bucket_for_run(run: &serde_json::Value) -> String {
    run.get("started_at")
        .and_then(|v| v.as_str())
        .or_else(|| run.get("startedAt").and_then(|v| v.as_str()))
        .and_then(iso_day_prefix)
        .unwrap_or_else(|| "unknown".to_string())
}

fn iso_day_prefix(ts: &str) -> Option<String> {
    let t = ts.trim();
    if t.len() >= 10 {
        Some(t[..10].to_string())
    } else {
        None
    }
}

pub(super) fn normalized_user_key(user_id: Option<String>) -> String {
    user_id
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_completed_status(status: &str) -> bool {
    matches!(status, "completed" | "success")
}

fn is_failed_status(status: &str) -> bool {
    matches!(status, "failed" | "error" | "cancelled" | "expired")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_run_facts_completed_status() {
        let run = serde_json::json!({
            "status": "completed",
            "model": "gpt-4",
            "feature": "compose",
            "usage": { "prompt_tokens": 100, "completion_tokens": 50 }
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.status, "completed");
        assert_eq!(facts.model, "gpt-4");
        assert_eq!(facts.feature, "compose");
        assert_eq!(facts.prompt_tokens, 100);
        assert_eq!(facts.completion_tokens, 50);
        assert_eq!(facts.total_tokens, 150);
    }

    #[test]
    fn extract_run_facts_failed_status() {
        let run = serde_json::json!({
            "status": "FAILED",
            "model": "gpt-4",
            "feature": "translate"
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.status, "failed");
    }

    #[test]
    fn extract_run_facts_camel_case_fields() {
        let run = serde_json::json!({
            "status": "success",
            "model": "claude-3",
            "feature": "triage",
            "promptTokens": 200,
            "completionTokens": 80,
            "totalTokens": 300,
            "latencyMs": 1500
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.prompt_tokens, 200);
        assert_eq!(facts.completion_tokens, 80);
        assert_eq!(facts.total_tokens, 300);
        assert_eq!(facts.latency_ms, 1500);
    }

    #[test]
    fn extract_run_facts_user_and_session() {
        let run = serde_json::json!({
            "status": "completed",
            "model": "gpt-4",
            "feature": "compose",
            "userId": "user-42",
            "sessionId": "sess-abc"
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.user_id, Some("user-42".to_string()));
        assert_eq!(facts.session_id, Some("sess-abc".to_string()));
    }

    #[test]
    fn extract_run_facts_day_bucket() {
        let run = serde_json::json!({
            "status": "completed",
            "model": "gpt-4",
            "feature": "compose",
            "startedAt": "2026-09-10T14:30:00Z"
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.day_bucket, "2026-09-10");
    }

    #[test]
    fn extract_run_facts_defaults() {
        let run = serde_json::json!({});
        let facts = extract_run_facts(&run);
        assert_eq!(facts.status, "unknown");
        assert_eq!(facts.model, "unknown");
        assert_eq!(facts.feature, "unknown");
        assert_eq!(facts.total_tokens, 0);
        assert_eq!(facts.day_bucket, "unknown");
    }

    #[test]
    fn is_completed_status_matches() {
        assert!(is_completed_status("completed"));
        assert!(is_completed_status("success"));
        assert!(!is_completed_status("failed"));
        assert!(!is_completed_status("running"));
    }

    #[test]
    fn is_failed_status_matches() {
        assert!(is_failed_status("failed"));
        assert!(is_failed_status("error"));
        assert!(is_failed_status("cancelled"));
        assert!(is_failed_status("expired"));
        assert!(!is_failed_status("completed"));
        assert!(!is_failed_status("running"));
    }

    #[test]
    fn update_global_counters_accumulates() {
        let mut completed = 0;
        let mut failed = 0;
        let mut prompt = 0;
        let mut completion = 0;
        let mut total = 0;
        let mut latencies = Vec::new();
        let facts = RunFacts {
            status: "completed".to_string(),
            model: "gpt-4".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            latency_ms: 200,
        };
        update_global_counters(
            &mut completed,
            &mut failed,
            &mut prompt,
            &mut completion,
            &mut total,
            &mut latencies,
            &facts,
        );
        assert_eq!(completed, 1);
        assert_eq!(failed, 0);
        assert_eq!(prompt, 100);
        assert_eq!(completion, 50);
        assert_eq!(total, 150);
        assert_eq!(latencies, vec![200]);
    }

    #[test]
    fn update_pricing_counters_priced() {
        let mut total_cost = 0.0;
        let mut priced = 0;
        let mut unpriced = 0;
        update_pricing_counters(&mut total_cost, &mut priced, &mut unpriced, 0.05);
        assert!((total_cost - 0.05).abs() < f64::EPSILON);
        assert_eq!(priced, 1);
        assert_eq!(unpriced, 0);
    }

    #[test]
    fn update_pricing_counters_unpriced() {
        let mut total_cost = 0.0;
        let mut priced = 0;
        let mut unpriced = 0;
        update_pricing_counters(&mut total_cost, &mut priced, &mut unpriced, 0.0);
        assert_eq!(priced, 0);
        assert_eq!(unpriced, 1);
    }

    #[test]
    fn estimate_run_cost_calculates() {
        let rate = PricingRate {
            input_per_1m_usd: 10.0,
            output_per_1m_usd: 30.0,
        };
        let cost = estimate_run_cost(1_000_000, 500_000, rate);
        assert!((cost - 25.0).abs() < 0.001);
    }

    #[test]
    fn iso_day_prefix_extracts_date() {
        assert_eq!(
            iso_day_prefix("2026-09-10T14:30:00Z"),
            Some("2026-09-10".to_string())
        );
    }

    #[test]
    fn iso_day_prefix_short_string() {
        assert_eq!(iso_day_prefix("short"), None);
    }

    #[test]
    fn normalized_user_key_returns_unknown_for_empty() {
        assert_eq!(normalized_user_key(None), "unknown");
        assert_eq!(normalized_user_key(Some("  ".to_string())), "unknown");
    }

    #[test]
    fn normalized_user_key_returns_id() {
        assert_eq!(
            normalized_user_key(Some("user-42".to_string())),
            "user-42"
        );
    }
}
