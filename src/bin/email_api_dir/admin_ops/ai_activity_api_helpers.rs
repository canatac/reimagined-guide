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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_user_key_valid() {
        assert_eq!(normalized_user_key(Some("user123".to_string())), "user123");
    }

    #[test]
    fn normalized_user_key_none() {
        assert_eq!(normalized_user_key(None), "unknown");
    }

    #[test]
    fn normalized_user_key_empty() {
        assert_eq!(normalized_user_key(Some("".to_string())), "unknown");
    }

    #[test]
    fn normalized_user_key_whitespace() {
        assert_eq!(normalized_user_key(Some("   ".to_string())), "unknown");
    }

    #[test]
    fn is_completed_status() {
        assert!(is_completed_status("completed"));
        assert!(is_completed_status("success"));
    }

    #[test]
    fn is_failed_status() {
        assert!(is_failed_status("failed"));
        assert!(is_failed_status("error"));
    }

    #[test]
    fn is_completed_status_false() {
        assert!(!is_completed_status("pending"));
        assert!(!is_completed_status("running"));
    }

    #[test]
    fn is_failed_status_false() {
        assert!(!is_failed_status("completed"));
        assert!(!is_failed_status("pending"));
    }

    #[test]
    fn iso_day_prefix_valid() {
        assert_eq!(iso_day_prefix("2026-09-10T12:00:00Z"), Some("2026-09-10".to_string()));
    }

    #[test]
    fn iso_day_prefix_short() {
        assert_eq!(iso_day_prefix("2026"), None);
    }

    #[test]
    fn iso_day_prefix_empty() {
        assert_eq!(iso_day_prefix(""), None);
    }

    #[test]
    fn day_bucket_for_run_valid() {
        let run = serde_json::json!({"started_at": "2026-09-10T12:00:00Z"});
        assert_eq!(day_bucket_for_run(&run), "2026-09-10");
    }

    #[test]
    fn day_bucket_for_run_alias() {
        let run = serde_json::json!({"startedAt": "2026-09-10T12:00:00Z"});
        assert_eq!(day_bucket_for_run(&run), "2026-09-10");
    }

    #[test]
    fn day_bucket_for_run_unknown() {
        let run = serde_json::json!({});
        assert_eq!(day_bucket_for_run(&run), "unknown");
    }

    #[test]
    fn estimate_run_cost_zero() {
        let rate = PricingRate { input_per_1m_usd: 0.0, output_per_1m_usd: 0.0 };
        assert_eq!(estimate_run_cost(1000, 1000, rate), 0.0);
    }

    #[test]
    fn estimate_run_cost_with_pricing() {
        let rate = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        let cost = estimate_run_cost(500_000, 500_000, rate);
        assert!(cost > 0.0);
    }

    #[test]
    fn estimate_run_cost_rounds() {
        let rate = PricingRate { input_per_1m_usd: 0.123456, output_per_1m_usd: 0.0 };
        let cost = estimate_run_cost(1000, 0, rate);
        assert_eq!(cost, 0.000123);
    }

    #[test]
    fn apply_bucket_for_run_increments() {
        let mut bucket = Bucket::default();
        let facts = RunFacts {
            status: "completed".to_string(),
            model: "test".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            latency_ms: 200,
        };
        apply_bucket_for_run(&mut bucket, &facts, 0.001);
        assert_eq!(bucket.runs, 1);
        assert_eq!(bucket.total_tokens, 150);
        assert_eq!(bucket.completed_runs, 1);
        assert!((bucket.total_cost_usd - 0.001).abs() < f64::EPSILON);
    }

    #[test]
    fn apply_bucket_for_run_failed() {
        let mut bucket = Bucket::default();
        let facts = RunFacts {
            status: "failed".to_string(),
            model: "test".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            latency_ms: 0,
        };
        apply_bucket_for_run(&mut bucket, &facts, 0.0);
        assert_eq!(bucket.failed_runs, 1);
        assert_eq!(bucket.completed_runs, 0);
    }

    #[test]
    fn update_pricing_counters_priced() {
        let mut total = 0.0;
        let mut priced = 0;
        let mut unpriced = 0;
        update_pricing_counters(&mut total, &mut priced, &mut unpriced, 0.01);
        assert!((total - 0.01).abs() < f64::EPSILON);
        assert_eq!(priced, 1);
        assert_eq!(unpriced, 0);
    }

    #[test]
    fn update_pricing_counters_unpriced() {
        let mut total = 0.0;
        let mut priced = 0;
        let mut unpriced = 0;
        update_pricing_counters(&mut total, &mut priced, &mut unpriced, 0.0);
        assert_eq!(unpriced, 1);
        assert_eq!(priced, 0);
    }
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
    fn extract_run_facts_basic() {
        let run = serde_json::json!({
            "status": "completed",
            "model": "gpt-4",
            "feature": "compose",
            "userId": "user1",
            "sessionId": "sess1",
            "startedAt": "2026-09-10T12:00:00Z",
            "usage": {
                "promptTokens": 100,
                "completionTokens": 50,
                "totalTokens": 150
            },
            "latencyMs": 200
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.status, "completed");
        assert_eq!(facts.model, "gpt-4");
        assert_eq!(facts.feature, "compose");
        assert_eq!(facts.user_id, Some("user1".to_string()));
        assert_eq!(facts.session_id, Some("sess1".to_string()));
        assert_eq!(facts.day_bucket, "2026-09-10");
        assert_eq!(facts.prompt_tokens, 100);
        assert_eq!(facts.completion_tokens, 50);
        assert_eq!(facts.total_tokens, 150);
        assert_eq!(facts.latency_ms, 200);
    }

    #[test]
    fn extract_run_facts_total_fallback() {
        let run = serde_json::json!({
            "status": "completed",
            "model": "gpt-4",
            "feature": "compose",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50
            }
        });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.total_tokens, 150);
    }

    #[test]
    fn extract_run_facts_defaults() {
        let run = serde_json::json!({});
        let facts = extract_run_facts(&run);
        assert_eq!(facts.status, "unknown");
        assert_eq!(facts.model, "unknown");
        assert_eq!(facts.feature, "unknown");
        assert_eq!(facts.user_id, None);
        assert_eq!(facts.session_id, None);
        assert_eq!(facts.day_bucket, "unknown");
        assert_eq!(facts.prompt_tokens, 0);
        assert_eq!(facts.completion_tokens, 0);
        assert_eq!(facts.total_tokens, 0);
        assert_eq!(facts.latency_ms, 0);
    }

    #[test]
    fn extract_run_facts_status_lowercase() {
        let run = serde_json::json!({ "status": "COMPLETED" });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.status, "completed");
    }

    #[test]
    fn extract_run_facts_model_trim() {
        let run = serde_json::json!({ "model": "  gpt-4  " });
        let facts = extract_run_facts(&run);
        assert_eq!(facts.model, "gpt-4");
    }

    #[test]
    fn normalized_user_key_valid() {
        assert_eq!(normalized_user_key(Some("user123".to_string())), "user123");
    }

    #[test]
    fn normalized_user_key_none() {
        assert_eq!(normalized_user_key(None), "unknown");
    }

    #[test]
    fn normalized_user_key_empty() {
        assert_eq!(normalized_user_key(Some("".to_string())), "unknown");
    }

    #[test]
    fn normalized_user_key_whitespace() {
        assert_eq!(normalized_user_key(Some("   ".to_string())), "unknown");
    }

    #[test]
    fn is_completed_status_true() {
        assert!(is_completed_status("completed"));
        assert!(is_completed_status("success"));
    }

    #[test]
    fn is_completed_status_false() {
        assert!(!is_completed_status("pending"));
        assert!(!is_completed_status("running"));
    }

    #[test]
    fn is_failed_status_true() {
        assert!(is_failed_status("failed"));
        assert!(is_failed_status("error"));
    }

    #[test]
    fn is_failed_status_false() {
        assert!(!is_failed_status("completed"));
        assert!(!is_failed_status("pending"));
    }

    #[test]
    fn iso_day_prefix_valid() {
        assert_eq!(iso_day_prefix("2026-09-10T12:00:00Z"), Some("2026-09-10".to_string()));
    }

    #[test]
    fn iso_day_prefix_short() {
        assert_eq!(iso_day_prefix("2026"), None);
    }

    #[test]
    fn iso_day_prefix_empty() {
        assert_eq!(iso_day_prefix(""), None);
    }

    #[test]
    fn day_bucket_for_run_valid() {
        let run = serde_json::json!({"started_at": "2026-09-10T12:00:00Z"});
        assert_eq!(day_bucket_for_run(&run), "2026-09-10");
    }

    #[test]
    fn day_bucket_for_run_alias() {
        let run = serde_json::json!({"startedAt": "2026-09-10T12:00:00Z"});
        assert_eq!(day_bucket_for_run(&run), "2026-09-10");
    }

    #[test]
    fn day_bucket_for_run_unknown() {
        let run = serde_json::json!({});
        assert_eq!(day_bucket_for_run(&run), "unknown");
    }

    #[test]
    fn estimate_run_cost_zero() {
        let rate = PricingRate { input_per_1m_usd: 0.0, output_per_1m_usd: 0.0 };
        assert_eq!(estimate_run_cost(1000, 1000, rate), 0.0);
    }

    #[test]
    fn estimate_run_cost_with_pricing() {
        let rate = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        let cost = estimate_run_cost(500_000, 500_000, rate);
        assert!(cost > 0.0);
    }

    #[test]
    fn estimate_run_cost_rounds() {
        let rate = PricingRate { input_per_1m_usd: 0.123456, output_per_1m_usd: 0.0 };
        let cost = estimate_run_cost(1000, 0, rate);
        assert_eq!(cost, 0.000123);
    }

    #[test]
    fn apply_bucket_for_run_increments() {
        let mut bucket = Bucket::default();
        let facts = RunFacts {
            status: "completed".to_string(),
            model: "test".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            latency_ms: 200,
        };
        apply_bucket_for_run(&mut bucket, &facts, 0.001);
        assert_eq!(bucket.runs, 1);
        assert_eq!(bucket.total_tokens, 150);
        assert_eq!(bucket.completed_runs, 1);
        assert!((bucket.total_cost_usd - 0.001).abs() < f64::EPSILON);
    }

    #[test]
    fn apply_bucket_for_run_failed() {
        let mut bucket = Bucket::default();
        let facts = RunFacts {
            status: "failed".to_string(),
            model: "test".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            latency_ms: 0,
        };
        apply_bucket_for_run(&mut bucket, &facts, 0.0);
        assert_eq!(bucket.failed_runs, 1);
        assert_eq!(bucket.completed_runs, 0);
    }

    #[test]
    fn update_pricing_counters_priced() {
        let mut total = 0.0;
        let mut priced = 0;
        let mut unpriced = 0;
        update_pricing_counters(&mut total, &mut priced, &mut unpriced, 0.01);
        assert!((total - 0.01).abs() < f64::EPSILON);
        assert_eq!(priced, 1);
        assert_eq!(unpriced, 0);
    }

    #[test]
    fn update_pricing_counters_unpriced() {
        let mut total = 0.0;
        let mut priced = 0;
        let mut unpriced = 0;
        update_pricing_counters(&mut total, &mut priced, &mut unpriced, 0.0);
        assert_eq!(unpriced, 1);
        assert_eq!(priced, 0);
    }

    #[test]
    fn update_global_counters_completed() {
        let mut completed = 0;
        let mut failed = 0;
        let mut prompt = 0;
        let mut completion = 0;
        let mut total = 0;
        let mut latencies = vec![];
        let facts = RunFacts {
            status: "completed".to_string(),
            model: "test".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
            latency_ms: 200,
        };
        update_global_counters(&mut completed, &mut failed, &mut prompt, &mut completion, &mut total, &mut latencies, &facts);
        assert_eq!(completed, 1);
        assert_eq!(failed, 0);
        assert_eq!(prompt, 100);
        assert_eq!(completion, 50);
        assert_eq!(total, 150);
        assert_eq!(latencies, vec![200]);
    }

    #[test]
    fn update_global_counters_failed() {
        let mut completed = 0;
        let mut failed = 0;
        let mut prompt = 0;
        let mut completion = 0;
        let mut total = 0;
        let mut latencies = vec![];
        let facts = RunFacts {
            status: "failed".to_string(),
            model: "test".to_string(),
            feature: "compose".to_string(),
            user_id: None,
            session_id: None,
            day_bucket: "2026-09-10".to_string(),
            prompt_tokens: 100,
            completion_tokens: 0,
            total_tokens: 100,
            latency_ms: 0,
        };
        update_global_counters(&mut completed, &mut failed, &mut prompt, &mut completion, &mut total, &mut latencies, &facts);
        assert_eq!(completed, 0);
        assert_eq!(failed, 1);
        assert!(latencies.is_empty());
    }
}
