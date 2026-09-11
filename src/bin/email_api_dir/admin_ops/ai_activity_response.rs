use super::*;

#[derive(Default, Clone)]
pub(crate) struct Bucket {
    pub(crate) runs: i64,
    pub(crate) completed_runs: i64,
    pub(crate) failed_runs: i64,
    pub(crate) prompt_tokens: i64,
    pub(crate) completion_tokens: i64,
    pub(crate) total_tokens: i64,
    pub(crate) total_cost_usd: f64,
}

pub(crate) fn render_ai_activity_response(
    limit: i64,
    total_runs: i64,
    completed_runs: i64,
    failed_runs: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    mut latencies: Vec<i64>,
    total_cost_usd: f64,
    priced_runs: i64,
    unpriced_runs: i64,
    by_user: HashMap<String, Bucket>,
    by_model: HashMap<String, Bucket>,
    by_feature: HashMap<String, Bucket>,
    trend_global: HashMap<String, Bucket>,
    trend_by_user: HashMap<String, HashMap<String, Bucket>>,
    default_rate: PricingRate,
    model_overrides: HashMap<String, PricingRate>,
    openrouter_rates: HashMap<String, PricingRate>,
    mut warnings: Vec<String>,
    normalized_runs: Vec<serde_json::Value>,
) -> HttpResponse {
    let (avg_latency, p95_latency) = latency_stats(&mut latencies);

    let mut by_user_rows = bucket_rows_with_identity(by_user, "userId");
    sort_rows_by_total_tokens_desc(&mut by_user_rows);

    let mut by_model_rows = bucket_rows_with_identity(by_model, "model");
    sort_rows_by_total_tokens_desc(&mut by_model_rows);

    let mut by_feature_rows = bucket_rows_with_identity(by_feature, "feature");
    sort_rows_by_total_tokens_desc(&mut by_feature_rows);

    let mut trend_global_rows = trend_rows_from_bucket_map(trend_global);
    sort_rows_by_day_asc(&mut trend_global_rows);

    let mut trend_by_user_rows = trend_by_user_rows(trend_by_user);
    sort_trend_by_user_rows_by_total_tokens_desc(&mut trend_by_user_rows);

    append_pricing_warnings(
        &default_rate,
        &model_overrides,
        &openrouter_rates,
        &mut warnings,
    );
    let pricing_source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);

    HttpResponse::Ok().json(serde_json::json!({
        "generatedAt": Utc::now().to_rfc3339(),
        "limit": limit,
        "metrics": {
            "totalRuns": total_runs,
            "completedRuns": completed_runs,
            "failedRuns": failed_runs,
            "successRate": safe_rate(completed_runs, total_runs),
            "avgLatencyMs": avg_latency,
            "p95LatencyMs": p95_latency,
            "promptTokens": prompt_tokens,
            "completionTokens": completion_tokens,
            "totalTokens": total_tokens,
            "avgTokensPerRun": safe_avg_i64(total_tokens, total_runs),
            "currency": "USD",
            "totalCostUsd": round6(total_cost_usd),
            "avgCostPerRunUsd": safe_avg_f64(total_cost_usd, total_runs),
            "pricedRuns": priced_runs,
            "unpricedRuns": unpriced_runs,
        },
        "byUser": by_user_rows,
        "byModel": by_model_rows,
        "byFeature": by_feature_rows,
        "trends": {
            "global": trend_global_rows,
            "byUser": trend_by_user_rows,
        },
        "pricing": {
            "source": pricing_source,
            "provider": "openrouter",
            "openRouterRatesCount": openrouter_rates.len(),
            "envModelOverridesCount": model_overrides.len(),
            "defaultInputPer1MUsd": round6(default_rate.input_per_1m_usd),
            "defaultOutputPer1MUsd": round6(default_rate.output_per_1m_usd),
        },
        "warnings": warnings,
        "runs": normalized_runs,
    }))
}

fn latency_stats(latencies: &mut [i64]) -> (i64, i64) {
    if latencies.is_empty() {
        return (0, 0);
    }
    latencies.sort_unstable();
    let avg = latencies.iter().sum::<i64>() / i64::try_from(latencies.len()).unwrap_or(1);
    let idx = ((latencies.len() as f64) * 0.95).ceil() as usize;
    let idx = idx.saturating_sub(1).min(latencies.len() - 1);
    (avg, latencies[idx])
}

fn bucket_rows_with_identity(
    buckets: HashMap<String, Bucket>,
    identity_key: &str,
) -> Vec<serde_json::Value> {
    buckets
        .into_iter()
        .map(|(identity, b)| {
            serde_json::json!({
                identity_key: identity,
                "runs": b.runs,
                "completedRuns": b.completed_runs,
                "failedRuns": b.failed_runs,
                "promptTokens": b.prompt_tokens,
                "completionTokens": b.completion_tokens,
                "totalTokens": b.total_tokens,
                "totalCostUsd": round6(b.total_cost_usd),
                "avgTokensPerRun": safe_avg_i64(b.total_tokens, b.runs),
                "avgCostPerRunUsd": safe_avg_f64(b.total_cost_usd, b.runs),
                "successRate": safe_rate(b.completed_runs, b.runs),
            })
        })
        .collect()
}

fn trend_rows_from_bucket_map(buckets: HashMap<String, Bucket>) -> Vec<serde_json::Value> {
    buckets
        .into_iter()
        .map(|(day, b)| {
            serde_json::json!({
                "day": day,
                "runs": b.runs,
                "completedRuns": b.completed_runs,
                "failedRuns": b.failed_runs,
                "promptTokens": b.prompt_tokens,
                "completionTokens": b.completion_tokens,
                "totalTokens": b.total_tokens,
                "totalCostUsd": round6(b.total_cost_usd),
                "successRate": safe_rate(b.completed_runs, b.runs),
            })
        })
        .collect()
}

fn trend_by_user_rows(
    trend_by_user: HashMap<String, HashMap<String, Bucket>>,
) -> Vec<serde_json::Value> {
    trend_by_user
        .into_iter()
        .map(|(user_id, days_map)| {
            let mut rows = trend_rows_from_bucket_map(days_map);
            sort_rows_by_day_asc(&mut rows);
            serde_json::json!({
                "userId": user_id,
                "days": rows,
            })
        })
        .collect()
}

fn append_pricing_warnings(
    default_rate: &PricingRate,
    model_overrides: &HashMap<String, PricingRate>,
    openrouter_rates: &HashMap<String, PricingRate>,
    warnings: &mut Vec<String>,
) {
    let has_default = default_rate.input_per_1m_usd > 0.0 || default_rate.output_per_1m_usd > 0.0;
    if has_default || !model_overrides.is_empty() || !openrouter_rates.is_empty() {
        return;
    }
    warnings.push("LLM pricing not configured: set LLM_COST_DEFAULT_INPUT_PER_1M_USD / LLM_COST_DEFAULT_OUTPUT_PER_1M_USD or LLM_COST_MODEL_OVERRIDES_JSON".to_string());
}

fn pricing_source_label(
    default_rate: &PricingRate,
    model_overrides: &HashMap<String, PricingRate>,
    openrouter_rates: &HashMap<String, PricingRate>,
) -> &'static str {
    if !openrouter_rates.is_empty() {
        return "openrouter_live";
    }
    if !model_overrides.is_empty() {
        return "env_model_overrides_only";
    }
    if default_rate.input_per_1m_usd > 0.0 || default_rate.output_per_1m_usd > 0.0 {
        return "env_default_only";
    }
    "unconfigured"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_empty() {
        let mut latencies: Vec<i64> = vec![];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 0);
        assert_eq!(p95, 0);
    }

    #[test]
    fn latency_stats_single() {
        let mut latencies = vec![42];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 42);
        assert_eq!(p95, 42);
    }

    #[test]
    fn latency_stats_multiple() {
        let mut latencies = vec![10, 20, 30, 40, 100];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 40);
        // p95 index: ceil(5 * 0.95) - 1 = 5 - 1 = 4, so sorted[4] = 100
        assert_eq!(p95, 100);
    }

    #[test]
    fn latency_stats_sorts() {
        let mut latencies = vec![100, 10, 50];
        let (_, p95) = latency_stats(&mut latencies);
        // sorted: [10, 50, 100], p95 at index ceil(3*0.95)-1 = 2 -> 100
        assert_eq!(p95, 100);
    }

    #[test]
    fn bucket_default_is_zero() {
        let bucket = Bucket::default();
        assert_eq!(bucket.runs, 0);
        assert_eq!(bucket.completed_runs, 0);
        assert_eq!(bucket.total_tokens, 0);
    }

    #[test]
    fn bucket_with_values() {
        let mut by_user: HashMap<String, Bucket> = HashMap::new();
        let mut b = Bucket::default();
        b.runs = 10;
        b.completed_runs = 8;
        b.failed_runs = 2;
        b.total_tokens = 5000;
        b.total_cost_usd = 0.0123456;
        by_user.insert("user1".to_string(), b);

        let rows = bucket_rows_with_identity(by_user, "userId");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["userId"], "user1");
        assert_eq!(rows[0]["runs"], 10);
        assert_eq!(rows[0]["successRate"], 0.8);
    }

    #[test]
    fn trend_rows_from_bucket_map_contains_day() {
        let mut trend: HashMap<String, Bucket> = HashMap::new();
        let mut b = Bucket::default();
        b.runs = 5;
        trend.insert("2026-09-10".to_string(), b);

        let rows = trend_rows_from_bucket_map(trend);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["day"], "2026-09-10");
    }

    #[test]
    fn append_pricing_warnings_adds_warning_when_unconfigured() {
        let default = PricingRate { input_per_1m_usd: 0.0, output_per_1m_usd: 0.0 };
        let mut warnings = Vec::new();
        append_pricing_warnings(&default, &HashMap::new(), &HashMap::new(), &mut warnings);
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("not configured"));
    }

    #[test]
    fn append_pricing_warnings_no_warning_when_configured() {
        let default = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        let mut warnings = Vec::new();
        append_pricing_warnings(&default, &HashMap::new(), &HashMap::new(), &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn pricing_source_label_unconfigured() {
        let default = PricingRate { input_per_1m_usd: 0.0, output_per_1m_usd: 0.0 };
        assert_eq!(pricing_source_label(&default, &HashMap::new(), &HashMap::new()), "unconfigured");
    }

    #[test]
    fn pricing_source_label_env_default() {
        let default = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        assert_eq!(pricing_source_label(&default, &HashMap::new(), &HashMap::new()), "env_default_only");
    }

    #[test]
    fn pricing_source_label_model_overrides() {
        let default = PricingRate { input_per_1m_usd: 0.0, output_per_1m_usd: 0.0 };
        let mut overrides = HashMap::new();
        overrides.insert("model1".to_string(), PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 });
        assert_eq!(pricing_source_label(&default, &overrides, &HashMap::new()), "env_model_overrides_only");
    }

    #[test]
    fn pricing_source_label_openrouter_rates() {
        let default = PricingRate { input_per_1m_usd: 0.0, output_per_1m_usd: 0.0 };
        let mut rates = HashMap::new();
        rates.insert("model1".to_string(), PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 });
        assert_eq!(pricing_source_label(&default, &HashMap::new(), &rates), "openrouter_live");
    }

    #[test]
    fn round6_rounds_correctly() {
        assert_eq!(round6(0.0123456), 0.012346);
        assert_eq!(round6(1.0), 1.0);
        assert_eq!(round6(0.0), 0.0);
    }
}

fn safe_avg_i64(total: i64, count: i64) -> i64 {
    if count > 0 { total / count } else { 0 }
}

fn safe_avg_f64(total: f64, count: i64) -> f64 {
    if count > 0 {
        round6(total / (count as f64))
    } else {
        0.0
    }
}

fn safe_rate(success_count: i64, total_count: i64) -> f64 {
    if total_count > 0 {
        (success_count as f64) / (total_count as f64)
    } else {
        0.0
    }
}

fn sort_rows_by_total_tokens_desc(rows: &mut [serde_json::Value]) {
    rows.sort_by(|a, b| {
        let at = a.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        let bt = b.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        bt.cmp(&at)
    });
}

fn sort_rows_by_day_asc(rows: &mut [serde_json::Value]) {
    rows.sort_by(|a, b| {
        let ad = a.get("day").and_then(|v| v.as_str()).unwrap_or("");
        let bd = b.get("day").and_then(|v| v.as_str()).unwrap_or("");
        ad.cmp(bd)
    });
}

fn sort_trend_by_user_rows_by_total_tokens_desc(rows: &mut [serde_json::Value]) {
    rows.sort_by(|a, b| {
        let at = trend_row_total_tokens(a);
        let bt = trend_row_total_tokens(b);
        bt.cmp(&at)
    });
}

fn trend_row_total_tokens(row: &serde_json::Value) -> i64 {
    row.get("days")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| v.get("totalTokens").and_then(|x| x.as_i64()).unwrap_or(0))
                .sum::<i64>()
        })
        .unwrap_or(0)
}
