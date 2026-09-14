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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_default() {
        let b: Bucket = Default::default();
        assert_eq!(b.runs, 0);
        assert_eq!(b.completed_runs, 0);
        assert_eq!(b.failed_runs, 0);
        assert_eq!(b.prompt_tokens, 0);
        assert_eq!(b.completion_tokens, 0);
        assert_eq!(b.total_tokens, 0);
        assert_eq!(b.total_cost_usd, 0.0);
    }

    #[test]
    fn bucket_with_values() {
        let b = Bucket {
            runs: 10,
            completed_runs: 8,
            failed_runs: 2,
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
            total_cost_usd: 0.05,
        };
        assert_eq!(b.runs, 10);
        assert_eq!(b.completed_runs, 8);
        assert_eq!(b.failed_runs, 2);
        assert_eq!(b.prompt_tokens, 1000);
        assert_eq!(b.completion_tokens, 500);
        assert_eq!(b.total_tokens, 1500);
        assert!((b.total_cost_usd - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_stats_empty() {
        let mut latencies: Vec<i64> = vec![];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 0);
        assert_eq!(p95, 0);
    }

    #[test]
    fn latency_stats_single() {
        let mut latencies = vec![100];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 100);
        assert_eq!(p95, 100);
    }

    #[test]
    fn latency_stats_multiple() {
        let mut latencies = vec![100, 200, 300, 400, 500];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 300);
        assert_eq!(p95, 500);
    }

    #[test]
    fn latency_stats_unsorted() {
        let mut latencies = vec![500, 100, 300, 200, 400];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 300);
        assert_eq!(p95, 500);
    }

    #[test]
    fn latency_stats_two_values() {
        let mut latencies = vec![100, 200];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 150);
        assert_eq!(p95, 200);
    }

    #[test]
    fn safe_avg_i64_zero_count() {
        assert_eq!(safe_avg_i64(100, 0), 0);
    }

    #[test]
    fn safe_avg_i64_positive_count() {
        assert_eq!(safe_avg_i64(100, 10), 10);
    }

    #[test]
    fn safe_avg_i64_rounds_down() {
        assert_eq!(safe_avg_i64(101, 10), 10);
    }

    #[test]
    fn safe_avg_f64_zero_count() {
        assert_eq!(safe_avg_f64(100.0, 0), 0.0);
    }

    #[test]
    fn safe_avg_f64_positive_count() {
        assert!((safe_avg_f64(100.0, 10) - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_avg_f64_rounds() {
        assert!((safe_avg_f64(100.0, 3) - 33.333333).abs() < 0.000001);
    }

    #[test]
    fn safe_rate_zero_total() {
        assert_eq!(safe_rate(0, 0), 0.0);
    }

    #[test]
    fn safe_rate_all_success() {
        assert_eq!(safe_rate(10, 10), 1.0);
    }

    #[test]
    fn safe_rate_partial() {
        assert_eq!(safe_rate(7, 10), 0.7);
    }

    #[test]
    fn safe_rate_none_success() {
        assert_eq!(safe_rate(0, 10), 0.0);
    }

    #[test]
    fn pricing_source_openrouter_live() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let mut openrouter_rates = HashMap::new();
        openrouter_rates.insert("gpt-4".to_string(), PricingRate::default());
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "openrouter_live");
    }

    #[test]
    fn pricing_source_env_model_overrides_only() {
        let default_rate = PricingRate::default();
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_model_overrides_only");
    }

    #[test]
    fn pricing_source_env_default_only() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_default_only");
    }

    #[test]
    fn pricing_source_unconfigured() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "unconfigured");
    }

    #[test]
    fn append_pricing_warnings_no_warning_when_configured() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn append_pricing_warnings_warning_when_unconfigured() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("LLM pricing not configured"));
    }

    #[test]
    fn append_pricing_warnings_no_warning_with_openrouter() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let mut openrouter_rates = HashMap::new();
        openrouter_rates.insert("gpt-4".to_string(), PricingRate::default());
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn append_pricing_warnings_no_warning_with_overrides() {
        let default_rate = PricingRate::default();
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn bucket_rows_with_identity_empty() {
        let buckets: HashMap<String, Bucket> = HashMap::new();
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert!(rows.is_empty());
    }

    #[test]
    fn bucket_rows_with_identity_single() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket {
            runs: 10,
            completed_runs: 8,
            failed_runs: 2,
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
            total_cost_usd: 0.05,
        });
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["userId"], "user-1");
        assert_eq!(rows[0]["runs"], 10);
        assert_eq!(rows[0]["completedRuns"], 8);
        assert_eq!(rows[0]["failedRuns"], 2);
        assert_eq!(rows[0]["totalTokens"], 1500);
    }

    #[test]
    fn bucket_rows_with_identity_multiple() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket::default());
        buckets.insert("user-2".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn trend_rows_from_bucket_map_empty() {
        let buckets: HashMap<String, Bucket> = HashMap::new();
        let rows = trend_rows_from_bucket_map(buckets);
        assert!(rows.is_empty());
    }

    #[test]
    fn trend_rows_from_bucket_map_single() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket {
            runs: 5,
            completed_runs: 4,
            failed_runs: 1,
            prompt_tokens: 500,
            completion_tokens: 250,
            total_tokens: 750,
            total_cost_usd: 0.025,
        });
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["day"], "2026-01-01");
        assert_eq!(rows[0]["runs"], 5);
    }

    #[test]
    fn sort_rows_by_total_tokens_desc() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": 100}),
            serde_json::json!({"totalTokens": 500}),
            serde_json::json!({"totalTokens": 300}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["totalTokens"], 500);
        assert_eq!(rows[1]["totalTokens"], 300);
        assert_eq!(rows[2]["totalTokens"], 100);
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_empty() {
        let mut rows: Vec<serde_json::Value> = vec![];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert!(rows.is_empty());
    }

    #[test]
    fn sort_rows_by_day_asc() {
        let mut rows = vec![
            serde_json::json!({"day": "2026-01-03"}),
            serde_json::json!({"day": "2026-01-01"}),
            serde_json::json!({"day": "2026-01-02"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows[0]["day"], "2026-01-01");
        assert_eq!(rows[1]["day"], "2026-01-02");
        assert_eq!(rows[2]["day"], "2026-01-03");
    }

    #[test]
    fn sort_rows_by_day_asc_empty() {
        let mut rows: Vec<serde_json::Value> = vec![];
        sort_rows_by_day_asc(&mut rows);
        assert!(rows.is_empty());
    }

    #[test]
    fn trend_row_total_tokens_empty() {
        let row = serde_json::json!({"days": []});
        assert_eq!(trend_row_total_tokens(&row), 0);
    }

    #[test]
    fn trend_row_total_tokens_with_values() {
        let row = serde_json::json!({"days": [
            {"totalTokens": 100},
            {"totalTokens": 200},
            {"totalTokens": 300},
        ]});
        assert_eq!(trend_row_total_tokens(&row), 600);
    }

    #[test]
    fn trend_row_total_tokens_missing_field() {
        let row = serde_json::json!({});
        assert_eq!(trend_row_total_tokens(&row), 0);
    }

    #[test]
    fn trend_row_total_tokens_missing_days() {
        let row = serde_json::json!({"other": "value"});
        assert_eq!(trend_row_total_tokens(&row), 0);
    }

    #[test]
    fn trend_by_user_rows_empty() {
        let trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        let rows = trend_by_user_rows(trend_by_user);
        assert!(rows.is_empty());
    }

    #[test]
    fn trend_by_user_rows_single_user() {
        let mut days: HashMap<String, Bucket> = HashMap::new();
        days.insert("2026-01-01".to_string(), Bucket::default());
        let mut trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        trend_by_user.insert("user-1".to_string(), days);
        let rows = trend_by_user_rows(trend_by_user);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["userId"], "user-1");
    }

    #[test]
    fn sort_trend_by_user_rows_by_total_tokens_desc() {
        let mut rows = vec![
            serde_json::json!({"userId": "user-1", "days": [{"totalTokens": 100}]}),
            serde_json::json!({"userId": "user-2", "days": [{"totalTokens": 500}]}),
            serde_json::json!({"userId": "user-3", "days": [{"totalTokens": 300}]}),
        ];
        sort_trend_by_user_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["userId"], "user-2");
        assert_eq!(rows[1]["userId"], "user-3");
        assert_eq!(rows[2]["userId"], "user-1");
    }

    #[test]
    fn sort_trend_by_user_rows_empty() {
        let mut rows: Vec<serde_json::Value> = vec![];
        sort_trend_by_user_rows_by_total_tokens_desc(&mut rows);
        assert!(rows.is_empty());
    }

    #[test]
    fn round6_zero() {
        assert_eq!(round6(0.0), 0.0);
    }

    #[test]
    fn round6_rounds() {
        assert!((round6(1.2345678) - 1.234568).abs() < f64::EPSILON);
    }

    #[test]
    fn round6_integer() {
        assert_eq!(round6(5.0), 5.0);
    }

    #[test]
    fn round6_negative() {
        assert!((round6(-1.2345678) - (-1.234568)).abs() < f64::EPSILON);
    }

    #[test]
    fn pricing_rate_default() {
        let rate: PricingRate = Default::default();
        assert_eq!(rate.input_per_1m_usd, 0.0);
        assert_eq!(rate.output_per_1m_usd, 0.0);
    }

    #[test]
    fn pricing_rate_with_values() {
        let rate = PricingRate {
            input_per_1m_usd: 1.5,
            output_per_1m_usd: 3.0,
        };
        assert!((rate.input_per_1m_usd - 1.5).abs() < f64::EPSILON);
        assert!((rate.output_per_1m_usd - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn bucket_clone() {
        let b = Bucket {
            runs: 10,
            completed_runs: 8,
            failed_runs: 2,
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
            total_cost_usd: 0.05,
        };
        let cloned = b.clone();
        assert_eq!(b.runs, cloned.runs);
        assert_eq!(b.completed_runs, cloned.completed_runs);
        assert_eq!(b.failed_runs, cloned.failed_runs);
        assert_eq!(b.prompt_tokens, cloned.prompt_tokens);
        assert_eq!(b.completion_tokens, cloned.completion_tokens);
        assert_eq!(b.total_tokens, cloned.total_tokens);
        assert!((b.total_cost_usd - cloned.total_cost_usd).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_stats_large_values() {
        let mut latencies = vec![1000000, 2000000, 3000000];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 2000000);
        assert_eq!(p95, 3000000);
    }

    #[test]
    fn latency_stats_identical_values() {
        let mut latencies = vec![500, 500, 500, 500];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 500);
        assert_eq!(p95, 500);
    }

    #[test]
    fn safe_avg_i64_negative_total() {
        assert_eq!(safe_avg_i64(-100, 10), -10);
    }

    #[test]
    fn safe_avg_f64_negative_total() {
        assert!((safe_avg_f64(-100.0, 10) - (-10.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_rate_negative_success() {
        assert_eq!(safe_rate(-5, 10), -0.5);
    }

    #[test]
    fn bucket_rows_with_identity_model_key() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("gpt-4".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "model");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["model"], "gpt-4");
    }

    #[test]
    fn bucket_rows_with_identity_feature_key() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("chat".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "feature");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["feature"], "chat");
    }

    #[test]
    fn trend_rows_from_bucket_map_multiple_days() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket { runs: 5, ..Default::default() });
        buckets.insert("2026-01-02".to_string(), Bucket { runs: 10, ..Default::default() });
        buckets.insert("2026-01-03".to_string(), Bucket { runs: 15, ..Default::default() });
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_missing_field() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": 100}),
            serde_json::json!({}),
            serde_json::json!({"totalTokens": 300}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["totalTokens"], 300);
        assert_eq!(rows[2]["totalTokens"], 100);
    }

    #[test]
    fn sort_rows_by_day_asc_missing_field() {
        let mut rows = vec![
            serde_json::json!({"day": "2026-01-03"}),
            serde_json::json!({}),
            serde_json::json!({"day": "2026-01-01"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows[0]["day"], "");
        assert_eq!(rows[1]["day"], "2026-01-01");
        assert_eq!(rows[2]["day"], "2026-01-03");
    }

    #[test]
    fn trend_row_total_tokens_missing_total_tokens() {
        let row = serde_json::json!({"days": [
            {"totalTokens": 100},
            {},
            {"totalTokens": 300},
        ]});
        assert_eq!(trend_row_total_tokens(&row), 400);
    }

    #[test]
    fn trend_by_user_rows_multiple_users() {
        let mut days1: HashMap<String, Bucket> = HashMap::new();
        days1.insert("2026-01-01".to_string(), Bucket::default());
        let mut days2: HashMap<String, Bucket> = HashMap::new();
        days2.insert("2026-01-01".to_string(), Bucket::default());
        let mut trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        trend_by_user.insert("user-1".to_string(), days1);
        trend_by_user.insert("user-2".to_string(), days2);
        let rows = trend_by_user_rows(trend_by_user);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn sort_trend_by_user_rows_missing_days() {
        let mut rows = vec![
            serde_json::json!({"userId": "user-1", "days": [{"totalTokens": 100}]}),
            serde_json::json!({"userId": "user-2"}),
            serde_json::json!({"userId": "user-3", "days": [{"totalTokens": 300}]}),
        ];
        sort_trend_by_user_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["userId"], "user-3");
        assert_eq!(rows[1]["userId"], "user-1");
        assert_eq!(rows[2]["userId"], "user-2");
    }

    #[test]
    fn append_pricing_warnings_empty_vec() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings: Vec<String> = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn append_pricing_warnings_existing_warnings() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec!["existing warning".to_string()];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], "existing warning");
    }

    #[test]
    fn pricing_source_default_input_only() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 0.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_default_only");
    }

    #[test]
    fn pricing_source_default_output_only() {
        let default_rate = PricingRate {
            input_per_1m_usd: 0.0,
            output_per_1m_usd: 2.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_default_only");
    }

    #[test]
    fn pricing_source_openrouter_takes_precedence() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let mut openrouter_rates = HashMap::new();
        openrouter_rates.insert("gpt-4".to_string(), PricingRate::default());
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "openrouter_live");
    }

    #[test]
    fn bucket_rows_with_identity_preserves_all_fields() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket {
            runs: 10,
            completed_runs: 8,
            failed_runs: 2,
            prompt_tokens: 1000,
            completion_tokens: 500,
            total_tokens: 1500,
            total_cost_usd: 0.05,
        });
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user-1");
        assert_eq!(rows[0]["runs"], 10);
        assert_eq!(rows[0]["completedRuns"], 8);
        assert_eq!(rows[0]["failedRuns"], 2);
        assert_eq!(rows[0]["promptTokens"], 1000);
        assert_eq!(rows[0]["completionTokens"], 500);
        assert_eq!(rows[0]["totalTokens"], 1500);
        assert!(rows[0].get("totalCostUsd").is_some());
        assert!(rows[0].get("avgTokensPerRun").is_some());
        assert!(rows[0].get("avgCostPerRunUsd").is_some());
        assert!(rows[0].get("successRate").is_some());
    }

    #[test]
    fn trend_rows_preserves_all_fields() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket {
            runs: 5,
            completed_runs: 4,
            failed_runs: 1,
            prompt_tokens: 500,
            completion_tokens: 250,
            total_tokens: 750,
            total_cost_usd: 0.025,
        });
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026-01-01");
        assert_eq!(rows[0]["runs"], 5);
        assert_eq!(rows[0]["completedRuns"], 4);
        assert_eq!(rows[0]["failedRuns"], 1);
        assert_eq!(rows[0]["promptTokens"], 500);
        assert_eq!(rows[0]["completionTokens"], 250);
        assert_eq!(rows[0]["totalTokens"], 750);
        assert!(rows[0].get("totalCostUsd").is_some());
        assert!(rows[0].get("successRate").is_some());
    }

    #[test]
    fn latency_stats_20_values() {
        let mut latencies: Vec<i64> = (1..=20).collect();
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 10);
        assert_eq!(p95, 19);
    }

    #[test]
    fn latency_stats_100_values() {
        let mut latencies: Vec<i64> = (1..=100).collect();
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 50);
        assert_eq!(p95, 95);
    }

    #[test]
    fn safe_avg_i64_large_values() {
        assert_eq!(safe_avg_i64(1000000, 1000), 1000);
    }

    #[test]
    fn safe_avg_f64_large_values() {
        assert!((safe_avg_f64(1000000.0, 1000) - 1000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_rate_large_values() {
        assert_eq!(safe_rate(950, 1000), 0.95);
    }

    #[test]
    fn bucket_rows_with_identity_empty_buckets() {
        let buckets: HashMap<String, Bucket> = HashMap::new();
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert!(rows.is_empty());
    }

    #[test]
    fn trend_rows_from_bucket_map_empty_buckets() {
        let buckets: HashMap<String, Bucket> = HashMap::new();
        let rows = trend_rows_from_bucket_map(buckets);
        assert!(rows.is_empty());
    }

    #[test]
    fn trend_by_user_rows_empty_map() {
        let trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        let rows = trend_by_user_rows(trend_by_user);
        assert!(rows.is_empty());
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_single() {
        let mut rows = vec![serde_json::json!({"totalTokens": 100})];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn sort_rows_by_day_asc_single() {
        let mut rows = vec![serde_json::json!({"day": "2026-01-01"})];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn sort_trend_by_user_rows_single() {
        let mut rows = vec![serde_json::json!({"userId": "user-1", "days": []})];
        sort_trend_by_user_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn trend_row_total_tokens_single_day() {
        let row = serde_json::json!({"days": [{"totalTokens": 500}]});
        assert_eq!(trend_row_total_tokens(&row), 500);
    }

    #[test]
    fn trend_row_total_tokens_zero_tokens() {
        let row = serde_json::json!({"days": [{"totalTokens": 0}]});
        assert_eq!(trend_row_total_tokens(&row), 0);
    }

    #[test]
    fn append_pricing_warnings_with_only_input() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 0.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn append_pricing_warnings_with_only_output() {
        let default_rate = PricingRate {
            input_per_1m_usd: 0.0,
            output_per_1m_usd: 2.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn pricing_source_model_overrides_take_precedence_over_default() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_model_overrides_only");
    }

    #[test]
    fn bucket_rows_with_identity_many_buckets() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        for i in 0..100 {
            buckets.insert(format!("user-{}", i), Bucket::default());
        }
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows.len(), 100);
    }

    #[test]
    fn trend_rows_from_bucket_map_many_days() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        for i in 0..365 {
            buckets.insert(format!("2026-01-{:02}", i + 1), Bucket::default());
        }
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows.len(), 365);
    }

    #[test]
    fn latency_stats_zero_values() {
        let mut latencies = vec![0, 0, 0];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 0);
        assert_eq!(p95, 0);
    }

    #[test]
    fn latency_stats_mixed_values() {
        let mut latencies = vec![0, 100, 200, 300, 400];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 200);
        assert_eq!(p95, 400);
    }

    #[test]
    fn safe_avg_i64_zero_total() {
        assert_eq!(safe_avg_i64(0, 10), 0);
    }

    #[test]
    fn safe_avg_f64_zero_total() {
        assert_eq!(safe_avg_f64(0.0, 10), 0.0);
    }

    #[test]
    fn safe_rate_zero_success() {
        assert_eq!(safe_rate(0, 10), 0.0);
    }

    #[test]
    fn safe_rate_all_failures() {
        assert_eq!(safe_rate(0, 100), 0.0);
    }

    #[test]
    fn bucket_rows_with_identity_with_cost() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket {
            total_cost_usd: 0.123456789,
            ..Default::default()
        });
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert!(rows[0].get("totalCostUsd").is_some());
    }

    #[test]
    fn trend_rows_with_cost() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket {
            total_cost_usd: 0.987654321,
            ..Default::default()
        });
        let rows = trend_rows_from_bucket_map(buckets);
        assert!(rows[0].get("totalCostUsd").is_some());
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_stable() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": 100, "id": "a"}),
            serde_json::json!({"totalTokens": 100, "id": "b"}),
            serde_json::json!({"totalTokens": 100, "id": "c"}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn sort_rows_by_day_asc_stable() {
        let mut rows = vec![
            serde_json::json!({"day": "2026-01-01", "id": "a"}),
            serde_json::json!({"day": "2026-01-01", "id": "b"}),
            serde_json::json!({"day": "2026-01-01", "id": "c"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn trend_row_total_tokens_many_days() {
        let mut days = vec![];
        for i in 0..100 {
            days.push(serde_json::json!({"totalTokens": i * 100}));
        }
        let row = serde_json::json!({"days": days});
        let expected: i64 = (0..100).map(|i| i * 100).sum();
        assert_eq!(trend_row_total_tokens(&row), expected);
    }

    #[test]
    fn append_pricing_warnings_with_both_overrides() {
        let default_rate = PricingRate::default();
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let mut openrouter_rates = HashMap::new();
        openrouter_rates.insert("gpt-4".to_string(), PricingRate::default());
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn pricing_source_all_configured_openrouter_wins() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let mut openrouter_rates = HashMap::new();
        openrouter_rates.insert("gpt-4".to_string(), PricingRate::default());
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "openrouter_live");
    }

    #[test]
    fn bucket_rows_with_identity_with_success_rate() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket {
            runs: 10,
            completed_runs: 8,
            ..Default::default()
        });
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert!(rows[0].get("successRate").is_some());
    }

    #[test]
    fn trend_rows_with_success_rate() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket {
            runs: 10,
            completed_runs: 8,
            ..Default::default()
        });
        let rows = trend_rows_from_bucket_map(buckets);
        assert!(rows[0].get("successRate").is_some());
    }

    #[test]
    fn latency_stats_negative_values() {
        let mut latencies = vec![-100, 0, 100];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 0);
        assert_eq!(p95, 100);
    }

    #[test]
    fn safe_avg_i64_negative_count() {
        assert_eq!(safe_avg_i64(100, -1), -100);
    }

    #[test]
    fn safe_avg_f64_negative_count() {
        assert!((safe_avg_f64(100.0, -1) - (-100.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_rate_negative_total() {
        assert_eq!(safe_rate(5, -10), -0.5);
    }

    #[test]
    fn bucket_rows_with_identity_with_zero_runs() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["runs"], 0);
        assert_eq!(rows[0]["successRate"], 0.0);
    }

    #[test]
    fn trend_rows_with_zero_runs() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["runs"], 0);
        assert_eq!(rows[0]["successRate"], 0.0);
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_with_zero() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": 0}),
            serde_json::json!({"totalTokens": 100}),
            serde_json::json!({"totalTokens": 50}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["totalTokens"], 100);
        assert_eq!(rows[1]["totalTokens"], 50);
        assert_eq!(rows[2]["totalTokens"], 0);
    }

    #[test]
    fn sort_rows_by_day_asc_with_empty() {
        let mut rows = vec![
            serde_json::json!({"day": ""}),
            serde_json::json!({"day": "2026-01-01"}),
            serde_json::json!({"day": "2025-12-31"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows[0]["day"], "");
        assert_eq!(rows[1]["day"], "2025-12-31");
        assert_eq!(rows[2]["day"], "2026-01-01");
    }

    #[test]
    fn trend_row_total_tokens_with_negative() {
        let row = serde_json::json!({"days": [
            {"totalTokens": -100},
            {"totalTokens": 200},
        ]});
        assert_eq!(trend_row_total_tokens(&row), 100);
    }

    #[test]
    fn append_pricing_warnings_with_zero_input() {
        let default_rate = PricingRate {
            input_per_1m_usd: 0.0,
            output_per_1m_usd: 0.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn pricing_source_with_zero_default() {
        let default_rate = PricingRate {
            input_per_1m_usd: 0.0,
            output_per_1m_usd: 0.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "unconfigured");
    }

    #[test]
    fn bucket_rows_with_identity_with_large_values() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-1".to_string(), Bucket {
            runs: 1000000,
            completed_runs: 950000,
            failed_runs: 50000,
            prompt_tokens: 100000000,
            completion_tokens: 50000000,
            total_tokens: 150000000,
            total_cost_usd: 100.0,
        });
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["runs"], 1000000);
        assert_eq!(rows[0]["totalTokens"], 150000000);
    }

    #[test]
    fn trend_rows_with_large_values() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01".to_string(), Bucket {
            runs: 1000000,
            completed_runs: 950000,
            failed_runs: 50000,
            prompt_tokens: 100000000,
            completion_tokens: 50000000,
            total_tokens: 150000000,
            total_cost_usd: 100.0,
        });
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["runs"], 1000000);
        assert_eq!(rows[0]["totalTokens"], 150000000);
    }

    #[test]
    fn latency_stats_with_duplicates() {
        let mut latencies = vec![100, 100, 200, 200, 300];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 180);
        assert_eq!(p95, 300);
    }

    #[test]
    fn safe_avg_i64_with_max_values() {
        assert_eq!(safe_avg_i64(i64::MAX, 1), i64::MAX);
    }

    #[test]
    fn safe_avg_f64_with_max_values() {
        assert!((safe_avg_f64(f64::MAX, 1) - f64::MAX).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_rate_with_max_values() {
        assert_eq!(safe_rate(i64::MAX, i64::MAX), 1.0);
    }

    #[test]
    fn bucket_rows_with_identity_with_special_chars() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user@domain.com".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user@domain.com");
    }

    #[test]
    fn trend_rows_with_special_chars() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01T00:00:00Z".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_with_duplicates() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": 100}),
            serde_json::json!({"totalTokens": 100}),
            serde_json::json!({"totalTokens": 100}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn sort_rows_by_day_asc_with_duplicates() {
        let mut rows = vec![
            serde_json::json!({"day": "2026-01-01"}),
            serde_json::json!({"day": "2026-01-01"}),
            serde_json::json!({"day": "2026-01-01"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn trend_row_total_tokens_with_empty_array() {
        let row = serde_json::json!({"days": []});
        assert_eq!(trend_row_total_tokens(&row), 0);
    }

    #[test]
    fn append_pricing_warnings_with_empty_warnings() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings: Vec<String> = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn pricing_source_with_empty_overrides() {
        let default_rate = PricingRate::default();
        let model_overrides: HashMap<String, PricingRate> = HashMap::new();
        let openrouter_rates: HashMap<String, PricingRate> = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "unconfigured");
    }

    #[test]
    fn bucket_rows_with_identity_with_unicode() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-日本語".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user-日本語");
    }

    #[test]
    fn trend_rows_with_unicode() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01-日本語".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026-01-01-日本語");
    }

    #[test]
    fn latency_stats_with_single_zero() {
        let mut latencies = vec![0];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 0);
        assert_eq!(p95, 0);
    }

    #[test]
    fn safe_avg_i64_with_zero_total_and_zero_count() {
        assert_eq!(safe_avg_i64(0, 0), 0);
    }

    #[test]
    fn safe_avg_f64_with_zero_total_and_zero_count() {
        assert_eq!(safe_avg_f64(0.0, 0), 0.0);
    }

    #[test]
    fn safe_rate_with_zero_success_and_zero_total() {
        assert_eq!(safe_rate(0, 0), 0.0);
    }

    #[test]
    fn bucket_rows_with_identity_with_emoji() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user-🎉".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user-🎉");
    }

    #[test]
    fn trend_rows_with_emoji() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026-01-01-🎉".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026-01-01-🎉");
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_with_negative() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": -100}),
            serde_json::json!({"totalTokens": 100}),
            serde_json::json!({"totalTokens": 0}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["totalTokens"], 100);
        assert_eq!(rows[1]["totalTokens"], 0);
        assert_eq!(rows[2]["totalTokens"], -100);
    }

    #[test]
    fn sort_rows_by_day_asc_with_special_formats() {
        let mut rows = vec![
            serde_json::json!({"day": "Jan 1, 2026"}),
            serde_json::json!({"day": "2026-01-01"}),
            serde_json::json!({"day": "01/01/2026"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows[0]["day"], "01/01/2026");
        assert_eq!(rows[1]["day"], "2026-01-01");
        assert_eq!(rows[2]["day"], "Jan 1, 2026");
    }

    #[test]
    fn trend_row_total_tokens_with_mixed() {
        let row = serde_json::json!({"days": [
            {"totalTokens": 100},
            {"totalTokens": -50},
            {"totalTokens": 200},
        ]});
        assert_eq!(trend_row_total_tokens(&row), 250);
    }

    #[test]
    fn append_pricing_warnings_with_multiple_calls() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn pricing_source_with_all_empty() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "unconfigured");
    }

    #[test]
    fn bucket_rows_with_identity_with_spaces() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user with spaces".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user with spaces");
    }

    #[test]
    fn trend_rows_with_spaces() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026 01 01".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026 01 01");
    }

    #[test]
    fn latency_stats_with_large_range() {
        let mut latencies = vec![1, 1000000];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 500000);
        assert_eq!(p95, 1000000);
    }

    #[test]
    fn safe_avg_i64_with_min_values() {
        assert_eq!(safe_avg_i64(i64::MIN, 1), i64::MIN);
    }

    #[test]
    fn safe_avg_f64_with_min_values() {
        assert!((safe_avg_f64(f64::MIN, 1) - f64::MIN).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_rate_with_min_values() {
        assert_eq!(safe_rate(i64::MIN, i64::MIN), 1.0);
    }

    #[test]
    fn bucket_rows_with_identity_with_newlines() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user\nwith\nnewlines".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user\nwith\nnewlines");
    }

    #[test]
    fn trend_rows_with_newlines() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026\n01\n01".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026\n01\n01");
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_with_max() {
        let mut rows = vec![
            serde_json::json!({"totalTokens": i64::MAX}),
            serde_json::json!({"totalTokens": 0}),
            serde_json::json!({"totalTokens": i64::MIN}),
        ];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows[0]["totalTokens"], i64::MAX);
        assert_eq!(rows[1]["totalTokens"], 0);
        assert_eq!(rows[2]["totalTokens"], i64::MIN);
    }

    #[test]
    fn sort_rows_by_day_asc_with_years() {
        let mut rows = vec![
            serde_json::json!({"day": "2026-01-01"}),
            serde_json::json!({"day": "2025-01-01"}),
            serde_json::json!({"day": "2024-01-01"}),
        ];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows[0]["day"], "2024-01-01");
        assert_eq!(rows[1]["day"], "2025-01-01");
        assert_eq!(rows[2]["day"], "2026-01-01");
    }

    #[test]
    fn trend_row_total_tokens_with_max_values() {
        let row = serde_json::json!({"days": [
            {"totalTokens": i64::MAX},
            {"totalTokens": i64::MAX},
        ]});
        assert_eq!(trend_row_total_tokens(&row), i64::MAX + i64::MAX);
    }

    #[test]
    fn append_pricing_warnings_with_configured_then_unconfigured() {
        let default_rate_configured = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let default_rate_unconfigured = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate_configured, &model_overrides, &openrouter_rates, &mut warnings);
        assert!(warnings.is_empty());
        append_pricing_warnings(&default_rate_unconfigured, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn pricing_source_with_only_input() {
        let default_rate = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 0.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_default_only");
    }

    #[test]
    fn pricing_source_with_only_output() {
        let default_rate = PricingRate {
            input_per_1m_usd: 0.0,
            output_per_1m_usd: 2.0,
        };
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_default_only");
    }

    #[test]
    fn bucket_rows_with_identity_with_tabs() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user\twith\ttabs".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user\twith\ttabs");
    }

    #[test]
    fn trend_rows_with_tabs() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026\t01\t01".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026\t01\t01");
    }

    #[test]
    fn latency_stats_with_all_same() {
        let mut latencies = vec![42; 100];
        let (avg, p95) = latency_stats(&mut latencies);
        assert_eq!(avg, 42);
        assert_eq!(p95, 42);
    }

    #[test]
    fn safe_avg_i64_with_one() {
        assert_eq!(safe_avg_i64(100, 1), 100);
    }

    #[test]
    fn safe_avg_f64_with_one() {
        assert!((safe_avg_f64(100.0, 1) - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn safe_rate_with_one() {
        assert_eq!(safe_rate(1, 1), 1.0);
    }

    #[test]
    fn bucket_rows_with_identity_with_quotes() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("user\"with\"quotes".to_string(), Bucket::default());
        let rows = bucket_rows_with_identity(buckets, "userId");
        assert_eq!(rows[0]["userId"], "user\"with\"quotes");
    }

    #[test]
    fn trend_rows_with_quotes() {
        let mut buckets: HashMap<String, Bucket> = HashMap::new();
        buckets.insert("2026\"01\"01".to_string(), Bucket::default());
        let rows = trend_rows_from_bucket_map(buckets);
        assert_eq!(rows[0]["day"], "2026\"01\"01");
    }

    #[test]
    fn sort_rows_by_total_tokens_desc_with_one() {
        let mut rows = vec![serde_json::json!({"totalTokens": 42})];
        sort_rows_by_total_tokens_desc(&mut rows);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn sort_rows_by_day_asc_with_one() {
        let mut rows = vec![serde_json::json!({"day": "2026-01-01"})];
        sort_rows_by_day_asc(&mut rows);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn trend_row_total_tokens_with_one() {
        let row = serde_json::json!({"days": [{"totalTokens": 42}]});
        assert_eq!(trend_row_total_tokens(&row), 42);
    }

    #[test]
    fn append_pricing_warnings_with_one_warning() {
        let default_rate = PricingRate::default();
        let model_overrides = HashMap::new();
        let openrouter_rates = HashMap::new();
        let mut warnings = vec![];
        append_pricing_warnings(&default_rate, &model_overrides, &openrouter_rates, &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn pricing_source_with_one_override() {
        let default_rate = PricingRate::default();
        let mut model_overrides = HashMap::new();
        model_overrides.insert("gpt-4".to_string(), PricingRate::default());
        let openrouter_rates = HashMap::new();
        let source = pricing_source_label(&default_rate, &model_overrides, &openrouter_rates);
        assert_eq!(source, "env_model_overrides_only");
    }
}
