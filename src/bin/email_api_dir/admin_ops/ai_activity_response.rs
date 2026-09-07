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
    latencies.sort_unstable();
    let avg_latency = if latencies.is_empty() {
        0
    } else {
        latencies.iter().sum::<i64>() / i64::try_from(latencies.len()).unwrap_or(1)
    };
    let p95_latency = if latencies.is_empty() {
        0
    } else {
        let idx = ((latencies.len() as f64) * 0.95).ceil() as usize;
        let idx = idx.saturating_sub(1).min(latencies.len() - 1);
        latencies[idx]
    };

    let mut by_user_rows: Vec<serde_json::Value> = by_user
        .into_iter()
        .map(|(user_id, b)| {
            serde_json::json!({
                "userId": user_id,
                "runs": b.runs,
                "completedRuns": b.completed_runs,
                "failedRuns": b.failed_runs,
                "promptTokens": b.prompt_tokens,
                "completionTokens": b.completion_tokens,
                "totalTokens": b.total_tokens,
                "totalCostUsd": round6(b.total_cost_usd),
                "avgTokensPerRun": if b.runs > 0 { b.total_tokens / b.runs } else { 0 },
                "avgCostPerRunUsd": if b.runs > 0 { round6(b.total_cost_usd / (b.runs as f64)) } else { 0.0 },
                "successRate": if b.runs > 0 { (b.completed_runs as f64) / (b.runs as f64) } else { 0.0 },
            })
        })
        .collect();
    by_user_rows.sort_by(|a, b| {
        let at = a.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        let bt = b.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        bt.cmp(&at)
    });

    let mut by_model_rows: Vec<serde_json::Value> = by_model
        .into_iter()
        .map(|(model, b)| {
            serde_json::json!({
                "model": model,
                "runs": b.runs,
                "promptTokens": b.prompt_tokens,
                "completionTokens": b.completion_tokens,
                "totalTokens": b.total_tokens,
                "totalCostUsd": round6(b.total_cost_usd),
                "avgTokensPerRun": if b.runs > 0 { b.total_tokens / b.runs } else { 0 },
            })
        })
        .collect();
    by_model_rows.sort_by(|a, b| {
        let at = a.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        let bt = b.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        bt.cmp(&at)
    });

    let mut by_feature_rows: Vec<serde_json::Value> = by_feature
        .into_iter()
        .map(|(feature, b)| {
            serde_json::json!({
                "feature": feature,
                "runs": b.runs,
                "promptTokens": b.prompt_tokens,
                "completionTokens": b.completion_tokens,
                "totalTokens": b.total_tokens,
                "totalCostUsd": round6(b.total_cost_usd),
                "avgTokensPerRun": if b.runs > 0 { b.total_tokens / b.runs } else { 0 },
            })
        })
        .collect();
    by_feature_rows.sort_by(|a, b| {
        let at = a.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        let bt = b.get("totalTokens").and_then(|v| v.as_i64()).unwrap_or(0);
        bt.cmp(&at)
    });

    let mut trend_global_rows: Vec<serde_json::Value> = trend_global
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
                "successRate": if b.runs > 0 { (b.completed_runs as f64) / (b.runs as f64) } else { 0.0 },
            })
        })
        .collect();
    trend_global_rows.sort_by(|a, b| {
        let ad = a.get("day").and_then(|v| v.as_str()).unwrap_or("");
        let bd = b.get("day").and_then(|v| v.as_str()).unwrap_or("");
        ad.cmp(bd)
    });

    let mut trend_by_user_rows: Vec<serde_json::Value> = trend_by_user
        .into_iter()
        .map(|(user_id, days_map)| {
            let mut rows: Vec<serde_json::Value> = days_map
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
                        "successRate": if b.runs > 0 { (b.completed_runs as f64) / (b.runs as f64) } else { 0.0 },
                    })
                })
                .collect();
            rows.sort_by(|a, b| {
                let ad = a.get("day").and_then(|v| v.as_str()).unwrap_or("");
                let bd = b.get("day").and_then(|v| v.as_str()).unwrap_or("");
                ad.cmp(bd)
            });
            serde_json::json!({
                "userId": user_id,
                "days": rows,
            })
        })
        .collect();
    trend_by_user_rows.sort_by(|a, b| {
        let at = a
            .get("days")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| v.get("totalTokens").and_then(|x| x.as_i64()).unwrap_or(0))
                    .sum::<i64>()
            })
            .unwrap_or(0);
        let bt = b
            .get("days")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|v| v.get("totalTokens").and_then(|x| x.as_i64()).unwrap_or(0))
                    .sum::<i64>()
            })
            .unwrap_or(0);
        bt.cmp(&at)
    });

    if default_rate.input_per_1m_usd == 0.0
        && default_rate.output_per_1m_usd == 0.0
        && model_overrides.is_empty()
        && openrouter_rates.is_empty()
    {
        warnings.push("LLM pricing not configured: set LLM_COST_DEFAULT_INPUT_PER_1M_USD / LLM_COST_DEFAULT_OUTPUT_PER_1M_USD or LLM_COST_MODEL_OVERRIDES_JSON".to_string());
    }

    let pricing_source = if !openrouter_rates.is_empty() {
        "openrouter_live"
    } else if !model_overrides.is_empty() {
        "env_model_overrides_only"
    } else if default_rate.input_per_1m_usd > 0.0 || default_rate.output_per_1m_usd > 0.0 {
        "env_default_only"
    } else {
        "unconfigured"
    };

    HttpResponse::Ok().json(serde_json::json!({
        "generatedAt": Utc::now().to_rfc3339(),
        "limit": limit,
        "metrics": {
            "totalRuns": total_runs,
            "completedRuns": completed_runs,
            "failedRuns": failed_runs,
            "successRate": if total_runs > 0 { (completed_runs as f64) / (total_runs as f64) } else { 0.0 },
            "avgLatencyMs": avg_latency,
            "p95LatencyMs": p95_latency,
            "promptTokens": prompt_tokens,
            "completionTokens": completion_tokens,
            "totalTokens": total_tokens,
            "avgTokensPerRun": if total_runs > 0 { total_tokens / total_runs } else { 0 },
            "currency": "USD",
            "totalCostUsd": round6(total_cost_usd),
            "avgCostPerRunUsd": if total_runs > 0 { round6(total_cost_usd / (total_runs as f64)) } else { 0.0 },
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

