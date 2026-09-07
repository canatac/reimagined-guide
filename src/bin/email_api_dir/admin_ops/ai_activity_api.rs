use super::*;

pub(crate) async fn api_admin_ai_activity(
    query: web::Query<AdminAiActivityQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(100).clamp(10, 500);
    let runs = match load_ai_activity_runs(mongo.get_ref(), limit).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_admin_ai_activity db read error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to read LLM activity",
            }));
        }
    };
    let default_rate = default_pricing_rate();
    let model_overrides = parse_pricing_overrides_json();
    let mut warnings: Vec<String> = Vec::new();
    let openrouter_rates = match fetch_openrouter_pricing_rates().await {
        Ok(rates) => rates,
        Err(e) => {
            warnings.push(format!(
                "OpenRouter pricing unavailable (fallback env pricing only): {}",
                e
            ));
            HashMap::new()
        }
    };

    let mut normalized_runs: Vec<serde_json::Value> = Vec::new();
    let mut by_user: HashMap<String, Bucket> = HashMap::new();
    let mut by_model: HashMap<String, Bucket> = HashMap::new();
    let mut by_feature: HashMap<String, Bucket> = HashMap::new();
    let mut trend_global: HashMap<String, Bucket> = HashMap::new();
    let mut trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();

    let total_runs = runs.len() as i64;
    let mut completed_runs = 0_i64;
    let mut failed_runs = 0_i64;
    let mut prompt_tokens = 0_i64;
    let mut completion_tokens = 0_i64;
    let mut total_tokens = 0_i64;
    let mut latencies: Vec<i64> = Vec::new();
    let mut total_cost_usd = 0.0_f64;
    let mut priced_runs = 0_i64;
    let mut unpriced_runs = 0_i64;

    for run in &runs {
        let status = run
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        let model = run
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .trim()
            .to_string();
        let feature = run
            .get("feature")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .trim()
            .to_string();
        let user_id = run
            .get("user_id")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .or_else(|| {
                run.get("userId")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            });
        let session_id = run
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string())
            .or_else(|| {
                run.get("sessionId")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            });
        let day_bucket = run
            .get("started_at")
            .and_then(|v| v.as_str())
            .or_else(|| run.get("startedAt").and_then(|v| v.as_str()))
            .and_then(|ts| {
                let t = ts.trim();
                if t.len() >= 10 {
                    Some(t[..10].to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string());

        if status == "completed" || status == "success" {
            completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            failed_runs += 1;
        }

        let usage = run.get("usage").unwrap_or(&serde_json::Value::Null);
        let p = as_i64(usage.get("prompt_tokens").or_else(|| usage.get("promptTokens")));
        let c = as_i64(
            usage
                .get("completion_tokens")
                .or_else(|| usage.get("completionTokens")),
        );
        let t = {
            let explicit = as_i64(usage.get("total_tokens").or_else(|| usage.get("totalTokens")));
            if explicit > 0 {
                explicit
            } else {
                p + c
            }
        };

        prompt_tokens += p;
        completion_tokens += c;
        total_tokens += t;

        let latency = as_i64(run.get("latency_ms").or_else(|| run.get("latencyMs")));
        if latency > 0 {
            latencies.push(latency);
        }

        let (pricing_rate, pricing_applied) =
            resolve_pricing_rate(&model, &openrouter_rates, &model_overrides, default_rate);
        let input_cost = ((p as f64) / 1_000_000.0) * pricing_rate.input_per_1m_usd;
        let output_cost = ((c as f64) / 1_000_000.0) * pricing_rate.output_per_1m_usd;
        let run_cost = round6(input_cost + output_cost);
        if run_cost > 0.0 {
            priced_runs += 1;
        } else {
            unpriced_runs += 1;
        }
        total_cost_usd += run_cost;

        let user_key = user_id
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        let ub = by_user.entry(user_key.clone()).or_default();
        ub.runs += 1;
        ub.prompt_tokens += p;
        ub.completion_tokens += c;
        ub.total_tokens += t;
        ub.total_cost_usd += run_cost;
        if status == "completed" || status == "success" {
            ub.completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            ub.failed_runs += 1;
        }

        let mb = by_model.entry(model.clone()).or_default();
        mb.runs += 1;
        mb.prompt_tokens += p;
        mb.completion_tokens += c;
        mb.total_tokens += t;
        mb.total_cost_usd += run_cost;
        if status == "completed" || status == "success" {
            mb.completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            mb.failed_runs += 1;
        }

        let fb = by_feature.entry(feature.clone()).or_default();
        fb.runs += 1;
        fb.prompt_tokens += p;
        fb.completion_tokens += c;
        fb.total_tokens += t;
        fb.total_cost_usd += run_cost;
        if status == "completed" || status == "success" {
            fb.completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            fb.failed_runs += 1;
        }

        let gb = trend_global.entry(day_bucket.clone()).or_default();
        gb.runs += 1;
        gb.prompt_tokens += p;
        gb.completion_tokens += c;
        gb.total_tokens += t;
        gb.total_cost_usd += run_cost;
        if status == "completed" || status == "success" {
            gb.completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            gb.failed_runs += 1;
        }

        let user_trend = trend_by_user.entry(user_key.clone()).or_default();
        let ub_day = user_trend.entry(day_bucket.clone()).or_default();
        ub_day.runs += 1;
        ub_day.prompt_tokens += p;
        ub_day.completion_tokens += c;
        ub_day.total_tokens += t;
        ub_day.total_cost_usd += run_cost;
        if status == "completed" || status == "success" {
            ub_day.completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            ub_day.failed_runs += 1;
        }

        normalized_runs.push(serde_json::json!({
            "id": run.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
            "status": status,
            "model": model,
            "feature": feature,
            "startedAt": run
                .get("started_at")
                .and_then(|v| v.as_str())
                .or_else(|| run.get("startedAt").and_then(|v| v.as_str())),
            "completedAt": run
                .get("completed_at")
                .and_then(|v| v.as_str())
                .or_else(|| run.get("completedAt").and_then(|v| v.as_str())),
            "latencyMs": if latency > 0 { Some(latency) } else { None::<i64> },
            "promptTokens": p,
            "completionTokens": c,
            "totalTokens": t,
            "estimatedCostUsd": run_cost,
            "pricingApplied": pricing_applied,
            "sessionId": session_id,
            "userId": user_id,
            "error": run
                .get("last_error")
                .and_then(|v| v.as_str())
                .or_else(|| run.get("error").and_then(|v| v.as_str())),
        }));
    }

    render_ai_activity_response(
        i64::from(limit),
        total_runs,
        completed_runs,
        failed_runs,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        latencies,
        total_cost_usd,
        priced_runs,
        unpriced_runs,
        by_user,
        by_model,
        by_feature,
        trend_global,
        trend_by_user,
        default_rate,
        model_overrides,
        openrouter_rates,
        warnings,
        normalized_runs,
    )
}
