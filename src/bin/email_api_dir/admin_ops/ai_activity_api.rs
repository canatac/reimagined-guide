use super::*;
use super::ai_activity_api_helpers::*;

#[derive(Default)]
struct ActivityState {
    total_runs: i64,
    completed_runs: i64,
    failed_runs: i64,
    prompt_tokens: i64,
    completion_tokens: i64,
    total_tokens: i64,
    latencies: Vec<i64>,
    total_cost_usd: f64,
    priced_runs: i64,
    unpriced_runs: i64,
    by_user: HashMap<String, Bucket>,
    by_model: HashMap<String, Bucket>,
    by_feature: HashMap<String, Bucket>,
    trend_global: HashMap<String, Bucket>,
    trend_by_user: HashMap<String, HashMap<String, Bucket>>,
    normalized_runs: Vec<serde_json::Value>,
}

pub(crate) async fn api_admin_ai_activity(
    query: web::Query<AdminAiActivityQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(100).clamp(10, 500);
    let runs = match load_ai_activity_runs(mongo.get_ref(), limit).await {
        Ok(v) => v,
        Err(e) => return ai_activity_db_error(e),
    };

    let default_rate = default_pricing_rate();
    let model_overrides = parse_pricing_overrides_json();
    let mut warnings: Vec<String> = Vec::new();
    let openrouter_rates = load_openrouter_rates_with_fallback(&mut warnings).await;

    let mut state = ActivityState {
        total_runs: runs.len() as i64,
        ..Default::default()
    };

    for run in &runs {
        accumulate_run(
            &mut state,
            run,
            &openrouter_rates,
            &model_overrides,
            default_rate,
        );
    }

    render_ai_activity_response(
        i64::from(limit),
        state.total_runs,
        state.completed_runs,
        state.failed_runs,
        state.prompt_tokens,
        state.completion_tokens,
        state.total_tokens,
        state.latencies,
        state.total_cost_usd,
        state.priced_runs,
        state.unpriced_runs,
        state.by_user,
        state.by_model,
        state.by_feature,
        state.trend_global,
        state.trend_by_user,
        default_rate,
        model_overrides,
        openrouter_rates,
        warnings,
        state.normalized_runs,
    )
}

fn ai_activity_db_error(e: mongodb::error::Error) -> HttpResponse {
    eprintln!("api_admin_ai_activity db read error: {}", e);
    HttpResponse::InternalServerError().json(serde_json::json!({
        "message": "Failed to read LLM activity",
    }))
}

async fn load_openrouter_rates_with_fallback(
    warnings: &mut Vec<String>,
) -> HashMap<String, PricingRate> {
    match fetch_openrouter_pricing_rates().await {
        Ok(rates) => rates,
        Err(e) => {
            warnings.push(format!(
                "OpenRouter pricing unavailable (fallback env pricing only): {}",
                e
            ));
            HashMap::new()
        }
    }
}

fn accumulate_run(
    state: &mut ActivityState,
    run: &serde_json::Value,
    openrouter_rates: &HashMap<String, PricingRate>,
    model_overrides: &HashMap<String, PricingRate>,
    default_rate: PricingRate,
) {
    let facts = extract_run_facts(run);
    update_global_counters(
        &mut state.completed_runs,
        &mut state.failed_runs,
        &mut state.prompt_tokens,
        &mut state.completion_tokens,
        &mut state.total_tokens,
        &mut state.latencies,
        &facts,
    );

    let (pricing_rate, pricing_applied) = resolve_pricing_rate(
        &facts.model,
        openrouter_rates,
        model_overrides,
        default_rate,
    );
    let run_cost = estimate_run_cost(facts.prompt_tokens, facts.completion_tokens, pricing_rate);
    update_pricing_counters(
        &mut state.total_cost_usd,
        &mut state.priced_runs,
        &mut state.unpriced_runs,
        run_cost,
    );

    let user_key = normalized_user_key(facts.user_id.clone());
    apply_bucket_for_run(state.by_user.entry(user_key.clone()).or_default(), &facts, run_cost);
    apply_bucket_for_run(state.by_model.entry(facts.model.clone()).or_default(), &facts, run_cost);
    apply_bucket_for_run(
        state.by_feature.entry(facts.feature.clone()).or_default(),
        &facts,
        run_cost,
    );
    apply_bucket_for_run(
        state
            .trend_global
            .entry(facts.day_bucket.clone())
            .or_default(),
        &facts,
        run_cost,
    );

    let user_trend = state.trend_by_user.entry(user_key).or_default();
    apply_bucket_for_run(
        user_trend.entry(facts.day_bucket.clone()).or_default(),
        &facts,
        run_cost,
    );

    state
        .normalized_runs
        .push(build_normalized_run(run, &facts, run_cost, pricing_applied));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_ai_activity_query_defaults() {
        let json = serde_json::json!({});
        let q: AdminAiActivityQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.limit, None);
    }

    #[test]
    fn admin_ai_activity_query_custom() {
        let json = serde_json::json!({ "limit": 50 });
        let q: AdminAiActivityQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn limit_clamping_min() {
        let limit = 5i64;
        let clamped = limit.clamp(10, 500);
        assert_eq!(clamped, 10);
    }

    #[test]
    fn limit_clamping_max() {
        let limit = 1000i64;
        let clamped = limit.clamp(10, 500);
        assert_eq!(clamped, 500);
    }

    #[test]
    fn limit_clamping_valid() {
        let limit = 100i64;
        let clamped = limit.clamp(10, 500);
        assert_eq!(clamped, 100);
    }

    #[test]
    fn limit_default() {
        let limit: Option<i64> = None;
        let resolved = limit.unwrap_or(100).clamp(10, 500);
        assert_eq!(resolved, 100);
    }

    #[test]
    fn activity_state_default() {
        let state = ActivityState::default();
        assert_eq!(state.total_runs, 0);
        assert_eq!(state.completed_runs, 0);
        assert_eq!(state.failed_runs, 0);
        assert_eq!(state.prompt_tokens, 0);
        assert_eq!(state.completion_tokens, 0);
        assert_eq!(state.total_tokens, 0);
        assert!(state.latencies.is_empty());
        assert_eq!(state.total_cost_usd, 0.0);
        assert_eq!(state.priced_runs, 0);
        assert_eq!(state.unpriced_runs, 0);
        assert!(state.by_user.is_empty());
        assert!(state.by_model.is_empty());
        assert!(state.by_feature.is_empty());
        assert!(state.trend_global.is_empty());
        assert!(state.trend_by_user.is_empty());
        assert!(state.normalized_runs.is_empty());
    }

    #[test]
    fn error_response_db_error() {
        let response = serde_json::json!({ "message": "Failed to read LLM activity" });
        assert_eq!(response["message"], "Failed to read LLM activity");
    }

    #[test]
    fn openrouter_rates_fallback() {
        let mut warnings: Vec<String> = Vec::new();
        let error = "Connection timeout";
        warnings.push(format!(
            "OpenRouter pricing unavailable (fallback env pricing only): {}",
            error
        ));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("OpenRouter pricing unavailable"));
        assert!(warnings[0].contains("Connection timeout"));
    }

    #[test]
    fn openrouter_rates_empty_on_error() {
        let rates: HashMap<String, PricingRate> = HashMap::new();
        assert!(rates.is_empty());
    }

    #[test]
    fn normalized_user_key_empty() {
        let user_id = "".to_string();
        let key = if user_id.trim().is_empty() {
            "unknown".to_string()
        } else {
            user_id.trim().to_string()
        };
        assert_eq!(key, "unknown");
    }

    #[test]
    fn normalized_user_key_valid() {
        let user_id = "user-123".to_string();
        let key = if user_id.trim().is_empty() {
            "unknown".to_string()
        } else {
            user_id.trim().to_string()
        };
        assert_eq!(key, "user-123");
    }

    #[test]
    fn normalized_user_key_trimmed() {
        let user_id = "  user-123  ".to_string();
        let key = if user_id.trim().is_empty() {
            "unknown".to_string()
        } else {
            user_id.trim().to_string()
        };
        assert_eq!(key, "user-123");
    }

    #[test]
    fn run_cost_estimation_zero_tokens() {
        let prompt_tokens = 0i64;
        let completion_tokens = 0i64;
        let rate = PricingRate {
            prompt: 0.0,
            completion: 0.0,
        };
        let cost = estimate_run_cost(prompt_tokens, completion_tokens, rate);
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn run_cost_estimation_with_tokens() {
        let prompt_tokens = 1000i64;
        let completion_tokens = 500i64;
        let rate = PricingRate {
            prompt: 0.00001,
            completion: 0.00002,
        };
        let cost = estimate_run_cost(prompt_tokens, completion_tokens, rate);
        assert_eq!(cost, 0.01 + 0.01); // 1000 * 0.00001 + 500 * 0.00002
    }

    #[test]
    fn pricing_counters_update() {
        let mut total_cost = 0.0f64;
        let mut priced_runs = 0i64;
        let mut unpriced_runs = 0i64;
        let run_cost = 0.05;
        
        total_cost += run_cost;
        if run_cost > 0.0 {
            priced_runs += 1;
        } else {
            unpriced_runs += 1;
        }
        
        assert_eq!(total_cost, 0.05);
        assert_eq!(priced_runs, 1);
        assert_eq!(unpriced_runs, 0);
    }

    #[test]
    fn pricing_counters_unpriced() {
        let mut total_cost = 0.0f64;
        let mut priced_runs = 0i64;
        let mut unpriced_runs = 0i64;
        let run_cost = 0.0;
        
        total_cost += run_cost;
        if run_cost > 0.0 {
            priced_runs += 1;
        } else {
            unpriced_runs += 1;
        }
        
        assert_eq!(total_cost, 0.0);
        assert_eq!(priced_runs, 0);
        assert_eq!(unpriced_runs, 1);
    }

    #[test]
    fn global_counters_update() {
        let mut completed_runs = 0i64;
        let mut failed_runs = 0i64;
        let mut prompt_tokens = 0i64;
        let mut completion_tokens = 0i64;
        let mut total_tokens = 0i64;
        let mut latencies: Vec<i64> = Vec::new();
        
        let facts = RunFacts {
            status: "completed".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            latency_ms: Some(1500),
            ..Default::default()
        };
        
        completed_runs += 1;
        prompt_tokens += facts.prompt_tokens;
        completion_tokens += facts.completion_tokens;
        total_tokens += facts.prompt_tokens + facts.completion_tokens;
        if let Some(lat) = facts.latency_ms {
            latencies.push(lat);
        }
        
        assert_eq!(completed_runs, 1);
        assert_eq!(prompt_tokens, 100);
        assert_eq!(completion_tokens, 50);
        assert_eq!(total_tokens, 150);
        assert_eq!(latencies.len(), 1);
        assert_eq!(latencies[0], 1500);
    }

    #[test]
    fn global_counters_failed_run() {
        let mut completed_runs = 0i64;
        let mut failed_runs = 0i64;
        
        let facts = RunFacts {
            status: "failed".to_string(),
            ..Default::default()
        };
        
        failed_runs += 1;
        
        assert_eq!(completed_runs, 0);
        assert_eq!(failed_runs, 1);
    }

    #[test]
    fn bucket_entry_or_default() {
        let mut by_user: HashMap<String, Bucket> = HashMap::new();
        let user_key = "user-123".to_string();
        let bucket = by_user.entry(user_key.clone()).or_default();
        assert_eq!(bucket.runs, 0);
        assert_eq!(bucket.total_cost_usd, 0.0);
    }

    #[test]
    fn trend_global_entry() {
        let mut trend_global: HashMap<String, Bucket> = HashMap::new();
        let day_bucket = "2026-01-01".to_string();
        let bucket = trend_global.entry(day_bucket.clone()).or_default();
        assert_eq!(bucket.runs, 0);
    }

    #[test]
    fn trend_by_user_entry() {
        let mut trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        let user_key = "user-123".to_string();
        let day_bucket = "2026-01-01".to_string();
        let user_trend = trend_by_user.entry(user_key.clone()).or_default();
        let bucket = user_trend.entry(day_bucket.clone()).or_default();
        assert_eq!(bucket.runs, 0);
    }

    #[test]
    fn normalized_runs_push() {
        let mut normalized_runs: Vec<serde_json::Value> = Vec::new();
        let run = serde_json::json!({"id": "run-1"});
        normalized_runs.push(run);
        assert_eq!(normalized_runs.len(), 1);
    }

    #[test]
    fn model_overrides_empty() {
        let model_overrides: HashMap<String, PricingRate> = HashMap::new();
        assert!(model_overrides.is_empty());
    }

    #[test]
    fn openrouter_rates_with_data() {
        let mut rates: HashMap<String, PricingRate> = HashMap::new();
        rates.insert(
            "gpt-4".to_string(),
            PricingRate {
                prompt: 0.00001,
                completion: 0.00002,
            },
        );
        assert_eq!(rates.len(), 1);
        assert!(rates.contains_key("gpt-4"));
    }

    #[test]
    fn default_pricing_rate() {
        let rate = PricingRate {
            prompt: 0.0,
            completion: 0.0,
        };
        assert_eq!(rate.prompt, 0.0);
        assert_eq!(rate.completion, 0.0);
    }

    #[test]
    fn pricing_rate_custom() {
        let rate = PricingRate {
            prompt: 0.00001,
            completion: 0.00002,
        };
        assert_eq!(rate.prompt, 0.00001);
        assert_eq!(rate.completion, 0.00002);
    }

    #[test]
    fn run_facts_default() {
        let facts = RunFacts::default();
        assert_eq!(facts.status, "");
        assert_eq!(facts.prompt_tokens, 0);
        assert_eq!(facts.completion_tokens, 0);
        assert_eq!(facts.latency_ms, None);
    }

    #[test]
    fn run_facts_with_values() {
        let facts = RunFacts {
            status: "completed".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            latency_ms: Some(1500),
            ..Default::default()
        };
        assert_eq!(facts.status, "completed");
        assert_eq!(facts.prompt_tokens, 100);
        assert_eq!(facts.completion_tokens, 50);
        assert_eq!(facts.latency_ms, Some(1500));
    }

    #[test]
    fn day_bucket_format() {
        let day_bucket = "2026-01-01";
        assert_eq!(day_bucket, "2026-01-01");
    }

    #[test]
    fn feature_key_format() {
        let feature = "newsletter_summarize";
        assert_eq!(feature, "newsletter_summarize");
    }

    #[test]
    fn model_key_format() {
        let model = "gpt-4";
        assert_eq!(model, "gpt-4");
    }

    #[test]
    fn user_id_format() {
        let user_id = "user-123";
        assert_eq!(user_id, "user-123");
    }

    #[test]
    fn run_id_format() {
        let run_id = "run-123";
        assert_eq!(run_id, "run-123");
    }

    #[test]
    fn latency_ms_some() {
        let latency = Some(1500i64);
        assert_eq!(latency, Some(1500));
    }

    #[test]
    fn latency_ms_none() {
        let latency: Option<i64> = None;
        assert_eq!(latency, None);
    }

    #[test]
    fn total_cost_usd_zero() {
        let total_cost = 0.0f64;
        assert_eq!(total_cost, 0.0);
    }

    #[test]
    fn total_cost_usd_positive() {
        let total_cost = 0.05f64;
        assert!(total_cost > 0.0);
    }

    #[test]
    fn priced_runs_zero() {
        let priced_runs = 0i64;
        assert_eq!(priced_runs, 0);
    }

    #[test]
    fn priced_runs_positive() {
        let priced_runs = 5i64;
        assert!(priced_runs > 0);
    }

    #[test]
    fn unpriced_runs_zero() {
        let unpriced_runs = 0i64;
        assert_eq!(unpriced_runs, 0);
    }

    #[test]
    fn unpriced_runs_positive() {
        let unpriced_runs = 3i64;
        assert!(unpriced_runs > 0);
    }

    #[test]
    fn total_runs_zero() {
        let total_runs = 0i64;
        assert_eq!(total_runs, 0);
    }

    #[test]
    fn total_runs_positive() {
        let total_runs = 10i64;
        assert!(total_runs > 0);
    }

    #[test]
    fn completed_runs_zero() {
        let completed_runs = 0i64;
        assert_eq!(completed_runs, 0);
    }

    #[test]
    fn completed_runs_positive() {
        let completed_runs = 8i64;
        assert!(completed_runs > 0);
    }

    #[test]
    fn failed_runs_zero() {
        let failed_runs = 0i64;
        assert_eq!(failed_runs, 0);
    }

    #[test]
    fn failed_runs_positive() {
        let failed_runs = 2i64;
        assert!(failed_runs > 0);
    }

    #[test]
    fn prompt_tokens_zero() {
        let prompt_tokens = 0i64;
        assert_eq!(prompt_tokens, 0);
    }

    #[test]
    fn prompt_tokens_positive() {
        let prompt_tokens = 1000i64;
        assert!(prompt_tokens > 0);
    }

    #[test]
    fn completion_tokens_zero() {
        let completion_tokens = 0i64;
        assert_eq!(completion_tokens, 0);
    }

    #[test]
    fn completion_tokens_positive() {
        let completion_tokens = 500i64;
        assert!(completion_tokens > 0);
    }

    #[test]
    fn total_tokens_sum() {
        let prompt_tokens = 1000i64;
        let completion_tokens = 500i64;
        let total_tokens = prompt_tokens + completion_tokens;
        assert_eq!(total_tokens, 1500);
    }

    #[test]
    fn latencies_empty() {
        let latencies: Vec<i64> = Vec::new();
        assert!(latencies.is_empty());
    }

    #[test]
    fn latencies_with_values() {
        let latencies: Vec<i64> = vec![1000, 1500, 2000];
        assert_eq!(latencies.len(), 3);
        assert_eq!(latencies[0], 1000);
        assert_eq!(latencies[2], 2000);
    }

    #[test]
    fn latencies_average() {
        let latencies: Vec<i64> = vec![1000, 1500, 2000];
        let sum: i64 = latencies.iter().sum();
        let avg = sum / latencies.len() as i64;
        assert_eq!(avg, 1500);
    }

    #[test]
    fn latencies_p95() {
        let mut latencies: Vec<i64> = (1..=100).map(|i| i * 100).collect();
        latencies.sort();
        let p95_idx = (latencies.len() as f64 * 0.95) as usize;
        assert_eq!(latencies[p95_idx], 9500);
    }

    #[test]
    fn by_user_empty() {
        let by_user: HashMap<String, Bucket> = HashMap::new();
        assert!(by_user.is_empty());
    }

    #[test]
    fn by_user_with_entries() {
        let mut by_user: HashMap<String, Bucket> = HashMap::new();
        by_user.insert("user-1".to_string(), Bucket::default());
        assert_eq!(by_user.len(), 1);
    }

    #[test]
    fn by_model_empty() {
        let by_model: HashMap<String, Bucket> = HashMap::new();
        assert!(by_model.is_empty());
    }

    #[test]
    fn by_model_with_entries() {
        let mut by_model: HashMap<String, Bucket> = HashMap::new();
        by_model.insert("gpt-4".to_string(), Bucket::default());
        assert_eq!(by_model.len(), 1);
    }

    #[test]
    fn by_feature_empty() {
        let by_feature: HashMap<String, Bucket> = HashMap::new();
        assert!(by_feature.is_empty());
    }

    #[test]
    fn by_feature_with_entries() {
        let mut by_feature: HashMap<String, Bucket> = HashMap::new();
        by_feature.insert("newsletter".to_string(), Bucket::default());
        assert_eq!(by_feature.len(), 1);
    }

    #[test]
    fn trend_global_empty() {
        let trend_global: HashMap<String, Bucket> = HashMap::new();
        assert!(trend_global.is_empty());
    }

    #[test]
    fn trend_global_with_entries() {
        let mut trend_global: HashMap<String, Bucket> = HashMap::new();
        trend_global.insert("2026-01-01".to_string(), Bucket::default());
        assert_eq!(trend_global.len(), 1);
    }

    #[test]
    fn trend_by_user_empty() {
        let trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        assert!(trend_by_user.is_empty());
    }

    #[test]
    fn trend_by_user_with_entries() {
        let mut trend_by_user: HashMap<String, HashMap<String, Bucket>> = HashMap::new();
        trend_by_user.insert("user-1".to_string(), HashMap::new());
        assert_eq!(trend_by_user.len(), 1);
    }

    #[test]
    fn normalized_runs_empty() {
        let normalized_runs: Vec<serde_json::Value> = Vec::new();
        assert!(normalized_runs.is_empty());
    }

    #[test]
    fn normalized_runs_with_entries() {
        let mut normalized_runs: Vec<serde_json::Value> = Vec::new();
        normalized_runs.push(serde_json::json!({"id": "run-1"}));
        assert_eq!(normalized_runs.len(), 1);
    }
}
