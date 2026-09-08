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
