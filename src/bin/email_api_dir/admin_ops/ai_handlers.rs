#![allow(unused_imports, dead_code)]
use super::*;  // inherit all imports from mod.rs

pub(crate) fn default_ai_feature_models() -> HashMap<String, String> {
    let mut m = HashMap::new();
    for key in [
        "compose",
        "translate",
        "triage",
        "security",
        "rewrite",
        "subject",
        "complete",
    ] {
        m.insert(key.to_string(), DEFAULT_AI_MODEL.to_string());
    }
    m
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AiSettingsDoc {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "defaultModel", alias = "default_model")]
    pub default_model: String,
    pub features: HashMap<String, String>,
    #[serde(rename = "updatedAt", alias = "updated_at", default)]
    pub updated_at: Option<String>,
}

impl AiSettingsDoc {
    fn defaults() -> Self {
        Self {
            id: AI_SETTINGS_ID.to_string(),
            default_model: DEFAULT_AI_MODEL.to_string(),
            features: default_ai_feature_models(),
            updated_at: Some(Utc::now().to_rfc3339()),
        }
    }

    fn merge_with_defaults(mut self) -> Self {
        let defaults = default_ai_feature_models();
        for (k, v) in defaults {
            self.features.entry(k).or_insert(v);
        }
        if self.default_model.trim().is_empty() {
            self.default_model = DEFAULT_AI_MODEL.to_string();
        }
        self
    }

    fn to_public_json(&self) -> serde_json::Value {
        serde_json::json!({
            "defaultModel": self.default_model,
            "features": self.features,
            "updatedAt": self.updated_at,
        })
    }
}

#[derive(Deserialize)]
pub(crate) struct AiSettingsUpdate {
    #[serde(rename = "defaultModel", alias = "default_model", default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub features: Option<HashMap<String, String>>,
}

pub(crate) fn mongo_db_name() -> String {
    env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

pub(crate) async fn load_ai_settings(client: &mongodb::Client) -> AiSettingsDoc {
    let coll = client
        .database(&mongo_db_name())
        .collection::<AiSettingsDoc>("ai_settings");
    match coll.find_one(doc! { "_id": AI_SETTINGS_ID }).await {
        Ok(Some(doc)) => doc.merge_with_defaults(),
        _ => AiSettingsDoc::defaults(),
    }
}

pub(crate) async fn api_get_ai_settings(mongo: web::Data<Arc<mongodb::Client>>) -> impl Responder {
    let settings = load_ai_settings(mongo.get_ref()).await;
    HttpResponse::Ok().json(settings.to_public_json())
}

pub(crate) async fn api_put_ai_settings(
    body: web::Json<AiSettingsUpdate>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let mut current = load_ai_settings(mongo.get_ref()).await;
    if let Some(model) = body.default_model.as_ref() {
        let m = model.trim();
        if !m.is_empty() {
            current.default_model = m.to_string();
        }
    }
    if let Some(features) = body.features.as_ref() {
        for (k, v) in features {
            let key = k.trim();
            let val = v.trim();
            if !key.is_empty() && !val.is_empty() {
                current.features.insert(key.to_string(), val.to_string());
            }
        }
    }
    current = current.merge_with_defaults();
    current.updated_at = Some(Utc::now().to_rfc3339());

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<AiSettingsDoc>("ai_settings");
    // mongodb 3.x: upsert via ReplaceOptions builder chain
    match coll
        .replace_one(doc! { "_id": AI_SETTINGS_ID }, current.clone())
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(current.to_public_json()),
        Err(e) => {
            eprintln!("ai_settings upsert failed: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to save AI settings",
            }))
        }
    }
}

pub(crate) async fn api_templates() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"templates": []}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HermesChatProxyRequest {
    pub messages: Vec<serde_json::Value>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_key: Option<String>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HermesRunsProxyRequest {
    #[serde(default)]
    pub input: Option<serde_json::Value>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HermesRunsListQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

pub(crate) fn normalize_hermes_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some(without_v1) = trimmed.strip_suffix("/v1") {
        without_v1.to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn resolve_hermes_base_url() -> String {
    let base =
        env::var("HERMES_BASE_URL").unwrap_or_else(|_| "http://172.16.12.2:8642".to_string());
    normalize_hermes_base_url(&base)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminAiActivityQuery {
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct LlmUsageEvent {
    pub feature: String,
    pub status: String,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
    pub latency_ms: Option<i64>,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub source_id: Option<String>,
    pub source_url: Option<String>,
    pub error: Option<String>,
}

fn as_i64(value: Option<&serde_json::Value>) -> i64 {
    value
        .and_then(|v| {
            v.as_i64().or_else(|| {
                v.as_u64()
                    .and_then(|n| i64::try_from(n).ok())
                    .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
            })
        })
        .unwrap_or(0)
}

pub(crate) fn extract_llm_usage_tokens(payload: &serde_json::Value) -> (i64, i64, i64) {
    let usage = payload.get("usage").unwrap_or(&serde_json::Value::Null);
    let prompt_tokens = as_i64(usage.get("prompt_tokens").or_else(|| usage.get("promptTokens")));
    let completion_tokens =
        as_i64(usage.get("completion_tokens").or_else(|| usage.get("completionTokens")));
    let total_tokens = {
        let explicit = as_i64(usage.get("total_tokens").or_else(|| usage.get("totalTokens")));
        if explicit > 0 {
            explicit
        } else {
            prompt_tokens + completion_tokens
        }
    };

    (prompt_tokens, completion_tokens, total_tokens)
}

fn trim_opt(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let t = v.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

pub(crate) async fn log_llm_usage_event(client: &mongodb::Client, event: LlmUsageEvent) {
    let coll = client
        .database(&mongo_db_name())
        .collection::<bson::Document>("ai_activity_events");
    let now_iso = Utc::now().to_rfc3339();
    let total_tokens = if event.total_tokens > 0 {
        event.total_tokens
    } else {
        event.prompt_tokens + event.completion_tokens
    };
    let doc = doc! {
        "id": format!("llm-{}", Uuid::new_v4()),
        "feature": event.feature,
        "status": event.status,
        "model": event.model,
        "promptTokens": event.prompt_tokens,
        "completionTokens": event.completion_tokens,
        "totalTokens": total_tokens,
        "latencyMs": event.latency_ms.unwrap_or(0),
        "sessionId": trim_opt(event.session_id),
        "userId": trim_opt(event.user_id),
        "sourceId": trim_opt(event.source_id),
        "sourceUrl": trim_opt(event.source_url),
        "error": trim_opt(event.error),
        "createdAt": now_iso,
    };

    if let Err(e) = coll.insert_one(doc).await {
        eprintln!("log_llm_usage_event insert error: {}", e);
    }
}

fn doc_str(doc: &bson::Document, key: &str) -> Option<String> {
    doc.get_str(key).ok().map(|v| v.to_string())
}

fn doc_i64(doc: &bson::Document, key: &str) -> i64 {
    match doc.get(key) {
        Some(bson::Bson::Int32(v)) => i64::from(*v),
        Some(bson::Bson::Int64(v)) => *v,
        Some(bson::Bson::Double(v)) => *v as i64,
        Some(bson::Bson::String(s)) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy)]
struct PricingRate {
    input_per_1m_usd: f64,
    output_per_1m_usd: f64,
}

#[derive(Debug, Deserialize)]
struct OpenRouterModelsResponse {
    #[serde(default)]
    data: Vec<OpenRouterModelItem>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterModelItem {
    id: String,
    #[serde(default)]
    pricing: Option<OpenRouterPricing>,
}

#[derive(Debug, Deserialize)]
struct OpenRouterPricing {
    #[serde(default)]
    prompt: Option<String>,
    #[serde(default)]
    completion: Option<String>,
}

fn parse_env_f64(key: &str) -> Option<f64> {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
}

fn parse_pricing_overrides_json() -> HashMap<String, PricingRate> {
    let raw = match env::var("LLM_COST_MODEL_OVERRIDES_JSON") {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let parsed = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("LLM_COST_MODEL_OVERRIDES_JSON parse error: {}", e);
            return HashMap::new();
        }
    };
    let mut map = HashMap::new();
    if let Some(obj) = parsed.as_object() {
        for (model, node) in obj {
            let input = node
                .get("input")
                .and_then(|v| v.as_f64())
                .filter(|v| v.is_finite() && *v >= 0.0);
            let output = node
                .get("output")
                .and_then(|v| v.as_f64())
                .filter(|v| v.is_finite() && *v >= 0.0);
            if let (Some(i), Some(o)) = (input, output) {
                map.insert(
                    model.trim().to_ascii_lowercase(),
                    PricingRate {
                        input_per_1m_usd: i,
                        output_per_1m_usd: o,
                    },
                );
            }
        }
    }
    map
}

fn default_pricing_rate() -> PricingRate {
    PricingRate {
        input_per_1m_usd: parse_env_f64("LLM_COST_DEFAULT_INPUT_PER_1M_USD").unwrap_or(0.0),
        output_per_1m_usd: parse_env_f64("LLM_COST_DEFAULT_OUTPUT_PER_1M_USD").unwrap_or(0.0),
    }
}

fn parse_openrouter_token_price_to_per_1m(raw: Option<&str>) -> Option<f64> {
    let per_token = raw
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)?;
    Some(per_token * 1_000_000.0)
}

async fn fetch_openrouter_pricing_rates(
) -> Result<HashMap<String, PricingRate>, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mut req = client.get("https://openrouter.ai/api/v1/models");
    if let Ok(api_key) = env::var("OPENROUTER_API_KEY") {
        let key = api_key.trim();
        if !key.is_empty() {
            req = req.bearer_auth(key);
        }
    }

    let payload: OpenRouterModelsResponse = req.send().await?.error_for_status()?.json().await?;

    let mut rates = HashMap::new();
    for model in payload.data {
        let pricing = match model.pricing {
            Some(v) => v,
            None => continue,
        };
        let input = parse_openrouter_token_price_to_per_1m(pricing.prompt.as_deref());
        let output = parse_openrouter_token_price_to_per_1m(pricing.completion.as_deref());
        if let (Some(i), Some(o)) = (input, output) {
            rates.insert(
                model.id.trim().to_ascii_lowercase(),
                PricingRate {
                    input_per_1m_usd: i,
                    output_per_1m_usd: o,
                },
            );
        }
    }

    Ok(rates)
}

fn resolve_pricing_rate(
    model: &str,
    openrouter_rates: &HashMap<String, PricingRate>,
    overrides: &HashMap<String, PricingRate>,
    default_rate: PricingRate,
) -> (PricingRate, &'static str) {
    let key = model.trim().to_ascii_lowercase();
    if let Some(rate) = overrides.get(&key) {
        return (*rate, "model_override");
    }
    if let Some(rate) = openrouter_rates.get(&key) {
        return (*rate, "openrouter");
    }
    (default_rate, "default")
}

fn round6(v: f64) -> f64 {
    (v * 1_000_000.0).round() / 1_000_000.0
}

pub(crate) async fn load_ai_activity_runs(
    client: &mongodb::Client,
    limit: u32,
) -> Result<Vec<serde_json::Value>, mongodb::error::Error> {
    let coll = client
        .database(&mongo_db_name())
        .collection::<bson::Document>("ai_activity_events");
    let mut cursor = coll
        .find(doc! {})
        .sort(doc! {"createdAt": -1})
        .limit(i64::from(limit))
        .await?;

    let mut runs = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        let prompt_tokens = doc_i64(&doc, "promptTokens");
        let completion_tokens = doc_i64(&doc, "completionTokens");
        let total_tokens = {
            let explicit = doc_i64(&doc, "totalTokens");
            if explicit > 0 {
                explicit
            } else {
                prompt_tokens + completion_tokens
            }
        };

        runs.push(serde_json::json!({
            "id": doc_str(&doc, "id").unwrap_or_else(|| format!("llm-{}", Uuid::new_v4())),
            "status": doc_str(&doc, "status").unwrap_or_else(|| "completed".to_string()),
            "model": doc_str(&doc, "model").unwrap_or_else(|| "unknown".to_string()),
            "started_at": doc_str(&doc, "createdAt"),
            "completed_at": doc_str(&doc, "createdAt"),
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
            "session_id": doc_str(&doc, "sessionId"),
            "user_id": doc_str(&doc, "userId"),
            "feature": doc_str(&doc, "feature"),
            "latency_ms": doc_i64(&doc, "latencyMs"),
            "last_error": doc_str(&doc, "error"),
        }));
    }

    Ok(runs)
}

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

    #[derive(Default, Clone)]
    struct Bucket {
        runs: i64,
        completed_runs: i64,
        failed_runs: i64,
        prompt_tokens: i64,
        completion_tokens: i64,
        total_tokens: i64,
        total_cost_usd: f64,
    }

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

