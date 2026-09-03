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

    let total_runs = runs.len() as i64;
    let mut completed_runs = 0_i64;
    let mut failed_runs = 0_i64;
    let mut prompt_tokens = 0_i64;
    let mut completion_tokens = 0_i64;
    let mut total_tokens = 0_i64;
    let mut latencies: Vec<i64> = Vec::new();

    for run in &runs {
        let status = run
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_ascii_lowercase();
        if status == "completed" || status == "success" {
            completed_runs += 1;
        }
        if ["failed", "error", "cancelled", "expired"].contains(&status.as_str()) {
            failed_runs += 1;
        }

        let usage = run.get("usage").unwrap_or(&serde_json::Value::Null);
        let p = as_i64(usage.get("prompt_tokens"));
        let c = as_i64(usage.get("completion_tokens"));
        let t = {
            let explicit = as_i64(usage.get("total_tokens"));
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
        },
        "runs": runs,
    }))
}

