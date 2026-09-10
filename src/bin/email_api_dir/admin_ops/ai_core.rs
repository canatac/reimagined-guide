use super::*;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ai_feature_models_contains_expected_keys() {
        let models = default_ai_feature_models();
        assert!(models.contains_key("compose"));
        assert!(models.contains_key("translate"));
        assert!(models.contains_key("triage"));
        assert!(models.contains_key("security"));
        assert!(models.contains_key("rewrite"));
        assert!(models.contains_key("subject"));
        assert!(models.contains_key("complete"));
    }

    #[test]
    fn default_ai_feature_models_uses_default_model() {
        let models = default_ai_feature_models();
        for (_, model) in models {
            assert_eq!(model, DEFAULT_AI_MODEL);
        }
    }

    #[test]
    fn ai_settings_doc_defaults() {
        let doc = AiSettingsDoc::defaults();
        assert_eq!(doc.id, AI_SETTINGS_ID);
        assert_eq!(doc.default_model, DEFAULT_AI_MODEL);
        assert!(doc.features.contains_key("compose"));
    }

    #[test]
    fn ai_settings_doc_merge_with_defaults_adds_missing() {
        let doc = AiSettingsDoc {
            id: AI_SETTINGS_ID.to_string(),
            default_model: "custom-model".to_string(),
            features: HashMap::new(),
            updated_at: None,
        };
        let merged = doc.merge_with_defaults();
        assert_eq!(merged.default_model, "custom-model");
        assert!(merged.features.contains_key("compose"));
        assert!(merged.features.contains_key("translate"));
    }

    #[test]
    fn ai_settings_doc_merge_with_defaults_fills_empty_model() {
        let doc = AiSettingsDoc {
            id: AI_SETTINGS_ID.to_string(),
            default_model: "".to_string(),
            features: HashMap::new(),
            updated_at: None,
        };
        let merged = doc.merge_with_defaults();
        assert_eq!(merged.default_model, DEFAULT_AI_MODEL);
    }

    #[test]
    fn ai_settings_doc_to_public_json() {
        let doc = AiSettingsDoc::defaults();
        let json = doc.to_public_json();
        assert!(json.get("defaultModel").is_some());
        assert!(json.get("features").is_some());
        assert!(json.get("updatedAt").is_some());
    }

    #[test]
    fn mongo_db_name_defaults_to_mailserver() {
        std::env::remove_var("MONGODB_DATABASE");
        assert_eq!(mongo_db_name(), "mailserver");
    }

    #[test]
    fn mongo_db_name_reads_from_env() {
        std::env::set_var("MONGODB_DATABASE", "test_db");
        assert_eq!(mongo_db_name(), "test_db");
        std::env::remove_var("MONGODB_DATABASE");
    }
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

pub(crate) fn as_i64(value: Option<&serde_json::Value>) -> i64 {
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

