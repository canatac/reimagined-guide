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

