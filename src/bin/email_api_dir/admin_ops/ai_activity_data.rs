use super::*;

pub(crate) fn doc_str(doc: &bson::Document, key: &str) -> Option<String> {
    doc.get_str(key).ok().map(|v| v.to_string())
}

pub(crate) fn doc_i64(doc: &bson::Document, key: &str) -> i64 {
    match doc.get(key) {
        Some(bson::Bson::Int32(v)) => i64::from(*v),
        Some(bson::Bson::Int64(v)) => *v,
        Some(bson::Bson::Double(v)) => *v as i64,
        Some(bson::Bson::String(s)) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PricingRate {
    pub(crate) input_per_1m_usd: f64,
    pub(crate) output_per_1m_usd: f64,
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

pub(crate) fn parse_env_f64(key: &str) -> Option<f64> {
    env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
}

pub(crate) fn parse_pricing_overrides_json() -> HashMap<String, PricingRate> {
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

pub(crate) fn default_pricing_rate() -> PricingRate {
    PricingRate {
        input_per_1m_usd: parse_env_f64("LLM_COST_DEFAULT_INPUT_PER_1M_USD").unwrap_or(0.0),
        output_per_1m_usd: parse_env_f64("LLM_COST_DEFAULT_OUTPUT_PER_1M_USD").unwrap_or(0.0),
    }
}

pub(crate) fn parse_openrouter_token_price_to_per_1m(raw: Option<&str>) -> Option<f64> {
    let per_token = raw
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)?;
    Some(per_token * 1_000_000.0)
}

pub(crate) async fn fetch_openrouter_pricing_rates(
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

pub(crate) fn resolve_pricing_rate(
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

pub(crate) fn round6(v: f64) -> f64 {
    (v * 1_000_000.0).round() / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_str_returns_string_value() {
        let mut doc = bson::Document::new();
        doc.insert("name", "test_value");
        assert_eq!(doc_str(&doc, "name"), Some("test_value".to_string()));
    }

    #[test]
    fn doc_str_returns_none_for_missing() {
        let doc = bson::Document::new();
        assert_eq!(doc_str(&doc, "missing"), None);
    }

    #[test]
    fn doc_i64_int32() {
        let mut doc = bson::Document::new();
        doc.insert("val", 42i32);
        assert_eq!(doc_i64(&doc, "val"), 42);
    }

    #[test]
    fn doc_i64_int64() {
        let mut doc = bson::Document::new();
        doc.insert("val", 999i64);
        assert_eq!(doc_i64(&doc, "val"), 999);
    }

    #[test]
    fn doc_i64_double() {
        let mut doc = bson::Document::new();
        doc.insert("val", 3.14f64);
        assert_eq!(doc_i64(&doc, "val"), 3);
    }

    #[test]
    fn doc_i64_string_parses() {
        let mut doc = bson::Document::new();
        doc.insert("val", "123");
        assert_eq!(doc_i64(&doc, "val"), 123);
    }

    #[test]
    fn doc_i64_string_invalid_fallback() {
        let mut doc = bson::Document::new();
        doc.insert("val", "not_a_number");
        assert_eq!(doc_i64(&doc, "val"), 0);
    }

    #[test]
    fn doc_i64_missing_returns_zero() {
        let doc = bson::Document::new();
        assert_eq!(doc_i64(&doc, "missing"), 0);
    }

    #[test]
    fn parse_env_f64_valid() {
        std::env::set_var("TEST_F64", "3.14");
        assert_eq!(parse_env_f64("TEST_F64"), Some(3.14));
        std::env::remove_var("TEST_F64");
    }

    #[test]
    fn parse_env_f64_invalid() {
        std::env::set_var("TEST_F64", "not_a_number");
        assert_eq!(parse_env_f64("TEST_F64"), None);
        std::env::remove_var("TEST_F64");
    }

    #[test]
    fn parse_env_f64_negative() {
        std::env::set_var("TEST_F64", "-1.0");
        assert_eq!(parse_env_f64("TEST_F64"), None);
        std::env::remove_var("TEST_F64");
    }

    #[test]
    fn parse_env_f64_infinite() {
        std::env::set_var("TEST_F64", "inf");
        assert_eq!(parse_env_f64("TEST_F64"), None);
        std::env::remove_var("TEST_F64");
    }

    #[test]
    fn parse_env_f64_unset() {
        std::env::remove_var("TEST_UNSET_F64");
        assert_eq!(parse_env_f64("TEST_UNSET_F64"), None);
    }

    #[test]
    fn parse_pricing_overrides_json_valid() {
        std::env::set_var("LLM_COST_MODEL_OVERRIDES_JSON", r#"{"model1":{"input":1.0,"output":2.0}}"#);
        let map = parse_pricing_overrides_json();
        assert!(map.contains_key("model1"));
        let rate = map.get("model1").unwrap();
        assert_eq!(rate.input_per_1m_usd, 1.0);
        assert_eq!(rate.output_per_1m_usd, 2.0);
        std::env::remove_var("LLM_COST_MODEL_OVERRIDES_JSON");
    }

    #[test]
    fn parse_pricing_overrides_json_empty() {
        std::env::remove_var("LLM_COST_MODEL_OVERRIDES_JSON");
        let map = parse_pricing_overrides_json();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_pricing_overrides_json_invalid() {
        std::env::set_var("LLM_COST_MODEL_OVERRIDES_JSON", "not json");
        let map = parse_pricing_overrides_json();
        assert!(map.is_empty());
        std::env::remove_var("LLM_COST_MODEL_OVERRIDES_JSON");
    }

    #[test]
    fn default_pricing_rate_zero() {
        std::env::remove_var("LLM_COST_DEFAULT_INPUT_PER_1M_USD");
        std::env::remove_var("LLM_COST_DEFAULT_OUTPUT_PER_1M_USD");
        let rate = default_pricing_rate();
        assert_eq!(rate.input_per_1m_usd, 0.0);
        assert_eq!(rate.output_per_1m_usd, 0.0);
    }

    #[test]
    fn parse_openrouter_token_price_valid() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(Some("0.000001")), Some(1.0));
    }

    #[test]
    fn parse_openrouter_token_price_none() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(None), None);
    }

    #[test]
    fn parse_openrouter_token_price_empty() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(Some("")), None);
    }

    #[test]
    fn parse_openrouter_token_price_negative() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(Some("-0.001")), None);
    }

    #[test]
    fn resolve_pricing_rate_override() {
        let default = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        let mut overrides = HashMap::new();
        overrides.insert("model1".to_string(), PricingRate { input_per_1m_usd: 5.0, output_per_1m_usd: 10.0 });
        let (rate, source) = resolve_pricing_rate("model1", &HashMap::new(), &overrides, default);
        assert_eq!(rate.input_per_1m_usd, 5.0);
        assert_eq!(source, "model_override");
    }

    #[test]
    fn resolve_pricing_rate_openrouter() {
        let default = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        let mut openrouter = HashMap::new();
        openrouter.insert("model1".to_string(), PricingRate { input_per_1m_usd: 3.0, output_per_1m_usd: 4.0 });
        let (rate, source) = resolve_pricing_rate("model1", &openrouter, &HashMap::new(), default);
        assert_eq!(rate.input_per_1m_usd, 3.0);
        assert_eq!(source, "openrouter");
    }

    #[test]
    fn resolve_pricing_rate_default() {
        let default = PricingRate { input_per_1m_usd: 1.0, output_per_1m_usd: 2.0 };
        let (rate, source) = resolve_pricing_rate("unknown", &HashMap::new(), &HashMap::new(), default);
        assert_eq!(rate.input_per_1m_usd, 1.0);
        assert_eq!(source, "default");
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

