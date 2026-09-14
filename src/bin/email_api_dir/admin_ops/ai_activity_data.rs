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
    fn doc_str_returns_some_for_valid_string() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc_str(&doc, "key"), Some("value".to_string()));
    }

    #[test]
    fn doc_str_returns_none_for_missing_key() {
        let doc = doc! {};
        assert_eq!(doc_str(&doc, "missing"), None);
    }

    #[test]
    fn doc_i64_parses_int32() {
        let doc = doc! { "val": 42 };
        assert_eq!(doc_i64(&doc, "val"), 42);
    }

    #[test]
    fn doc_i64_parses_int64() {
        let doc = doc! { "val": 9999999999i64 };
        assert_eq!(doc_i64(&doc, "val"), 9999999999);
    }

    #[test]
    fn doc_i64_parses_double() {
        let doc = doc! { "val": 3.14 };
        assert_eq!(doc_i64(&doc, "val"), 3);
    }

    #[test]
    fn doc_i64_parses_string() {
        let doc = doc! { "val": "123" };
        assert_eq!(doc_i64(&doc, "val"), 123);
    }

    #[test]
    fn doc_i64_returns_zero_for_missing() {
        let doc = doc! {};
        assert_eq!(doc_i64(&doc, "missing"), 0);
    }

    #[test]
    fn parse_env_f64_returns_some_for_valid() {
        std::env::set_var("TEST_VAR_F64", "3.14");
        assert_eq!(parse_env_f64("TEST_VAR_F64"), Some(3.14));
        std::env::remove_var("TEST_VAR_F64");
    }

    #[test]
    fn parse_env_f64_returns_none_for_missing() {
        assert_eq!(parse_env_f64("NONEXISTENT_VAR_XYZ"), None);
    }

    #[test]
    fn parse_env_f64_returns_none_for_negative() {
        std::env::set_var("TEST_VAR_NEG", "-1.0");
        assert_eq!(parse_env_f64("TEST_VAR_NEG"), None);
        std::env::remove_var("TEST_VAR_NEG");
    }

    #[test]
    fn parse_env_f64_returns_none_for_nan() {
        std::env::set_var("TEST_VAR_NAN", "NaN");
        assert_eq!(parse_env_f64("TEST_VAR_NAN"), None);
        std::env::remove_var("TEST_VAR_NAN");
    }

    #[test]
    fn default_pricing_rate_uses_env_vars() {
        std::env::set_var("LLM_COST_DEFAULT_INPUT_PER_1M_USD", "10.0");
        std::env::set_var("LLM_COST_DEFAULT_OUTPUT_PER_1M_USD", "30.0");
        let rate = default_pricing_rate();
        assert!((rate.input_per_1m_usd - 10.0).abs() < f64::EPSILON);
        assert!((rate.output_per_1m_usd - 30.0).abs() < f64::EPSILON);
        std::env::remove_var("LLM_COST_DEFAULT_INPUT_PER_1M_USD");
        std::env::remove_var("LLM_COST_DEFAULT_OUTPUT_PER_1M_USD");
    }

    #[test]
    fn default_pricing_rate_defaults_to_zero() {
        std::env::remove_var("LLM_COST_DEFAULT_INPUT_PER_1M_USD");
        std::env::remove_var("LLM_COST_DEFAULT_OUTPUT_PER_1M_USD");
        let rate = default_pricing_rate();
        assert_eq!(rate.input_per_1m_usd, 0.0);
        assert_eq!(rate.output_per_1m_usd, 0.0);
    }

    #[test]
    fn parse_openrouter_token_price_scales() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(Some("0.00001")), Some(10.0));
    }

    #[test]
    fn parse_openrouter_token_price_empty() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(Some("")), None);
    }

    #[test]
    fn parse_openrouter_token_price_negative() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(Some("-1")), None);
    }

    #[test]
    fn parse_openrouter_token_price_none() {
        assert_eq!(parse_openrouter_token_price_to_per_1m(None), None);
    }

    #[test]
    fn resolve_pricing_rate_prefers_override() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "gpt-4".to_string(),
            PricingRate {
                input_per_1m_usd: 100.0,
                output_per_1m_usd: 200.0,
            },
        );
        let openrouter = HashMap::new();
        let default = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let (rate, source) = resolve_pricing_rate("gpt-4", &openrouter, &overrides, default);
        assert_eq!(source, "model_override");
        assert!((rate.input_per_1m_usd - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn resolve_pricing_rate_falls_back_to_openrouter() {
        let overrides = HashMap::new();
        let mut openrouter = HashMap::new();
        openrouter.insert(
            "claude-3".to_string(),
            PricingRate {
                input_per_1m_usd: 50.0,
                output_per_1m_usd: 100.0,
            },
        );
        let default = PricingRate {
            input_per_1m_usd: 1.0,
            output_per_1m_usd: 2.0,
        };
        let (rate, source) = resolve_pricing_rate("claude-3", &openrouter, &overrides, default);
        assert_eq!(source, "openrouter");
        assert!((rate.input_per_1m_usd - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn resolve_pricing_rate_defaults() {
        let overrides = HashMap::new();
        let openrouter = HashMap::new();
        let default = PricingRate {
            input_per_1m_usd: 5.0,
            output_per_1m_usd: 10.0,
        };
        let (rate, source) = resolve_pricing_rate("unknown-model", &openrouter, &overrides, default);
        assert_eq!(source, "default");
        assert!((rate.input_per_1m_usd - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn round6_rounds_to_6_decimals() {
        assert!((round6(1.123456789) - 1.123457).abs() < 1e-10);
    }

    #[test]
    fn round6_zero() {
        assert_eq!(round6(0.0), 0.0);
    }

    #[test]
    fn parse_pricing_overrides_json_empty_when_unset() {
        std::env::remove_var("LLM_COST_MODEL_OVERRIDES_JSON");
        let map = parse_pricing_overrides_json();
        assert!(map.is_empty());
    }

    #[test]
    fn parse_pricing_overrides_json_parses_valid() {
        std::env::set_var(
            "LLM_COST_MODEL_OVERRIDES_JSON",
            r#"{"gpt-4": {"input": 10.0, "output": 30.0}}"#,
        );
        let map = parse_pricing_overrides_json();
        assert_eq!(map.len(), 1);
        let rate = map.get("gpt-4").unwrap();
        assert!((rate.input_per_1m_usd - 10.0).abs() < f64::EPSILON);
        assert!((rate.output_per_1m_usd - 30.0).abs() < f64::EPSILON);
        std::env::remove_var("LLM_COST_MODEL_OVERRIDES_JSON");
    }

    #[test]
    fn parse_pricing_overrides_json_handles_invalid() {
        std::env::set_var("LLM_COST_MODEL_OVERRIDES_JSON", "not-json");
        let map = parse_pricing_overrides_json();
        assert!(map.is_empty());
        std::env::remove_var("LLM_COST_MODEL_OVERRIDES_JSON");
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

