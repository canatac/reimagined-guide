#![allow(unused_imports)]
use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SummarizeNewsletterSourceInput {
    #[serde(default)]
    topic: Option<String>,
}

pub(crate) struct SourceSummarizeContext {
    pub(crate) source_name: String,
    pub(crate) source_url: String,
    pub(crate) snippet: String,
    pub(crate) discovered_links: Vec<String>,
    pub(crate) links_overview: String,
    pub(crate) context_blob: String,
    pub(crate) topic: String,
}

pub(crate) struct LlmSummaryData {
    pub(crate) model: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) parsed_signal: Option<i32>,
    pub(crate) curated_links: Vec<(String, String)>,
    pub(crate) llm_suggested_url: Option<String>,
}

pub(crate) fn normalize_topic(raw: Option<&str>) -> String {
    let t = raw.unwrap_or("Tech").trim();
    if t.is_empty() {
        return "Tech".to_string();
    }
    t.to_string()
}

pub(crate) fn normalize_url(raw: Option<&str>) -> Option<String> {
    let trimmed = raw.unwrap_or("").trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.to_string());
    }
    Some(format!("https://{}", trimmed))
}

pub(crate) fn compute_signal(summary: &str) -> i32 {
    let boost = (summary.trim().chars().count() / 20) as i32;
    (65 + boost).clamp(50, 98)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_topic_returns_default_for_none() {
        assert_eq!(normalize_topic(None), "Tech");
    }

    #[test]
    fn normalize_topic_returns_default_for_empty() {
        assert_eq!(normalize_topic(Some("")), "Tech");
        assert_eq!(normalize_topic(Some("   ")), "Tech");
    }

    #[test]
    fn normalize_topic_preserves_value() {
        assert_eq!(normalize_topic(Some("AI")), "AI");
        assert_eq!(normalize_topic(Some("Rust")), "Rust");
    }

    #[test]
    fn normalize_url_none() {
        assert_eq!(normalize_url(None), None);
    }

    #[test]
    fn normalize_url_empty() {
        assert_eq!(normalize_url(Some("")), None);
        assert_eq!(normalize_url(Some("   ")), None);
    }

    #[test]
    fn normalize_url_preserves_http() {
        assert_eq!(
            normalize_url(Some("http://example.com")),
            Some("http://example.com".to_string())
        );
    }

    #[test]
    fn normalize_url_preserves_https() {
        assert_eq!(
            normalize_url(Some("https://example.com")),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn normalize_url_adds_scheme() {
        assert_eq!(
            normalize_url(Some("example.com")),
            Some("https://example.com".to_string())
        );
    }

    #[test]
    fn compute_signal_empty() {
        assert_eq!(compute_signal(""), 65);
    }

    #[test]
    fn compute_signal_short() {
        assert_eq!(compute_signal("short"), 65);
    }

    #[test]
    fn compute_signal_longer_text() {
        let long_text = "a".repeat(400);
        let signal = compute_signal(&long_text);
        assert!(signal >= 50 && signal <= 98);
    }

    #[test]
    fn compute_signal_clamps_max() {
        let very_long = "a".repeat(10000);
        let signal = compute_signal(&very_long);
        assert_eq!(signal, 98);
    }

    #[test]
    fn compute_signal_clamps_min() {
        let signal = compute_signal("a");
        assert!(signal >= 50);
    }
}

#[path = "newsletter_summarize_links.rs"]
mod links;
#[path = "newsletter_summarize_parsing.rs"]
mod parsing;
#[path = "newsletter_summarize_fetch.rs"]
mod fetch;
#[path = "newsletter_summarize_llm.rs"]
mod llm;
#[path = "newsletter_summarize_persist.rs"]
mod persist;

pub(crate) async fn api_newsletter_sources_summarize(
    req: actix_web::HttpRequest,
    source_id: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: Option<web::Json<SummarizeNewsletterSourceInput>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = source_id.trim();
    if id.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Source id is required",
        }));
    }

    let db = mongo.database(&mongo_db_name());
    let sources_coll = db.collection::<bson::Document>("newsletter_sources");
    let items_coll = db.collection::<bson::Document>("newsletter_items");

    let topic = normalize_topic(body.as_ref().and_then(|b| b.topic.as_deref()));

    let context = match fetch::build_source_context(&sources_coll, id, &user_id, topic).await {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let llm_data = match llm::summarize_with_hermes(mongo.get_ref(), &user_id, id, &context).await {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    persist::persist_summary_item(
        &sources_coll,
        &items_coll,
        id,
        &user_id,
        &context,
        llm_data,
    )
    .await
}
