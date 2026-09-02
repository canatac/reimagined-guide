#![allow(unused_imports)]
use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SummarizeNewsletterSourceInput {
    #[serde(default)]
    topic: Option<String>,
}

fn normalize_topic(raw: Option<&str>) -> String {
    let t = raw.unwrap_or("Tech").trim();
    if t.is_empty() {
        return "Tech".to_string();
    }
    t.to_string()
}

fn normalize_url(raw: Option<&str>) -> Option<String> {
    let trimmed = raw.unwrap_or("").trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.to_string());
    }
    Some(format!("https://{}", trimmed))
}

fn compute_signal(summary: &str) -> i32 {
    let boost = (summary.trim().chars().count() / 20) as i32;
    (65 + boost).clamp(50, 98)
}

fn normalize_plain_text(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(raw: &str, max_chars: usize) -> String {
    if raw.chars().count() <= max_chars {
        return raw.to_string();
    }
    raw.chars().take(max_chars).collect::<String>()
}

fn extract_completion_content(payload: &serde_json::Value) -> Option<String> {
    let content = payload
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?;

    if let Some(text) = content.as_str() {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let arr = content.as_array()?;
    let combined = arr
        .iter()
        .filter_map(|part| part.get("text").and_then(|v| v.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();

    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}

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

    let source_doc = match sources_coll.find_one(doc! { "user_id": &user_id, "id": id }).await {
        Ok(Some(docu)) => docu,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Source not found",
            }))
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize source lookup error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to summarize source",
            }));
        }
    };

    let source_name = source_doc
        .get_str("name")
        .ok()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Source".to_string());

    let source_url = match source_doc.get_str("url").ok().and_then(|v| normalize_url(Some(v))) {
        Some(url) => url,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Source URL is required before generating a summary",
            }))
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("misfits-newsletter-summarizer/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize reqwest build error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to initialize URL fetch client",
            }));
        }
    };

    let fetched = match client.get(&source_url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                return HttpResponse::BadGateway().json(serde_json::json!({
                    "message": format!("Failed to fetch source URL (status {})", resp.status()),
                }));
            }
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            let raw_body = match resp.text().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("api_newsletter_sources_summarize body read error: {}", e);
                    return HttpResponse::BadGateway().json(serde_json::json!({
                        "message": "Unable to read source URL content",
                    }));
                }
            };
            if content_type.contains("text/html") || raw_body.to_ascii_lowercase().contains("<html") {
                normalize_plain_text(&strip_tags(&raw_body))
            } else {
                normalize_plain_text(&raw_body)
            }
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize fetch error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Unable to fetch source URL",
            }));
        }
    };

    if fetched.is_empty() {
        return HttpResponse::BadGateway().json(serde_json::json!({
            "message": "Source URL content is empty",
        }));
    }

    let snippet = truncate_chars(&fetched, 12_000);
    let topic = normalize_topic(body.as_ref().and_then(|b| b.topic.as_deref()));

    let settings = load_ai_settings(mongo.get_ref()).await;
    let model = settings
        .features
        .get("newsletter")
        .or_else(|| settings.features.get("triage"))
        .cloned()
        .unwrap_or_else(|| settings.default_model.clone());

    let hermes_base = resolve_hermes_base_url();
    let hermes_api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "HERMES_API_KEY is not configured",
            }))
        }
    };

    let hermes_payload = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Tu es un analyste de veille. Réponds en français, factuel, sans invention."
            },
            {
                "role": "user",
                "content": format!(
                    "Parcours ce contenu web extrait depuis la source newsletter et génère un résumé actionnable.\n\nSource: {}\nURL: {}\nSujet: {}\n\nFormat attendu:\n1) Titre court\n2) 5 points clés max\n3) 3 actions recommandées\n4) Niveau de signal (0-100) en fin de réponse: Signal: <nombre>\n\nContenu extrait:\n{}",
                    source_name,
                    source_url,
                    topic,
                    snippet
                )
            }
        ],
        "temperature": 0.2,
        "max_tokens": 700
    });

    let hermes_response = match reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", hermes_base))
        .bearer_auth(hermes_api_key)
        .header("X-Hermes-Session-Id", format!("newsletter-source-{}", id))
        .header("X-Hermes-Session-Key", format!("user-{}", user_id))
        .json(&hermes_payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize hermes request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Newsletter summarization upstream is unavailable",
            }));
        }
    };

    if !hermes_response.status().is_success() {
        let status = hermes_response.status();
        let body = hermes_response.text().await.unwrap_or_default();
        eprintln!(
            "api_newsletter_sources_summarize hermes upstream status={} body={}",
            status, body
        );
        return HttpResponse::BadGateway().json(serde_json::json!({
            "message": format!("Newsletter summarization failed (status {})", status),
        }));
    }

    let hermes_json = match hermes_response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize hermes json parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Invalid summarization upstream response",
            }));
        }
    };

    let summary = match extract_completion_content(&hermes_json) {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Summarization upstream returned empty content",
            }))
        }
    };

    let now = Utc::now().to_rfc3339();
    let item_id = format!("n-{}", Uuid::new_v4());
    let title = format!("Digest {}", source_name);
    let signal = compute_signal(&summary);

    let item_doc = doc! {
        "id": &item_id,
        "user_id": &user_id,
        "sourceId": id,
        "title": title,
        "topic": topic,
        "summary": &summary,
        "signal": signal,
        "links": [
            {
                "name": source_name,
                "url": source_url,
            }
        ],
        "createdAt": &now,
        "updatedAt": &now,
    };

    match items_coll.insert_one(item_doc.clone()).await {
        Ok(_) => {
            let mut out = item_doc;
            out.remove("_id");
            out.remove("user_id");
            let item_json = bson::from_bson::<serde_json::Value>(bson::Bson::Document(out))
                .unwrap_or_else(|_| serde_json::json!({}));
            HttpResponse::Created().json(serde_json::json!({
                "item": item_json,
                "source": {
                    "id": id,
                    "name": source_name,
                    "url": source_url,
                },
                "model": model,
                "fetchedChars": snippet.chars().count(),
            }))
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize insert error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to persist generated summary",
            }))
        }
    }
}
