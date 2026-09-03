#![allow(unused_imports)]
use super::*;
use std::collections::HashSet;

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

fn is_html_payload(content_type: &str, raw_body: &str) -> bool {
    content_type.contains("text/html") || raw_body.to_ascii_lowercase().contains("<html")
}

fn normalize_discovered_link(base_url: &str, candidate: &str) -> Option<String> {
    let raw = candidate
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .replace("&amp;", "&");
    if raw.is_empty()
        || raw.starts_with('#')
        || raw.starts_with("mailto:")
        || raw.starts_with("javascript:")
    {
        return None;
    }

    if raw.starts_with("http://") || raw.starts_with("https://") {
        return Some(raw);
    }

    let base = reqwest::Url::parse(base_url).ok()?;
    let joined = base.join(&raw).ok()?;
    let scheme = joined.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    Some(joined.to_string())
}

fn looks_like_content_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower.contains("/login")
        || lower.contains("/signup")
        || lower.contains("/register")
        || lower.contains("/privacy")
        || lower.contains("/terms")
        || lower.contains("/contact")
        || lower.contains("/about")
    {
        return false;
    }

    if lower.ends_with(".css")
        || lower.ends_with(".js")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".svg")
        || lower.ends_with(".webp")
        || lower.ends_with(".gif")
        || lower.ends_with(".ico")
    {
        return false;
    }

    true
}

fn extract_html_links(base_url: &str, html: &str, max_links: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let lower = html.to_ascii_lowercase();
    let mut idx = 0usize;

    while idx < lower.len() {
        let rel = match lower[idx..].find("href=") {
            Some(v) => v,
            None => break,
        };

        let href_pos = idx + rel;
        let value_start = href_pos + 5;
        if value_start >= html.len() {
            break;
        }

        let bytes = html.as_bytes();
        let quote = bytes[value_start] as char;
        let (value, next_idx) = if quote == '"' || quote == '\'' {
            let start = value_start + 1;
            let rem = &html[start..];
            match rem.find(quote) {
                Some(end_rel) => (&html[start..start + end_rel], start + end_rel + 1),
                None => ("", value_start + 1),
            }
        } else {
            let rem = &html[value_start..];
            let end_rel = rem
                .find(|c: char| c.is_whitespace() || c == '>')
                .unwrap_or(rem.len());
            (&html[value_start..value_start + end_rel], value_start + end_rel)
        };

        if let Some(abs) = normalize_discovered_link(base_url, value) {
            if looks_like_content_url(&abs) && seen.insert(abs.clone()) {
                out.push(abs);
                if out.len() >= max_links {
                    break;
                }
            }
        }

        idx = next_idx;
    }

    out
}

fn is_homepage_url(url: &str) -> bool {
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            let path = parsed.path().trim();
            path.is_empty() || path == "/"
        }
        Err(_) => false,
    }
}

fn has_specific_path(url: &str) -> bool {
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            let path = parsed.path().trim();
            !path.is_empty() && path != "/"
        }
        Err(_) => false,
    }
}

fn same_site(a: &str, b: &str) -> bool {
    let host_a = reqwest::Url::parse(a)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));
    let host_b = reqwest::Url::parse(b)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()));

    match (host_a, host_b) {
        (Some(ha), Some(hb)) => {
            ha == hb || ha.ends_with(&format!(".{}", hb)) || hb.ends_with(&format!(".{}", ha))
        }
        _ => false,
    }
}

fn should_update_source_url(previous: &str, candidate: &str) -> bool {
    if previous == candidate {
        return false;
    }
    if !same_site(previous, candidate) {
        return false;
    }
    is_homepage_url(previous) && has_specific_path(candidate)
}

fn discover_section_urls(base_url: &str) -> Vec<String> {
    let base = match reqwest::Url::parse(base_url) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let candidates = [
        "/blog",
        "/blogs",
        "/insights",
        "/news",
        "/articles",
        "/publications",
        "/technology",
        "/engineering",
    ];

    for path in candidates {
        if let Ok(url) = base.join(path) {
            let s = url.to_string();
            if seen.insert(s.clone()) {
                out.push(s);
            }
        }
    }
    out
}

fn merge_links(target: &mut Vec<String>, incoming: Vec<String>, max_links: usize) {
    let mut seen: HashSet<String> = target.iter().cloned().collect();
    for link in incoming {
        if seen.insert(link.clone()) {
            target.push(link);
            if target.len() >= max_links {
                break;
            }
        }
    }
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

fn extract_json_object(text: &str) -> Option<serde_json::Value> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        return Some(v);
    }

    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }

    serde_json::from_str::<serde_json::Value>(&text[start..=end]).ok()
}

fn extract_http_urls(text: &str, max_urls: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut idx = 0usize;

    while idx < text.len() {
        let next_http = text[idx..].find("http://");
        let next_https = text[idx..].find("https://");
        let rel = match (next_http, next_https) {
            (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let rel = match rel {
            Some(v) => v,
            None => break,
        };

        let start = idx + rel;
        let tail = &text[start..];
        let end_rel = tail
            .find(|c: char| c.is_whitespace() || c == ')' || c == ']' || c == '>' || c == '"')
            .unwrap_or(tail.len());

        let url = tail[..end_rel]
            .trim_end_matches('.')
            .trim_end_matches(',')
            .trim_end_matches(';');

        if let Some(norm) = normalize_url(Some(url)) {
            if seen.insert(norm.clone()) {
                out.push(norm);
                if out.len() >= max_urls {
                    break;
                }
            }
        }

        idx = start + end_rel;
    }

    out
}

fn build_summary_from_article_digests(parsed_json: &Option<serde_json::Value>) -> Option<String> {
    let digests = parsed_json
        .as_ref()
        .and_then(|v| v.get("articleDigests"))
        .and_then(|v| v.as_array())?;

    let rows: Vec<(String, String, String)> = digests
        .iter()
        .filter_map(|entry| {
            let url = entry
                .get("url")
                .and_then(|v| v.as_str())
                .and_then(|v| normalize_url(Some(v)))?;
            let title = entry
                .get("title")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "Article".to_string());
            let digest = entry
                .get("summary")
                .and_then(|v| v.as_str())
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())?;
            Some((title, url, digest))
        })
        .take(5)
        .collect();

    if rows.is_empty() {
        return None;
    }

    let body = rows
        .iter()
        .enumerate()
        .map(|(idx, (title, _url, digest))| format!("{}. {} — {}", idx + 1, title, digest))
        .collect::<Vec<_>>()
        .join("\n");

    let sources = rows
        .iter()
        .enumerate()
        .map(|(idx, (title, url, _digest))| format!("{}. {} — {}", idx + 1, title, url))
        .collect::<Vec<_>>()
        .join("\n");

    Some(format!("{}\n\nSources:\n{}", body, sources))
}

fn ensure_sources_block(summary: &str, curated_links: &[(String, String)]) -> String {
    let trimmed = summary.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if curated_links.is_empty() {
        return trimmed.to_string();
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("\nsources:") || lower.starts_with("sources:") {
        return trimmed.to_string();
    }

    let sources = curated_links
        .iter()
        .take(6)
        .enumerate()
        .map(|(idx, (name, url))| format!("{}. {} — {}", idx + 1, name, url))
        .collect::<Vec<_>>()
        .join("\n");

    format!("{}\n\nSources:\n{}", trimmed, sources)
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

    let (raw_source_body, source_content_type) = match client.get(&source_url).send().await {
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

            (raw_body, content_type)
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize fetch error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Unable to fetch source URL",
            }));
        }
    };

    let fetched = if is_html_payload(&source_content_type, &raw_source_body) {
        normalize_plain_text(&strip_tags(&raw_source_body))
    } else {
        normalize_plain_text(&raw_source_body)
    };

    if fetched.is_empty() {
        return HttpResponse::BadGateway().json(serde_json::json!({
            "message": "Source URL content is empty",
        }));
    }

    let snippet = truncate_chars(&fetched, 12_000);
    let mut discovered_links = if is_html_payload(&source_content_type, &raw_source_body) {
        extract_html_links(&source_url, &raw_source_body, 20)
    } else {
        Vec::new()
    };

    if discovered_links.len() < 8 {
        for section_url in discover_section_urls(&source_url) {
            let section_resp = match client.get(&section_url).send().await {
                Ok(resp) if resp.status().is_success() => resp,
                _ => continue,
            };
            let section_type = section_resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            let section_body = match section_resp.text().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !is_html_payload(&section_type, &section_body) {
                continue;
            }
            merge_links(
                &mut discovered_links,
                extract_html_links(&section_url, &section_body, 12),
                20,
            );
            if discovered_links.len() >= 12 {
                break;
            }
        }
    }

    let mut link_contexts: Vec<String> = Vec::new();
    for link in discovered_links.iter().take(4) {
        let page_text = match client.get(link).send().await {
            Ok(resp) if resp.status().is_success() => {
                let content_type = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                match resp.text().await {
                    Ok(body) => {
                        if is_html_payload(&content_type, &body) {
                            normalize_plain_text(&strip_tags(&body))
                        } else {
                            normalize_plain_text(&body)
                        }
                    }
                    Err(_) => continue,
                }
            }
            _ => continue,
        };

        if page_text.is_empty() {
            continue;
        }

        link_contexts.push(format!(
            "URL: {}\nExtrait: {}",
            link,
            truncate_chars(&page_text, 1_800)
        ));
    }

    let links_overview = if discovered_links.is_empty() {
        "Aucun lien d'article détecté automatiquement sur la page source.".to_string()
    } else {
        discovered_links
            .iter()
            .take(12)
            .enumerate()
            .map(|(i, link)| format!("{}. {}", i + 1, link))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let context_blob = if link_contexts.is_empty() {
        "Aucun extrait additionnel récupéré depuis des URLs candidates.".to_string()
    } else {
        link_contexts.join("\n\n---\n\n")
    };

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
                "content": "Tu es un analyste de veille éditoriale. Réponds en français, factuel, sans invention. Tu dois sélectionner des liens pertinents toi-même et ne jamais demander à l'utilisateur de fournir une URL plus précise."
            },
            {
                "role": "user",
                "content": format!(
                    "Objectif: générer un item newsletter pertinent à partir d'une URL généraliste (homepage possible), sans travail supplémentaire demandé à l'utilisateur.\n\nSource: {}\nURL directionnelle initiale: {}\nSujet: {}\n\nLiens candidats détectés sur le site:\n{}\n\nExtraits de pages candidates:\n{}\n\nContenu de la page source:\n{}\n\nRéponds UNIQUEMENT en JSON valide (pas de markdown hors champ summary, pas de commentaire) avec ce schéma:\n{{\n  \"title\": \"string\",\n  \"summary\": \"synthèse éditoriale en français du contenu des publications (pas de call-to-action). Termine impérativement par une section 'Sources:' avec les URLs utilisées\",\n  \"signal\": 0-100,\n  \"updatedSourceUrl\": \"url absolue de page de veille à suivre automatiquement pour les prochains runs\",\n  \"recommendedLinks\": [{{\"name\":\"string\",\"url\":\"https://...\",\"reason\":\"pourquoi ce lien est pertinent\"}}],\n  \"articleDigests\": [{{\"title\":\"string\",\"url\":\"https://...\",\"summary\":\"3-5 phrases factuelles résumant ce contenu\"}}]\n}}\n\nContraintes strictes:\n- Ne demande jamais à l'utilisateur de fournir une autre URL.\n- Tu choisis toi-même les meilleures URLs depuis les liens candidats/extraits disponibles.\n- Priorité aux contenus tech récents et éditoriaux (articles, blogs, insights, publications).\n- Interdit de répondre avec des actions du type 'lis cet article'. Tu dois résumer le contenu.\n- Termine la sortie avec les sources (URLs) en fin de texte.\n- Si aucune page spécifique n'est fiable, garde updatedSourceUrl sur l'URL initiale.",
                    source_name,
                    source_url,
                    topic,
                    links_overview,
                    context_blob,
                    snippet
                )
            }
        ],
        "temperature": 0.2,
        "max_tokens": 900
    });

    let llm_session_id = format!("newsletter-source-{}", id);
    let llm_started = std::time::Instant::now();
    let hermes_response = match reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", hermes_base))
        .bearer_auth(hermes_api_key)
        .header("X-Hermes-Session-Id", llm_session_id.clone())
        .header("X-Hermes-Session-Key", format!("user-{}", user_id))
        .json(&hermes_payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize hermes request error: {}", e);
            log_llm_usage_event(
                mongo.get_ref(),
                LlmUsageEvent {
                    feature: "newsletter_summarize".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(llm_session_id.clone()),
                    user_id: Some(user_id.clone()),
                    source_id: Some(id.to_string()),
                    source_url: Some(source_url.clone()),
                    error: Some(format!("request_error: {}", e)),
                },
            )
            .await;
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Newsletter summarization upstream is unavailable",
            }));
        }
    };

    if !hermes_response.status().is_success() {
        let status = hermes_response.status();
        let body = hermes_response.text().await.unwrap_or_default();
        log_llm_usage_event(
            mongo.get_ref(),
            LlmUsageEvent {
                feature: "newsletter_summarize".to_string(),
                status: "failed".to_string(),
                model: model.clone(),
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
                latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
                session_id: Some(llm_session_id.clone()),
                user_id: Some(user_id.clone()),
                source_id: Some(id.to_string()),
                source_url: Some(source_url.clone()),
                error: Some(format!("status_{}", status.as_u16())),
            },
        )
        .await;
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
            log_llm_usage_event(
                mongo.get_ref(),
                LlmUsageEvent {
                    feature: "newsletter_summarize".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(llm_session_id.clone()),
                    user_id: Some(user_id.clone()),
                    source_id: Some(id.to_string()),
                    source_url: Some(source_url.clone()),
                    error: Some(format!("invalid_json: {}", e)),
                },
            )
            .await;
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Invalid summarization upstream response",
            }));
        }
    };

    let (prompt_tokens, completion_tokens, total_tokens) = extract_llm_usage_tokens(&hermes_json);
    log_llm_usage_event(
        mongo.get_ref(),
        LlmUsageEvent {
            feature: "newsletter_summarize".to_string(),
            status: "completed".to_string(),
            model: model.clone(),
            prompt_tokens,
            completion_tokens,
            total_tokens,
            latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
            session_id: Some(llm_session_id.clone()),
            user_id: Some(user_id.clone()),
            source_id: Some(id.to_string()),
            source_url: Some(source_url.clone()),
            error: None,
        },
    )
    .await;

    let summary_payload = match extract_completion_content(&hermes_json) {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Summarization upstream returned empty content",
            }))
        }
    };

    let parsed_json = extract_json_object(&summary_payload);
    let fallback_summary = summary_payload.trim().to_string();

    let title = parsed_json
        .as_ref()
        .and_then(|v| v.get("title"))
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("Digest {}", source_name));

    let base_summary = parsed_json
        .as_ref()
        .and_then(|v| v.get("summary"))
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or(fallback_summary);

    let parsed_signal = parsed_json
        .as_ref()
        .and_then(|v| v.get("signal"))
        .and_then(|v| v.as_i64())
        .map(|v| v.clamp(0, 100) as i32);

    let mut curated_links: Vec<(String, String)> = parsed_json
        .as_ref()
        .and_then(|v| v.get("recommendedLinks"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let url = entry.get("url")?.as_str()?;
                    let normalized = normalize_url(Some(url))?;
                    let name = entry
                        .get("name")
                        .and_then(|n| n.as_str())
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "Article à suivre".to_string());
                    Some((name, normalized))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if curated_links.is_empty() {
        curated_links = extract_http_urls(&base_summary, 4)
            .into_iter()
            .enumerate()
            .map(|(idx, url)| (format!("Lien recommandé {}", idx + 1), url))
            .collect::<Vec<_>>();
    }

    if curated_links.is_empty() {
        curated_links = discovered_links
            .iter()
            .take(3)
            .enumerate()
            .map(|(idx, url)| (format!("Article {}", idx + 1), url.to_string()))
            .collect::<Vec<_>>();
    }

    if curated_links.is_empty() {
        curated_links.push((source_name.clone(), source_url.clone()));
    }

    let summary = build_summary_from_article_digests(&parsed_json)
        .unwrap_or(base_summary);
    let summary = ensure_sources_block(&summary, &curated_links);

    let llm_suggested_url = parsed_json
        .as_ref()
        .and_then(|v| v.get("updatedSourceUrl"))
        .and_then(|v| v.as_str())
        .and_then(|v| normalize_url(Some(v)));

    let mut final_source_url = source_url.clone();
    let mut source_set_doc = doc! {};
    let now_update = Utc::now().to_rfc3339();
    source_set_doc.insert("updatedAt", now_update);

    let tracked_links_docs: Vec<bson::Document> = curated_links
        .iter()
        .take(12)
        .map(|(name, url)| {
            doc! {
                "name": name,
                "url": url,
            }
        })
        .collect();
    source_set_doc.insert("trackedLinks", tracked_links_docs);

    if let Some(next_source_url) = llm_suggested_url {
        if should_update_source_url(&source_url, &next_source_url) {
            source_set_doc.insert("url", next_source_url.clone());
            final_source_url = next_source_url;
        }
    }

    if let Err(e) = sources_coll
        .update_one(
            doc! { "user_id": &user_id, "id": id },
            doc! { "$set": source_set_doc },
        )
        .await
    {
        eprintln!("api_newsletter_sources_summarize source update error: {}", e);
    }

    let now = Utc::now().to_rfc3339();
    let item_id = format!("n-{}", Uuid::new_v4());
    let signal = parsed_signal.unwrap_or_else(|| compute_signal(&summary));
    let links_docs: Vec<bson::Document> = curated_links
        .iter()
        .map(|(name, url)| {
            doc! {
                "name": name,
                "url": url,
            }
        })
        .collect();

    let item_doc = doc! {
        "id": &item_id,
        "user_id": &user_id,
        "sourceId": id,
        "title": title,
        "topic": topic,
        "summary": &summary,
        "signal": signal,
        "links": links_docs,
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
                    "url": final_source_url,
                },
                "model": model,
                "fetchedChars": snippet.chars().count(),
                "discoveredLinks": discovered_links.len(),
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

#[cfg(test)]
mod tests {
    use super::{
        build_summary_from_article_digests, discover_section_urls, ensure_sources_block,
        extract_html_links, extract_http_urls, should_update_source_url,
    };

    #[test]
    fn extract_html_links_resolves_relative_urls() {
        let html = r#"<a href=\"/blog/post-1\">Post</a><a href=\"https://example.com/news\">News</a>"#;
        let links = extract_html_links("https://example.com", html, 10);
        assert!(links.contains(&"https://example.com/blog/post-1".to_string()));
        assert!(links.contains(&"https://example.com/news".to_string()));
    }

    #[test]
    fn extract_http_urls_grabs_embedded_links() {
        let txt = "Lire https://example.com/a puis https://example.com/b.";
        let urls = extract_http_urls(txt, 10);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/a");
    }

    #[test]
    fn should_update_source_url_only_from_homepage_to_specific_path() {
        assert!(should_update_source_url(
            "https://example.com",
            "https://example.com/blog/post-1"
        ));
        assert!(!should_update_source_url(
            "https://example.com/blog/post-0",
            "https://example.com/blog/post-1"
        ));
        assert!(!should_update_source_url(
            "https://example.com",
            "https://other.com/post"
        ));
    }

    #[test]
    fn discover_section_urls_contains_common_editorial_paths() {
        let urls = discover_section_urls("https://thoughtworks.com");
        assert!(urls.contains(&"https://thoughtworks.com/insights".to_string()));
        assert!(urls.contains(&"https://thoughtworks.com/blog".to_string()));
    }

    #[test]
    fn ensure_sources_block_appends_sources_when_missing() {
        let summary = "Synthèse des tendances cloud et IA.";
        let links = vec![
            (
                "Article A".to_string(),
                "https://example.com/a".to_string(),
            ),
            (
                "Article B".to_string(),
                "https://example.com/b".to_string(),
            ),
        ];

        let rendered = ensure_sources_block(summary, &links);
        assert!(rendered.contains("Sources:"));
        assert!(rendered.contains("https://example.com/a"));
        assert!(rendered.contains("https://example.com/b"));
    }

    #[test]
    fn build_summary_from_article_digests_renders_summary_and_sources() {
        let payload = serde_json::json!({
            "articleDigests": [
                {
                    "title": "Post 1",
                    "url": "https://example.com/p1",
                    "summary": "Contenu orienté architecture distribuée."
                },
                {
                    "title": "Post 2",
                    "url": "https://example.com/p2",
                    "summary": "Contenu orienté fiabilité et observabilité."
                }
            ]
        });

        let out = build_summary_from_article_digests(&Some(payload)).unwrap_or_default();
        assert!(out.contains("1. Post 1 — Contenu orienté architecture distribuée."));
        assert!(out.contains("2. Post 2 — Contenu orienté fiabilité et observabilité."));
        assert!(out.contains("Sources:"));
        assert!(out.contains("https://example.com/p1"));
    }
}
