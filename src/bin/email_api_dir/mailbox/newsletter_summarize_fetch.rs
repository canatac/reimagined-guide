use super::*;

pub(crate) async fn build_source_context(
    sources_coll: &mongodb::Collection<bson::Document>,
    id: &str,
    user_id: &str,
    topic: String,
) -> Result<SourceSummarizeContext, HttpResponse> {
    let source_doc = match sources_coll.find_one(doc! { "user_id": user_id, "id": id }).await {
        Ok(Some(docu)) => docu,
        Ok(None) => {
            return Err(HttpResponse::NotFound().json(serde_json::json!({
                "message": "Source not found",
            })))
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize source lookup error: {}", e);
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to summarize source",
            })));
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
            return Err(HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Source URL is required before generating a summary",
            })))
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
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to initialize URL fetch client",
            })));
        }
    };

    let (raw_source_body, source_content_type) = match client.get(&source_url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                return Err(HttpResponse::BadGateway().json(serde_json::json!({
                    "message": format!("Failed to fetch source URL (status {})", resp.status()),
                })));
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
                    return Err(HttpResponse::BadGateway().json(serde_json::json!({
                        "message": "Unable to read source URL content",
                    })));
                }
            };

            (raw_body, content_type)
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize fetch error: {}", e);
            return Err(HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Unable to fetch source URL",
            })));
        }
    };

    let fetched = if links::is_html_payload(&source_content_type, &raw_source_body) {
        links::normalize_plain_text(&strip_tags(&raw_source_body))
    } else {
        links::normalize_plain_text(&raw_source_body)
    };

    if fetched.is_empty() {
        return Err(HttpResponse::BadGateway().json(serde_json::json!({
            "message": "Source URL content is empty",
        })));
    }

    let snippet = links::truncate_chars(&fetched, 12_000);

    let mut discovered_links = if links::is_html_payload(&source_content_type, &raw_source_body) {
        links::extract_html_links(&source_url, &raw_source_body, 20)
    } else {
        Vec::new()
    };

    if discovered_links.len() < 8 {
        for section_url in links::discover_section_urls(&source_url) {
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
            if !links::is_html_payload(&section_type, &section_body) {
                continue;
            }
            links::merge_links(
                &mut discovered_links,
                links::extract_html_links(&section_url, &section_body, 12),
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
                        if links::is_html_payload(&content_type, &body) {
                            links::normalize_plain_text(&strip_tags(&body))
                        } else {
                            links::normalize_plain_text(&body)
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
            links::truncate_chars(&page_text, 1_800)
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

    Ok(SourceSummarizeContext {
        source_name,
        source_url,
        snippet,
        discovered_links,
        links_overview,
        context_blob,
        topic,
    })
}
