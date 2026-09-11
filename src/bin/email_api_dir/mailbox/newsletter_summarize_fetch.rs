use super::*;

pub(crate) async fn build_source_context(
    sources_coll: &mongodb::Collection<bson::Document>,
    id: &str,
    user_id: &str,
    topic: String,
) -> Result<SourceSummarizeContext, HttpResponse> {
    let source_doc = load_source_doc(sources_coll, id, user_id).await?;
    let source_name = source_name(&source_doc);
    let source_url = source_url(&source_doc)?;
    let client = build_client()?;

    let (raw_source_body, source_content_type) = fetch_text_response(
        &client,
        &source_url,
        "api_newsletter_sources_summarize",
        "source URL",
    )
    .await?;

    let fetched = normalize_source_text(&source_content_type, &raw_source_body);
    if fetched.is_empty() {
        return Err(HttpResponse::BadGateway().json(serde_json::json!({
            "message": "Source URL content is empty",
        })));
    }

    let snippet = links::truncate_chars(&fetched, 12_000);
    let discovered_links = collect_discovered_links(&client, &source_url, &raw_source_body, &source_content_type).await;
    let link_contexts = fetch_link_contexts(&client, &discovered_links).await;

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

async fn load_source_doc(
    sources_coll: &mongodb::Collection<bson::Document>,
    id: &str,
    user_id: &str,
) -> Result<bson::Document, HttpResponse> {
    match sources_coll.find_one(doc! { "user_id": user_id, "id": id }).await {
        Ok(Some(docu)) => Ok(docu),
        Ok(None) => Err(HttpResponse::NotFound().json(serde_json::json!({
            "message": "Source not found",
        }))),
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize source lookup error: {}", e);
            Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to summarize source",
            })))
        }
    }
}

fn source_name(source_doc: &bson::Document) -> String {
    source_doc
        .get_str("name")
        .ok()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Source".to_string())
}

fn source_url(source_doc: &bson::Document) -> Result<String, HttpResponse> {
    source_doc
        .get_str("url")
        .ok()
        .and_then(|v| normalize_url(Some(v)))
        .ok_or_else(|| {
            HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Source URL is required before generating a summary",
            }))
        })
}

fn build_client() -> Result<reqwest::Client, HttpResponse> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .user_agent("misfits-newsletter-summarizer/1.0")
        .build()
        .map_err(|e| {
            eprintln!("api_newsletter_sources_summarize reqwest build error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to initialize URL fetch client",
            }))
        })
}

async fn fetch_text_response(
    client: &reqwest::Client,
    url: &str,
    log_prefix: &str,
    target: &str,
) -> Result<(String, String), HttpResponse> {
    let response = client.get(url).send().await.map_err(|e| {
        eprintln!("{log_prefix} fetch error: {}", e);
        HttpResponse::BadGateway().json(serde_json::json!({
            "message": format!("Unable to fetch {target}"),
        }))
    })?;

    if !response.status().is_success() {
        return Err(HttpResponse::BadGateway().json(serde_json::json!({
            "message": format!("Failed to fetch {target} (status {})", response.status()),
        })));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    let body = response.text().await.map_err(|e| {
        eprintln!("{log_prefix} body read error: {}", e);
        HttpResponse::BadGateway().json(serde_json::json!({
            "message": format!("Unable to read {target} content"),
        }))
    })?;

    Ok((body, content_type))
}

fn normalize_source_text(content_type: &str, body: &str) -> String {
    if links::is_html_payload(content_type, body) {
        links::normalize_plain_text(&strip_tags(body))
    } else {
        links::normalize_plain_text(body)
    }
}

async fn collect_discovered_links(
    client: &reqwest::Client,
    source_url: &str,
    raw_source_body: &str,
    source_content_type: &str,
) -> Vec<String> {
    let mut discovered_links = if links::is_html_payload(source_content_type, raw_source_body) {
        links::extract_html_links(source_url, raw_source_body, 20)
    } else {
        Vec::new()
    };

    if discovered_links.len() >= 8 {
        return discovered_links;
    }

    for section_url in links::discover_section_urls(source_url) {
        let Ok(section_resp) = client.get(&section_url).send().await else {
            continue;
        };
        if !section_resp.status().is_success() {
            continue;
        }

        let section_type = section_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let Ok(section_body) = section_resp.text().await else {
            continue;
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

    discovered_links
}

async fn fetch_link_contexts(client: &reqwest::Client, discovered_links: &[String]) -> Vec<String> {
    let mut link_contexts: Vec<String> = Vec::new();

    for link in discovered_links.iter().take(4) {
        let Ok(response) = client.get(link).send().await else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();

        let Ok(body) = response.text().await else {
            continue;
        };

        let page_text = normalize_source_text(&content_type, &body);
        if page_text.is_empty() {
            continue;
        }

        link_contexts.push(format!(
            "URL: {}\nExtrait: {}",
            link,
            links::truncate_chars(&page_text, 1_800)
        ));
    }

    link_contexts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_name_returns_name_field() {
        let doc = doc! { "name": "TechCrunch" };
        assert_eq!(source_name(&doc), "TechCrunch");
    }

    #[test]
    fn source_name_defaults_to_source() {
        let doc = doc! { "url": "https://example.com" };
        assert_eq!(source_name(&doc), "Source");
    }

    #[test]
    fn source_name_empty_doc() {
        let doc = doc! {};
        assert_eq!(source_name(&doc), "Source");
    }

    #[test]
    fn normalize_source_text_html() {
        let result = normalize_source_text("text/html", "<p>Hello   World</p>");
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn normalize_source_text_plain() {
        let result = normalize_source_text("text/plain", "Hello   World");
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn normalize_source_text_html_body_without_content_type() {
        let result = normalize_source_text("text/plain", "<html><body>Hello   World</body></html>");
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn normalize_source_text_empty() {
        let result = normalize_source_text("text/plain", "");
        assert_eq!(result, "");
    }

    #[test]
    fn source_url_valid() {
        let doc = doc! { "url": "example.com" };
        assert!(source_url(&doc).is_ok());
        assert_eq!(source_url(&doc).unwrap(), "https://example.com");
    }

    #[test]
    fn source_url_with_https() {
        let doc = doc! { "url": "https://example.com" };
        assert_eq!(source_url(&doc).unwrap(), "https://example.com");
    }

    #[test]
    fn source_url_missing() {
        let doc = doc! { "name": "No URL" };
        assert!(source_url(&doc).is_err());
    }

    #[test]
    fn source_url_empty() {
        let doc = doc! { "url": "" };
        assert!(source_url(&doc).is_err());
    }
}
