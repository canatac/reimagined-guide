use super::*;

pub(crate) async fn summarize_with_hermes(
    mongo: &Arc<mongodb::Client>,
    user_id: &str,
    id: &str,
    context: &SourceSummarizeContext,
) -> Result<LlmSummaryData, HttpResponse> {
    let settings = load_ai_settings(mongo).await;
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
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "HERMES_API_KEY is not configured",
            })))
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
                    context.source_name,
                    context.source_url,
                    context.topic,
                    context.links_overview,
                    context.context_blob,
                    context.snippet
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
                mongo,
                LlmUsageEvent {
                    feature: "newsletter_summarize".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(llm_session_id.clone()),
                    user_id: Some(user_id.to_string()),
                    source_id: Some(id.to_string()),
                    source_url: Some(context.source_url.clone()),
                    error: Some(format!("request_error: {}", e)),
                },
            )
            .await;
            return Err(HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Newsletter summarization upstream is unavailable",
            })));
        }
    };

    if !hermes_response.status().is_success() {
        let status = hermes_response.status();
        let body = hermes_response.text().await.unwrap_or_default();
        log_llm_usage_event(
            mongo,
            LlmUsageEvent {
                feature: "newsletter_summarize".to_string(),
                status: "failed".to_string(),
                model: model.clone(),
                prompt_tokens: 0,
                completion_tokens: 0,
                total_tokens: 0,
                latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
                session_id: Some(llm_session_id.clone()),
                user_id: Some(user_id.to_string()),
                source_id: Some(id.to_string()),
                source_url: Some(context.source_url.clone()),
                error: Some(format!("status_{}", status.as_u16())),
            },
        )
        .await;
        eprintln!(
            "api_newsletter_sources_summarize hermes upstream status={} body={}",
            status, body
        );
        return Err(HttpResponse::BadGateway().json(serde_json::json!({
            "message": format!("Newsletter summarization failed (status {})", status),
        })));
    }

    let hermes_json = match hermes_response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_newsletter_sources_summarize hermes json parse error: {}", e);
            log_llm_usage_event(
                mongo,
                LlmUsageEvent {
                    feature: "newsletter_summarize".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(llm_session_id.clone()),
                    user_id: Some(user_id.to_string()),
                    source_id: Some(id.to_string()),
                    source_url: Some(context.source_url.clone()),
                    error: Some(format!("invalid_json: {}", e)),
                },
            )
            .await;
            return Err(HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Invalid summarization upstream response",
            })));
        }
    };

    let (prompt_tokens, completion_tokens, total_tokens) = extract_llm_usage_tokens(&hermes_json);
    log_llm_usage_event(
        mongo,
        LlmUsageEvent {
            feature: "newsletter_summarize".to_string(),
            status: "completed".to_string(),
            model: model.clone(),
            prompt_tokens,
            completion_tokens,
            total_tokens,
            latency_ms: Some(i64::try_from(llm_started.elapsed().as_millis()).unwrap_or(0)),
            session_id: Some(llm_session_id.clone()),
            user_id: Some(user_id.to_string()),
            source_id: Some(id.to_string()),
            source_url: Some(context.source_url.clone()),
            error: None,
        },
    )
    .await;

    let summary_payload = match parsing::extract_completion_content(&hermes_json) {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return Err(HttpResponse::BadGateway().json(serde_json::json!({
                "message": "Summarization upstream returned empty content",
            })))
        }
    };

    let parsed_json = parsing::extract_json_object(&summary_payload);
    let fallback_summary = summary_payload.trim().to_string();

    let title = parsed_json
        .as_ref()
        .and_then(|v| v.get("title"))
        .and_then(|v| v.as_str())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("Digest {}", context.source_name));

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
        curated_links = parsing::extract_http_urls(&base_summary, 4)
            .into_iter()
            .enumerate()
            .map(|(idx, url)| (format!("Lien recommandé {}", idx + 1), url))
            .collect::<Vec<_>>();
    }

    if curated_links.is_empty() {
        curated_links = context
            .discovered_links
            .iter()
            .take(3)
            .enumerate()
            .map(|(idx, url)| (format!("Article {}", idx + 1), url.to_string()))
            .collect::<Vec<_>>();
    }

    if curated_links.is_empty() {
        curated_links.push((context.source_name.clone(), context.source_url.clone()));
    }

    let summary = parsing::build_summary_from_article_digests(&parsed_json).unwrap_or(base_summary);
    let summary = parsing::ensure_sources_block(&summary, &curated_links);

    let llm_suggested_url = parsed_json
        .as_ref()
        .and_then(|v| v.get("updatedSourceUrl"))
        .and_then(|v| v.as_str())
        .and_then(|v| normalize_url(Some(v)));

    Ok(LlmSummaryData {
        model,
        title,
        summary,
        parsed_signal,
        curated_links,
        llm_suggested_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_summary_data_default_model_fallback() {
        // Test that when no newsletter/triage feature is set, default_model is used
        // This is a logic test since we can't easily mock load_ai_settings
        let default_model = "gpt-4".to_string();
        let features = std::collections::HashMap::new();
        
        let model = features
            .get("newsletter")
            .or_else(|| features.get("triage"))
            .cloned()
            .unwrap_or_else(|| default_model.clone());
        
        assert_eq!(model, "gpt-4");
    }

    #[test]
    fn llm_summary_data_newsletter_feature_preferred() {
        let default_model = "gpt-4".to_string();
        let mut features = std::collections::HashMap::new();
        features.insert("newsletter".to_string(), "claude-3".to_string());
        features.insert("triage".to_string(), "gpt-3.5".to_string());
        
        let model = features
            .get("newsletter")
            .or_else(|| features.get("triage"))
            .cloned()
            .unwrap_or_else(|| default_model.clone());
        
        assert_eq!(model, "claude-3");
    }

    #[test]
    fn llm_summary_data_triage_fallback() {
        let default_model = "gpt-4".to_string();
        let mut features = std::collections::HashMap::new();
        features.insert("triage".to_string(), "gpt-3.5".to_string());
        
        let model = features
            .get("newsletter")
            .or_else(|| features.get("triage"))
            .cloned()
            .unwrap_or_else(|| default_model.clone());
        
        assert_eq!(model, "gpt-3.5");
    }
}
