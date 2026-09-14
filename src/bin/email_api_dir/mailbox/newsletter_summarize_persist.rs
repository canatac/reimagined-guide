use super::*;

pub(crate) async fn persist_summary_item(
    sources_coll: &mongodb::Collection<bson::Document>,
    items_coll: &mongodb::Collection<bson::Document>,
    id: &str,
    user_id: &str,
    context: &SourceSummarizeContext,
    llm_data: LlmSummaryData,
) -> HttpResponse {
    let mut final_source_url = context.source_url.clone();
    let mut source_set_doc = doc! {};
    source_set_doc.insert("updatedAt", Utc::now().to_rfc3339());

    let tracked_links_docs: Vec<bson::Document> = llm_data
        .curated_links
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

    if let Some(next_source_url) = llm_data.llm_suggested_url.as_ref() {
        if links::should_update_source_url(&context.source_url, next_source_url) {
            source_set_doc.insert("url", next_source_url.clone());
            final_source_url = next_source_url.clone();
        }
    }

    if let Err(e) = sources_coll
        .update_one(
            doc! { "user_id": user_id, "id": id },
            doc! { "$set": source_set_doc },
        )
        .await
    {
        eprintln!("api_newsletter_sources_summarize source update error: {}", e);
    }

    let now = Utc::now().to_rfc3339();
    let item_id = format!("n-{}", Uuid::new_v4());
    let signal = llm_data
        .parsed_signal
        .unwrap_or_else(|| compute_signal(&llm_data.summary));
    let links_docs: Vec<bson::Document> = llm_data
        .curated_links
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
        "user_id": user_id,
        "sourceId": id,
        "title": llm_data.title,
        "topic": context.topic.clone(),
        "summary": &llm_data.summary,
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
                    "name": context.source_name,
                    "url": final_source_url,
                },
                "model": llm_data.model,
                "fetchedChars": context.snippet.chars().count(),
                "discoveredLinks": context.discovered_links.len(),
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
    use super::*;

    #[test]
    fn test_compute_signal_short_summary() {
        assert_eq!(compute_signal("short"), 65);
    }

    #[test]
    fn test_compute_signal_long_summary() {
        let long = "a".repeat(400);
        assert_eq!(compute_signal(&long), 85);
    }

    #[test]
    fn test_compute_signal_clamps_max() {
        let huge = "a".repeat(1000);
        assert_eq!(compute_signal(&huge), 98);
    }
}
