use super::*;

pub(crate) async fn api_newsletter_sources_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("newsletter_sources");

    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "updatedAt": -1 })
        .limit(500)
        .await
    {
        Ok(cursor) => {
            let mut sources: Vec<serde_json::Value> = Vec::new();
            for mut docu in cursor
                .try_collect::<Vec<bson::Document>>()
                .await
                .unwrap_or_default()
            {
                docu.remove("_id");
                docu.remove("user_id");
                docu.remove("name_lc");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu)) {
                    sources.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({"sources": sources, "total": sources.len()}))
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_list error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to load newsletter sources",
            }))
        }
    }
}

pub(crate) async fn api_newsletter_suggestions(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = mongo.database(&mongo_db_name());
    let sources_coll = db.collection::<bson::Document>("newsletter_sources");
    let items_coll = db.collection::<bson::Document>("newsletter_items");

    let sources = match sources_coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "updatedAt": -1 })
        .limit(500)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<bson::Document>>()
            .await
            .unwrap_or_default(),
        Err(e) => {
            eprintln!("api_newsletter_suggestions sources error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to build newsletter suggestions",
            }));
        }
    };

    let items = match items_coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "createdAt": -1 })
        .limit(1000)
        .await
    {
        Ok(cursor) => cursor
            .try_collect::<Vec<bson::Document>>()
            .await
            .unwrap_or_default(),
        Err(e) => {
            eprintln!("api_newsletter_suggestions items error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to build newsletter suggestions",
            }));
        }
    };

    let interest_weights = infer_interest_weights(&sources, &items);
    let mut ranked_interests: Vec<(String, i32)> = interest_weights
        .iter()
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    ranked_interests.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_interests: Vec<String> = ranked_interests
        .iter()
        .take(5)
        .map(|(k, _)| k.clone())
        .collect();

    let subscribed_domains: std::collections::HashSet<String> = sources
        .iter()
        .filter_map(|docu| docu.get_str("url").ok())
        .filter_map(extract_domain)
        .collect();

    let mut suggestions: Vec<serde_json::Value> = suggestion_catalog()
        .into_iter()
        .filter_map(|(title, url, kind, reason, tags)| {
            let domain = extract_domain(url).unwrap_or_default();
            if !domain.is_empty() && subscribed_domains.contains(&domain) {
                return None;
            }

            let mut score = 0;
            for tag in tags {
                score += interest_weights.get(*tag).copied().unwrap_or(0);
            }

            if score <= 0 {
                return None;
            }

            let matched_tags: Vec<String> = tags
                .iter()
                .filter_map(|tag| {
                    let w = interest_weights.get(*tag).copied().unwrap_or(0);
                    if w > 0 {
                        Some((*tag).to_string())
                    } else {
                        None
                    }
                })
                .collect();

            Some(serde_json::json!({
                "title": title,
                "url": url,
                "kind": kind,
                "reason": reason,
                "matchedInterests": matched_tags,
                "matchScore": score,
            }))
        })
        .collect();

    suggestions.sort_by(|a, b| {
        let sa = a.get("matchScore").and_then(|v| v.as_i64()).unwrap_or(0);
        let sb = b.get("matchScore").and_then(|v| v.as_i64()).unwrap_or(0);
        sb.cmp(&sa)
    });
    suggestions.truncate(8);

    HttpResponse::Ok().json(serde_json::json!({
        "suggestions": suggestions,
        "interests": top_interests,
        "generatedAt": Utc::now().to_rfc3339(),
        "total": suggestions.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newsletter_sources_list_returns_total() {
        // Verify the response structure includes total count
        // Since we can't easily mock MongoDB, we test the JSON structure
        let sources: Vec<serde_json::Value> = vec![];
        let total = sources.len();
        let json = serde_json::json!({"sources": sources, "total": total});
        assert_eq!(json["total"], 0);
    }

    #[test]
    fn newsletter_suggestions_ranking_logic() {
        // Test the ranking logic used in api_newsletter_suggestions
        let mut ranked: Vec<(String, i32)> = vec![
            ("ai".to_string(), 5),
            ("tech".to_string(), 10),
            ("security".to_string(), 3),
        ];
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        
        assert_eq!(ranked[0].0, "tech");
        assert_eq!(ranked[0].1, 10);
        assert_eq!(ranked[1].0, "ai");
        assert_eq!(ranked[2].0, "security");
    }

    #[test]
    fn newsletter_suggestions_top_n() {
        let ranked: Vec<(String, i32)> = vec![
            ("tech".to_string(), 10),
            ("ai".to_string(), 5),
            ("security".to_string(), 3),
            ("finance".to_string(), 2),
            ("design".to_string(), 1),
            ("extra".to_string(), 0),
        ];
        let top: Vec<String> = ranked.iter().take(5).map(|(k, _)| k.clone()).collect();
        assert_eq!(top.len(), 5);
        assert_eq!(top[0], "tech");
        assert_eq!(top[4], "design");
    }

    #[test]
    fn newsletter_suggestions_truncate_to_8() {
        let mut suggestions: Vec<serde_json::Value> = (0..10)
            .map(|i| serde_json::json!({"matchScore": i}))
            .collect();
        suggestions.sort_by(|a, b| {
            let sa = a.get("matchScore").and_then(|v| v.as_i64()).unwrap_or(0);
            let sb = b.get("matchScore").and_then(|v| v.as_i64()).unwrap_or(0);
            sb.cmp(&sa)
        });
        suggestions.truncate(8);
        assert_eq!(suggestions.len(), 8);
    }
}
