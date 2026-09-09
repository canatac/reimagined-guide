use super::*;

pub(crate) async fn api_newsletter_items_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("newsletter_items");

    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "createdAt": -1 })
        .limit(1000)
        .await
    {
        Ok(cursor) => {
            let mut items: Vec<serde_json::Value> = Vec::new();
            for mut docu in cursor
                .try_collect::<Vec<bson::Document>>()
                .await
                .unwrap_or_default()
            {
                docu.remove("_id");
                docu.remove("user_id");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu)) {
                    items.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({"items": items, "total": items.len()}))
        }
        Err(e) => {
            eprintln!("api_newsletter_items_list error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to load newsletter items",
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_url;

    #[test]
    fn normalize_url_removes_blank_values() {
        assert_eq!(normalize_url(Some("   ")), None);
    }

    #[test]
    fn normalize_url_preserves_absolute_urls() {
        assert_eq!(
            normalize_url(Some("http://example.com/news")),
            Some("http://example.com/news".to_string())
        );
        assert_eq!(
            normalize_url(Some("https://example.com/news")),
            Some("https://example.com/news".to_string())
        );
    }

    #[test]
    fn normalize_url_adds_https_scheme_when_missing() {
        assert_eq!(
            normalize_url(Some("example.com/news")),
            Some("https://example.com/news".to_string())
        );
    }
}

pub(crate) async fn api_newsletter_items_create(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<CreateNewsletterItemInput>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);

    let source_id = body.source_id.trim();
    let title = body.title.trim();
    let summary = body.summary.trim();

    if source_id.is_empty() || title.is_empty() || summary.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "sourceId, title and summary are required",
        }));
    }

    let db = mongo.database(&mongo_db_name());
    let src_coll = db.collection::<bson::Document>("newsletter_sources");
    let items_coll = db.collection::<bson::Document>("newsletter_items");

    let source_doc = match src_coll
        .find_one(doc! { "user_id": &user_id, "id": source_id })
        .await
    {
        Ok(Some(docu)) => docu,
        Ok(None) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "sourceId does not exist",
            }))
        }
        Err(e) => {
            eprintln!("api_newsletter_items_create source lookup error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to create newsletter item",
            }));
        }
    };

    let source_name = source_doc
        .get_str("name")
        .ok()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Source".to_string());
    let source_url = source_doc.get_str("url").ok().map(|s| s.to_string());

    let now = Utc::now().to_rfc3339();
    let id = format!("n-{}", Uuid::new_v4());
    let topic = normalize_topic(body.topic.as_deref());
    let signal = compute_signal(summary, body.signal);
    let link = normalize_url(body.link.as_deref())
        .or(source_url)
        .unwrap_or_else(|| "#".to_string());

    let item_doc = doc! {
        "id": &id,
        "user_id": &user_id,
        "sourceId": source_id,
        "title": title,
        "topic": topic,
        "summary": summary,
        "signal": signal,
        "links": [
            {
                "name": source_name,
                "url": link,
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
            let json = bson::from_bson::<serde_json::Value>(bson::Bson::Document(out))
                .unwrap_or_else(|_| serde_json::json!({}));
            HttpResponse::Created().json(json)
        }
        Err(e) => {
            eprintln!("api_newsletter_items_create insert error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to create newsletter item",
            }))
        }
    }
}
