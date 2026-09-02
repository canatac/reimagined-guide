#![allow(unused_imports)]
use super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateNewsletterSourceInput {
    name: String,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateNewsletterItemInput {
    source_id: String,
    title: String,
    summary: String,
    #[serde(default)]
    topic: Option<String>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    signal: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateNewsletterSourceInput {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    url: Option<String>,
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

fn compute_signal(summary: &str, requested: Option<i32>) -> i32 {
    if let Some(v) = requested {
        return v.clamp(0, 100);
    }
    let boost = (summary.trim().chars().count() / 20) as i32;
    (65 + boost).clamp(50, 98)
}

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

pub(crate) async fn api_newsletter_sources_create(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<CreateNewsletterSourceInput>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let name = body.name.trim();
    if name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Source name is required",
        }));
    }

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("newsletter_sources");

    let name_lc = name.to_lowercase();
    match coll
        .find_one(doc! { "user_id": &user_id, "name_lc": &name_lc })
        .await
    {
        Ok(Some(mut existing)) => {
            existing.remove("_id");
            existing.remove("user_id");
            existing.remove("name_lc");
            let json = bson::from_bson::<serde_json::Value>(bson::Bson::Document(existing))
                .unwrap_or_else(|_| serde_json::json!({}));
            return HttpResponse::Ok().json(json);
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("api_newsletter_sources_create precheck error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to create source",
            }));
        }
    }

    let now = Utc::now().to_rfc3339();
    let id = format!("src-{}", Uuid::new_v4());
    let mut source_doc = doc! {
        "id": &id,
        "user_id": &user_id,
        "name": name,
        "name_lc": &name_lc,
        "createdAt": &now,
        "updatedAt": &now,
    };

    if let Some(url) = normalize_url(body.url.as_deref()) {
        source_doc.insert("url", url);
    }

    match coll.insert_one(source_doc.clone()).await {
        Ok(_) => {
            source_doc.remove("_id");
            source_doc.remove("user_id");
            source_doc.remove("name_lc");
            let json = bson::from_bson::<serde_json::Value>(bson::Bson::Document(source_doc))
                .unwrap_or_else(|_| serde_json::json!({}));
            HttpResponse::Created().json(json)
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_create insert error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to create source",
            }))
        }
    }
}

pub(crate) async fn api_newsletter_sources_update(
    req: actix_web::HttpRequest,
    source_id: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<UpdateNewsletterSourceInput>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = source_id.trim();
    if id.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Source id is required",
        }));
    }

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("newsletter_sources");

    let existing = match coll.find_one(doc! { "user_id": &user_id, "id": id }).await {
        Ok(Some(docu)) => docu,
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Source not found",
            }));
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_update find error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to update source",
            }));
        }
    };

    let current_name = existing
        .get_str("name")
        .ok()
        .map(str::to_string)
        .unwrap_or_else(|| "Source".to_string());

    let next_name = match body.name.as_ref() {
        Some(raw) => {
            let name = raw.trim();
            if name.is_empty() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "message": "Source name cannot be empty",
                }));
            }
            name.to_string()
        }
        None => current_name,
    };

    let next_name_lc = next_name.to_lowercase();
    match coll
        .find_one(doc! { "user_id": &user_id, "name_lc": &next_name_lc, "id": { "$ne": id } })
        .await
    {
        Ok(Some(conflict)) => {
            let conflict_name = conflict.get_str("name").ok().unwrap_or("Source");
            return HttpResponse::Conflict().json(serde_json::json!({
                "message": format!("Source name already exists: {}", conflict_name),
            }));
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("api_newsletter_sources_update duplicate check error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to update source",
            }));
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut set_doc = doc! {
        "name": &next_name,
        "name_lc": &next_name_lc,
        "updatedAt": &now,
    };
    let mut unset_doc = doc! {};

    if let Some(raw_url) = body.url.as_ref() {
        if let Some(url) = normalize_url(Some(raw_url)) {
            set_doc.insert("url", url);
        } else {
            unset_doc.insert("url", "");
        }
    }

    let mut update_doc = doc! {
        "$set": set_doc,
    };
    if !unset_doc.is_empty() {
        update_doc.insert("$unset", unset_doc);
    }

    if let Err(e) = coll
        .update_one(doc! { "user_id": &user_id, "id": id }, update_doc)
        .await
    {
        eprintln!("api_newsletter_sources_update update error: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "message": "Failed to update source",
        }));
    }

    match coll.find_one(doc! { "user_id": &user_id, "id": id }).await {
        Ok(Some(mut docu)) => {
            docu.remove("_id");
            docu.remove("user_id");
            docu.remove("name_lc");
            let json = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu))
                .unwrap_or_else(|_| serde_json::json!({}));
            HttpResponse::Ok().json(json)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Source not found",
        })),
        Err(e) => {
            eprintln!("api_newsletter_sources_update post-read error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to update source",
            }))
        }
    }
}

pub(crate) async fn api_newsletter_sources_delete(
    req: actix_web::HttpRequest,
    source_id: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
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

    match sources_coll
        .find_one(doc! { "user_id": &user_id, "id": id })
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Source not found",
            }));
        }
        Err(e) => {
            eprintln!("api_newsletter_sources_delete find error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to delete source",
            }));
        }
    }

    let deleted_items = match items_coll
        .delete_many(doc! { "user_id": &user_id, "sourceId": id })
        .await
    {
        Ok(res) => res.deleted_count,
        Err(e) => {
            eprintln!("api_newsletter_sources_delete item cleanup error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to delete source",
            }));
        }
    };

    match sources_coll
        .delete_one(doc! { "user_id": &user_id, "id": id })
        .await
    {
        Ok(res) if res.deleted_count == 1 => HttpResponse::Ok().json(serde_json::json!({
            "deleted": true,
            "deletedItems": deleted_items,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Source not found",
        })),
        Err(e) => {
            eprintln!("api_newsletter_sources_delete source delete error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to delete source",
            }))
        }
    }
}

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
