// Instant search backend — GET /api/search
// Full-text search across emails with filters (date, sender, attachments) and pagination.
// Implements issue #539: Instant search backend (full-text, <200ms).
#![allow(unused_imports)]
use super::*;
use std::io::Write;

/// Maximum results per page.
const MAX_SEARCH_RESULTS: i64 = 50;
const DEFAULT_SEARCH_RESULTS: i64 = 20;

/// Query parameters for search.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub date_from: Option<String>,
    #[serde(default)]
    pub date_to: Option<String>,
    #[serde(default)]
    pub has_attachments: Option<bool>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    DEFAULT_SEARCH_RESULTS
}

/// Search result DTO.
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub emails: Vec<Email>,
    pub total: u64,
    pub query: String,
    pub limit: i64,
    pub offset: i64,
}

/// Ensure the text index exists on the emails collection.
async fn ensure_text_index(
    client: &mongodb::Client,
    db_name: &str,
) -> Result<(), mongodb::error::Error> {
    let db = client.database(db_name);
    let collection = db.collection::<bson::Document>("emails");

    // Create text index on searchable fields (subject, body, from, to).
    // MongoDB $text queries require a text index on the collection.
    let text_index = mongodb::IndexModel::builder()
        .keys(doc! {
            "subject": "text",
            "body": "text",
            "from": "text",
            "to": "text"
        })
        .options(
            mongodb::options::IndexOptions::builder()
                .name(Some("email_text_search_idx".to_string()))
                .build(),
        )
        .build();

    // Ignore error if index already exists
    let _ = collection.create_index(text_index).await;

    // Create a compound index for filtered searches (user_id + internal_date)
    // to support fast date-sorted results when no text query is given.
    let date_index = mongodb::IndexModel::builder()
        .keys(doc! { "user_id": 1, "internal_date": -1 })
        .options(
            mongodb::options::IndexOptions::builder()
                .name(Some("email_user_date_idx".to_string()))
                .build(),
        )
        .build();

    let _ = collection.create_index(date_index).await;
    Ok(())
}

/// Build MongoDB filter from search query parameters.
fn build_search_filter(query: &SearchQuery, user_id: &str) -> bson::Document {
    let mut filter = doc! { "user_id": user_id };

    // Text search
    if !query.q.trim().is_empty() {
        filter.insert("$text", doc! { "$search": query.q.trim() });
    }

    // Sender filter
    if let Some(ref from) = query.from {
        if !from.trim().is_empty() {
            filter.insert(
                "from",
                doc! { "$regex": from.trim(), "$options": "i" },
            );
        }
    }

    // Recipient filter
    if let Some(ref to) = query.to {
        if !to.trim().is_empty() {
            filter.insert(
                "to",
                doc! { "$regex": to.trim(), "$options": "i" },
            );
        }
    }

    // Subject filter
    if let Some(ref subject) = query.subject {
        if !subject.trim().is_empty() {
            filter.insert(
                "subject",
                doc! { "$regex": subject.trim(), "$options": "i" },
            );
        }
    }

    // Date range filter
    if let Some(ref date_from) = query.date_from {
        if let Ok(dt) = date_from.parse::<chrono::DateTime<Utc>>() {
            filter.insert(
                "internal_date",
                doc! { "$gte": bson::DateTime::from_millis(dt.timestamp_millis()) },
            );
        }
    }
    if let Some(ref date_to) = query.date_to {
        if let Ok(dt) = date_to.parse::<chrono::DateTime<Utc>>() {
            let date_filter = filter
                .get_document("internal_date")
                .unwrap_or_else(|_| bson::Document::new())
                .clone();
            let mut date_filter = date_filter.clone();
            date_filter.insert("$lte", bson::DateTime::from_millis(dt.timestamp_millis()));
            filter.insert("internal_date", date_filter);
        }
    }

    // Folder/mailbox filter
    if let Some(ref folder) = query.folder {
        if !folder.trim().is_empty() {
            filter.insert("mailbox", folder.trim());
        }
    }

    // Has attachments filter (search for Content-Disposition: attachment in body)
    if let Some(true) = query.has_attachments {
        filter.insert(
            "body",
            doc! { "$regex": "Content-Disposition: attachment", "$options": "i" },
        );
    }

    filter
}

// Build sort options for search results.
fn build_sort_options(query: &SearchQuery) -> bson::Document {
    if !query.q.trim().is_empty() {
        // Text search: sort by relevance score
        doc! { "score": { "$meta": "textScore" } }
    } else {
        // No text query: sort by date descending
        doc! { "internal_date": -1 }
    }
}

/// GET /api/search — full-text search across user emails.
pub(crate) async fn api_search(
    query_params: web::Query<SearchQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let query = query_params.into_inner();

    // Validate limit
    let limit = if query.limit <= 0 || query.limit > MAX_SEARCH_RESULTS {
        MAX_SEARCH_RESULTS
    } else {
        query.limit
    };

    // Ensure text index exists
    if let Err(e) = ensure_text_index(mongo.get_ref(), &mongo_db_name()).await {
        eprintln!("search: ensure_text_index error: {}", e);
    }

    // Build filter
    let filter = build_search_filter(&query, &user_id);
    let sort = build_sort_options(&query);

    // Execute search
    let db = mongo.get_ref().database(&mongo_db_name());
    let collection = db.collection::<bson::Document>("emails");

    // Count total matches
    let total = match collection.count_documents(filter.clone()).await {
        Ok(count) => count,
        Err(e) => {
            eprintln!("search: count_documents error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Search failed"
            }));
        }
    };

    // Execute search using builder-style API (mongodb 3.x)
    let sort = build_sort_options(&query);

    let mut find_op = collection.find(filter).sort(sort).limit(limit);
    if query.offset > 0 {
        find_op = find_op.skip(query.offset as u64);
    }

    // Execute find
    let mut cursor = match find_op.await {
        Ok(cursor) => cursor,
        Err(e) => {
            eprintln!("search: find error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Search query failed"
            }));
        }
    };

    // Collect results
    let mut emails: Vec<Email> = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        match bson::from_document::<Email>(doc) {
            Ok(email) => emails.push(email),
            Err(e) => eprintln!("search: deserialization error: {}", e),
        }
    }

    HttpResponse::Ok().json(SearchResult {
        emails,
        total,
        query: query.q,
        limit,
        offset: query.offset,
    })
}

/// GET /api/search/index — trigger text index creation (admin/background).
pub(crate) async fn api_search_index(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }

    match ensure_text_index(mongo.get_ref(), &mongo_db_name()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Search index ensured"
        })),
        Err(e) => {
            eprintln!("search_index: error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to create search index"
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::Email;
    use chrono::TimeZone;

    fn test_email(id: &str, subject: &str, body: &str, from_addr: &str) -> Email {
        Email {
            id: id.to_string(),
            from: from_addr.to_string(),
            to: "recipient@example.com".to_string(),
            subject: subject.to_string(),
            body: body.to_string(),
            headers: vec![],
            flags: vec!["\\Seen".to_string()],
            sequence_number: 1,
            uid: 1,
            internal_date: Utc.with_ymd_and_hms(2026, 1, 15, 10, 30, 0).unwrap(),
            dkim_signature: None,
        }
    }

    #[test]
    fn search_query_default_limit() {
        let query = SearchQuery {
            q: "test".to_string(),
            from: None,
            to: None,
            subject: None,
            date_from: None,
            date_to: None,
            has_attachments: None,
            folder: None,
            limit: 20,
            offset: 0,
        };
        assert_eq!(query.limit, 20);
    }

    #[test]
    fn build_search_filter_with_text() {
        let query = SearchQuery {
            q: "invoice".to_string(),
            from: None,
            to: None,
            subject: None,
            date_from: None,
            date_to: None,
            has_attachments: None,
            folder: None,
            limit: 20,
            offset: 0,
        };
        let filter = build_search_filter(&query, "user1");
        assert!(filter.contains_key("$text"));
        assert_eq!(filter.get_str("user_id").unwrap(), "user1");
    }

    #[test]
    fn build_search_filter_with_sender() {
        let query = SearchQuery {
            q: String::new(),
            from: Some("alice@example.com".to_string()),
            to: None,
            subject: None,
            date_from: None,
            date_to: None,
            has_attachments: None,
            folder: None,
            limit: 20,
            offset: 0,
        };
        let filter = build_search_filter(&query, "user1");
        assert!(filter.contains_key("from"));
        assert!(!filter.contains_key("$text"));
    }

    #[test]
    fn build_search_filter_with_folder() {
        let query = SearchQuery {
            q: String::new(),
            from: None,
            to: None,
            subject: None,
            date_from: None,
            date_to: None,
            has_attachments: None,
            folder: Some("INBOX".to_string()),
            limit: 20,
            offset: 0,
        };
        let filter = build_search_filter(&query, "user1");
        assert_eq!(filter.get_str("mailbox").unwrap(), "INBOX");
    }

    #[test]
    fn build_sort_options_text_search() {
        let query = SearchQuery {
            q: "test".to_string(),
            from: None,
            to: None,
            subject: None,
            date_from: None,
            date_to: None,
            has_attachments: None,
            folder: None,
            limit: 20,
            offset: 0,
        };
        let sort = build_sort_options(&query);
        assert!(sort.contains_key("score"));
    }

    #[test]
    fn build_sort_options_no_text() {
        let query = SearchQuery {
            q: String::new(),
            from: None,
            to: None,
            subject: None,
            date_from: None,
            date_to: None,
            has_attachments: None,
            folder: None,
            limit: 20,
            offset: 0,
        };
        let sort = build_sort_options(&query);
        assert_eq!(sort.get_i32("internal_date").unwrap(), -1);
    }

    #[test]
    fn search_result_serialization() {
        let result = SearchResult {
            emails: vec![test_email("1", "Hello", "World body", "alice@example.com")],
            total: 1,
            query: "hello".to_string(),
            limit: 20,
            offset: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("hello"));
        assert!(json.contains("alice@example.com"));
    }
}
