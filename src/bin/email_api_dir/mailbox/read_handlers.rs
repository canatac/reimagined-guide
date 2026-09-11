// Sprint 8: split from mailbox_handlers.rs
#![allow(unused_imports)]
use super::*;

pub(crate) async fn api_email_attachment_download(
    path: web::Path<(String, String)>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let (email_id, attachment_id) = path.into_inner();

    match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => {
            let attachments = extract_attachments_for_ui(&email);
            if let Some(att) = attachments.into_iter().find(|a| a.id == attachment_id) {
                let safe_name = att.filename.replace('"', "_");
                return HttpResponse::Ok()
                    .insert_header(("Content-Type", att.content_type))
                    .insert_header((
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", safe_name),
                    ))
                    .body(att.data);
            }
            HttpResponse::NotFound().json(serde_json::json!({
                "message": "Attachment not found",
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("api_email_attachment_download fetch_email error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch attachment",
            }))
        }
    }
}

pub(crate) fn email_to_list_dto(email: &Email, folder: &str) -> EmailDto {
    email_to_dto(email, folder, false)
}

pub(crate) fn email_to_detail_dto(email: &Email, folder: &str) -> EmailDto {
    email_to_dto(email, folder, true)
}

pub(crate) async fn api_emails(
    query: web::Query<EmailListQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let folder = query.folder.trim().to_ascii_lowercase();
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 100);
    // Over-fetch a single page-sized chunk per mailbox candidate, then merge.
    // Skip huge dumps: limit from Mongo already newest-first.
    let fetch_limit = (page_size as i64)
        .saturating_mul(page as i64)
        .max(page_size as i64);

    let mut collected: Vec<Email> = Vec::new();
    let mut failed_mailboxes: Vec<String> = Vec::new();
    for mailbox in folder_to_mailboxes(&folder) {
        match logic
            .get_emails_page(&user_id, &mailbox, fetch_limit, 0)
            .await
        {
            Ok(mut batch) => {
                collected.append(&mut batch);
            }
            Err(e) => {
                eprintln!("get_emails mailbox={}: {}", mailbox, e);
                failed_mailboxes.push(mailbox);
            }
        }
    }

    if collected.is_empty() && !failed_mailboxes.is_empty() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "message": "Failed to read mailbox storage",
            "failedMailboxes": failed_mailboxes,
        }));
    }

    // Newest first (Mongo sort already does this; keep stable merge)
    collected.sort_by(|a, b| b.internal_date.cmp(&a.internal_date));
    // Dedup by id / message-id fallback
    let mut seen = std::collections::HashSet::new();
    collected.retain(|e| {
        let key = if e.id.is_empty() {
            format!(
                "{}|{}|{}",
                e.from,
                e.subject,
                e.internal_date.timestamp_millis()
            )
        } else {
            e.id.clone()
        };
        seen.insert(key)
    });

    let total = collected.len() as u32;
    let start = ((page - 1) * page_size) as usize;
    let page_items: Vec<EmailDto> = collected
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .map(|e| email_to_list_dto(&e, &folder))
        .collect();
    let has_more = start + page_items.len() < total as usize;

    HttpResponse::Ok().json(serde_json::json!({
        "emails": page_items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "hasMore": has_more,
    }))
}

#[derive(Deserialize)]
pub(crate) struct PersonalAnalyticsQuery {
    #[serde(default = "default_analytics_days")]
    pub days: u32,
}

fn default_analytics_days() -> u32 {
    30
}

pub(crate) async fn api_personal_analytics(
    query: web::Query<PersonalAnalyticsQuery>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let days = query.days.clamp(1, 365);
    let since = Utc::now() - chrono::Duration::days(days as i64);

    let inbox = match logic.get_emails_page(&user_id, "inbox", 500, 0).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_personal_analytics inbox error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to compute analytics"
            }));
        }
    };
    let sent = match logic.get_emails_page(&user_id, "sent", 500, 0).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_personal_analytics sent error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to compute analytics"
            }));
        }
    };

    let inbox_recent: Vec<Email> = inbox
        .into_iter()
        .filter(|m| m.internal_date >= since)
        .collect();
    let sent_recent: Vec<Email> = sent
        .into_iter()
        .filter(|m| m.internal_date >= since)
        .collect();

    let mut received_per_day: std::collections::BTreeMap<String, u32> =
        std::collections::BTreeMap::new();
    let mut sent_per_day: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut contact_count: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    for mail in &inbox_recent {
        let day = chrono::DateTime::<Utc>::from_timestamp_millis(
            mail.internal_date.timestamp_millis(),
        )
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string());
        *received_per_day.entry(day).or_insert(0) += 1;
        *contact_count.entry(mail.from.clone()).or_insert(0) += 1;
    }

    for mail in &sent_recent {
        let day = chrono::DateTime::<Utc>::from_timestamp_millis(
            mail.internal_date.timestamp_millis(),
        )
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".to_string());
        *sent_per_day.entry(day).or_insert(0) += 1;
        *contact_count.entry(mail.to.clone()).or_insert(0) += 1;
    }

    let mut top_contacts: Vec<(String, u32)> = contact_count.into_iter().collect();
    top_contacts.sort_by(|a, b| b.1.cmp(&a.1));
    let top_contacts: Vec<serde_json::Value> = top_contacts
        .into_iter()
        .take(5)
        .map(|(contact, count)| serde_json::json!({"contact": contact, "count": count}))
        .collect();

    let received_total = inbox_recent.len() as u32;
    let sent_total = sent_recent.len() as u32;
    let total = received_total + sent_total;
    let sent_ratio = if total == 0 {
        0.0
    } else {
        (sent_total as f64 / total as f64 * 100.0 * 10.0).round() / 10.0
    };

    let insights = vec![
        format!(
            "Sur les {} derniers jours: {} emails reçus et {} envoyés.",
            days, received_total, sent_total
        ),
        format!("Part des emails envoyés: {}% du volume total.", sent_ratio),
    ];

    HttpResponse::Ok().json(serde_json::json!({
        "windowDays": days,
        "metrics": {
            "receivedTotal": received_total,
            "sentTotal": sent_total,
            "total": total,
            "receivedPerDay": received_per_day,
            "sentPerDay": sent_per_day,
            "topContacts": top_contacts,
        },
        "insights": insights,
    }))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MailLabel {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub color: String,
    pub icon: Option<String>,
    pub parent_id: Option<String>,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MailLabelCreateRequest {
    pub name: String,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub parent_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MailLabelUpdateRequest {
    pub name: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub parent_id: Option<String>,
}

fn labels_coll(mongo: &Arc<mongodb::Client>) -> mongodb::Collection<bson::Document> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    mongo.database(&db).collection::<bson::Document>("mail_labels")
}

fn normalize_label_name(raw: &str) -> String {
    raw.trim().to_string()
}

fn normalize_label_color(raw: Option<String>) -> String {
    raw.map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "#64748b".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_analytics_days_returns_30() {
        assert_eq!(default_analytics_days(), 30);
    }

    #[test]
    fn normalize_label_name_trims() {
        assert_eq!(normalize_label_name("  Work  "), "Work");
    }

    #[test]
    fn normalize_label_name_empty() {
        assert_eq!(normalize_label_name(""), "");
    }

    #[test]
    fn normalize_label_color_defaults() {
        assert_eq!(normalize_label_color(None), "#64748b");
    }

    #[test]
    fn normalize_label_color_empty_string() {
        assert_eq!(normalize_label_color(Some("".to_string())), "#64748b");
    }

    #[test]
    fn normalize_label_color_whitespace() {
        assert_eq!(normalize_label_color(Some("   ".to_string())), "#64748b");
    }

    #[test]
    fn normalize_label_color_valid() {
        assert_eq!(normalize_label_color(Some("#ff0000".to_string())), "#ff0000");
    }

    #[test]
    fn normalize_label_color_trims() {
        assert_eq!(normalize_label_color(Some("  #ff0000  ".to_string())), "#ff0000");
    }
}

pub(crate) async fn api_tags(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = labels_coll(&mongo);
    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "name": 1 })
        .await
    {
        Ok(cursor) => {
            let docs: Vec<bson::Document> = cursor.try_collect().await.unwrap_or_default();
            let tags: Vec<MailLabel> = docs
                .into_iter()
                .filter_map(|doc| bson::from_document::<MailLabel>(doc).ok())
                .collect();
            HttpResponse::Ok().json(serde_json::json!({ "tags": tags }))
        }
        Err(e) => {
            eprintln!("api_tags error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to list tags" }))
        }
    }
}

pub(crate) async fn api_tags_create(
    body: web::Json<MailLabelCreateRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let name = normalize_label_name(&body.name);
    if name.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "name is required"
        }));
    }

    let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
    let tag = MailLabel {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.clone(),
        name,
        color: normalize_label_color(body.color.clone()),
        icon: body.icon.clone().filter(|v| !v.trim().is_empty()),
        parent_id: body.parent_id.clone().filter(|v| !v.trim().is_empty()),
        created_at: now,
        updated_at: now,
    };

    let coll = labels_coll(&mongo);
    let payload = match bson::to_document(&tag) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_tags_create serialize error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create tag" }));
        }
    };

    match coll.insert_one(payload).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "tag": tag })),
        Err(e) => {
            eprintln!("api_tags_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create tag" }))
        }
    }
}

pub(crate) async fn api_tags_update(
    path: web::Path<String>,
    body: web::Json<MailLabelUpdateRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = path.into_inner();
    let mut set_doc = doc! {};

    if let Some(name) = body.name.as_ref() {
        let normalized = normalize_label_name(name);
        if normalized.is_empty() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "name must not be empty"
            }));
        }
        set_doc.insert("name", normalized);
    }
    if let Some(color) = body.color.as_ref() {
        set_doc.insert("color", normalize_label_color(Some(color.clone())));
    }
    if let Some(icon) = body.icon.as_ref() {
        let value = icon.trim();
        if value.is_empty() {
            set_doc.insert("icon", bson::Bson::Null);
        } else {
            set_doc.insert("icon", value.to_string());
        }
    }
    if let Some(parent_id) = body.parent_id.as_ref() {
        let value = parent_id.trim();
        if value.is_empty() {
            set_doc.insert("parent_id", bson::Bson::Null);
        } else {
            set_doc.insert("parent_id", value.to_string());
        }
    }

    if set_doc.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "No fields to update"
        }));
    }
    set_doc.insert("updated_at", bson::DateTime::from_millis(Utc::now().timestamp_millis()));

    let coll = labels_coll(&mongo);
    match coll
        .update_one(doc! { "user_id": &user_id, "id": &id }, doc! { "$set": set_doc })
        .await
    {
        Ok(result) if result.matched_count == 0 => {
            HttpResponse::NotFound().json(serde_json::json!({ "message": "Tag not found" }))
        }
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "id": id })),
        Err(e) => {
            eprintln!("api_tags_update error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update tag" }))
        }
    }
}

pub(crate) async fn api_tags_delete(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = path.into_inner();
    let coll = labels_coll(&mongo);
    match coll.delete_one(doc! { "user_id": &user_id, "id": &id }).await {
        Ok(result) if result.deleted_count == 0 => {
            HttpResponse::NotFound().json(serde_json::json!({ "message": "Tag not found" }))
        }
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "id": id })),
        Err(e) => {
            eprintln!("api_tags_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete tag" }))
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NotificationPreferences {
    pub push_enabled: bool,
    pub ai_filter_enabled: bool,
    pub mute_newsletters: bool,
    pub dnd_enabled: bool,
    pub dnd_start_hour: u8,
    pub dnd_end_hour: u8,
    pub daily_digest_enabled: bool,
    pub daily_digest_hour: u8,
    pub priority_reply_enabled: bool,
    #[serde(default)]
    pub whitelist_senders: Vec<String>,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            push_enabled: true,
            ai_filter_enabled: true,
            mute_newsletters: true,
            dnd_enabled: false,
            dnd_start_hour: 22,
            dnd_end_hour: 7,
            daily_digest_enabled: true,
            daily_digest_hour: 8,
            priority_reply_enabled: true,
            whitelist_senders: vec![],
        }
    }
}

fn notifications_coll(mongo: &Arc<mongodb::Client>) -> mongodb::Collection<bson::Document> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    mongo.database(&db).collection::<bson::Document>("notification_preferences")
}

pub(crate) async fn api_notifications_preferences_get(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = notifications_coll(&mongo);
    match coll.find_one(doc! { "user_id": &user_id }).await {
        Ok(Some(doc)) => {
            let prefs: NotificationPreferences = bson::from_document(doc).unwrap_or_default();
            HttpResponse::Ok().json(serde_json::json!({ "userId": user_id, "preferences": prefs }))
        }
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({
            "userId": user_id,
            "preferences": NotificationPreferences::default()
        })),
        Err(e) => {
            eprintln!("api_notifications_preferences_get error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "message": "Failed to read notification preferences" }))
        }
    }
}

pub(crate) async fn api_notifications_preferences_put(
    body: web::Json<NotificationPreferences>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    if body.dnd_start_hour > 23 || body.dnd_end_hour > 23 || body.daily_digest_hour > 23 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Hour fields must be between 0 and 23"
        }));
    }

    let coll = notifications_coll(&mongo);
    let mut payload = match bson::to_document(&body.into_inner()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_notifications_preferences_put serialize error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({ "message": "Failed to save notification preferences" }));
        }
    };
    payload.insert("user_id", user_id.clone());
    payload.insert("updated_at", bson::DateTime::from_millis(Utc::now().timestamp_millis()));

    match coll
        .replace_one(doc! { "user_id": &user_id }, payload)
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "userId": user_id })),
        Err(e) => {
            eprintln!("api_notifications_preferences_put error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({ "message": "Failed to save notification preferences" }))
        }
    }
}

