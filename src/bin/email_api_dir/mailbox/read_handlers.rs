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

pub(crate) async fn api_tags() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"tags": []}))
}

