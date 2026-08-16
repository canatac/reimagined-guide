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
    for mailbox in folder_to_mailboxes(&folder) {
        match logic
            .get_emails_page(&user_id, &mailbox, fetch_limit, 0)
            .await
        {
            Ok(mut batch) => {
                collected.append(&mut batch);
            }
            Err(e) => {
                eprintln!("get_emails user={} mailbox={}: {}", user_id, mailbox, e);
            }
        }
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

pub(crate) async fn api_tags() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"tags": []}))
}

