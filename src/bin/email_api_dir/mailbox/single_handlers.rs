// Sprint 8: split from mailbox_handlers.rs
#![allow(unused_imports)]
use super::*;

pub(crate) async fn api_email_by_id(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    bus: web::Data<EventBus>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();
    match logic.fetch_email(&user_id, &email_id).await {
        Ok(Some(email)) => {
            emit_event(
                &bus,
                &mongo,
                MailEvent {
                    id: Uuid::new_v4().to_string(),
                    kind: MailEventKind::Read,
                    user_id: user_id.clone(),
                    email_id: email.id.clone(),
                    subject: email.subject.clone(),
                    from: email.from.clone(),
                    to: email.to.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                },
            )
            .await;
            let dto = email_to_detail_dto(&email, "inbox");
            HttpResponse::Ok().json(dto)
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("fetch_email error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch email",
            }))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailActionRequest {
    action: String,
    #[serde(default)]
    target_folder: Option<String>,
}

pub(crate) async fn api_email_action(
    path: web::Path<String>,
    body: web::Json<EmailActionRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let email_id = path.into_inner();
    let action = body.action.trim().to_ascii_lowercase();

    let result = match action.as_str() {
        "archive" => logic.move_email_to_mailbox(&user_id, &email_id, "archive").await,
        "trash" | "delete" => logic.move_email_to_mailbox(&user_id, &email_id, "trash").await,
        "restore" => logic.move_email_to_mailbox(&user_id, &email_id, "inbox").await,
        "move" => {
            let Some(target) = body
                .target_folder
                .as_ref()
                .and_then(|f| canonical_folder(f))
            else {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "ok": false,
                    "message": "targetFolder must be one of inbox|sent|drafts|archive|trash|spam",
                }));
            };
            logic.move_email_to_mailbox(&user_id, &email_id, &target).await
        }
        "markread" => logic.set_email_read(&user_id, &email_id, true).await,
        "markunread" => logic.set_email_read(&user_id, &email_id, false).await,
        "star" => logic.set_email_starred(&user_id, &email_id, true).await,
        "unstar" => logic.set_email_starred(&user_id, &email_id, false).await,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "ok": false,
                "message": "Unsupported action. Use move|archive|trash|delete|restore|markRead|markUnread|star|unstar",
            }))
        }
    };

    match result {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({
            "ok": true,
            "id": email_id,
            "action": body.action,
        })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({
            "ok": false,
            "message": "Email not found",
        })),
        Err(e) => {
            eprintln!("api_email_action error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "ok": false,
                "message": "Failed to apply email action",
            }))
        }
    }
}
