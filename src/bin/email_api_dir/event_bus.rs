use super::*;


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum MailEventKind {
    Sent,
    Received,
    Read,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MailEvent {
    id: String,
    kind: MailEventKind,
    user_id: String,
    email_id: String,
    subject: String,
    from: String,
    to: String,
    timestamp: String,
}

pub(super) type EventBus = broadcast::Sender<MailEvent>;

// --- Shared auth types (moved to auth_handlers.rs) ---
// LoginRequest, RegisterRequest, OAuthCallbackQuery, TwoFactorVerifyRequest
// PasswordResetRequestBody, PasswordResetConfirmBody are in auth_handlers module.

// --- 2FA default helper (still needed by main.rs serde defaults) ---

// --- Send queue types ---

pub(super) const SEND_QUEUE_COLL: &str = "send_queue";

#[derive(Deserialize)]
pub(super) struct UndoSendRequest {
    id: String,
}

#[derive(Deserialize)]
pub(super) struct ScheduleSendBody {
    #[serde(default)]
    to: Vec<ComposerRecipient>,
    #[serde(default)]
    cc: Vec<ComposerRecipient>,
    #[serde(default)]
    bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    attachments: Vec<ComposeAttachmentInput>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default, rename = "inReplyTo", alias = "in_reply_to")]
    in_reply_to: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    send_at: String,
}

// --- OAuth provider response types ---

#[derive(Deserialize)]
pub(super) struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GithubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Serialize)]
pub(super) struct UserResponse {
    id: String,
    email: String,
    display_name: String,
    role: String,
    two_factor_enabled: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
pub(super) struct SessionResponse {
    id: String,
    user: UserResponse,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    refresh_expires_at: u64,
    issued_at: u64,
}

#[derive(Serialize)]
pub(super) struct AuthResponse {
    session: SessionResponse,
}

// make_session, verify_totp, generate_totp_secret, generate_otp_code
// → moved to auth_handlers module



pub(super) async fn persist_event(mongo: &mongodb::Client, event: &MailEvent) {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("mail_events");
    if let Ok(doc) = bson::to_document(event) {
        if let Err(e) = coll.insert_one(doc).await {
            eprintln!("persist_event error: {}", e);
        }
    }
}

pub(super) async fn emit_event(bus: &EventBus, mongo: &mongodb::Client, event: MailEvent) {
    persist_event(mongo, &event).await;
    let _ = bus.send(event);
}

pub(super) async fn api_events(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("mail_events");
    let filter = doc! { "user_id": &user_id };
    match coll
        .find(filter)
        .sort(doc! { "timestamp": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => match cursor.try_collect::<Vec<_>>().await {
            Ok(docs) => {
                let events: Vec<serde_json::Value> = docs
                    .into_iter()
                    .filter_map(|d| bson::from_document::<MailEvent>(d).ok())
                    .filter_map(|e| serde_json::to_value(&e).ok())
                    .collect();
                HttpResponse::Ok().json(serde_json::json!({ "events": events }))
            }
            Err(e) => HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() })),
        },
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({ "error": e.to_string() }))
        }
    }
}

pub(super) async fn api_events_stream(bus: web::Data<EventBus>, req: actix_web::HttpRequest) -> HttpResponse {
    let user_id = resolve_user_id(&req);
    let rx = bus.subscribe();
    let event_stream = stream::unfold((rx, user_id), |(mut rx, uid)| async move {
        loop {
            match rx.recv().await {
                Ok(event) if event.user_id == uid => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let chunk = format!("data: {}\n\n", data);
                    return Some((
                        Ok::<web::Bytes, actix_web::Error>(web::Bytes::from(chunk)),
                        (rx, uid),
                    ));
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(event_stream)
}
