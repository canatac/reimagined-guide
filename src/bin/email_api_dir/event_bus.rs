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
    pub id: String,
    pub kind: MailEventKind,
    pub user_id: String,
    pub email_id: String,
    pub subject: String,
    pub from: String,
    pub to: String,
    pub timestamp: String,
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
    pub id: String,
}

#[derive(Deserialize)]
pub(super) struct ScheduleSendBody {
    #[serde(default)]
    pub to: Vec<ComposerRecipient>,
    #[serde(default)]
    pub cc: Vec<ComposerRecipient>,
    #[serde(default)]
    pub bcc: Vec<ComposerRecipient>,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub attachments: Vec<ComposeAttachmentInput>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default, rename = "inReplyTo", alias = "in_reply_to")]
    pub in_reply_to: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub send_at: String,
}

// --- OAuth provider response types ---

#[derive(Deserialize)]
pub(super) struct GithubTokenResponse {
    pub access_token: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GithubUser {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct GithubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}

#[derive(Serialize)]
pub(super) struct UserResponse {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub two_factor_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub(super) struct SessionResponse {
    pub id: String,
    pub user: UserResponse,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
    pub refresh_expires_at: u64,
    pub issued_at: u64,
}

#[derive(Serialize)]
pub(super) struct AuthResponse {
    pub session: SessionResponse,
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
