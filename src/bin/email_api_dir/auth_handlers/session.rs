// session.rs — Auth request types + logout/refresh stubs. Handlers split : login.rs, register.rs, password_reset.rs.
#![allow(unused_imports, dead_code)]
use super::super::*;

// ─── Auth types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub(crate) struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub(crate) struct RegisterRequest {
    #[serde(default)]
    pub first_name: String,
    #[serde(default)]
    pub last_name: String,
    /// Alias optionnel → alias@misfits.ai → prenom.nom@misfits.ai
    #[serde(default)]
    pub alias: Option<String>,
    pub password: String,
    #[serde(default)]
    pub condition_accepted: bool,
}

#[derive(Deserialize)]
pub(crate) struct PasswordResetRequestBody {
    pub email: String,
}

#[derive(Deserialize)]
pub(crate) struct PasswordResetConfirmBody {
    pub token: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub(crate) struct PatchLocaleRequest {
    pub locale: String,
}

// ─── Stateless stubs ────────────────────────────────────────────────────────

pub(crate) async fn auth_logout() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

pub(crate) async fn auth_refresh() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "session": {
            "id": Uuid::new_v4().to_string(),
            "user": { "id": Uuid::new_v4().to_string(), "email": "admin@misfits.ai", "displayName": "admin", "role": "admin", "twoFactorEnabled": false, "createdAt": Utc::now().to_rfc3339(), "updatedAt": Utc::now().to_rfc3339() },
            "accessToken": Uuid::new_v4().to_string(),
            "refreshToken": Uuid::new_v4().to_string(),
            "expiresAt": (Utc::now().timestamp_millis() + 3600000) as u64,
            "refreshExpiresAt": (Utc::now().timestamp_millis() + 604800000) as u64,
            "issuedAt": Utc::now().timestamp_millis() as u64,
        }
    }))
}
