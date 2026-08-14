//! Admin RBAC — PR1 (fondation).
//!
//! Ce module fournit une garde RBAC minimaliste, gated par la variable
//! d'environnement `ADMIN_RBAC_ENFORCE`. Comportement:
//!
//! - `ADMIN_RBAC_ENFORCE` absent ou différent de "1" / "true"  → **désactivé** :
//!   `require_admin` renvoie toujours `Ok(AuthUser::system())` et n'appelle
//!   même pas Mongo. C'est le comportement par défaut à la mise en prod pour
//!   éviter toute régression pendant que le frontend n'a pas encore été mis
//!   à jour pour transmettre le token.
//!
//! - `ADMIN_RBAC_ENFORCE=1`  → **activé** : la session est extraite depuis le
//!   header `Authorization: Bearer <token>` ou depuis le cookie `session_token`,
//!   validée contre la collection `admin_sessions`, et le rôle est comparé à
//!   la liste des rôles autorisés.
//!
//! Le module est volontairement autonome (pas d'import des types du binaire)
//! pour rester facile à extraire vers un crate séparé plus tard sans casser
//! l'API publique.

use std::env;
use std::sync::Arc;

use actix_web::{http::StatusCode, HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

/// Nom de la collection Mongo où l'on persiste les sessions admin.
pub const ADMIN_SESSIONS_COLL: &str = "admin_sessions";

/// Retourne `true` si le RBAC est activé (feature flag).
pub fn rbac_enabled() -> bool {
    matches!(
        env::var("ADMIN_RBAC_ENFORCE")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Nombre de secondes avant expiration d'une session admin (24h par défaut).
fn session_ttl_secs() -> i64 {
    env::var("ADMIN_SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(24 * 3600)
}

/// Enregistrement Mongo d'une session admin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub token: String,
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

/// Représente l'utilisateur authentifié courant, extrait par `require_admin`.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
    pub role: String,
}

impl AuthUser {
    /// Utilisateur "système" utilisé quand le feature flag est OFF ou dans les
    /// contextes internes (cron). Pas de vrai utilisateur, mais rôle admin
    /// pour ne pas bloquer les endpoints protégés.
    pub fn system() -> Self {
        AuthUser {
            user_id: "system".to_string(),
            email: "system@misfits.ai".to_string(),
            role: "admin".to_string(),
        }
    }
}

/// Extrait un token depuis un `HttpRequest`.
///
/// Priorité: header `Authorization: Bearer …` puis cookie `session_token`.
fn extract_token(req: &HttpRequest) -> Option<String> {
    if let Some(h) = req.headers().get("Authorization") {
        if let Ok(s) = h.to_str() {
            if let Some(tok) = s.strip_prefix("Bearer ") {
                let t = tok.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    if let Some(c) = req.cookie("session_token") {
        let v = c.value().trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    None
}

/// Persiste une nouvelle session admin en base et renvoie le token.
///
/// Appelé depuis `auth_login` après authentification réussie. La signature
/// tolère l'absence de mongo (best-effort) — si l'insertion échoue, on log
/// simplement l'erreur : le login reste réussi et le token utilisable tant
/// que le feature flag `ADMIN_RBAC_ENFORCE` n'est pas activé.
pub async fn issue_admin_session(
    mongo: &mongodb::Client,
    db_name: &str,
    user_id: &str,
    email: &str,
    role: &str,
    user_agent: Option<String>,
    ip: Option<String>,
) -> AdminSession {
    let token = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires = now + Duration::seconds(session_ttl_secs());
    let session = AdminSession {
        token: token.clone(),
        user_id: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        created_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        last_seen_at: Some(now.to_rfc3339()),
        user_agent,
        ip,
    };
    let coll = mongo
        .database(db_name)
        .collection::<AdminSession>(ADMIN_SESSIONS_COLL);
    if let Err(e) = coll.insert_one(&session).await {
        eprintln!("issue_admin_session: insert_one failed: {}", e);
    }
    session
}

/// Cherche une session valide (non expirée) par son token.
pub async fn lookup_session(
    mongo: &mongodb::Client,
    db_name: &str,
    token: &str,
) -> Option<AdminSession> {
    let coll = mongo
        .database(db_name)
        .collection::<AdminSession>(ADMIN_SESSIONS_COLL);
    match coll.find_one(doc! { "token": token }).await {
        Ok(Some(sess)) => {
            let now = Utc::now();
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(&sess.expires_at) {
                if now.with_timezone(&chrono::FixedOffset::east_opt(0).unwrap()) > exp {
                    return None; // expirée
                }
            }
            Some(sess)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("lookup_session: find_one failed: {}", e);
            None
        }
    }
}

/// Révoque une session (best-effort).
pub async fn revoke_session(mongo: &mongodb::Client, db_name: &str, token: &str) {
    let coll = mongo
        .database(db_name)
        .collection::<AdminSession>(ADMIN_SESSIONS_COLL);
    if let Err(e) = coll.delete_one(doc! { "token": token }).await {
        eprintln!("revoke_session: delete_one failed: {}", e);
    }
}

/// Garde principale — à appeler en début de chaque handler `/api/admin/*`
/// qui doit être réservé aux admins.
///
/// - Feature flag OFF → renvoie `Ok(AuthUser::system())`.
/// - Feature flag ON  → exige un token valide dont le rôle est "admin".
///
/// En cas de refus, renvoie une réponse HTTP prête à être servie par le
/// handler (401 si non authentifié, 403 si role insuffisant).
pub async fn require_admin(
    req: &HttpRequest,
    mongo: &Arc<mongodb::Client>,
    db_name: &str,
) -> Result<AuthUser, HttpResponse> {
    if !rbac_enabled() {
        return Ok(AuthUser::system());
    }
    let token = match extract_token(req) {
        Some(t) => t,
        None => {
            return Err(HttpResponse::build(StatusCode::UNAUTHORIZED).json(
                serde_json::json!({
                    "code": "AUTH_REQUIRED",
                    "message": "Missing session token"
                }),
            ))
        }
    };
    let session = match lookup_session(mongo.as_ref(), db_name, &token).await {
        Some(s) => s,
        None => {
            return Err(HttpResponse::build(StatusCode::UNAUTHORIZED).json(
                serde_json::json!({
                    "code": "AUTH_INVALID",
                    "message": "Session token unknown or expired"
                }),
            ))
        }
    };
    if session.role != "admin" {
        return Err(HttpResponse::build(StatusCode::FORBIDDEN).json(
            serde_json::json!({
                "code": "FORBIDDEN",
                "message": "Admin role required",
                "role": session.role,
            }),
        ));
    }
    Ok(AuthUser {
        user_id: session.user_id,
        email: session.email,
        role: session.role,
    })
}
