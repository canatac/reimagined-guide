// session_store.rs — une seule façon d'ouvrir, de renouveler et de fermer une session (#751).
//
// Toute authentification réussie (mot de passe, 2FA, inscription, inscription
// anonyme, GitHub) enregistre sa session dans `admin_sessions`, la collection
// que lisent `require_user_auth`, `require_auth` et `require_admin` : un jeton
// rendu au client est donc toujours un jeton que l'API reconnaît. Le jeton de
// renouvellement est enregistré avec la session, et `/api/auth/refresh` le
// fait tourner dans cette même collection.
#![allow(unused_imports, dead_code)]
use super::super::*;
use super::super::admin_auth::{self, AdminSession};
use super::login::make_session_with_token;
use mongodb::bson::Document;

/// Durée de vie du jeton de renouvellement : 7 jours.
pub(crate) const REFRESH_TTL_SECS: i64 = 7 * 24 * 3600;
/// Chemin du cookie du jeton de renouvellement : seules les routes d'authentification le reçoivent.
pub(crate) const REFRESH_COOKIE_PATH: &str = "/api/auth";

fn db_name() -> String {
    env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

/// Le compte et le rôle d'une adresse : l'administrateur actif de
/// `admin_users`, sinon un utilisateur (rôle `user`, identifié par son
/// adresse). Une erreur de lecture donne le rôle le moins privilégié.
pub(crate) async fn account_of(mongo: &mongodb::Client, email: &str) -> (String, String) {
    let email_lc = email.trim().to_lowercase();
    let coll = mongo
        .database(&db_name())
        .collection::<AdminUserRecord>(super::super::admin_ops::ADMIN_USERS_COLL);
    match coll.find_one(doc! { "$or": [{ "email": &email_lc }, { "email": email }] }).await {
        Ok(Some(u)) if u.status == "active" => (u.id, u.role),
        Ok(_) => (email_lc, "user".to_string()),
        Err(e) => {
            eprintln!("account_of: find_one failed: {}", e);
            (email_lc, "user".to_string())
        }
    }
}

/// Une session et son jeton de renouvellement, telles qu'enregistrées.
#[derive(Debug, Clone)]
pub(crate) struct StoredSession {
    pub session: AdminSession,
    pub display_name: String,
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
}

/// Une nouvelle session pour ce compte, ouverte à NOW, avec des jetons neufs.
pub(crate) fn new_session(user_id: &str, email: &str, display_name: &str, role: &str, now: DateTime<Utc>) -> StoredSession {
    StoredSession {
        session: AdminSession {
            token: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            created_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::seconds(admin_auth::session_ttl_secs())).to_rfc3339(),
            last_seen_at: Some(now.to_rfc3339()),
            user_agent: None,
            ip: None,
        },
        display_name: display_name.to_string(),
        refresh_token: Uuid::new_v4().to_string(),
        refresh_expires_at: now + chrono::Duration::seconds(REFRESH_TTL_SECS),
    }
}

/// Le document Mongo de la session : celui d'`AdminSession`, plus le jeton de
/// renouvellement, son expiration et le nom affiché.
pub(crate) fn document_of(stored: &StoredSession) -> Result<Document, mongodb::bson::ser::Error> {
    let mut document = mongodb::bson::to_document(&stored.session)?;
    document.insert("refresh_token", stored.refresh_token.clone());
    document.insert("refresh_expires_at", stored.refresh_expires_at.to_rfc3339());
    document.insert("display_name", stored.display_name.clone());
    Ok(document)
}

/// La session d'un document lu, si son jeton de renouvellement vaut encore à NOW.
pub(crate) fn stored_of(document: Document, now: DateTime<Utc>) -> Option<StoredSession> {
    let refresh_token = document.get_str("refresh_token").ok()?.to_string();
    let refresh_expires_at = DateTime::parse_from_rfc3339(document.get_str("refresh_expires_at").ok()?)
        .ok()?
        .with_timezone(&Utc);
    if refresh_token.is_empty() || now >= refresh_expires_at {
        return None;
    }
    let display_name = document.get_str("display_name").unwrap_or_default().to_string();
    let session: AdminSession = mongodb::bson::from_document(document).ok()?;
    Some(StoredSession { session, display_name, refresh_token, refresh_expires_at })
}

fn millis(text: &str) -> u64 {
    DateTime::parse_from_rfc3339(text).map(|t| t.timestamp_millis().max(0) as u64).unwrap_or(0)
}

/// La réponse rendue au client : les jetons, les expirations, l'identifiant
/// et le rôle de la session enregistrée, jamais d'autres.
pub(crate) fn response_of(stored: &StoredSession) -> AuthResponse {
    let s = &stored.session;
    let mut response = make_session_with_token(&s.email, &stored.display_name, &s.token);
    response.session.user.id = s.user_id.clone();
    response.session.user.role = s.role.clone();
    response.session.refresh_token = stored.refresh_token.clone();
    response.session.expires_at = millis(&s.expires_at);
    response.session.refresh_expires_at = stored.refresh_expires_at.timestamp_millis().max(0) as u64;
    response.session.issued_at = millis(&s.created_at);
    response
}

/// La réponse quand la session ne peut pas être enregistrée : aucun jeton
/// n'est rendu, puisque l'API ne le reconnaîtrait pas.
pub(crate) fn unavailable() -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(serde_json::json!({
        "code": "SESSION_UNAVAILABLE",
        "message": "The session could not be opened. Please try again."
    }))
}

/// Ouvre et enregistre la session de cette adresse, avec le rôle de son compte.
pub(crate) async fn open_session(mongo: &mongodb::Client, email: &str, display_name: &str) -> Result<AuthResponse, HttpResponse> {
    let (user_id, role) = account_of(mongo, email).await;
    let stored = new_session(&user_id, email, display_name, &role, Utc::now());
    let document = document_of(&stored).map_err(|e| {
        eprintln!("open_session: serialization failed: {}", e);
        unavailable()
    })?;
    mongo
        .database(&db_name())
        .collection::<Document>(admin_auth::ADMIN_SESSIONS_COLL)
        .insert_one(document)
        .await
        .map_err(|e| {
            eprintln!("open_session: insert_one failed: {}", e);
            unavailable()
        })?;
    Ok(response_of(&stored))
}

/// Les cookies HttpOnly de la session : le jeton d'accès pour l'API, le jeton
/// de renouvellement pour les seules routes d'authentification.
pub(crate) fn session_cookies(response: &AuthResponse) -> [actix_web::cookie::Cookie<'static>; 2] {
    use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};
    let access = Cookie::build("session_token", response.session.access_token.clone())
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(admin_auth::session_ttl_secs()))
        .finish();
    let refresh = Cookie::build("refresh_token", response.session.refresh_token.clone())
        .path(REFRESH_COOKIE_PATH)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(REFRESH_TTL_SECS))
        .finish();
    [access, refresh]
}

/// Les cookies qui effacent la session du navigateur.
pub(crate) fn cleared_cookies() -> [actix_web::cookie::Cookie<'static>; 2] {
    use actix_web::cookie::{time::Duration as CookieDuration, Cookie, SameSite};
    let clear = |name: &'static str, path: &'static str| {
        Cookie::build(name, "")
            .path(path)
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(CookieDuration::ZERO)
            .finish()
    };
    [clear("session_token", "/"), clear("refresh_token", REFRESH_COOKIE_PATH)]
}

/// La réponse d'une connexion réussie : STATUS, les cookies de la session et BODY.
pub(crate) fn with_session(mut builder: actix_web::HttpResponseBuilder, response: &AuthResponse, body: serde_json::Value) -> HttpResponse {
    for cookie in session_cookies(response) {
        builder.cookie(cookie);
    }
    builder.json(body)
}

/// Ouvre la session de cette adresse et la rend au client, en 200 : la
/// réponse des connexions (mot de passe, 2FA).
pub(crate) async fn signed_in(mongo: &mongodb::Client, email: &str, display_name: &str) -> HttpResponse {
    match open_session(mongo, email, display_name).await {
        Ok(response) => {
            let body = serde_json::to_value(&response).unwrap_or_default();
            with_session(HttpResponse::Ok(), &response, body)
        }
        Err(refused) => refused,
    }
}

/// Fait tourner les jetons de la session de ce jeton de renouvellement :
/// l'ancien ne vaut plus rien. None si le jeton est inconnu ou expiré, ou si
/// une autre requête l'a déjà fait tourner.
pub(crate) async fn rotate_session(mongo: &mongodb::Client, refresh_token: &str) -> Option<StoredSession> {
    let coll = mongo
        .database(&db_name())
        .collection::<Document>(admin_auth::ADMIN_SESSIONS_COLL);
    let document = match coll.find_one(doc! { "refresh_token": refresh_token }).await {
        Ok(found) => found?,
        Err(e) => {
            eprintln!("rotate_session: find_one failed: {}", e);
            return None;
        }
    };
    let now = Utc::now();
    let old = stored_of(document, now)?;
    let s = &old.session;
    let mut next = new_session(&s.user_id, &s.email, &old.display_name, &s.role, now);
    next.session.created_at = s.created_at.clone();
    let update = doc! { "$set": {
        "token": &next.session.token,
        "expires_at": &next.session.expires_at,
        "last_seen_at": now.to_rfc3339(),
        "refresh_token": &next.refresh_token,
        "refresh_expires_at": next.refresh_expires_at.to_rfc3339(),
    } };
    match coll.update_one(doc! { "refresh_token": refresh_token }, update).await {
        Ok(result) if result.modified_count == 1 => Some(next),
        Ok(_) => None,
        Err(e) => {
            eprintln!("rotate_session: update_one failed: {}", e);
            None
        }
    }
}

/// Ferme la session de ce jeton d'accès (best-effort : le client efface ses cookies de toute façon).
pub(crate) async fn close_session(mongo: &mongodb::Client, access_token: &str) {
    admin_auth::revoke_session(mongo, &db_name(), access_token).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn a_new_session_has_fresh_tokens_and_the_role_of_its_account() {
        let now = at("2026-11-20T12:00:00Z");
        let a = new_session("u-1", "alice@example.com", "Alice", "user", now);
        let b = new_session("u-1", "alice@example.com", "Alice", "user", now);
        assert_ne!(a.session.token, b.session.token);
        assert_ne!(a.refresh_token, b.refresh_token);
        assert_ne!(a.session.token, a.refresh_token);
        assert_eq!(a.session.role, "user");
        assert_eq!(a.session.user_id, "u-1");
        assert_eq!(a.refresh_expires_at, at("2026-11-27T12:00:00Z"));
        assert!(at(&a.session.expires_at) > now);
    }

    #[test]
    fn the_response_gives_the_stored_tokens_and_role_never_admin_by_default() {
        let now = at("2026-11-20T12:00:00Z");
        let stored = new_session("alice@example.com", "alice@example.com", "Alice", "user", now);
        let response = response_of(&stored);
        let s = &response.session;
        assert_eq!(s.access_token, stored.session.token);
        assert_eq!(s.refresh_token, stored.refresh_token);
        assert_eq!(s.user.role, "user");
        assert_eq!(s.user.id, "alice@example.com");
        assert_eq!(s.user.display_name, "Alice");
        assert_eq!(s.issued_at, now.timestamp_millis() as u64);
        assert_eq!(s.expires_at, millis(&stored.session.expires_at));
        assert_eq!(s.refresh_expires_at, at("2026-11-27T12:00:00Z").timestamp_millis() as u64);
    }

    #[test]
    fn a_stored_session_reads_back_while_its_refresh_token_is_valid() {
        let now = at("2026-11-20T12:00:00Z");
        let stored = new_session("u-2", "admin@example.com", "Admin", "admin", now);
        let document = document_of(&stored).unwrap();
        assert_eq!(document.get_str("token").unwrap(), stored.session.token);
        let read = stored_of(document.clone(), at("2026-11-26T12:00:00Z")).unwrap();
        assert_eq!(read.refresh_token, stored.refresh_token);
        assert_eq!(read.session.role, "admin");
        assert_eq!(read.display_name, "Admin");
        assert!(stored_of(document, at("2026-11-27T12:00:00Z")).is_none());
    }

    #[test]
    fn a_session_without_a_refresh_token_cannot_be_renewed() {
        let now = at("2026-11-20T12:00:00Z");
        let stored = new_session("u-3", "old@example.com", "Old", "admin", now);
        // A session stored before this change: no refresh token.
        let document = mongodb::bson::to_document(&stored.session).unwrap();
        assert!(stored_of(document, now).is_none());
    }

    #[test]
    fn the_cookies_are_http_only_and_the_refresh_one_stays_on_the_auth_routes() {
        let stored = new_session("u-4", "bob@example.com", "Bob", "user", Utc::now());
        let response = response_of(&stored);
        let [access, refresh] = session_cookies(&response);
        assert_eq!(access.name(), "session_token");
        assert_eq!(access.value(), stored.session.token);
        assert_eq!(access.path(), Some("/"));
        assert_eq!(refresh.name(), "refresh_token");
        assert_eq!(refresh.value(), stored.refresh_token);
        assert_eq!(refresh.path(), Some(REFRESH_COOKIE_PATH));
        for cookie in [&access, &refresh] {
            assert_eq!(cookie.http_only(), Some(true));
            assert_eq!(cookie.secure(), Some(true));
            assert_eq!(cookie.same_site(), Some(actix_web::cookie::SameSite::Lax));
        }
        let [gone_access, gone_refresh] = cleared_cookies();
        assert_eq!(gone_access.value(), "");
        assert_eq!(gone_access.max_age(), Some(actix_web::cookie::time::Duration::ZERO));
        assert_eq!(gone_refresh.path(), Some(REFRESH_COOKIE_PATH));
    }

    #[test]
    fn a_session_that_cannot_be_stored_returns_no_token() {
        let response = unavailable();
        assert_eq!(response.status(), actix_web::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.cookies().next().is_none());
    }
}
