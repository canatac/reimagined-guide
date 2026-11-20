// challenge.rs — Le défi de la 2FA, lié à une connexion par mot de passe (#753).
//
// Après un mot de passe correct pour un compte avec 2FA, l'API enregistre un
// défi : identifiant aléatoire, adresse, expiration à 5 minutes, usage
// unique, 5 essais au plus. `/api/auth/2fa/verify` et `/api/auth/2fa/recovery`
// n'ouvrent une session que sur un défi valide, pour l'adresse du défi : un
// code seul, sans mot de passe, n'ouvre rien. Le contrat est celui du site
// (misfits-web) : `202 { twoFactorRequired, challengeId, expiresIn }`, puis
// `{ challengeId, code }`.
#![allow(unused_imports, dead_code)]
use super::super::*;
use mongodb::bson::Document;
use mongodb::options::ReturnDocument;

pub(crate) const CHALLENGES_COLL: &str = "login_challenges";
pub(crate) const CHALLENGE_TTL_SECS: i64 = 300;
pub(crate) const MAX_ATTEMPTS: i32 = 5;

fn db_name() -> String {
    env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
}

/// Le document d'un nouveau défi pour EMAIL, créé à NOW.
pub(crate) fn challenge_doc(challenge_id: &str, email: &str, now: DateTime<Utc>) -> Document {
    doc! {
        "challenge_id": challenge_id,
        "email": email.trim().to_lowercase(),
        "created_at": bson::DateTime::from_millis(now.timestamp_millis()),
        "expires_at": bson::DateTime::from_millis((now + chrono::Duration::seconds(CHALLENGE_TTL_SECS)).timestamp_millis()),
        "attempts": 0_i32,
        "used": false,
    }
}

/// Le filtre d'un défi encore utilisable à NOW : non consommé, non expiré,
/// moins de MAX_ATTEMPTS essais.
pub(crate) fn usable_filter(challenge_id: &str, now: DateTime<Utc>) -> Document {
    doc! {
        "challenge_id": challenge_id,
        "used": false,
        "attempts": { "$lt": MAX_ATTEMPTS },
        "expires_at": { "$gt": bson::DateTime::from_millis(now.timestamp_millis()) },
    }
}

/// La réponse du site quand le mot de passe est correct et qu'un code est demandé.
pub(crate) fn challenge_body(challenge_id: &str) -> serde_json::Value {
    serde_json::json!({
        "twoFactorRequired": true,
        "requires_2fa": true,
        "challengeId": challenge_id,
        "expiresIn": CHALLENGE_TTL_SECS,
        "methods": ["totp", "recovery"],
    })
}

pub(crate) fn refused() -> HttpResponse {
    HttpResponse::Unauthorized().json(serde_json::json!({
        "verified": false,
        "code": "CHALLENGE_INVALID",
        "message": "Unknown, expired or already used challenge, or invalid code."
    }))
}

/// Enregistre un défi pour EMAIL et répond 202 au site ; 503 sans défi si
/// l'enregistrement échoue.
pub(crate) async fn challenge_started(mongo: &mongodb::Client, email: &str) -> HttpResponse {
    let challenge_id = Uuid::new_v4().to_string();
    let coll = mongo.database(&db_name()).collection::<Document>(CHALLENGES_COLL);
    match coll.insert_one(challenge_doc(&challenge_id, email, Utc::now())).await {
        Ok(_) => HttpResponse::Accepted().json(challenge_body(&challenge_id)),
        Err(e) => {
            eprintln!("challenge_started: insert_one failed: {}", e);
            super::session_store::unavailable()
        }
    }
}

/// Compte un essai sur le défi, de façon atomique, et rend son adresse ;
/// None si le défi est inconnu, expiré, consommé ou épuisé.
pub(crate) async fn attempt(mongo: &mongodb::Client, challenge_id: &str) -> Option<String> {
    let coll = mongo.database(&db_name()).collection::<Document>(CHALLENGES_COLL);
    match coll
        .find_one_and_update(usable_filter(challenge_id, Utc::now()), doc! { "$inc": { "attempts": 1 } })
        .return_document(ReturnDocument::After)
        .await
    {
        Ok(Some(found)) => found.get_str("email").ok().map(str::to_string),
        Ok(None) => None,
        Err(e) => {
            eprintln!("challenge attempt: find_one_and_update failed: {}", e);
            None
        }
    }
}

/// Consomme le défi après un code valide : true pour une seule requête.
pub(crate) async fn consume(mongo: &mongodb::Client, challenge_id: &str) -> bool {
    let coll = mongo.database(&db_name()).collection::<Document>(CHALLENGES_COLL);
    match coll
        .update_one(doc! { "challenge_id": challenge_id, "used": false }, doc! { "$set": { "used": true } })
        .await
    {
        Ok(result) => result.modified_count == 1,
        Err(e) => {
            eprintln!("challenge consume: update_one failed: {}", e);
            false
        }
    }
}

/// Le compte 2FA d'une adresse : `users` (par nom), sinon `admin_users` (par adresse).
pub(crate) async fn two_factor_account(mongo: &mongodb::Client, email: &str) -> Option<Document> {
    let db = mongo.database(&db_name());
    let local = email.split('@').next().unwrap_or(email);
    if let Ok(Some(found)) = db
        .collection::<Document>("users")
        .find_one(doc! { "$or": [{ "username": local }, { "username": email }] })
        .await
    {
        return Some(found);
    }
    db.collection::<Document>("admin_users")
        .find_one(doc! { "email": email.trim().to_lowercase() })
        .await
        .ok()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn a_challenge_lasts_five_minutes_unused_with_no_attempt() {
        let now = at("2026-11-20T12:00:00Z");
        let d = challenge_doc("c-1", " Alice@Example.com ", now);
        assert_eq!(d.get_str("challenge_id").unwrap(), "c-1");
        assert_eq!(d.get_str("email").unwrap(), "alice@example.com");
        assert_eq!(d.get_i32("attempts").unwrap(), 0);
        assert!(!d.get_bool("used").unwrap());
        assert_eq!(
            d.get_datetime("expires_at").unwrap().timestamp_millis(),
            at("2026-11-20T12:05:00Z").timestamp_millis()
        );
    }

    #[test]
    fn only_an_unused_unexpired_challenge_under_five_attempts_is_usable() {
        let now = at("2026-11-20T12:03:00Z");
        let f = usable_filter("c-1", now);
        assert_eq!(f.get_str("challenge_id").unwrap(), "c-1");
        assert!(!f.get_bool("used").unwrap());
        assert_eq!(f.get_document("attempts").unwrap().get_i32("$lt").unwrap(), MAX_ATTEMPTS);
        assert_eq!(
            f.get_document("expires_at").unwrap().get_datetime("$gt").unwrap().timestamp_millis(),
            now.timestamp_millis()
        );
    }

    #[test]
    fn the_web_receives_its_challenge_contract() {
        let body = challenge_body("c-1");
        assert_eq!(body["twoFactorRequired"], true);
        assert_eq!(body["challengeId"], "c-1");
        assert_eq!(body["expiresIn"], 300);
    }

    #[test]
    fn a_refused_challenge_gives_no_session() {
        let response = refused();
        assert_eq!(response.status(), actix_web::http::StatusCode::UNAUTHORIZED);
        assert!(response.cookies().next().is_none());
    }
}
