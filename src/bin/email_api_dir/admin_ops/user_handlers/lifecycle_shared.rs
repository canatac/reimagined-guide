#![allow(unused_imports, dead_code)]
use super::super::*;
use super::audit::log_admin_action;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResetPasswordInput {
    /// Optionnel — si non fourni, un mot de passe temporaire est généré.
    new_password: Option<String>,
    /// Si true, invalide toutes les sessions existantes en plus.
    #[serde(default)]
    revoke_sessions: bool,
}

/// Génère un mot de passe temporaire (16 chars, avec 2 symboles) conforme
/// aux politiques classiques.
pub(crate) fn generate_temp_password() -> String {
    let a = Uuid::new_v4().simple().to_string();
    let b = Uuid::new_v4().simple().to_string();
    let mixed = format!("{}{}", &a[..7], &b[..7]);
    format!("{}!{}#", &mixed[..7], &mixed[7..])
}

/// Résout le mot de passe à appliquer : celui fourni par l'admin ou un
/// mot de passe temporaire généré. Retourne (password, generated).
pub(crate) fn resolve_new_password(input: &Option<String>) -> (String, bool) {
    match input {
        Some(p) if !p.trim().is_empty() => (p.trim().to_string(), false),
        _ => (generate_temp_password(), true),
    }
}

/// Propage le nouveau hash à la collection `users` (login classique + IMAP/SMTP).
/// Non-bloquant : seulement un log en cas d'erreur.
pub(crate) async fn sync_users_password(
    mongo: &Arc<mongodb::Client>,
    email: &str,
    hash: &str,
) {
    let users_coll = mongo
        .database(&mongo_db_name())
        .collection::<mongodb::bson::Document>("users");
    if let Err(e) = users_coll
        .update_one(
            doc! { "username": email },
            doc! { "$set": { "password": hash } },
        )
        .await
    {
        eprintln!("reset_password: users sync warning: {}", e);
    }
}

/// Supprime toutes les sessions actives d'un user (best-effort).
pub(crate) async fn revoke_all_sessions(mongo: &Arc<mongodb::Client>, user_id: &str) {
    let sessions = mongo
        .database(&mongo_db_name())
        .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
    if let Err(e) = sessions.delete_many(doc! { "user_id": user_id }).await {
        eprintln!("reset_password: revoke sessions error: {}", e);
    }
}
