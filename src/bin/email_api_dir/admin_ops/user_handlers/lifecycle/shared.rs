#![allow(unused_imports, dead_code)]
use super::super::super::*;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResetPasswordInput {
    pub(crate) new_password: Option<String>,
    #[serde(default)]
    pub(crate) revoke_sessions: bool,
}

pub(crate) fn generate_temp_password() -> String {
    let a = Uuid::new_v4().simple().to_string();
    let b = Uuid::new_v4().simple().to_string();
    let mixed = format!("{}{}", &a[..7], &b[..7]);
    format!("{}!{}#", &mixed[..7], &mixed[7..])
}

pub(crate) fn resolve_new_password(input: &Option<String>) -> (String, bool) {
    match input {
        Some(p) if !p.trim().is_empty() => (p.trim().to_string(), false),
        _ => (generate_temp_password(), true),
    }
}

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

pub(crate) async fn revoke_all_sessions(mongo: &Arc<mongodb::Client>, user_id: &str) {
    let sessions = mongo
        .database(&mongo_db_name())
        .collection::<admin_auth::AdminSession>(admin_auth::ADMIN_SESSIONS_COLL);
    if let Err(e) = sessions.delete_many(doc! { "user_id": user_id }).await {
        eprintln!("reset_password: revoke sessions error: {}", e);
    }
}
