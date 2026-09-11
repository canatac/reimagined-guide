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

#[cfg(test)]
mod tests {
    use super::*;

    // --- generate_temp_password ---

    #[test]
    fn test_generate_temp_password_format() {
        let pw = generate_temp_password();
        // Format: XXXXXXX!XXXXXXX# = 7 chars + ! + 7 chars + # = 16 chars
        assert_eq!(pw.len(), 16);
        assert!(pw.contains('!'));
        assert!(pw.ends_with('#'));
    }

    #[test]
    fn test_generate_temp_password_has_separator_at_pos_7() {
        let pw = generate_temp_password();
        let chars: Vec<char> = pw.chars().collect();
        assert_eq!(chars[7], '!');
        assert_eq!(chars[15], '#');
    }

    #[test]
    fn test_generate_temp_password_alphanumeric_parts() {
        let pw = generate_temp_password();
        let part1 = &pw[..7];
        let part2 = &pw[8..15];
        assert!(part1.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(part2.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_temp_password_unique() {
        let pw1 = generate_temp_password();
        let pw2 = generate_temp_password();
        assert_ne!(pw1, pw2);
    }

    // --- resolve_new_password ---

    #[test]
    fn test_resolve_new_password_provided() {
        let (pw, generated) = resolve_new_password(&Some("MyPass123".into()));
        assert_eq!(pw, "MyPass123");
        assert!(!generated);
    }

    #[test]
    fn test_resolve_new_password_empty_string() {
        let (pw, generated) = resolve_new_password(&Some("".into()));
        assert!(generated);
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_resolve_new_password_whitespace_only() {
        let (pw, generated) = resolve_new_password(&Some("   ".into()));
        assert!(generated);
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_resolve_new_password_none() {
        let (pw, generated) = resolve_new_password(&None);
        assert!(generated);
        assert_eq!(pw.len(), 16);
    }

    #[test]
    fn test_resolve_new_password_trims_whitespace() {
        let (pw, generated) = resolve_new_password(&Some("  password  ".into()));
        assert_eq!(pw, "password");
        assert!(!generated);
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
