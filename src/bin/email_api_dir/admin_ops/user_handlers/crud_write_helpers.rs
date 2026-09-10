#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) fn build_new_admin_user(
    id: String,
    email: String,
    display_name: Option<String>,
    role: String,
    status: String,
    two_factor_enabled: bool,
    now: String,
) -> AdminUserRecord {
    AdminUserRecord {
        id,
        email,
        display_name,
        role,
        status,
        two_factor_enabled,
        last_login_at: None,
        last_activity_at: Some(now.clone()),
        sessions24h: 0,
        actions7d: 0,
        change_requests30d: 0,
        recent_activity: vec![AdminUserActivity {
            at: now.clone(),
            label: "User created".to_string(),
            kind: "admin_action".to_string(),
        }],
        created_at: now.clone(),
        updated_at: now,
        password_hash: None,
        invite_token: None,
        invite_expires_at: None,
        invited_at: None,
        notes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_new_admin_user_sets_fields() {
        let user = build_new_admin_user(
            "user-1".into(),
            "<EMAIL>".into(),
            Some("John".into()),
            "admin".into(),
            "active".into(),
            true,
            "2026-01-01T00:00:00Z".into(),
        );
        assert_eq!(user.id, "user-1");
        assert_eq!(user.email, "<EMAIL>");
        assert_eq!(user.role, "admin");
        assert_eq!(user.status, "active");
        assert!(user.two_factor_enabled);
        assert_eq!(user.recent_activity.len(), 1);
        assert_eq!(user.recent_activity[0].label, "User created");
    }

    #[test]
    fn build_new_admin_user_no_display_name() {
        let user = build_new_admin_user(
            "user-2".into(),
            "<EMAIL>".into(),
            None,
            "viewer".into(),
            "active".into(),
            false,
            "2026-01-01T00:00:00Z".into(),
        );
        assert_eq!(user.display_name, None);
        assert!(!user.two_factor_enabled);
    }
}
