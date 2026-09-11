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
    fn build_new_admin_user_fields_propagated() {
        let user = build_new_admin_user(
            "u1".to_string(),
            "a@b.com".to_string(),
            Some("Alice".to_string()),
            "admin".to_string(),
            "active".to_string(),
            false,
            "2026-01-01T00:00:00Z".to_string(),
        );
        assert_eq!(user.id, "u1");
        assert_eq!(user.email, "a@b.com");
        assert_eq!(user.display_name, Some("Alice".to_string()));
        assert_eq!(user.role, "admin");
        assert_eq!(user.status, "active");
        assert!(!user.two_factor_enabled);
    }

    #[test]
    fn build_new_admin_user_timestamps() {
        let now = "2026-01-01T00:00:00Z".to_string();
        let user = build_new_admin_user(
            "u1".to_string(),
            "a@b.com".to_string(),
            None,
            "admin".to_string(),
            "active".to_string(),
            false,
            now.clone(),
        );
        assert_eq!(user.created_at, now);
        assert_eq!(user.updated_at, now);
        assert_eq!(user.last_activity_at, Some(now));
    }

    #[test]
    fn build_new_admin_user_optional_fields_none() {
        let user = build_new_admin_user(
            "u1".to_string(),
            "a@b.com".to_string(),
            None,
            "admin".to_string(),
            "active".to_string(),
            false,
            "2026-01-01".to_string(),
        );
        assert!(user.password_hash.is_none());
        assert!(user.invite_token.is_none());
        assert!(user.invite_expires_at.is_none());
        assert!(user.invited_at.is_none());
        assert!(user.notes.is_none());
    }

    #[test]
    fn build_new_admin_user_login_null() {
        let user = build_new_admin_user(
            "u1".to_string(),
            "a@b.com".to_string(),
            None,
            "admin".to_string(),
            "active".to_string(),
            false,
            "2026-01-01".to_string(),
        );
        assert!(user.last_login_at.is_none());
    }

    #[test]
    fn build_new_admin_user_initial_counters_zero() {
        let user = build_new_admin_user(
            "u1".to_string(),
            "a@b.com".to_string(),
            None,
            "admin".to_string(),
            "active".to_string(),
            false,
            "2026-01-01".to_string(),
        );
        assert_eq!(user.sessions24h, 0);
        assert_eq!(user.actions7d, 0);
        assert_eq!(user.change_requests30d, 0);
    }

    #[test]
    fn build_new_admin_user_activity_record() {
        let user = build_new_admin_user(
            "u1".to_string(),
            "a@b.com".to_string(),
            None,
            "admin".to_string(),
            "active".to_string(),
            false,
            "2026-01-01".to_string(),
        );
        assert_eq!(user.recent_activity.len(), 1);
        assert_eq!(user.recent_activity[0].label, "User created");
        assert_eq!(user.recent_activity[0].kind, "admin_action");
    }
}
