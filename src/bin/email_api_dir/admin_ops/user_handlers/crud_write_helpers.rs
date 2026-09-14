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
    fn test_build_new_admin_user_basic() {
        let user = build_new_admin_user(
            "usr-1".into(),
            "a@b.com".into(),
            Some("Alice".into()),
            "admin".into(),
            "active".into(),
            false,
            "2026-01-01T00:00:00Z".into(),
        );
        assert_eq!(user.id, "usr-1");
        assert_eq!(user.email, "a@b.com");
        assert_eq!(user.display_name, Some("Alice".into()));
        assert_eq!(user.role, "admin");
        assert_eq!(user.status, "active");
        assert!(!user.two_factor_enabled);
    }

    #[test]
    fn test_build_new_admin_user_timestamps() {
        let user = build_new_admin_user(
            "usr-2".into(),
            "b@c.com".into(),
            None,
            "viewer".into(),
            "active".into(),
            true,
            "2026-02-02T12:00:00Z".into(),
        );
        assert_eq!(user.created_at, "2026-02-02T12:00:00Z");
        assert_eq!(user.updated_at, "2026-02-02T12:00:00Z");
        assert_eq!(user.last_activity_at, Some("2026-02-02T12:00:00Z".into()));
        assert_eq!(user.last_login_at, None);
    }

    #[test]
    fn test_build_new_admin_user_two_factor() {
        let user = build_new_admin_user(
            "usr-3".into(),
            "c@d.com".into(),
            Some("Carol".into()),
            "admin".into(),
            "active".into(),
            true,
            "2026-03-03T00:00:00Z".into(),
        );
        assert!(user.two_factor_enabled);
    }

    #[test]
    fn test_build_new_admin_user_recent_activity() {
        let user = build_new_admin_user(
            "usr-4".into(),
            "d@e.com".into(),
            Some("Dan".into()),
            "editor".into(),
            "active".into(),
            false,
            "2026-04-04T00:00:00Z".into(),
        );
        assert_eq!(user.recent_activity.len(), 1);
        assert_eq!(user.recent_activity[0].label, "User created");
        assert_eq!(user.recent_activity[0].kind, "admin_action");
        assert_eq!(user.recent_activity[0].at, "2026-04-04T00:00:00Z");
    }

    #[test]
    fn test_build_new_admin_user_counters_zero() {
        let user = build_new_admin_user(
            "usr-5".into(),
            "e@f.com".into(),
            None,
            "viewer".into(),
            "pending".into(),
            false,
            "2026-05-05T00:00:00Z".into(),
        );
        assert_eq!(user.sessions24h, 0);
        assert_eq!(user.actions7d, 0);
        assert_eq!(user.change_requests30d, 0);
    }

    #[test]
    fn test_build_new_admin_user_no_password() {
        let user = build_new_admin_user(
            "usr-6".into(),
            "f@g.com".into(),
            Some("Eve".into()),
            "admin".into(),
            "active".into(),
            true,
            "2026-06-06T00:00:00Z".into(),
        );
        assert_eq!(user.password_hash, None);
        assert_eq!(user.invite_token, None);
    }
}
