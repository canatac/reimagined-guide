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
