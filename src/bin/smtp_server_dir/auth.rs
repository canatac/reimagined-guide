//! Vérification de credentials SMTP AUTH.
//! Extrait de smtp_server.rs (refactor architecte).

use std::env;
use constant_time_eq::constant_time_eq;
use log::debug;

pub(crate) fn check_credentials(username: &[u8], password: &[u8]) -> bool {
    // Implement your authentication logic here
    // For example:
    let expected_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let expected_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

    let username_match = constant_time_eq(username, expected_username.as_bytes());
    let password_match = constant_time_eq(password, expected_password.as_bytes());

    debug!("Username match: {}", username_match);
    debug!("Password match: {}", password_match);

    username_match && password_match
}
