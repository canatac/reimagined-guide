// Split into domain-focused test submodules to keep this file < 300 LOC.
#[cfg(test)]
#[path = "main_tests/dkim.rs"]
mod dkim;
#[cfg(test)]
#[path = "main_tests/hermes.rs"]
mod hermes;
#[cfg(test)]
#[path = "main_tests/auth.rs"]
mod auth;
#[cfg(test)]
#[path = "main_tests/emails_send.rs"]
mod emails_send;
#[cfg(test)]
#[path = "main_tests/monitoring_admin.rs"]
mod monitoring_admin;
