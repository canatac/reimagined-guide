// Split into domain-focused test submodules to keep this file < 300 LOC.
#[cfg(test)]
mod tests {
    #[path = "main_tests/dkim.rs"] mod dkim;
    #[path = "main_tests/hermes.rs"] mod hermes;
    #[path = "main_tests/auth.rs"] mod auth;
    #[path = "main_tests/emails_send.rs"] mod emails_send;
    #[path = "main_tests/monitoring_admin.rs"] mod monitoring_admin;
}
