// mongo_adapter/mod.rs — Adaptateur MongoDB pour DatabaseInterface.
//
// Refactor : le fichier monolithique original (896 LOC) est découpé par domaine
// en sous-modules (users, emails, mailboxes, mailboxes_user, calendar). Chaque
// sous-module fournit des méthodes inhérentes `*_impl` sur MongoDatabaseAdapter ;
// le trait `DatabaseInterface` est implémenté dans `trait_impl.rs` et délègue
// à ces méthodes. Comportement inchangé — pur re-arrangement du code.

use mongodb::Client;
use std::sync::Arc;

mod calendar;
mod emails;
mod mailboxes;
mod mailboxes_user;
mod trait_impl;
mod users;

/// Adaptateur MongoDB qui implémente le port `DatabaseInterface`.
pub struct MongoDatabaseAdapter {
    pub client: Arc<Client>,
}

impl MongoDatabaseAdapter {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    pub(crate) fn database_name() -> String {
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
    }

    pub(crate) fn users_collection_name() -> String {
        std::env::var("MONGODB_USERS_COLLECTION").unwrap_or_else(|_| "users".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_name_defaults_to_mailserver() {
        std::env::remove_var("MONGODB_DATABASE");
        assert_eq!(database_name(), "mailserver");
    }

    #[test]
    fn database_name_reads_from_env() {
        std::env::set_var("MONGODB_DATABASE", "custom_db");
        assert_eq!(database_name(), "custom_db");
        std::env::remove_var("MONGODB_DATABASE");
    }

    #[test]
    fn users_collection_name_defaults_to_users() {
        std::env::remove_var("MONGODB_USERS_COLLECTION");
        assert_eq!(users_collection_name(), "users");
    }

    #[test]
    fn users_collection_name_reads_from_env() {
        std::env::set_var("MONGODB_USERS_COLLECTION", "my_users");
        assert_eq!(users_collection_name(), "my_users");
        std::env::remove_var("MONGODB_USERS_COLLECTION");
    }
}
