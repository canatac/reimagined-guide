// External IMAP service module.
// Provides the ExternalImapService and its OAuth2 token helpers.

use mongodb::Client;
use std::sync::Arc;

pub struct ExternalImapService {
    client: Arc<Client>,
}

impl ExternalImapService {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    /// Get a reference to the MongoDB client (for OAuth2 token storage, etc.)
    pub fn client(&self) -> Arc<Client> {
        self.client.clone()
    }

    fn db_name() -> String {
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
    }
}
