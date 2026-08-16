use crate::entities::{CalendarEvent, Email};
use chrono::Utc;
use futures_util::TryStreamExt;
use mongodb::bson;
use mongodb::error::Error;
use mongodb::{bson::doc, error::Result, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(not(test))]
pub mod mongo_adapter;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct User {
    #[serde(rename = "_id", skip_serializing, skip_deserializing)]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    pub username: String,
    pub password: String,
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
    #[serde(default)]
    pub condition_accepted: bool,
    #[serde(default)]
    pub locale: Option<String>,
}

pub(crate) fn default_mailbox() -> String {
    "inbox".to_string()
}

pub(crate) fn user_from_document(doc: &bson::Document, fallback_username: &str) -> User {
    let id = doc.get_object_id("_id").ok();
    let username = doc
        .get_str("username")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| fallback_username.to_string());
    let password = doc
        .get_str("password")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let mailbox = doc
        .get_str("mailbox")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| default_mailbox());

    User {
        id,
        username,
        password,
        mailbox,
        condition_accepted: false,
        locale: doc.get_str("locale").ok().map(str::to_owned),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mailbox {
    pub name: String,
    pub flags: Vec<String>,
    pub exists: u32,
    pub recent: u32,
    pub unseen: u32,
    pub permanent_flags: Vec<String>,
    pub uid_validity: u32,
    pub uid_next: u32,
    pub user_id: String,
}

pub struct Logic {
    /// Client MongoDB brut — utilisé par les méthodes non-encore-migrées.
    /// TODO(hex): à retirer une fois toutes les méthodes passent par `repo`.
    #[cfg(not(test))]
    client: Arc<Client>,
    #[cfg(test)]
    client: Box<dyn DatabaseInterface + Send + Sync>,
    /// Port du domaine (hexagonal). En prod : MongoDatabaseAdapter.
    /// En test : mock injecté. Utilisé par create_user, authenticate_user,
    /// find_user, find_emails, find_email (Boucle A — port honnête).
    #[cfg(not(test))]
    repo: Arc<dyn DatabaseInterface + Send + Sync>,
}

impl Logic {
    #[cfg(not(test))]
    pub fn new(client: Arc<Client>) -> Self {
        let repo: Arc<dyn DatabaseInterface + Send + Sync> = Arc::new(
            crate::logic::mongo_adapter::MongoDatabaseAdapter::new(client.clone()),
        );
        Logic { client, repo }
    }

    #[cfg(test)]
    pub fn new_with_mock(client: Box<dyn DatabaseInterface + Send + Sync>) -> Self {
        Logic { client }
    }

    pub async fn update_user_locale(&self, username: &str, locale: &str) -> Result<()> {
        self.repo.update_user_locale(username, locale).await
    }

    pub async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()> {
        let new_user = User {
            id: None,
            username: username.to_string(),
            password: password.to_string(),
            mailbox: mailbox.to_string(),
            condition_accepted: false,
            locale: None,
        };
        self.repo.insert_user(new_user).await
    }

    /// Enregistre alias → target dans la collection `aliases`.
    pub async fn create_alias(&self, alias: &str, target: &str) -> Result<()> {
        self.repo.create_alias(alias, target).await
    }

    /// Dépose un email directement dans l'inbox MongoDB d'un utilisateur (sans SMTP).
    pub async fn deliver_to_inbox(&self, username: &str, email: &crate::entities::Email) -> Result<()> {
        self.repo.deliver_to_inbox(username, email).await
    }

    pub async fn log_mail_event(
        &self,
        kind: &str,
        user_id: &str,
        email_id: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        self.repo.log_mail_event(kind, user_id, email_id, subject, from, to).await
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>> {
        self.repo.authenticate_user(username, password).await
    }

    pub async fn find_or_create_oauth_user(
        &self,
        provider: &str,
        provider_user_id: &str,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<User> {
        self.repo.find_or_create_oauth_user(provider, provider_user_id, email, display_name).await
    }
}

mod email_impl;
mod mailbox_impl;
mod calendar_impl;

mod traits;
pub use traits::{DatabaseInterface, LogicTrait};
#[cfg(test)]
pub use traits::MockDatabaseInterface;

#[cfg(test)]
mod tests;
