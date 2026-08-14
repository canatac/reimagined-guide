// mongo_adapter.rs — Adaptateur MongoDB pour DatabaseInterface (Boucle A - Hexagonal).
//
// Objectif : rendre le port `DatabaseInterface` honnête. Avant cette PR, la
// prod n'utilisait le trait NULLE PART (le vrai code passait par `self.client.database(...)`
// dans des blocs `#[cfg(not(test))]`) — les tests n'étaient donc que théoriques.
//
// Ce fichier fournit une seule implémentation `MongoDatabaseAdapter` qui expose
// les méthodes du trait pour la prod. Cette PR migre 3 méthodes clés de `Logic`
// pour passer par cet adaptateur en toutes conditions (prod ET test), prouvant
// que le port fonctionne réellement.
//
// Les autres méthodes (~30) restent temporairement sur `self.client` direct
// avec un commentaire `TODO(hex)` — migrations progressives dans les sprints
// suivants.

use crate::entities::Email;
use crate::logic::{DatabaseInterface, Mailbox, User};
use async_trait::async_trait;
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;
use mongodb::Client;
use std::sync::Arc;

/// Adaptateur MongoDB qui implémente le port `DatabaseInterface`.
///
/// Détient une `Arc<Client>` MongoDB et traduit les appels du domaine
/// en opérations Mongo concrètes.
pub struct MongoDatabaseAdapter {
    pub client: Arc<Client>,
}

impl MongoDatabaseAdapter {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    fn database_name() -> String {
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
    }

    fn users_collection_name() -> String {
        std::env::var("MONGODB_USERS_COLLECTION").unwrap_or_else(|_| "users".to_string())
    }
}

#[async_trait]
impl DatabaseInterface for MongoDatabaseAdapter {
    async fn insert_user(&self, user: User) -> Result<()> {
        let db_name = Self::database_name();
        let coll_name = Self::users_collection_name();
        let username = user.username.clone();

        let users = self
            .client
            .database(&db_name)
            .collection::<User>(&coll_name);
        users.insert_one(user).await?;

        // Créer les mailboxes standard (comportement historique de create_user).
        let mailboxes = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        for &name in &["inbox", "sent", "drafts", "archive", "trash"] {
            let filter = doc! { "name": name, "user_id": &username };
            if mailboxes.find_one(filter).await?.is_none() {
                let mailbox = Mailbox {
                    name: name.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: username.clone(),
                };
                mailboxes.insert_one(mailbox).await?;
            }
        }
        Ok(())
    }

    async fn find_user(&self, username: &str, password: &str) -> Result<Option<User>> {
        let db_name = Self::database_name();
        let coll_name = Self::users_collection_name();
        let users = self
            .client
            .database(&db_name)
            .collection::<User>(&coll_name);
        let filter = doc! { "username": username, "password": password };
        users.find_one(filter).await
    }

    async fn find_emails(&self, mailbox: &str) -> Result<Vec<Email>> {
        let db_name = Self::database_name();
        let emails = self.client.database(&db_name).collection::<Email>("emails");
        let filter = doc! { "mailbox": mailbox };
        let cursor = emails.find(filter).await?;
        cursor.try_collect().await
    }

    async fn find_email(&self, email_id: &str) -> Result<Option<Email>> {
        let db_name = Self::database_name();
        let emails = self.client.database(&db_name).collection::<Email>("emails");
        emails.find_one(doc! { "id": email_id }).await
    }

    // ---------------------------------------------------------------------
    // Les méthodes suivantes du trait sont laissées avec des stubs Ok(...) :
    // elles ne sont PAS encore appelées via `self.repo` par Logic (TODO(hex)).
    // La migration progressive se fera dans les sprints suivants. Fournir des
    // stubs permet de satisfaire le compilateur en attendant.
    // ---------------------------------------------------------------------

    async fn update_email_flag(&self, _email_id: &str, _flag: &str) -> Result<()> {
        // TODO(hex): implémenter via MongoDB (voir Logic::update_email_flag)
        Ok(())
    }
    async fn delete_email(&self, _email_id: &str) -> Result<()> {
        Ok(())
    }
    async fn archive_email(&self, _email_id: &str) -> Result<()> {
        Ok(())
    }
    async fn select_mailbox(&self, mailbox: &str) -> Result<Mailbox> {
        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        })
    }
    async fn search_messages(&self, _criteria: &str) -> Result<Vec<u32>> {
        Ok(vec![])
    }
    async fn expunge_mailbox(&self) -> Result<Vec<u32>> {
        Ok(vec![])
    }
    async fn copy_messages(&self, _sequence_set: &str, _target_mailbox: &str) -> Result<()> {
        Ok(())
    }
    async fn store_flags(
        &self,
        _sequence_set: &str,
        _flags: Vec<String>,
        _mode: &str,
    ) -> Result<()> {
        Ok(())
    }
    async fn find_mailbox(&self, _name: &str) -> Result<Option<Mailbox>> {
        Ok(None)
    }
    async fn update_mailbox(&self, _mailbox: &str, _update: Mailbox) -> Result<()> {
        Ok(())
    }
    async fn create_mailbox(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }
    async fn delete_mailbox(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }
    async fn rename_mailbox(&self, _old_name: &str, _new_name: &str) -> Result<()> {
        Ok(())
    }
    async fn subscribe_mailbox(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }
    async fn unsubscribe_mailbox(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }
    async fn list_subscribed_mailboxes(
        &self,
        _username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }
    async fn get_mailbox_status_items(
        &self,
        _username: &str,
        _mailbox: &str,
        _items: &str,
    ) -> Result<String> {
        Ok(String::new())
    }
    async fn store_email(
        &self,
        _username: &str,
        _mailbox: &str,
        _message: &str,
    ) -> Result<()> {
        Ok(())
    }
    async fn get_mailbox_status(&self, _username: &str, mailbox: &str) -> Result<Mailbox> {
        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        })
    }
    async fn noop(&self) -> Result<()> {
        Ok(())
    }
    async fn close_mailbox(&self) -> Result<()> {
        Ok(())
    }
    async fn check_mailbox(&self) -> Result<()> {
        Ok(())
    }
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> Result<()> {
        // Délègue à insert_user pour cohérence (même chemin).
        self.insert_user(User {
            id: None,
            username: username.to_string(),
            password: password.to_string(),
            mailbox: mailbox.to_string(),
            condition_accepted: false,
            locale: None,
        })
        .await
    }
    async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>> {
        self.find_user(username, password).await
    }
    async fn list_mailboxes(
        &self,
        _username: &str,
        _reference: &str,
        _mailbox: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

// Silencer l'import inutilisé de bson::Document si non exploité (le use ci-dessus
// évite les warnings dans le module lorsque des variantes futures s'ajoutent).
#[allow(dead_code)]
fn _bson_use() -> bson::Document {
    doc! {}
}
