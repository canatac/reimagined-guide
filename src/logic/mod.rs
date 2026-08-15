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

fn default_mailbox() -> String {
    "inbox".to_string()
}

fn user_from_document(doc: &bson::Document, fallback_username: &str) -> User {
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
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection_name =
                std::env::var("MONGODB_USERS_COLLECTION").unwrap_or_else(|_| "users".to_string());
            let collection = self
                .client
                .database(&database_name)
                .collection::<bson::Document>(&collection_name);

            let oauth_filter = doc! {
                "oauth.provider": provider,
                "oauth.subject": provider_user_id
            };
            if let Some(doc) = collection.find_one(oauth_filter).await? {
                return Ok(user_from_document(&doc, email));
            }

            let username_filter = doc! { "username": email };
            let oauth_set = doc! {
                "oauth": {
                    "provider": provider,
                    "subject": provider_user_id
                },
                "updated_at": bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis())
            };
            if collection
                .find_one(username_filter.clone())
                .await?
                .is_some()
            {
                collection
                    .update_one(username_filter.clone(), doc! { "$set": oauth_set })
                    .await?;
            } else {
                collection
                    .insert_one(doc! {
                        "username": email,
                        "password": "",
                        "mailbox": default_mailbox(),
                        "display_name": display_name.unwrap_or(email),
                        "oauth": {
                            "provider": provider,
                            "subject": provider_user_id
                        },
                        "created_at": bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis()),
                        "updated_at": bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis())
                    })
                    .await?;
            }

            let final_filter = doc! {
                "oauth.provider": provider,
                "oauth.subject": provider_user_id
            };
            if let Some(doc) = collection.find_one(final_filter).await? {
                Ok(user_from_document(&doc, email))
            } else {
                Ok(User {
                    id: None,
                    username: email.to_string(),
                    password: String::new(),
                    mailbox: default_mailbox(),
                    condition_accepted: false,
                    locale: None,
                })
            }
        }
        #[cfg(test)]
        {
            let _ = (provider, provider_user_id, display_name);
            Ok(User {
                id: None,
                username: email.to_string(),
                password: String::new(),
                mailbox: default_mailbox(),
                condition_accepted: false,
                locale: None,
            })
        }
    }
}

mod email_impl;
mod mailbox_impl;
mod calendar_impl;


#[async_trait::async_trait]

#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait DatabaseInterface: Send + Sync {
    async fn insert_user(&self, user: User) -> Result<()>;
    async fn find_user(&self, username: &str, password: &str) -> Result<Option<User>>;
    async fn find_emails(&self, mailbox: &str) -> Result<Vec<Email>>;
    async fn find_email(&self, email_id: &str) -> Result<Option<Email>>;
    async fn update_email_flag(&self, email_id: &str, flag: &str) -> Result<()>;
    async fn delete_email(&self, email_id: &str) -> Result<()>;
    async fn archive_email(&self, email_id: &str) -> Result<()>;
    async fn select_mailbox(&self, mailbox: &str) -> Result<Mailbox>;
    async fn search_messages(&self, criteria: &str) -> Result<Vec<u32>>;
    async fn expunge_mailbox(&self) -> Result<Vec<u32>>;
    async fn copy_messages(&self, sequence_set: &str, target_mailbox: &str) -> Result<()>;
    async fn store_flags(&self, sequence_set: &str, flags: Vec<String>, mode: &str) -> Result<()>;
    async fn find_mailbox(&self, name: &str) -> Result<Option<Mailbox>>;
    async fn update_mailbox(&self, mailbox: &str, update: Mailbox) -> Result<()>;
    async fn create_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn delete_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn rename_mailbox(&self, old_name: &str, new_name: &str) -> Result<()>;
    async fn subscribe_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn unsubscribe_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn list_subscribed_mailboxes(
        &self,
        username: &str,
        reference: &str,
        pattern: &str,
    ) -> Result<Vec<String>>;
    async fn get_mailbox_status_items(
        &self,
        username: &str,
        mailbox: &str,
        items: &str,
    ) -> Result<String>;
    async fn store_email(&self, username: &str, mailbox: &str, email: &Email) -> Result<()>;
    async fn get_mailbox_status(&self, username: &str, mailbox: &str) -> Result<Mailbox>;
    async fn noop(&self) -> Result<()>;
    async fn close_mailbox(&self) -> Result<()>;
    async fn check_mailbox(&self) -> Result<()>;
    async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()>;
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>>;
    async fn list_mailboxes(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>>;

    // Boucle 6 — extensions du port pour lecture/écriture email par user.
    async fn get_emails_page(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>>;
    async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>>;
    async fn set_email_read(
        &self,
        username: &str,
        email_id: &str,
        read: bool,
    ) -> Result<bool>;
    async fn set_email_starred(
        &self,
        username: &str,
        email_id: &str,
        starred: bool,
    ) -> Result<bool>;
    async fn move_email_to_mailbox(
        &self,
        username: &str,
        email_id: &str,
        target_mailbox: &str,
    ) -> Result<bool>;

    // Boucle 7 — extensions user-scopées pour l'administration des mailboxes.
    async fn create_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;
    async fn delete_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;
    async fn rename_mailbox_for_user(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()>;
    async fn subscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;
    async fn unsubscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;

    // Boucle 8 — sélection mailbox user-scopée.
    async fn select_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<Mailbox>;

    // Boucle 9 — calendar via port.
    async fn create_calendar_event(&self, event: &CalendarEvent) -> Result<()>;
    async fn get_calendar_events(
        &self,
        username: &str,
        start_after: Option<bson::DateTime>,
        start_before: Option<bson::DateTime>,
    ) -> Result<Vec<CalendarEvent>>;
    async fn get_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> Result<Option<CalendarEvent>>;
    async fn update_calendar_event(
        &self,
        username: &str,
        event_id: &str,
        update_doc: bson::Document,
    ) -> Result<Option<CalendarEvent>>;
    async fn delete_calendar_event(&self, username: &str, event_id: &str) -> Result<()>;

    // Boucle 10 — user admin + delivery + logging.
    async fn update_user_locale(&self, username: &str, locale: &str) -> Result<()>;
    async fn create_alias(&self, alias: &str, target: &str) -> Result<()>;
    async fn deliver_to_inbox(&self, username: &str, email: &Email) -> Result<()>;
    async fn log_mail_event(
        &self,
        kind: &str,
        user_id: &str,
        email_id: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> Result<()>;

    // Boucle 11 — IMAP: search/expunge/copy/store_flags/list_subscribed/status_items/list.
    async fn search_messages_for_user(&self, username: &str, criteria: &str) -> Result<Vec<u32>>;
    async fn expunge_mailbox_for_user(&self, username: &str) -> Result<Vec<u32>>;
    async fn copy_messages_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        target_mailbox: &str,
    ) -> Result<()>;
    async fn store_flags_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()>;
    async fn list_subscribed_mailboxes_for_user(
        &self,
        username: &str,
    ) -> Result<Vec<String>>;
    async fn list_mailboxes_for_user(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>>;
}

#[async_trait::async_trait]
pub trait LogicTrait: Send + Sync {
    async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()>;
}

#[async_trait::async_trait]
impl LogicTrait for Logic {
    async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()> {
        self.create_user(username, password, mailbox).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::Email;
    use crate::logic::Logic;
    use dotenv::dotenv;
    use mockall::predicate::eq;

    #[tokio::test]
    async fn test_create_user() {
        dotenv::from_filename(".env.test").ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());
        let test_password = uuid::Uuid::new_v4().to_string();

        mock_client
            .expect_insert_user()
            .times(1)
            .returning(|_user| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic
            .create_user("testuser", &test_password, "testmailbox")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_authenticate_user() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());
        let test_password = uuid::Uuid::new_v4().to_string();
        let expected_password = test_password.clone();

        mock_client
            .expect_find_user()
            .with(eq("testuser"), eq(test_password.as_str()))
            .times(1)
            .returning(move |_, _| {
                Ok(Some(User {
                    id: None,
                    username: "testuser".to_string(),
                    password: expected_password.clone(),
                    mailbox: "testmailbox".to_string(),
                    condition_accepted: false,
                }))
            });

        let logic = Logic::new_with_mock(mock_client);
        let user = logic
            .authenticate_user("testuser", &test_password)
            .await
            .unwrap();
        assert!(user.is_some());
    }

    #[tokio::test]
    async fn test_get_emails() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_find_emails()
            .with(eq("testmailbox"))
            .times(1)
            .returning(|_| {
                Ok(vec![Email::new(
                    "1",
                    "from@test.com",
                    "to@test.com",
                    "Test Subject",
                    "Test Body",
                )])
            });

        let logic = Logic::new_with_mock(mock_client);
        let emails = logic.get_emails("testuser", "testmailbox").await.unwrap();
        assert!(!emails.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_find_email()
            .with(eq("testemail"))
            .times(1)
            .returning(|_| {
                Ok(Some(Email::new(
                    "testemail",
                    "from@test.com",
                    "to@test.com",
                    "Test Subject",
                    "Test Body",
                )))
            });

        let logic = Logic::new_with_mock(mock_client);
        let email = logic.fetch_email("testuser", "testemail").await.unwrap();
        assert!(email.is_some());
    }

    #[tokio::test]
    async fn test_store_email_flag() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_update_email_flag()
            .with(eq("testemail"), eq("Seen"))
            .times(1)
            .returning(|_, _| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic
            .store_email_flag("testuser", "testemail", "Seen")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_delete_email()
            .with(eq("testemail"))
            .times(1)
            .returning(|_| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.delete_email("testuser", "testemail").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_archive_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_archive_email()
            .with(eq("testemail"))
            .times(1)
            .returning(|_| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.archive_email("testuser", "testemail").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_select_mailbox() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_select_mailbox()
            .with(eq("testmailbox"))
            .times(1)
            .returning(|name| {
                Ok(Mailbox {
                    name: name.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: "testuser".to_string(),
                })
            });

        let logic = Logic::new_with_mock(mock_client);
        let mailbox = logic
            .select_mailbox("testuser", "testmailbox")
            .await
            .unwrap();
        assert_eq!(mailbox.name, "testmailbox");
    }

    #[tokio::test]
    async fn test_search_messages() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_search_messages()
            .with(eq("ALL"))
            .times(1)
            .returning(|_| Ok(vec![1, 2, 3]));

        let logic = Logic::new_with_mock(mock_client);
        let messages = logic.search_messages("testuser", "ALL").await.unwrap();
        assert!(!messages.is_empty());
    }

    #[tokio::test]
    async fn test_expunge_mailbox() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_expunge_mailbox()
            .times(1)
            .returning(|| Ok(vec![1, 2, 3]));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.expunge_mailbox("testuser").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_copy_messages() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_copy_messages()
            .with(eq("1"), eq("testmailbox"))
            .times(1)
            .returning(|_, _| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic.copy_messages("testuser", "1", "testmailbox").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_store_flags() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_store_flags()
            .with(eq("1"), eq(vec!["Seen".to_string()]), eq("+"))
            .times(1)
            .returning(|_, _, _| Ok(()));

        let logic = Logic::new_with_mock(mock_client);
        let result = logic
            .store_flags("testuser", "1", vec!["Seen".to_string()], "+")
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_noop() {
        dotenv().ok();
        let mock_client = Box::new(MockDatabaseInterface::new());
        let logic = Logic::new_with_mock(mock_client);
        let result = logic.noop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_mailbox_status() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_select_mailbox()
            .with(eq("testmailbox"))
            .times(1)
            .returning(|name| {
                Ok(Mailbox {
                    name: name.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: "testuser".to_string(),
                })
            });

        let logic = Logic::new_with_mock(mock_client);
        let mailbox = logic
            .get_mailbox_status("testuser", "testmailbox")
            .await
            .unwrap();
        assert_eq!(mailbox.name, "testmailbox");
    }

    #[tokio::test]
    async fn test_get_mailbox_status_items() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_get_mailbox_status_items()
            .with(
                eq("testuser"),
                eq("testmailbox"),
                eq("MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY"),
            )
            .times(1)
            .returning(|_, _, _| {
                Ok("MESSAGES 1 RECENT 1 UNSEEN 1 UIDNEXT 2 UIDVALIDITY 1".to_string())
            });

        let logic = Logic::new_with_mock(mock_client);
        let status = logic
            .get_mailbox_status_items(
                "testuser",
                "testmailbox",
                "MESSAGES RECENT UNSEEN UIDNEXT UIDVALIDITY",
            )
            .await
            .unwrap();
        assert_eq!(
            status,
            "MESSAGES 1 RECENT 1 UNSEEN 1 UIDNEXT 2 UIDVALIDITY 1"
        );
    }

    #[tokio::test]
    async fn test_store_email() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_store_email()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let email = Email::new(
            "testemail",
            "from@test.com",
            "to@test.com",
            "Test Subject",
            "Test Body",
        );
        let logic = Logic::new_with_mock(mock_client);
        let result = logic.store_email("testuser", "testmailbox", &email).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_mailboxes() {
        dotenv().ok();
        let mut mock_client = Box::new(MockDatabaseInterface::new());

        mock_client
            .expect_list_mailboxes()
            .with(eq("testuser"), eq("*"), eq("testmailbox"))
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![
                    "inbox".to_string(),
                    "sent".to_string(),
                    "drafts".to_string(),
                ])
            });

        let logic = Logic::new_with_mock(mock_client);
        let mailboxes = logic
            .list_mailboxes("testuser", "*", "testmailbox")
            .await
            .unwrap();
        assert_eq!(mailboxes, vec!["inbox", "sent", "drafts"]);
    }
}
