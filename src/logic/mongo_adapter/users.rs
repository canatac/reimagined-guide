// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{Mailbox, User};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn insert_user_impl(&self, user: User) -> Result<()> {
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

    pub async fn find_user_impl(&self, username: &str, password: &str) -> Result<Option<User>> {
        let db_name = Self::database_name();
        let coll_name = Self::users_collection_name();
        let users = self
            .client
            .database(&db_name)
            .collection::<User>(&coll_name);
        let filter = doc! { "username": username, "password": password };
        users.find_one(filter).await
    }

    pub async fn create_user_impl(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> Result<()> {
        // Délègue à insert_user pour cohérence (même chemin).
        self.insert_user_impl(User {
            id: None,
            username: username.to_string(),
            password: password.to_string(),
            mailbox: mailbox.to_string(),
            condition_accepted: false,
            locale: None,
        })
        .await
    }

    pub async fn authenticate_user_impl(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>> {
        // Boucle 4 — impl réelle : porte la logique de Logic::authenticate_user
        // (bcrypt + fallback legacy plaintext, lookup par username sur la
        // collection users dédiée).
        let db_name = Self::database_name();
        let coll_name = Self::users_collection_name();
        let users = self
            .client
            .database(&db_name)
            .collection::<User>(&coll_name);
        let filter = doc! { "username": username };
        match users.find_one(filter).await? {
            Some(user) => {
                let ok = if user.password.starts_with("$2") {
                    bcrypt::verify(password, &user.password).unwrap_or(false)
                } else {
                    constant_time_eq::constant_time_eq(
                        password.as_bytes(),
                        user.password.as_bytes(),
                    )
                };
                Ok(if ok { Some(user) } else { None })
            }
            None => Ok(None),
        }
    }

    pub async fn update_user_locale_impl(&self, username: &str, locale: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection_name = std::env::var("MONGODB_USERS_COLLECTION")
            .unwrap_or_else(|_| "users".to_string());
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>(&collection_name);
        collection
            .update_one(
                doc! { "username": username },
                doc! { "$set": { "locale": locale } },
            )
            .await?;
        Ok(())
    }

    pub async fn find_or_create_oauth_user_impl(
        &self,
        provider: &str,
        provider_user_id: &str,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<User> {
        let db_name = Self::database_name();
        let collection_name = std::env::var("MONGODB_USERS_COLLECTION")
            .unwrap_or_else(|_| "users".to_string());
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>(&collection_name);

        let oauth_filter = doc! {
            "oauth.provider": provider,
            "oauth.subject": provider_user_id
        };
        if let Some(doc) = collection.find_one(oauth_filter).await? {
            return Ok(crate::logic::user_from_document(&doc, email));
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
                    "mailbox": crate::logic::default_mailbox(),
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
            Ok(crate::logic::user_from_document(&doc, email))
        } else {
            Ok(User {
                id: None,
                username: email.to_string(),
                password: String::new(),
                mailbox: crate::logic::default_mailbox(),
                condition_accepted: false,
                locale: None,
            })
        }
    }

    pub async fn create_alias_impl(&self, alias: &str, target: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>("aliases");
        let now = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
        collection
            .insert_one(doc! {
                "alias": alias,
                "target": target,
                "created_at": now,
            })
            .await?;
        Ok(())
    }

}
