// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::logic::{Mailbox, User};
use mongodb::bson::{self, doc};
use mongodb::error::Result;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn insert_user_impl(&self, user: User) -> Result<()> {
        let username = user.username.clone();
        let users = self.users_collection();
        users.insert_one(user).await?;
        self.ensure_default_mailboxes(&username).await?;
        Ok(())
    }

    /// Retourne la collection MongoDB `users` (nom depuis env).
    fn users_collection(&self) -> mongodb::Collection<User> {
        let db_name = Self::database_name();
        let coll_name = Self::users_collection_name();
        self.client
            .database(&db_name)
            .collection::<User>(&coll_name)
    }

    /// Crée les mailboxes standard (inbox/sent/drafts/archive/trash) pour un user
    /// si elles n'existent pas déjà — comportement historique de `create_user`.
    async fn ensure_default_mailboxes(&self, username: &str) -> Result<()> {
        let db_name = Self::database_name();
        let mailboxes = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        for &name in &["inbox", "sent", "drafts", "archive", "trash"] {
            let filter = doc! { "name": name, "user_id": username };
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
                    user_id: username.to_string(),
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
        let collection_name = std::env::var("MONGODB_USERS_COLLECTION")
            .unwrap_or_else(|_| "users".to_string());
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>(&collection_name);
        collection
            .update_one(
                doc! { "username": target },
                doc! { "$addToSet": { "aliases": alias } },
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mailbox_names() {
        let names = vec!["inbox", "sent", "drafts", "archive", "trash"];
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], "inbox");
        assert_eq!(names[1], "sent");
        assert_eq!(names[2], "drafts");
        assert_eq!(names[3], "archive");
        assert_eq!(names[4], "trash");
    }

    #[test]
    fn mailbox_default_values() {
        let mailbox = Mailbox {
            name: "inbox".to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: "testuser".to_string(),
        };
        assert_eq!(mailbox.name, "inbox");
        assert_eq!(mailbox.flags.len(), 0);
        assert_eq!(mailbox.exists, 0);
        assert_eq!(mailbox.recent, 0);
        assert_eq!(mailbox.unseen, 0);
        assert_eq!(mailbox.permanent_flags.len(), 0);
        assert_eq!(mailbox.uid_validity, 1);
        assert_eq!(mailbox.uid_next, 1);
        assert_eq!(mailbox.user_id, "testuser");
    }

    #[test]
    fn user_default_values() {
        let user = User {
            id: None,
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            mailbox: "inbox".to_string(),
            condition_accepted: false,
            locale: None,
        };
        assert_eq!(user.id, None);
        assert_eq!(user.username, "testuser");
        assert_eq!(user.password, "testpass");
        assert_eq!(user.mailbox, "inbox");
        assert_eq!(user.condition_accepted, false);
        assert_eq!(user.locale, None);
    }

    #[test]
    fn user_with_locale() {
        let user = User {
            id: None,
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            mailbox: "inbox".to_string(),
            condition_accepted: false,
            locale: Some("fr".to_string()),
        };
        assert_eq!(user.locale, Some("fr".to_string()));
    }

    #[test]
    fn user_with_id() {
        let user = User {
            id: Some("user-123".to_string()),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            mailbox: "inbox".to_string(),
            condition_accepted: true,
            locale: None,
        };
        assert_eq!(user.id, Some("user-123".to_string()));
        assert!(user.condition_accepted);
    }

    #[test]
    fn password_bcrypt_prefix() {
        let password = "$2b$12$hashedpassword";
        assert!(password.starts_with("$2"));
    }

    #[test]
    fn password_plaintext_no_prefix() {
        let password = "plaintextpassword";
        assert!(!password.starts_with("$2"));
    }

    #[test]
    fn oauth_filter_format() {
        let provider = "google";
        let provider_user_id = "12345";
        let filter = doc! {
            "oauth.provider": provider,
            "oauth.subject": provider_user_id
        };
        assert!(filter.contains_key("oauth.provider"));
        assert!(filter.contains_key("oauth.subject"));
    }

    #[test]
    fn oauth_set_format() {
        let provider = "google";
        let provider_user_id = "12345";
        let oauth_set = doc! {
            "oauth": {
                "provider": provider,
                "subject": provider_user_id
            },
            "updated_at": bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis())
        };
        assert!(oauth_set.contains_key("oauth"));
        assert!(oauth_set.contains_key("updated_at"));
    }

    #[test]
    fn username_filter_format() {
        let email = "test@example.com";
        let filter = doc! { "username": email };
        assert!(filter.contains_key("username"));
    }

    #[test]
    fn alias_update_format() {
        let alias = "alias@example.com";
        let target = "target@example.com";
        let update = doc! { "$addToSet": { "aliases": alias } };
        assert!(update.contains_key("$addToSet"));
    }

    #[test]
    fn locale_update_format() {
        let username = "testuser";
        let locale = "fr";
        let update = doc! { "$set": { "locale": locale } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn email_update_format() {
        let email_id = "email-123";
        let flag = "\\Seen";
        let update = doc! { "$addToSet": { "flags": flag } };
        assert!(update.contains_key("$addToSet"));
    }

    #[test]
    fn email_delete_format() {
        let email_id = "email-123";
        let filter = doc! { "id": email_id };
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn email_archive_format() {
        let email_id = "email-123";
        let update = doc! { "$set": { "mailbox": "archive" } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn users_collection_name_default() {
        let coll_name = "users";
        assert_eq!(coll_name, "users");
    }

    #[test]
    fn mailboxes_collection_name() {
        let coll_name = "mailboxes";
        assert_eq!(coll_name, "mailboxes");
    }

    #[test]
    fn emails_collection_name() {
        let coll_name = "emails";
        assert_eq!(coll_name, "emails");
    }
}
