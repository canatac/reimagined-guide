use crate::entities::{CalendarEvent, Email};
use chrono::Utc;
use futures_util::TryStreamExt;
use mongodb::bson;
use mongodb::error::Error;
use mongodb::{bson::doc, error::Result, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct User {
    #[serde(rename = "_id", skip_serializing, skip_deserializing)]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    pub username: String,
    pub password: String,
    #[serde(default = "default_mailbox")]
    pub mailbox: String,
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
    #[cfg(not(test))]
    client: Arc<Client>,
    #[cfg(test)]
    client: Box<dyn DatabaseInterface + Send + Sync>,
}

impl Logic {
    #[cfg(not(test))]
    pub fn new(client: Arc<Client>) -> Self {
        Logic { client }
    }

    #[cfg(test)]
    pub fn new_with_mock(client: Box<dyn DatabaseInterface + Send + Sync>) -> Self {
        Logic { client }
    }

    pub async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()> {
        let new_user = User {
            id: None,
            username: username.to_string(),
            password: password.to_string(),
            mailbox: mailbox.to_string(),
        };
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection_name =
                std::env::var("MONGODB_COLLECTION").expect("MONGODB_COLLECTION must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>(&collection_name);

            // Insert the user
            collection.insert_one(new_user).await?;

            // Standard mailboxes to create
            let standard_mailboxes = vec!["inbox", "sent", "drafts", "archive", "trash"];
            let mailbox_collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            for &mailbox_name in &standard_mailboxes {
                let mailbox_filter = doc! { "name": mailbox_name, "user_id": username };
                if mailbox_collection
                    .find_one(mailbox_filter.clone())
                    .await?
                    .is_none()
                {
                    let mailbox = Mailbox {
                        name: mailbox_name.to_string(),
                        flags: vec![],
                        exists: 0,
                        recent: 0,
                        unseen: 0,
                        permanent_flags: vec![],
                        uid_validity: 1,
                        uid_next: 1,
                        user_id: username.to_string(),
                    };
                    mailbox_collection.insert_one(mailbox).await?;
                }
            }
            Ok(())
        }
        #[cfg(test)]
        {
            self.client.insert_user(new_user).await
        }
    }

    pub async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            // Prefer dedicated users collection — never scan "emails" with a User shape.
            let collection_name =
                std::env::var("MONGODB_USERS_COLLECTION").unwrap_or_else(|_| "users".to_string());
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>(&collection_name);

            let filter = doc! { "username": username };
            match collection.find_one(filter).await? {
                Some(user) => {
                    // Verify bcrypt hash; fall back to plaintext for legacy accounts.
                    let ok = if user.password.starts_with("$2") {
                        bcrypt::verify(password, &user.password).unwrap_or(false)
                    } else {
                        constant_time_eq::constant_time_eq(password.as_bytes(), user.password.as_bytes())
                    };
                    Ok(if ok { Some(user) } else { None })
                }
                None => Ok(None),
            }
        }
        #[cfg(test)]
        {
            self.client.find_user(username, password).await
        }
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
            })
        }
    }

    pub async fn get_emails(&self, username: &str, mailbox: &str) -> Result<Vec<Email>> {
        self.get_emails_page(username, mailbox, 200, 0).await
    }

    /// Sorted newest-first page; omits heavy headers projection at the driver level when possible.
    pub async fn get_emails_page(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "mailbox": mailbox };
            let cursor = collection
                .find(filter)
                .sort(doc! { "internal_date": -1 })
                .skip(skip)
                .limit(limit.max(1).min(200))
                // Omit very large SMTP header blobs when listing (Email.headers is #[serde(default)])
                .projection(doc! { "headers": 0 })
                .await?;
            cursor.try_collect().await
        }
        #[cfg(test)]
        {
            let _ = (limit, skip);
            let emails = vec![Email::new(
                "testemail",
                "from@test.com",
                "to@test.com",
                "Test Subject",
                "Test Body",
            )];
            Ok(emails)
        }
    }

    pub async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            collection.find_one(filter).await
        }
        #[cfg(test)]
        {
            //For test, we need to return an email
            let email = Email::new(
                "testemail",
                "from@test.com",
                "to@test.com",
                "Test Subject",
                "Test Body",
            );
            Ok(Some(email))
        }
    }

    pub async fn store_email_flag(&self, username: &str, email_id: &str, flag: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            let update = doc! { "$addToSet": { "flags": flag } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn delete_email(&self, username: &str, email_id: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let filter = doc! { "user_id": username, "id": email_id };
            collection.delete_one(filter).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            self.client.delete_email(email_id).await
        }
    }

    pub async fn archive_email(&self, username: &str, email_id: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");
            let archive_collection = self
                .client
                .database(&database_name)
                .collection::<Email>("archive");

            let filter = doc! { "user_id": username, "id": email_id };
            if let Some(document) = collection.find_one(filter.clone()).await? {
                archive_collection.insert_one(document).await?;
                collection.delete_one(filter).await?;
                Ok(())
            } else {
                Err(Error::from(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Email not found",
                )))
            }
        }
        #[cfg(test)]
        {
            self.client.archive_email(email_id).await
        }
    }

    pub async fn select_mailbox(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! { "user_id": username, "name": mailbox };
            if let Some(mailbox) = collection.find_one(filter).await? {
                Ok(mailbox)
            } else {
                Err(Error::from(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Mailbox not found",
                )))
            }
        }
        #[cfg(test)]
        {
            Ok(Mailbox {
                name: mailbox.to_string(),
                flags: vec![],
                exists: 10,
                recent: 2,
                unseen: 5,
                permanent_flags: vec![],
                uid_validity: 1,
                uid_next: 11,
                user_id: username.to_string(),
            })
        }
    }

    pub async fn search_messages(&self, username: &str, criteria: &str) -> Result<Vec<u32>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = match criteria {
                "ALL" => doc! { "user_id": username },
                "UNSEEN" => doc! { "user_id": username, "flags": { "$nin": ["\\Seen"] } },
                "SEEN" => doc! { "user_id": username, "flags": "\\Seen" },
                _ => doc! { "user_id": username },
            };

            let mut cursor = collection.find(filter).await?;
            let mut sequence_numbers = Vec::new();
            while let Some(email) = cursor.try_next().await? {
                sequence_numbers.push(email.sequence_number);
            }
            Ok(sequence_numbers)
        }
        #[cfg(test)]
        {
            //For test, we need to return a vector of sequence numbers
            let sequence_numbers = vec![1, 2, 3];
            Ok(sequence_numbers)
        }
    }

    pub async fn expunge_mailbox(&self, username: &str) -> Result<Vec<u32>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = doc! { "user_id": username, "flags": "\\Deleted" };
            let mut cursor = collection.find(filter.clone()).await?;
            let mut deleted_sequence_numbers = Vec::new();

            while let Some(email) = cursor.try_next().await? {
                deleted_sequence_numbers.push(email.sequence_number);
            }

            collection.delete_many(filter).await?;
            Ok(deleted_sequence_numbers)
        }
        #[cfg(test)]
        {
            self.client.expunge_mailbox().await
        }
    }

    pub async fn copy_messages(
        &self,
        username: &str,
        sequence_set: &str,
        _target_mailbox: &str,
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = doc! { "user_id": username, "sequence_number": sequence_set.parse::<u32>().unwrap_or(0) };
            if let Some(mut email) = collection.find_one(filter).await? {
                email.id = format!("{}_{}", email.id, Utc::now().timestamp());
                collection.insert_one(email).await?;
            }
            Ok(())
        }
        #[cfg(test)]
        {
            self.client
                .copy_messages(sequence_set, _target_mailbox)
                .await
        }
    }

    pub async fn store_flags(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Email>("emails");

            let filter = doc! { "user_id": username, "sequence_number": sequence_set.parse::<u32>().unwrap_or(0) };
            let update = match mode {
                "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
                "-" => doc! { "$pullAll": { "flags": flags } },
                _ => doc! { "$set": { "flags": flags } },
            };

            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            self.client.store_flags(sequence_set, flags, mode).await
        }
    }

    pub async fn check_mailbox(&self) -> Result<()> {
        Ok(())
    }

    pub async fn close_mailbox(&self, username: &str) -> Result<()> {
        self.expunge_mailbox(username).await?;
        Ok(())
    }

    pub async fn noop(&self) -> Result<()> {
        Ok(())
    }

    pub async fn get_mailbox_status(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        self.select_mailbox(username, mailbox).await
    }

    pub async fn create_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            // Vérifiez si la boîte aux lettres existe déjà
            let mailbox_filter = doc! { "name": mailbox, "user_id": username };
            if collection.find_one(mailbox_filter.clone()).await?.is_none() {
                println!("Creating mailbox: {}", mailbox);
                let new_mailbox = Mailbox {
                    name: mailbox.to_string(),
                    flags: vec![],
                    exists: 0,
                    recent: 0,
                    unseen: 0,
                    permanent_flags: vec![String::from("\\*")],
                    uid_validity: 1,
                    uid_next: 1,
                    user_id: username.to_string(),
                };
                collection.insert_one(new_mailbox).await?;
                println!("Mailbox created: {}", mailbox);
            } else {
                println!("Mailbox already exists: {}", mailbox);
            }
            Ok(())
        }
        #[cfg(test)]
        {
            // Pour les tests, nous devons retourner un résultat vide
            Ok(())
        }
    }

    pub async fn delete_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! { "user_id": username, "name": mailbox };
            collection.delete_one(filter).await?;

            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn rename_mailbox(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! { "user_id": username, "name": old_name };
            let update = doc! { "$set": { "name": new_name } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn subscribe_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>("subscriptions");

            let filter = doc! { "user_id": username, "mailbox": mailbox };
            let update = doc! { "$set": { "subscribed": true } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn unsubscribe_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>("subscriptions");

            let filter = doc! { "user_id": username, "mailbox": mailbox };
            let update = doc! { "$set": { "subscribed": false } };
            collection.update_one(filter, update).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(())
        }
    }

    pub async fn list_subscribed_mailboxes(
        &self,
        username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<User>("subscriptions");

            let filter = doc! { "user_id": username, "subscribed": true };
            let mut cursor = collection.find(filter).await?;
            let mut mailboxes = Vec::new();

            while let Some(subscription) = cursor.try_next().await? {
                mailboxes.push(subscription.mailbox);
            }

            Ok(mailboxes)
        }
        #[cfg(test)]
        {
            self.client
                .list_subscribed_mailboxes(username, _reference, _pattern)
                .await
        }
    }

    pub async fn get_mailbox_status_items(
        &self,
        username: &str,
        mailbox: &str,
        items: &str,
    ) -> Result<String> {
        #[cfg(not(test))]
        {
            let status = self.select_mailbox(username, mailbox).await?;
            let mut response = Vec::new();

            for item in items.split_whitespace() {
                match item.trim_matches(|c| c == '(' || c == ')') {
                    "MESSAGES" => response.push(format!("MESSAGES {}", status.exists)),
                    "RECENT" => response.push(format!("RECENT {}", status.recent)),
                    "UNSEEN" => response.push(format!("UNSEEN {}", status.unseen)),
                    "UIDNEXT" => response.push(format!("UIDNEXT {}", status.uid_next)),
                    "UIDVALIDITY" => response.push(format!("UIDVALIDITY {}", status.uid_validity)),
                    _ => continue,
                }
            }

            Ok(response.join(" "))
        }
        #[cfg(test)]
        {
            //For test, we need to return an empty result
            Ok(String::new())
        }
    }

    pub async fn store_email(&self, username: &str, mailbox: &str, email: &Email) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<mongodb::bson::Document>("emails");

            // Count existing emails to generate sequence_number and uid
            let count = collection
                .count_documents(doc! {"user_id": username, "mailbox": mailbox})
                .await?;
            let sequence_number = (count + 1) as u32;
            let uid = (count + 1) as u32;

            // Serialize the Email struct into a BSON document
            let mut document = bson::to_document(email)?;
            document.insert("user_id", username);
            document.insert("mailbox", mailbox);
            document.insert("sequence_number", sequence_number as i64);
            document.insert("uid", uid as i64);
            // Store internal_date as BSON datetime
            document.insert(
                "internal_date",
                mongodb::bson::DateTime::from_millis(email.internal_date.timestamp_millis()),
            );
            // Insert the document into the collection
            collection.insert_one(document).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    pub async fn list_mailboxes(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<Mailbox>("mailboxes");

            let filter = doc! {
                "user_id": username,
                "name": { "$regex": format!("^{}.*{}", reference, mailbox) }
            };

            let cursor = collection.find(filter).await?;
            let mailboxes: Vec<String> = cursor.map_ok(|doc| doc.name).try_collect().await?;
            Ok(mailboxes)
        }
        #[cfg(test)]
        {
            Ok(vec![
                "inbox".to_string(),
                "sent".to_string(),
                "drafts".to_string(),
            ])
        }
    }

    // --- Calendar Event CRUD ---

    pub async fn create_calendar_event(&self, event: &CalendarEvent) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<CalendarEvent>("calendar_events");
            collection.insert_one(event.clone()).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }

    pub async fn get_calendar_events(
        &self,
        username: &str,
        start_after: Option<bson::DateTime>,
        start_before: Option<bson::DateTime>,
    ) -> Result<Vec<CalendarEvent>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<CalendarEvent>("calendar_events");

            let mut filter = doc! { "user_id": username };
            if let Some(after) = start_after {
                filter.insert("start", doc! { "$gte": after });
            }
            if let Some(before) = start_before {
                if filter.contains_key("start") {
                    if let Ok(start_doc) = filter.get_document_mut("start") {
                        start_doc.insert("$lte", before);
                    }
                } else {
                    filter.insert("start", doc! { "$lte": before });
                }
            }

            let cursor = collection.find(filter).await?;
            cursor.try_collect().await
        }
        #[cfg(test)]
        {
            Ok(vec![])
        }
    }

    pub async fn get_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> Result<Option<CalendarEvent>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<CalendarEvent>("calendar_events");
            let filter = doc! { "user_id": username, "id": event_id };
            collection.find_one(filter).await
        }
        #[cfg(test)]
        {
            Ok(None)
        }
    }

    pub async fn update_calendar_event(
        &self,
        username: &str,
        event_id: &str,
        update_doc: bson::Document,
    ) -> Result<Option<CalendarEvent>> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<CalendarEvent>("calendar_events");
            let filter = doc! { "user_id": username, "id": event_id };

            let mut update = update_doc;
            update.insert(
                "updated_at",
                bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis()),
            );

            collection
                .update_one(filter.clone(), doc! { "$set": update })
                .await?;
            collection.find_one(filter).await
        }
        #[cfg(test)]
        {
            Ok(None)
        }
    }

    pub async fn delete_calendar_event(&self, username: &str, event_id: &str) -> Result<()> {
        #[cfg(not(test))]
        {
            let database_name =
                std::env::var("MONGODB_DATABASE").expect("MONGODB_DATABASE must be set");
            let collection = self
                .client
                .database(&database_name)
                .collection::<CalendarEvent>("calendar_events");
            let filter = doc! { "user_id": username, "id": event_id };
            collection.delete_one(filter).await?;
            Ok(())
        }
        #[cfg(test)]
        {
            Ok(())
        }
    }
}

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
    async fn store_email(&self, username: &str, mailbox: &str, message: &str) -> Result<()>;
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
