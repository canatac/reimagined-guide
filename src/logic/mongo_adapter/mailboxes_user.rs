// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{Mailbox, User};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn create_mailbox_for_user_impl(&self, username: &str, mailbox: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        let filter = doc! { "name": mailbox, "user_id": username };
        if collection.find_one(filter.clone()).await?.is_none() {
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
        }
        Ok(())
    }

    pub async fn delete_mailbox_for_user_impl(&self, username: &str, mailbox: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        let filter = doc! { "user_id": username, "name": mailbox };
        collection.delete_one(filter).await?;
        Ok(())
    }

    pub async fn rename_mailbox_for_user_impl(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        let filter = doc! { "user_id": username, "name": old_name };
        let update = doc! { "$set": { "name": new_name } };
        collection.update_one(filter, update).await?;
        Ok(())
    }

    pub async fn subscribe_mailbox_for_user_impl(&self, username: &str, mailbox: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>("subscriptions");
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        let update = doc! { "$set": { "subscribed": true } };
        collection.update_one(filter, update).upsert(true).await?;
        Ok(())
    }

    pub async fn unsubscribe_mailbox_for_user_impl(&self, username: &str, mailbox: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>("subscriptions");
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        let update = doc! { "$set": { "subscribed": false } };
        collection.update_one(filter, update).upsert(true).await?;
        Ok(())
    }

    pub async fn select_mailbox_for_user_impl(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        let filter = doc! { "user_id": username, "name": mailbox };
        if let Some(mb) = collection.find_one(filter).await? {
            Ok(mb)
        } else {
            Err(mongodb::error::Error::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Mailbox not found",
            )))
        }
    }

    pub async fn search_messages_for_user_impl(&self, username: &str, criteria: &str) -> Result<Vec<u32>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
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

    pub async fn expunge_mailbox_for_user_impl(&self, username: &str) -> Result<Vec<u32>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
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

    pub async fn copy_messages_for_user_impl(
        &self,
        username: &str,
        sequence_set: &str,
        _target_mailbox: &str,
    ) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! {
            "user_id": username,
            "sequence_number": sequence_set.parse::<u32>().unwrap_or(0)
        };
        if let Some(mut email) = collection.find_one(filter).await? {
            email.id = format!("{}_{}", email.id, chrono::Utc::now().timestamp());
            collection.insert_one(email).await?;
        }
        Ok(())
    }

    pub async fn store_flags_for_user_impl(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! {
            "user_id": username,
            "sequence_number": sequence_set.parse::<u32>().unwrap_or(0)
        };
        let update = match mode {
            "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
            "-" => doc! { "$pullAll": { "flags": flags } },
            _ => doc! { "$set": { "flags": flags } },
        };
        collection.update_one(filter, update).await?;
        Ok(())
    }

    pub async fn list_subscribed_mailboxes_for_user_impl(
        &self,
        username: &str,
    ) -> Result<Vec<String>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<User>("subscriptions");
        let filter = doc! { "user_id": username, "subscribed": true };
        let mut cursor = collection.find(filter).await?;
        let mut mailboxes = Vec::new();
        while let Some(subscription) = cursor.try_next().await? {
            mailboxes.push(subscription.mailbox);
        }
        Ok(mailboxes)
    }

    pub async fn list_mailboxes_for_user_impl(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Mailbox>("mailboxes");
        let filter = doc! {
            "user_id": username,
            "name": { "$regex": format!("^{}.*{}", reference, mailbox) }
        };
        let cursor = collection.find(filter).await?;
        let mailboxes: Vec<String> = cursor.map_ok(|doc| doc.name).try_collect().await?;
        Ok(mailboxes)
    }

}
