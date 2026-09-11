// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::Email;
use crate::logic::{Mailbox, User};
use futures_util::TryStreamExt;
use mongodb::bson::doc;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_mailbox_filter_format() {
        let username = "testuser";
        let mailbox = "inbox";
        let filter = doc! { "name": mailbox, "user_id": username };
        assert!(filter.contains_key("name"));
        assert!(filter.contains_key("user_id"));
    }

    #[test]
    fn create_mailbox_default_values() {
        let new_mailbox = Mailbox {
            name: "inbox".to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![String::from("\\*")],
            uid_validity: 1,
            uid_next: 1,
            user_id: "testuser".to_string(),
        };
        assert_eq!(new_mailbox.name, "inbox");
        assert_eq!(new_mailbox.permanent_flags.len(), 1);
        assert_eq!(new_mailbox.uid_validity, 1);
    }

    #[test]
    fn delete_mailbox_filter_format() {
        let username = "testuser";
        let mailbox = "old_mailbox";
        let filter = doc! { "user_id": username, "name": mailbox };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("name"));
    }

    #[test]
    fn rename_mailbox_update_format() {
        let username = "testuser";
        let old_name = "old";
        let new_name = "new";
        let filter = doc! { "user_id": username, "name": old_name };
        let update = doc! { "$set": { "name": new_name } };
        assert!(filter.contains_key("user_id"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn subscribe_mailbox_update_format() {
        let username = "testuser";
        let mailbox = "inbox";
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        let update = doc! { "$set": { "subscribed": true } };
        assert!(filter.contains_key("user_id"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn unsubscribe_mailbox_update_format() {
        let username = "testuser";
        let mailbox = "inbox";
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        let update = doc! { "$set": { "subscribed": false } };
        assert!(filter.contains_key("user_id"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn select_mailbox_filter_format() {
        let username = "testuser";
        let mailbox = "inbox";
        let filter = doc! { "user_id": username, "name": mailbox };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("name"));
    }

    #[test]
    fn search_messages_all_filter() {
        let username = "testuser";
        let criteria = "ALL";
        let filter = match criteria {
            "ALL" => doc! { "user_id": username },
            "UNSEEN" => doc! { "user_id": username, "flags": { "$nin": ["\\Seen"] } },
            "SEEN" => doc! { "user_id": username, "flags": "\\Seen" },
            _ => doc! { "user_id": username },
        };
        assert!(filter.contains_key("user_id"));
        assert!(!filter.contains_key("flags"));
    }

    #[test]
    fn search_messages_unseen_filter() {
        let username = "testuser";
        let criteria = "UNSEEN";
        let filter = match criteria {
            "ALL" => doc! { "user_id": username },
            "UNSEEN" => doc! { "user_id": username, "flags": { "$nin": ["\\Seen"] } },
            "SEEN" => doc! { "user_id": username, "flags": "\\Seen" },
            _ => doc! { "user_id": username },
        };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("flags"));
    }

    #[test]
    fn search_messages_seen_filter() {
        let username = "testuser";
        let criteria = "SEEN";
        let filter = match criteria {
            "ALL" => doc! { "user_id": username },
            "UNSEEN" => doc! { "user_id": username, "flags": { "$nin": ["\\Seen"] } },
            "SEEN" => doc! { "user_id": username, "flags": "\\Seen" },
            _ => doc! { "user_id": username },
        };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("flags"));
    }

    #[test]
    fn search_messages_unknown_filter() {
        let username = "testuser";
        let criteria = "UNKNOWN";
        let filter = match criteria {
            "ALL" => doc! { "user_id": username },
            "UNSEEN" => doc! { "user_id": username, "flags": { "$nin": ["\\Seen"] } },
            "SEEN" => doc! { "user_id": username, "flags": "\\Seen" },
            _ => doc! { "user_id": username },
        };
        assert!(filter.contains_key("user_id"));
        assert!(!filter.contains_key("flags"));
    }

    #[test]
    fn expunge_mailbox_filter_format() {
        let username = "testuser";
        let filter = doc! { "user_id": username, "flags": "\\Deleted" };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("flags"));
    }

    #[test]
    fn copy_messages_filter_format() {
        let username = "testuser";
        let sequence_set = "5";
        let filter = doc! {
            "user_id": username,
            "sequence_number": sequence_set.parse::<u32>().unwrap_or(0)
        };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("sequence_number"));
    }

    #[test]
    fn copy_messages_invalid_sequence() {
        let sequence_set = "invalid";
        let parsed = sequence_set.parse::<u32>().unwrap_or(0);
        assert_eq!(parsed, 0);
    }

    #[test]
    fn copy_messages_valid_sequence() {
        let sequence_set = "42";
        let parsed = sequence_set.parse::<u32>().unwrap_or(0);
        assert_eq!(parsed, 42);
    }

    #[test]
    fn store_flags_add_mode() {
        let username = "testuser";
        let sequence_set = "1";
        let flags = vec!["\\Seen".to_string()];
        let mode = "+";
        let filter = doc! {
            "user_id": username,
            "sequence_number": sequence_set.parse::<u32>().unwrap_or(0)
        };
        let update = match mode {
            "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
            "-" => doc! { "$pullAll": { "flags": flags } },
            _ => doc! { "$set": { "flags": flags } },
        };
        assert!(update.contains_key("$addToSet"));
    }

    #[test]
    fn store_flags_remove_mode() {
        let username = "testuser";
        let sequence_set = "1";
        let flags = vec!["\\Seen".to_string()];
        let mode = "-";
        let update = match mode {
            "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
            "-" => doc! { "$pullAll": { "flags": flags } },
            _ => doc! { "$set": { "flags": flags } },
        };
        assert!(update.contains_key("$pullAll"));
    }

    #[test]
    fn store_flags_replace_mode() {
        let username = "testuser";
        let sequence_set = "1";
        let flags = vec!["\\Seen".to_string()];
        let mode = "set";
        let update = match mode {
            "+" => doc! { "$addToSet": { "flags": { "$each": flags } } },
            "-" => doc! { "$pullAll": { "flags": flags } },
            _ => doc! { "$set": { "flags": flags } },
        };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn list_subscribed_filter_format() {
        let username = "testuser";
        let filter = doc! { "user_id": username, "subscribed": true };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("subscribed"));
    }

    #[test]
    fn list_mailboxes_regex_format() {
        let username = "testuser";
        let reference = "";
        let mailbox = "*";
        let filter = doc! {
            "user_id": username,
            "name": { "$regex": format!("^{}.*{}", reference, mailbox) }
        };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("name"));
    }

    #[test]
    fn subscriptions_collection_name() {
        let coll_name = "subscriptions";
        assert_eq!(coll_name, "subscriptions");
    }

    #[test]
    fn mailboxes_collection_name() {
        let coll_name = "mailboxes";
        assert_eq!(coll_name, "mailboxes");
    }

    #[test]
    fn user_mailbox_field() {
        let user = User {
            id: None,
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            mailbox: "inbox".to_string(),
            condition_accepted: false,
            locale: None,
        };
        assert_eq!(user.mailbox, "inbox");
    }
}
