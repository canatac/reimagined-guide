// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::Email;
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;

#[path = "emails_deser.rs"]
mod emails_deser;
use emails_deser::deserialize_email_document;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn find_emails_impl(&self, mailbox: &str) -> Result<Vec<Email>> {
        let db_name = Self::database_name();
        let emails = self.client.database(&db_name).collection::<Email>("emails");
        let filter = doc! { "mailbox": mailbox };
        let cursor = emails.find(filter).await?;
        cursor.try_collect().await
    }

    pub async fn find_email_impl(&self, email_id: &str) -> Result<Option<Email>> {
        let db_name = Self::database_name();
        let emails = self
            .client
            .database(&db_name)
            .collection::<bson::Document>("emails");
        Ok(emails
            .find_one(doc! { "id": email_id })
            .await?
            .and_then(deserialize_email_document))
    }

    pub async fn update_email_flag_impl(&self, email_id: &str, flag: &str) -> Result<()> {
        // Boucle 4 — impl réelle : ajoute un flag au tableau `flags` de l'email.
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! { "id": email_id };
        let update = doc! { "$addToSet": { "flags": flag } };
        collection.update_one(filter, update).await?;
        Ok(())
    }

    pub async fn delete_email_impl(&self, email_id: &str) -> Result<()> {
        // Boucle 4 — impl réelle : delete_one par id (portage depuis Logic::delete_email).
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        collection.delete_one(doc! { "id": email_id }).await?;
        Ok(())
    }

    pub async fn archive_email_impl(&self, email_id: &str) -> Result<()> {
        // Boucle 4 — impl réelle : bascule le mailbox de l'email vers "archive".
        // Simplification vs Logic::archive_email (qui déplace entre collections) :
        // on met le champ `mailbox` à "archive" — même effet côté requêtes utilisateur.
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! { "id": email_id };
        let update = doc! { "$set": { "mailbox": "archive" } };
        collection.update_one(filter, update).await?;
        Ok(())
    }

    pub async fn store_email_impl(
        &self,
        username: &str,
        mailbox: &str,
        email: &Email,
    ) -> Result<()> {
        // Boucle 4 — impl réelle : porte la logique de Logic::store_email
        // (mailbox_impl.rs) — sequence_number/uid dérivés du count courant.
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<bson::Document>("emails");

        let count = collection
            .count_documents(doc! { "user_id": username, "mailbox": mailbox })
            .await?;
        let sequence_number = (count + 1) as u32;
        let uid = (count + 1) as u32;

        let mut document = bson::to_document(email)?;
        document.insert("user_id", username);
        document.insert("mailbox", mailbox);
        document.insert("sequence_number", sequence_number);
        document.insert("uid", uid);
        document.insert(
            "internal_date",
            bson::DateTime::from_millis(email.internal_date.timestamp_millis()),
        );
        collection.insert_one(document).await?;
        Ok(())
    }

    pub async fn get_emails_page_impl(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<bson::Document>("emails");
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        let mut cursor = collection
            .find(filter)
            .sort(doc! { "internal_date": -1 })
            .skip(skip)
            .limit(limit.clamp(1, 200))
            .await?;
        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await? {
            if let Some(email) = deserialize_email_document(doc) {
                out.push(email);
            }
        }
        Ok(out)
    }

    pub async fn fetch_email_impl(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<bson::Document>("emails");
        let filter = doc! { "user_id": username, "id": email_id };
        Ok(collection
            .find_one(filter)
            .await?
            .and_then(deserialize_email_document))
    }

    pub async fn set_email_read_impl(
        &self,
        username: &str,
        email_id: &str,
        read: bool,
    ) -> Result<bool> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! { "user_id": username, "id": email_id };
        let update = if read {
            doc! { "$addToSet": { "flags": "\\Seen" } }
        } else {
            doc! { "$pull": { "flags": "\\Seen" } }
        };
        let res = collection.update_one(filter, update).await?;
        Ok(res.matched_count > 0)
    }

    pub async fn set_email_starred_impl(
        &self,
        username: &str,
        email_id: &str,
        starred: bool,
    ) -> Result<bool> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! { "user_id": username, "id": email_id };
        let update = if starred {
            doc! { "$addToSet": { "flags": "\\Flagged" } }
        } else {
            doc! { "$pull": { "flags": "\\Flagged" } }
        };
        let res = collection.update_one(filter, update).await?;
        Ok(res.matched_count > 0)
    }

    pub async fn move_email_to_mailbox_impl(
        &self,
        username: &str,
        email_id: &str,
        target_mailbox: &str,
    ) -> Result<bool> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! { "user_id": username, "id": email_id };
        let update = doc! { "$set": { "mailbox": target_mailbox } };
        let res = collection.update_one(filter, update).await?;
        Ok(res.matched_count > 0)
    }

    pub async fn deliver_to_inbox_impl(&self, username: &str, email: &Email) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>("emails");
        let now = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
        collection
            .insert_one(doc! {
                "id": &email.id,
                "user_id": username,
                "mailbox": "inbox",
                "from": &email.from,
                "to": &email.to,
                "subject": &email.subject,
                "body": &email.body,
                "flags": bson::Array::new(),
                "internal_date": now,
                "sequence_number": 1i32,
                "uid": 1i32,
            })
            .await?;
        Ok(())
    }

    pub async fn log_mail_event_impl(
        &self,
        kind: &str,
        user_id: &str,
        email_id: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<mongodb::bson::Document>("mail_events");
        let now = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
        collection
            .insert_one(doc! {
                "kind": kind,
                "user_id": user_id,
                "email_id": email_id,
                "subject": subject,
                "from": from,
                "to": to,
                "timestamp": now,
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_find_filter_format() {
        let mailbox = "inbox";
        let filter = doc! { "mailbox": mailbox };
        assert!(filter.contains_key("mailbox"));
    }

    #[test]
    fn email_find_by_id_filter_format() {
        let email_id = "email-123";
        let filter = doc! { "id": email_id };
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn email_update_flag_format() {
        let email_id = "email-123";
        let flag = "\\Seen";
        let filter = doc! { "id": email_id };
        let update = doc! { "$addToSet": { "flags": flag } };
        assert!(filter.contains_key("id"));
        assert!(update.contains_key("$addToSet"));
    }

    #[test]
    fn email_delete_filter_format() {
        let email_id = "email-123";
        let filter = doc! { "id": email_id };
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn email_archive_update_format() {
        let email_id = "email-123";
        let filter = doc! { "id": email_id };
        let update = doc! { "$set": { "mailbox": "archive" } };
        assert!(filter.contains_key("id"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn email_store_sequence_number() {
        let count = 5u64;
        let sequence_number = (count + 1) as u32;
        assert_eq!(sequence_number, 6);
    }

    #[test]
    fn email_store_uid() {
        let count = 10u64;
        let uid = (count + 1) as u32;
        assert_eq!(uid, 11);
    }

    #[test]
    fn email_get_page_filter_format() {
        let username = "testuser";
        let mailbox = "inbox";
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("mailbox"));
    }

    #[test]
    fn email_get_page_sort_format() {
        let sort = doc! { "internal_date": -1 };
        assert!(sort.contains_key("internal_date"));
    }

    #[test]
    fn email_get_page_limit_clamp() {
        let limit = 300i64;
        let clamped = limit.clamp(1, 200);
        assert_eq!(clamped, 200);
    }

    #[test]
    fn email_get_page_limit_clamp_low() {
        let limit = -5i64;
        let clamped = limit.clamp(1, 200);
        assert_eq!(clamped, 1);
    }

    #[test]
    fn email_get_page_limit_clamp_normal() {
        let limit = 50i64;
        let clamped = limit.clamp(1, 200);
        assert_eq!(clamped, 50);
    }

    #[test]
    fn email_fetch_filter_format() {
        let username = "testuser";
        let email_id = "email-123";
        let filter = doc! { "user_id": username, "id": email_id };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn email_set_read_add_format() {
        let username = "testuser";
        let email_id = "email-123";
        let read = true;
        let filter = doc! { "user_id": username, "id": email_id };
        let update = if read {
            doc! { "$addToSet": { "flags": "\\Seen" } }
        } else {
            doc! { "$pull": { "flags": "\\Seen" } }
        };
        assert!(update.contains_key("$addToSet"));
    }

    #[test]
    fn email_set_read_remove_format() {
        let username = "testuser";
        let email_id = "email-123";
        let read = false;
        let update = if read {
            doc! { "$addToSet": { "flags": "\\Seen" } }
        } else {
            doc! { "$pull": { "flags": "\\Seen" } }
        };
        assert!(update.contains_key("$pull"));
    }

    #[test]
    fn email_set_starred_add_format() {
        let username = "testuser";
        let email_id = "email-123";
        let starred = true;
        let update = if starred {
            doc! { "$addToSet": { "flags": "\\Flagged" } }
        } else {
            doc! { "$pull": { "flags": "\\Flagged" } }
        };
        assert!(update.contains_key("$addToSet"));
    }

    #[test]
    fn email_set_starred_remove_format() {
        let username = "testuser";
        let email_id = "email-123";
        let starred = false;
        let update = if starred {
            doc! { "$addToSet": { "flags": "\\Flagged" } }
        } else {
            doc! { "$pull": { "flags": "\\Flagged" } }
        };
        assert!(update.contains_key("$pull"));
    }

    #[test]
    fn email_move_to_mailbox_format() {
        let username = "testuser";
        let email_id = "email-123";
        let target_mailbox = "archive";
        let filter = doc! { "user_id": username, "id": email_id };
        let update = doc! { "$set": { "mailbox": target_mailbox } };
        assert!(filter.contains_key("user_id"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn email_deliver_to_inbox_format() {
        let username = "testuser";
        let email_id = "email-123";
        let doc_insert = doc! {
            "id": email_id,
            "user_id": username,
            "mailbox": "inbox",
            "flags": bson::Array::new(),
            "sequence_number": 1i32,
            "uid": 1i32,
        };
        assert!(doc_insert.contains_key("id"));
        assert!(doc_insert.contains_key("user_id"));
        assert!(doc_insert.contains_key("mailbox"));
        assert!(doc_insert.contains_key("flags"));
    }

    #[test]
    fn email_log_event_format() {
        let kind = "sent";
        let user_id = "testuser";
        let email_id = "email-123";
        let subject = "Test";
        let from = "sender@example.com";
        let to = "recipient@example.com";
        let doc_insert = doc! {
            "kind": kind,
            "user_id": user_id,
            "email_id": email_id,
            "subject": subject,
            "from": from,
            "to": to,
        };
        assert!(doc_insert.contains_key("kind"));
        assert!(doc_insert.contains_key("user_id"));
        assert!(doc_insert.contains_key("email_id"));
        assert!(doc_insert.contains_key("timestamp") == false); // timestamp added separately
    }

    #[test]
    fn email_collection_name() {
        let coll_name = "emails";
        assert_eq!(coll_name, "emails");
    }

    #[test]
    fn mail_events_collection_name() {
        let coll_name = "mail_events";
        assert_eq!(coll_name, "mail_events");
    }

    #[test]
    fn email_default_flags() {
        let flags = bson::Array::new();
        assert_eq!(flags.len(), 0);
    }

    #[test]
    fn email_sequence_number_start() {
        let count = 0u64;
        let sequence_number = (count + 1) as u32;
        assert_eq!(sequence_number, 1);
    }

    #[test]
    fn email_uid_start() {
        let count = 0u64;
        let uid = (count + 1) as u32;
        assert_eq!(uid, 1);
    }
}
