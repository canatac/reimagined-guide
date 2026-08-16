// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{Mailbox, User};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;

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
        let emails = self.client.database(&db_name).collection::<Email>("emails");
        emails.find_one(doc! { "id": email_id }).await
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
        let sequence_number = (count + 1) as i64;
        let uid = (count + 1) as i64;

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
            .collection::<Email>("emails");
        let filter = doc! { "user_id": username, "mailbox": mailbox };
        let cursor = collection
            .find(filter)
            .sort(doc! { "internal_date": -1 })
            .skip(skip)
            .limit(limit.max(1).min(200))
            .await?;
        cursor.try_collect().await
    }

    pub async fn fetch_email_impl(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<Email>("emails");
        let filter = doc! { "user_id": username, "id": email_id };
        collection.find_one(filter).await
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
                "sequence_number": 1i64,
                "uid": 1i64,
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
