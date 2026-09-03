// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{Mailbox, User};
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc, Bson};
use mongodb::error::Result;

fn normalize_email_document_for_deser(mut doc: bson::Document) -> bson::Document {
    if let Ok(v) = doc.get_i64("sequence_number") {
        if v >= 0 {
            doc.insert("sequence_number", v as i32);
        }
    }
    if let Ok(v) = doc.get_i64("uid") {
        if v >= 0 {
            doc.insert("uid", v as i32);
        }
    }
    doc
}

fn deserialize_email_document(doc: bson::Document) -> Option<Email> {
    let mut normalized = normalize_email_document_for_deser(doc);

    if let Ok(email) = bson::from_document::<Email>(normalized.clone()) {
        return Some(email);
    }

    // Backward-compat fallback: build Email manually so inbox listing still
    // works when `internal_date`/`headers` BSON shapes drift.
    let internal_date = match normalized.get("internal_date") {
        Some(Bson::DateTime(dt)) => {
            DateTime::<Utc>::from_timestamp_millis(dt.timestamp_millis()).unwrap_or_else(Utc::now)
        }
        Some(Bson::String(s)) => DateTime::parse_from_rfc3339(s)
            .map(|v| v.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        _ => Utc::now(),
    };

    let headers = match normalized.get("headers") {
        Some(Bson::Array(items)) => items
            .iter()
            .filter_map(|it| match it {
                Bson::Array(pair) if pair.len() >= 2 => {
                    let k = pair[0].as_str()?.to_string();
                    let v = pair[1].as_str()?.to_string();
                    Some((k, v))
                }
                Bson::Document(d) => {
                    let k = d
                        .get_str("name")
                        .or_else(|_| d.get_str("key"))
                        .ok()?
                        .to_string();
                    let v = d
                        .get_str("value")
                        .or_else(|_| d.get_str("val"))
                        .ok()?
                        .to_string();
                    Some((k, v))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    let flags = match normalized.get("flags") {
        Some(Bson::Array(items)) => items
            .iter()
            .filter_map(|it| it.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };

    let sequence_number = normalized
        .get_i32("sequence_number")
        .ok()
        .map(|v| v as u32)
        .or_else(|| normalized.get_i64("sequence_number").ok().map(|v| v as u32))
        .unwrap_or(0);

    let uid = normalized
        .get_i32("uid")
        .ok()
        .map(|v| v as u32)
        .or_else(|| normalized.get_i64("uid").ok().map(|v| v as u32))
        .unwrap_or(0);

    let email = Email {
        id: normalized.get_str("id").unwrap_or_default().to_string(),
        from: normalized.get_str("from").unwrap_or_default().to_string(),
        to: normalized.get_str("to").unwrap_or_default().to_string(),
        subject: normalized
            .get_str("subject")
            .unwrap_or_default()
            .to_string(),
        body: normalized.get_str("body").unwrap_or_default().to_string(),
        headers,
        flags,
        sequence_number,
        uid,
        internal_date,
        dkim_signature: normalized
            .get_str("dkim_signature")
            .ok()
            .map(str::to_string),
    };

    if !email.id.is_empty() && !email.to.is_empty() {
        return Some(email);
    }

    eprintln!(
        "deserialize_email_document dropped id={} user_id={} mailbox={} (schema mismatch)",
        normalized.get_str("id").unwrap_or("<missing>"),
        normalized.get_str("user_id").unwrap_or("<missing>"),
        normalized.get_str("mailbox").unwrap_or("<missing>")
    );
    None
}

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
            .limit(limit.max(1).min(200))
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
