// calendar_impl.rs — split from logic/mod.rs (Sprint 11)
// Extends impl Logic with a subset of methods.
#![allow(unused_imports)]
use super::*;

impl Logic {

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
