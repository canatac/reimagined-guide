// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{Mailbox, User};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn create_calendar_event_impl(&self, event: &CalendarEvent) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<CalendarEvent>("calendar_events");
        collection.insert_one(event.clone()).await?;
        Ok(())
    }

    pub async fn get_calendar_events_impl(
        &self,
        username: &str,
        start_after: Option<bson::DateTime>,
        start_before: Option<bson::DateTime>,
    ) -> Result<Vec<CalendarEvent>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
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

    pub async fn get_calendar_event_impl(
        &self,
        username: &str,
        event_id: &str,
    ) -> Result<Option<CalendarEvent>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<CalendarEvent>("calendar_events");
        let filter = doc! { "user_id": username, "id": event_id };
        collection.find_one(filter).await
    }

    pub async fn update_calendar_event_impl(
        &self,
        username: &str,
        event_id: &str,
        update_doc: bson::Document,
    ) -> Result<Option<CalendarEvent>> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
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

    pub async fn delete_calendar_event_impl(&self, username: &str, event_id: &str) -> Result<()> {
        let db_name = Self::database_name();
        let collection = self
            .client
            .database(&db_name)
            .collection::<CalendarEvent>("calendar_events");
        let filter = doc! { "user_id": username, "id": event_id };
        collection.delete_one(filter).await?;
        Ok(())
    }

}
