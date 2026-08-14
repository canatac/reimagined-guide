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
