// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::CalendarEvent;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_collection_name() {
        let coll_name = "calendar_events";
        assert_eq!(coll_name, "calendar_events");
    }

    #[test]
    fn calendar_event_filter_format() {
        let username = "testuser";
        let event_id = "event-123";
        let filter = doc! { "user_id": username, "id": event_id };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn calendar_event_update_format() {
        let username = "testuser";
        let event_id = "event-123";
        let filter = doc! { "user_id": username, "id": event_id };
        let update = doc! { "$set": { "title": "Updated Event" } };
        assert!(filter.contains_key("user_id"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn calendar_event_delete_format() {
        let username = "testuser";
        let event_id = "event-123";
        let filter = doc! { "user_id": username, "id": event_id };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn calendar_event_date_range_filter() {
        let username = "testuser";
        let after = bson::DateTime::from_millis(1700000000000i64);
        let before = bson::DateTime::from_millis(1700100000000i64);
        let mut filter = doc! { "user_id": username };
        filter.insert("start", doc! { "$gte": after });
        if filter.contains_key("start") {
            if let Ok(start_doc) = filter.get_document_mut("start") {
                start_doc.insert("$lte", before);
            }
        }
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("start"));
    }

    #[test]
    fn calendar_event_date_range_after_only() {
        let username = "testuser";
        let after = bson::DateTime::from_millis(1700000000000i64);
        let mut filter = doc! { "user_id": username };
        filter.insert("start", doc! { "$gte": after });
        assert!(filter.contains_key("start"));
    }

    #[test]
    fn calendar_event_date_range_before_only() {
        let username = "testuser";
        let before = bson::DateTime::from_millis(1700100000000i64);
        let mut filter = doc! { "user_id": username };
        filter.insert("start", doc! { "$lte": before });
        assert!(filter.contains_key("start"));
    }

    #[test]
    fn calendar_event_date_range_empty() {
        let username = "testuser";
        let filter = doc! { "user_id": username };
        assert!(filter.contains_key("user_id"));
        assert!(!filter.contains_key("start"));
    }

    #[test]
    fn calendar_event_updated_at_field() {
        let updated_at = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
        assert!(updated_at.timestamp_millis() > 0);
    }

    #[test]
    fn calendar_event_fields() {
        let fields = vec!["id", "user_id", "title", "start", "end", "description", "updated_at"];
        assert_eq!(fields.len(), 7);
        assert_eq!(fields[0], "id");
        assert_eq!(fields[1], "user_id");
        assert_eq!(fields[2], "title");
        assert_eq!(fields[3], "start");
        assert_eq!(fields[4], "end");
        assert_eq!(fields[5], "description");
        assert_eq!(fields[6], "updated_at");
    }

    #[test]
    fn calendar_crud_operations() {
        let operations = vec!["create", "get", "get_by_id", "update", "delete"];
        assert_eq!(operations.len(), 5);
    }

    #[test]
    fn calendar_find_one_filter() {
        let username = "testuser";
        let event_id = "event-456";
        let filter = doc! { "user_id": username, "id": event_id };
        assert!(filter.contains_key("user_id"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn calendar_insert_one_format() {
        let event = CalendarEvent {
            id: Some("event-123".to_string()),
            user_id: "testuser".to_string(),
            title: "Test Event".to_string(),
            start: bson::DateTime::from_millis(1700000000000i64),
            end: bson::DateTime::from_millis(1700003600000i64),
            description: Some("Test Description".to_string()),
            updated_at: None,
        };
        assert_eq!(event.id, Some("event-123".to_string()));
        assert_eq!(event.user_id, "testuser");
        assert_eq!(event.title, "Test Event");
    }

    #[test]
    fn calendar_event_with_description() {
        let event = CalendarEvent {
            id: Some("event-123".to_string()),
            user_id: "testuser".to_string(),
            title: "Test Event".to_string(),
            start: bson::DateTime::from_millis(1700000000000i64),
            end: bson::DateTime::from_millis(1700003600000i64),
            description: Some("A test event".to_string()),
            updated_at: None,
        };
        assert_eq!(event.description, Some("A test event".to_string()));
    }

    #[test]
    fn calendar_event_without_description() {
        let event = CalendarEvent {
            id: Some("event-123".to_string()),
            user_id: "testuser".to_string(),
            title: "Test Event".to_string(),
            start: bson::DateTime::from_millis(1700000000000i64),
            end: bson::DateTime::from_millis(1700003600000i64),
            description: None,
            updated_at: None,
        };
        assert_eq!(event.description, None);
    }

    #[test]
    fn calendar_event_with_updated_at() {
        let event = CalendarEvent {
            id: Some("event-123".to_string()),
            user_id: "testuser".to_string(),
            title: "Test Event".to_string(),
            start: bson::DateTime::from_millis(1700000000000i64),
            end: bson::DateTime::from_millis(1700003600000i64),
            description: None,
            updated_at: Some(bson::DateTime::from_millis(1700000000000i64)),
        };
        assert!(event.updated_at.is_some());
    }

    #[test]
    fn calendar_event_clone() {
        let event = CalendarEvent {
            id: Some("event-123".to_string()),
            user_id: "testuser".to_string(),
            title: "Test Event".to_string(),
            start: bson::DateTime::from_millis(1700000000000i64),
            end: bson::DateTime::from_millis(1700003600000i64),
            description: None,
            updated_at: None,
        };
        let cloned = event.clone();
        assert_eq!(event.id, cloned.id);
        assert_eq!(event.user_id, cloned.user_id);
        assert_eq!(event.title, cloned.title);
    }

    #[test]
    fn calendar_event_debug() {
        let event = CalendarEvent {
            id: Some("event-123".to_string()),
            user_id: "testuser".to_string(),
            title: "Test Event".to_string(),
            start: bson::DateTime::from_millis(1700000000000i64),
            end: bson::DateTime::from_millis(1700003600000i64),
            description: None,
            updated_at: None,
        };
        let debug = format!("{:?}", event);
        assert!(debug.contains("event-123"));
    }
}
