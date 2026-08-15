// calendar_impl.rs — split from logic/mod.rs (Sprint 11)
// Boucle 9: méthodes calendar migrent via port DatabaseInterface.
#![allow(unused_imports)]
use super::*;

impl Logic {
    pub async fn create_calendar_event(&self, event: &CalendarEvent) -> Result<()> {
        self.repo.create_calendar_event(event).await
    }

    pub async fn get_calendar_events(
        &self,
        username: &str,
        start_after: Option<bson::DateTime>,
        start_before: Option<bson::DateTime>,
    ) -> Result<Vec<CalendarEvent>> {
        self.repo
            .get_calendar_events(username, start_after, start_before)
            .await
    }

    pub async fn get_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> Result<Option<CalendarEvent>> {
        self.repo.get_calendar_event(username, event_id).await
    }

    pub async fn update_calendar_event(
        &self,
        username: &str,
        event_id: &str,
        update_doc: bson::Document,
    ) -> Result<Option<CalendarEvent>> {
        self.repo
            .update_calendar_event(username, event_id, update_doc)
            .await
    }

    pub async fn delete_calendar_event(&self, username: &str, event_id: &str) -> Result<()> {
        self.repo.delete_calendar_event(username, event_id).await
    }
}
