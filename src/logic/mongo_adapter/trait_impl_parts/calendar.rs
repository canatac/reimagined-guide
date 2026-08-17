// Calendar-related trait method delegations.
async fn create_calendar_event(&self, event: &CalendarEvent) -> Result<()> {
    self.create_calendar_event_impl(event).await
}
async fn get_calendar_events(
    &self,
    username: &str,
    start_after: Option<bson::DateTime>,
    start_before: Option<bson::DateTime>,
) -> Result<Vec<CalendarEvent>> {
    self.get_calendar_events_impl(username, start_after, start_before).await
}
async fn get_calendar_event(
    &self,
    username: &str,
    event_id: &str,
) -> Result<Option<CalendarEvent>> {
    self.get_calendar_event_impl(username, event_id).await
}
async fn update_calendar_event(
    &self,
    username: &str,
    event_id: &str,
    update_doc: bson::Document,
) -> Result<Option<CalendarEvent>> {
    self.update_calendar_event_impl(username, event_id, update_doc).await
}
async fn delete_calendar_event(&self, username: &str, event_id: &str) -> Result<()> {
    self.delete_calendar_event_impl(username, event_id).await
}
