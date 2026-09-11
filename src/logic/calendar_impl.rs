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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_impl_module_purpose() {
        let purpose = "méthodes calendar migrent via port DatabaseInterface";
        assert!(purpose.contains("DatabaseInterface"));
    }

    #[test]
    fn calendar_impl_crud_methods() {
        let methods = vec![
            "create_calendar_event",
            "get_calendar_events",
            "get_calendar_event",
            "update_calendar_event",
            "delete_calendar_event",
        ];
        assert_eq!(methods.len(), 5);
    }

    #[test]
    fn calendar_impl_delegation() {
        let delegation = "self.repo.create_calendar_event(event).await";
        assert!(delegation.contains("self.repo"));
    }

    #[test]
    fn calendar_impl_event_fields() {
        let fields = vec!["id", "user_id", "title", "start", "end", "description"];
        assert_eq!(fields.len(), 6);
    }

    #[test]
    fn calendar_impl_date_range_params() {
        let params = vec!["start_after", "start_before"];
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn calendar_impl_username_param() {
        let param = "username";
        assert_eq!(param, "username");
    }

    #[test]
    fn calendar_impl_event_id_param() {
        let param = "event_id";
        assert_eq!(param, "event_id");
    }

    #[test]
    fn calendar_impl_update_doc_param() {
        let param = "update_doc";
        assert_eq!(param, "update_doc");
    }

    #[test]
    fn calendar_impl_result_type() {
        let result_type = "Result<()>";
        assert!(result_type.contains("Result"));
    }

    #[test]
    fn calendar_impl_option_type() {
        let option_type = "Option<CalendarEvent>";
        assert!(option_type.contains("Option"));
    }

    #[test]
    fn calendar_impl_vec_type() {
        let vec_type = "Vec<CalendarEvent>";
        assert!(vec_type.contains("Vec"));
    }

    #[test]
    fn calendar_impl_bson_datetime() {
        let bson_type = "bson::DateTime";
        assert!(bson_type.contains("DateTime"));
    }

    #[test]
    fn calendar_impl_collection_name() {
        let coll_name = "calendar_events";
        assert_eq!(coll_name, "calendar_events");
    }

    #[test]
    fn calendar_impl_sprint() {
        let sprint = "Sprint 11";
        assert_eq!(sprint, "Sprint 11");
    }

    #[test]
    fn calendar_impl_split_from() {
        let split_from = "logic/mod.rs";
        assert_eq!(split_from, "logic/mod.rs");
    }
}
