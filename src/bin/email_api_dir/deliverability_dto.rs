use super::*;

#[derive(Deserialize)]
pub(super) struct DeliverabilityDiagnosticsQuery {
    #[serde(default = "default_window")]
    pub window: String,
    pub domain: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliverability_diagnostics_query_defaults() {
        let json = serde_json::json!({});
        let q: DeliverabilityDiagnosticsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "1h");
        assert_eq!(q.domain, None);
    }

    #[test]
    fn deliverability_diagnostics_query_custom() {
        let json = serde_json::json!({ "window": "7d", "domain": "example.com" });
        let q: DeliverabilityDiagnosticsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "7d");
        assert_eq!(q.domain, Some("example.com".to_string()));
    }

    #[test]
    fn deliverability_procedure_update_request_deserializes() {
        let json = serde_json::json!({
            "checklist": [{"id": "spf", "checked": true, "note": "done"}],
            "reminder": {"enabled": true, "cadenceHours": 24}
        });
        let req: DeliverabilityProcedureUpdateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.checklist.as_ref().unwrap().len(), 1);
        assert!(req.reminder.as_ref().unwrap().enabled);
    }
}

#[derive(Deserialize)]
pub(super) struct DeliverabilityProcedureUpdateRequest {
    pub checklist: Option<Vec<DeliverabilityChecklistUpdate>>,
    pub reminder: Option<DeliverabilityReminderUpdate>,
}

#[derive(Deserialize)]
pub(super) struct DeliverabilityChecklistUpdate {
    pub id: String,
    pub checked: bool,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeliverabilityReminderUpdate {
    pub enabled: bool,
    pub cadence_hours: u32,
}
