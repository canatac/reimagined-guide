use super::*;

#[derive(Deserialize)]
pub(super) struct DeliverabilityDiagnosticsQuery {
    #[serde(default = "default_window")]
    pub window: String,
    pub domain: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_window_is_1h() {
        assert_eq(default_window(), "1h");
    }

    #[test]
    fn deliverability_checklist_update_fields() {
        let update = DeliverabilityChecklistUpdate {
            id: "check-1".to_string(),
            checked: true,
            note: Some("Looks good".to_string()),
        };
        assert_eq!(update.id, "check-1");
        assert!(update.checked);
        assert_eq!(update.note, Some("Looks good".to_string()));
    }

    #[test]
    fn deliverability_reminder_update_fields() {
        let update = DeliverabilityReminderUpdate {
            enabled: true,
            cadence_hours: 24,
        };
        assert!(update.enabled);
        assert_eq!(update.cadence_hours, 24);
    }

    #[test]
    fn deliverability_diagnostics_query_fields() {
        let query = DeliverabilityDiagnosticsQuery {
            window: "1h".to_string(),
            domain: Some("example.com".to_string()),
        };
        assert_eq!(query.window, "1h");
        assert_eq!(query.domain, Some("example.com".to_string()));
    }
}
