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
