use super::*;

#[derive(Deserialize)]
pub(super) struct DeliverabilityDiagnosticsQuery {
    #[serde(default = "default_window")]
    window: String,
    domain: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeliverabilityProcedureUpdateRequest {
    checklist: Option<Vec<DeliverabilityChecklistUpdate>>,
    reminder: Option<DeliverabilityReminderUpdate>,
}

#[derive(Deserialize)]
pub(super) struct DeliverabilityChecklistUpdate {
    id: String,
    checked: bool,
    note: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DeliverabilityReminderUpdate {
    enabled: bool,
    cadence_hours: u32,
}
