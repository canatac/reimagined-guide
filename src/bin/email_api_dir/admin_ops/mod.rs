// admin_ops_handlers.rs — extracted from email_api_dir/main.rs Sprint 2
// Handlers: api_admin_users_list, api_admin_user_*, api_admin_whoami,
//           api_admin_audit_log, api_admin_change_requests_*, log_admin_action,
//           api_admin_deliverability_*, api_admin_security_posture,
//           api_admin_observability_overview, ai-activity, change-request workflow

use super::*;

pub(crate) const ADMIN_USERS_COLL: &str = "admin_users";
pub(crate) const ADMIN_CHANGE_REQUESTS_COLL: &str = "admin_change_requests";

pub(crate) fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

pub(crate) fn admin_workflow_order() -> Vec<&'static str> {
    vec![
        "submitted",
        "triaged",
        "planned",
        "in_progress",
        "qa",
        "released",
    ]
}

pub(crate) fn compute_priority(urgency: &str, impact: &str) -> String {
    if urgency == "high" && impact == "high" {
        "P0".to_string()
    } else if urgency == "high" || impact == "high" {
        "P1".to_string()
    } else {
        "P2".to_string()
    }
}

pub(crate) fn build_initial_stages() -> Vec<WorkflowStage> {
    vec![
        WorkflowStage {
            key: "discovery".to_string(),
            label: "Discovery produit".to_string(),
            owner: "product".to_string(),
            status: "active".to_string(),
            checklist: vec![
                "Clarifier le problème utilisateur".to_string(),
                "Mesurer impact business/ops".to_string(),
                "Valider la portée UX + Backend".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "spec".to_string(),
            label: "Spécification".to_string(),
            owner: "backend".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Définir contrat API + payload".to_string(),
                "Définir telemetry & changelog".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "build".to_string(),
            label: "Implémentation".to_string(),
            owner: "frontend".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Implémenter UI/UX".to_string(),
                "Implémenter endpoint backend".to_string(),
                "Ajouter tests critiques".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "qa".to_string(),
            label: "Validation".to_string(),
            owner: "qa".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Typecheck + lint + tests".to_string(),
                "Validation de non-régression admin".to_string(),
            ],
            done_at: None,
        },
        WorkflowStage {
            key: "release".to_string(),
            label: "Rollout".to_string(),
            owner: "ops".to_string(),
            status: "pending".to_string(),
            checklist: vec![
                "Publier changelog".to_string(),
                "Surveiller métriques post-release".to_string(),
                "Préparer rollback playbook".to_string(),
            ],
            done_at: None,
        },
    ]
}

pub(crate) fn build_acceptance_criteria(scope: &str) -> Vec<String> {
    let mut base = vec![
        "Le flux admin expose un état lisible de la demande".to_string(),
        "Le backend retourne un état workflow déterministe".to_string(),
        "Le changement apparaît dans le flux changelog une fois released".to_string(),
    ];

    if scope == "ux" || scope == "fullstack" {
        base.push("Parcours UX sans ambiguïté: soumission -> triage -> release".to_string());
    }
    if scope == "backend" || scope == "fullstack" {
        base.push("Contrat API versionné et validé sur payloads invalides".to_string());
    }
    if scope == "security" {
        base.push("Audit trail incluant owner, horodatage et note de transition".to_string());
    }

    base
}

pub(crate) fn advance_workflow(stages: &[WorkflowStage]) -> Vec<WorkflowStage> {
    let now = now_iso();
    let current_idx = stages.iter().position(|s| s.status == "active");
    if current_idx.is_none() {
        return stages.to_vec();
    }
    let current_idx = current_idx.unwrap();
    stages
        .iter()
        .enumerate()
        .map(|(idx, stage)| {
            if idx == current_idx {
                let mut done = stage.clone();
                done.status = "done".to_string();
                done.done_at = Some(now.clone());
                done
            } else if idx == current_idx + 1 {
                let mut active = stage.clone();
                active.status = "active".to_string();
                active
            } else {
                stage.clone()
            }
        })
        .collect()
}

pub(crate) fn status_counts(items: &[ChangeRequestItem]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for status in [
        "submitted",
        "triaged",
        "planned",
        "in_progress",
        "qa",
        "released",
        "rejected",
    ] {
        map.insert(status.to_string(), serde_json::Value::from(0));
    }
    for item in items {
        if let Some(v) = map.get_mut(&item.status) {
            let next = v.as_i64().unwrap_or(0) + 1;
            *v = serde_json::Value::from(next);
        }
    }
    serde_json::Value::Object(map)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateAdminUserInput {
    id: Option<String>,
    email: String,
    display_name: Option<String>,
    role: String,
    status: Option<String>,
    two_factor_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateAdminUserInput {
    role: Option<String>,
    status: Option<String>,
    // PR3 — champs additionnels supportés par PATCH
    email: Option<String>,
    display_name: Option<String>,
    two_factor_enabled: Option<bool>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateChangeRequestInputApi {
    title: String,
    problem: String,
    desired_outcome: String,
    scope: String,
    urgency: String,
    impact: String,
    requested_by: String,
    linked_repo: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PatchChangeRequestInputApi {
    action: Option<String>,
    note: Option<String>,
    actor: Option<String>,
    title: Option<String>,
    problem: Option<String>,
    desired_outcome: Option<String>,
    status: Option<String>,
    execution_run_id: Option<String>,
    execution_error: Option<String>,
}

/// PR4 — query params optionnels : ?q=&role=&status=&page=&size=
#[derive(Debug, Deserialize)]
pub(crate) struct AdminUsersQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    page: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
}


pub mod user_handlers;
pub mod cr_handlers;
pub mod ai_handlers;
pub mod hermes_handlers;
pub mod hermes_runs;
pub mod hermes_events;
pub mod diag_handlers;

pub use user_handlers::*;
pub use cr_handlers::*;
pub use ai_handlers::*;
pub use hermes_handlers::*;
pub use hermes_runs::*;
pub use hermes_events::*;
pub use diag_handlers::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_iso_returns_rfc3339() {
        let s = now_iso();
        let dt = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        assert!(dt <= chrono::Utc::now());
    }

    #[test]
    fn admin_workflow_order_contains_expected() {
        let order = admin_workflow_order();
        assert!(order.contains(&"submitted"));
        assert!(order.contains(&"triaged"));
        assert!(order.contains(&"planned"));
        assert!(order.contains(&"in_progress"));
        assert!(order.contains(&"qa"));
        assert!(order.contains(&"released"));
    }

    #[test]
    fn compute_priority_p0() {
        assert_eq!(compute_priority("high", "high"), "P0");
    }

    #[test]
    fn compute_priority_p1_high_urgency() {
        assert_eq!(compute_priority("high", "medium"), "P1");
        assert_eq!(compute_priority("high", "small"), "P1");
    }

    #[test]
    fn compute_priority_p1_high_impact() {
        assert_eq!(compute_priority("medium", "high"), "P1");
        assert_eq!(compute_priority("low", "high"), "P1");
    }

    #[test]
    fn compute_priority_p2() {
        assert_eq!(compute_priority("medium", "medium"), "P2");
        assert_eq!(compute_priority("low", "small"), "P2");
    }

    #[test]
    fn build_initial_stages_len() {
        let stages = build_initial_stages();
        assert!(stages.len() >= 4);
    }

    #[test]
    fn build_initial_stages_first_active() {
        let stages = build_initial_stages();
        assert_eq!(stages[0].status, "active");
        for stage in &stages[1..] {
            assert_eq!(stage.status, "pending");
        }
    }

    #[test]
    fn build_acceptance_criteria_base() {
        let criteria = build_acceptance_criteria("ux");
        assert!(criteria.len() >= 3);
    }

    #[test]
    fn build_acceptance_criteria_ux_adds_criterion() {
        let criteria = build_acceptance_criteria("ux");
        assert!(criteria.iter().any(|c| c.contains("UX") || c.contains("ux") || c.contains("parcours")));
    }

    #[test]
    fn build_acceptance_criteria_backend_adds_criterion() {
        let criteria = build_acceptance_criteria("backend");
        assert!(criteria.iter().any(|c| c.contains("API") || c.contains("api") || c.contains("contrat")));
    }

    #[test]
    fn build_acceptance_criteria_security_adds_criterion() {
        let criteria = build_acceptance_criteria("security");
        assert!(criteria.iter().any(|c| c.contains("Audit") || c.contains("audit")));
    }

    #[test]
    fn build_acceptance_criteria_fullstack() {
        let criteria = build_acceptance_criteria("fullstack");
        assert!(criteria.len() >= 4);
    }

    #[test]
    fn advance_workflow_first_to_second() {
        let stages = build_initial_stages();
        assert_eq!(stages[0].status, "active");
        let advanced = advance_workflow(&stages);
        assert_eq!(advanced[0].status, "done");
        assert!(advanced[0].done_at.is_some());
        assert_eq!(advanced[1].status, "active");
    }

    #[test]
    fn advance_workflow_no_active_returns_unchanged() {
        let stages = vec![
            WorkflowStage { key: "a".to_string(), label: "A".to_string(), owner: "x".to_string(), status: "done".to_string(), checklist: vec![], done_at: None },
            WorkflowStage { key: "b".to_string(), label: "B".to_string(), owner: "x".to_string(), status: "done".to_string(), checklist: vec![], done_at: None },
        ];
        let result = advance_workflow(&stages);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].status, "done");
        assert_eq!(result[1].status, "done");
    }

    #[test]
    fn status_counts_empty() {
        let items: Vec<ChangeRequestItem> = vec![];
        let counts = status_counts(&items);
        let obj = counts.as_object().unwrap();
        assert_eq!(obj.get("submitted").unwrap().as_i64().unwrap(), 0);
        assert_eq!(obj.get("released").unwrap().as_i64().unwrap(), 0);
    }

    #[test]
    fn status_counts_with_items() {
        let items = vec![
            ChangeRequestItem {
                id: "cr_1".to_string(), title: "T".to_string(), problem: "P".to_string(),
                desired_outcome: "D".to_string(), scope: "backend".to_string(),
                priority: "P1".to_string(), status: "submitted".to_string(),
                requested_by: "a".to_string(), linked_repo: "reimagined-guide".to_string(),
                created_at: "2026-01-01".to_string(), updated_at: "2026-01-01".to_string(),
                taken_in_charge_at: None, taken_in_charge_by: None, target_release_window: "next-72h".to_string(),
                acceptance_criteria: vec![], workflow: vec![], workflow_events: vec![],
                execution_state: "idle".to_string(), execution_run_id: None,
                execution_started_at: None, execution_last_heartbeat_at: None,
                execution_finished_at: None, execution_last_error: None, changelog_entry: None,
            },
        ];
        let counts = status_counts(&items);
        let obj = counts.as_object().unwrap();
        assert_eq!(obj.get("submitted").unwrap().as_i64().unwrap(), 1);
    }
}
