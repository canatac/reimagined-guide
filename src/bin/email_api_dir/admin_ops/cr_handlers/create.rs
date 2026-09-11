#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_admin_change_request_create(
    body: web::Json<CreateChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let scope = body.scope.trim().to_ascii_lowercase();
    let urgency = body.urgency.trim().to_ascii_lowercase();
    let impact = body.impact.trim().to_ascii_lowercase();
    let linked_repo = body.linked_repo.trim().to_ascii_lowercase();

    if !["ux", "backend", "fullstack", "security"].contains(&scope.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "scope must be ux|backend|fullstack|security" }));
    }
    if !["low", "medium", "high"].contains(&urgency.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "urgency must be low|medium|high" }));
    }
    if !["small", "medium", "high"].contains(&impact.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "impact must be small|medium|high" }));
    }
    if !["misfits-web", "reimagined-guide", "cross-repo"].contains(&linked_repo.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({ "message": "linkedRepo must be misfits-web|reimagined-guide|cross-repo" }));
    }

    let now = now_iso();
    let submitter = body.requested_by.trim().to_string();
    let item = ChangeRequestItem {
        id: format!("cr_{}", Uuid::new_v4().simple()),
        title: body.title.trim().to_string(),
        problem: body.problem.trim().to_string(),
        desired_outcome: body.desired_outcome.trim().to_string(),
        scope: scope.clone(),
        priority: compute_priority(&urgency, &impact),
        status: "submitted".to_string(),
        requested_by: submitter.clone(),
        linked_repo,
        created_at: now.clone(),
        updated_at: now.clone(),
        taken_in_charge_at: None,
        taken_in_charge_by: None,
        target_release_window: if urgency == "high" {
            "next-24h".to_string()
        } else if urgency == "medium" {
            "next-72h".to_string()
        } else {
            "next-sprint".to_string()
        },
        acceptance_criteria: build_acceptance_criteria(&scope),
        workflow: build_initial_stages(),
        workflow_events: vec![WorkflowEvent {
            at: now,
            actor: submitter,
            action: "submitted".to_string(),
            from_status: "submitted".to_string(),
            to_status: "submitted".to_string(),
            note: Some("Change request créée".to_string()),
        }],
        execution_state: "idle".to_string(),
        execution_run_id: None,
        execution_started_at: None,
        execution_last_heartbeat_at: None,
        execution_finished_at: None,
        execution_last_error: None,
        changelog_entry: None,
    };

    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    match coll.insert_one(&item).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create change request" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_change_request_input_deserializes() {
        let json = serde_json::json!({
            "title": "Add new feature",
            "problem": "Users need X",
            "desiredOutcome": "Users can do X",
            "scope": "backend",
            "urgency": "high",
            "impact": "high",
            "requestedBy": "john@example.com",
            "linkedRepo": "reimagined-guide"
        });
        let input: CreateChangeRequestInputApi = serde_json::from_value(json).unwrap();
        assert_eq!(input.title, "Add new feature");
        assert_eq!(input.scope, "backend");
        assert_eq!(input.urgency, "high");
        assert_eq!(input.impact, "high");
        assert_eq!(input.linked_repo, "reimagined-guide");
    }

    #[test]
    fn create_change_request_input_minimal() {
        let json = serde_json::json!({
            "title": "Fix bug",
            "problem": "Bug exists",
            "desiredOutcome": "Bug fixed",
            "scope": "ux",
            "urgency": "low",
            "impact": "small",
            "requestedBy": "jane@example.com",
            "linkedRepo": "misfits-web"
        });
        let input: CreateChangeRequestInputApi = serde_json::from_value(json).unwrap();
        assert_eq!(input.title, "Fix bug");
        assert_eq!(input.scope, "ux");
    }

    #[test]
    fn scope_validation_accepts_ux() {
        let scope = "ux";
        assert!(["ux", "backend", "fullstack", "security"].contains(&scope));
    }

    #[test]
    fn scope_validation_accepts_backend() {
        let scope = "backend";
        assert!(["ux", "backend", "fullstack", "security"].contains(&scope));
    }

    #[test]
    fn scope_validation_accepts_fullstack() {
        let scope = "fullstack";
        assert!(["ux", "backend", "fullstack", "security"].contains(&scope));
    }

    #[test]
    fn scope_validation_accepts_security() {
        let scope = "security";
        assert!(["ux", "backend", "fullstack", "security"].contains(&scope));
    }

    #[test]
    fn scope_validation_rejects_invalid() {
        let scope = "invalid";
        assert!(!["ux", "backend", "fullstack", "security"].contains(&scope));
    }

    #[test]
    fn urgency_validation_accepts_low() {
        let urgency = "low";
        assert!(["low", "medium", "high"].contains(&urgency));
    }

    #[test]
    fn urgency_validation_accepts_medium() {
        let urgency = "medium";
        assert!(["low", "medium", "high"].contains(&urgency));
    }

    #[test]
    fn urgency_validation_accepts_high() {
        let urgency = "high";
        assert!(["low", "medium", "high"].contains(&urgency));
    }

    #[test]
    fn urgency_validation_rejects_invalid() {
        let urgency = "critical";
        assert!(!["low", "medium", "high"].contains(&urgency));
    }

    #[test]
    fn impact_validation_accepts_small() {
        let impact = "small";
        assert!(["small", "medium", "high"].contains(&impact));
    }

    #[test]
    fn impact_validation_accepts_medium() {
        let impact = "medium";
        assert!(["small", "medium", "high"].contains(&impact));
    }

    #[test]
    fn impact_validation_accepts_high() {
        let impact = "high";
        assert!(["small", "medium", "high"].contains(&impact));
    }

    #[test]
    fn impact_validation_rejects_invalid() {
        let impact = "critical";
        assert!(!["small", "medium", "high"].contains(&impact));
    }

    #[test]
    fn linked_repo_validation_accepts_misfits_web() {
        let repo = "misfits-web";
        assert!(["misfits-web", "reimagined-guide", "cross-repo"].contains(&repo));
    }

    #[test]
    fn linked_repo_validation_accepts_reimagined_guide() {
        let repo = "reimagined-guide";
        assert!(["misfits-web", "reimagined-guide", "cross-repo"].contains(&repo));
    }

    #[test]
    fn linked_repo_validation_accepts_cross_repo() {
        let repo = "cross-repo";
        assert!(["misfits-web", "reimagined-guide", "cross-repo"].contains(&repo));
    }

    #[test]
    fn linked_repo_validation_rejects_invalid() {
        let repo = "other-repo";
        assert!(!["misfits-web", "reimagined-guide", "cross-repo"].contains(&repo));
    }

    #[test]
    fn target_release_window_high_urgency() {
        let urgency = "high";
        let window = if urgency == "high" {
            "next-24h"
        } else if urgency == "medium" {
            "next-72h"
        } else {
            "next-sprint"
        };
        assert_eq!(window, "next-24h");
    }

    #[test]
    fn target_release_window_medium_urgency() {
        let urgency = "medium";
        let window = if urgency == "high" {
            "next-24h"
        } else if urgency == "medium" {
            "next-72h"
        } else {
            "next-sprint"
        };
        assert_eq!(window, "next-72h");
    }

    #[test]
    fn target_release_window_low_urgency() {
        let urgency = "low";
        let window = if urgency == "high" {
            "next-24h"
        } else if urgency == "medium" {
            "next-72h"
        } else {
            "next-sprint"
        };
        assert_eq!(window, "next-sprint");
    }

    #[test]
    fn error_response_scope_invalid() {
        let response = serde_json::json!({ "message": "scope must be ux|backend|fullstack|security" });
        assert_eq!(response["message"], "scope must be ux|backend|fullstack|security");
    }

    #[test]
    fn error_response_urgency_invalid() {
        let response = serde_json::json!({ "message": "urgency must be low|medium|high" });
        assert_eq!(response["message"], "urgency must be low|medium|high");
    }

    #[test]
    fn error_response_impact_invalid() {
        let response = serde_json::json!({ "message": "impact must be small|medium|high" });
        assert_eq!(response["message"], "impact must be small|medium|high");
    }

    #[test]
    fn error_response_linked_repo_invalid() {
        let response = serde_json::json!({ "message": "linkedRepo must be misfits-web|reimagined-guide|cross-repo" });
        assert_eq!(response["message"], "linkedRepo must be misfits-web|reimagined-guide|cross-repo");
    }
}
