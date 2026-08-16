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
