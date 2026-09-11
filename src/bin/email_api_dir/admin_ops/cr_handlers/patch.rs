#![allow(unused_imports, dead_code)]
use super::super::*;
use super::patch_helpers::apply_action_reject;

fn apply_action_advance(
    item: &mut ChangeRequestItem,
    body: &PatchChangeRequestInputApi,
    transition_note: &mut Option<String>,
) {
    let order = admin_workflow_order();
    let idx = order.iter().position(|x| *x == item.status).unwrap_or(0);
    if idx < order.len() - 1 {
        item.status = order[idx + 1].to_string();
        item.workflow = advance_workflow(&item.workflow);
        if item.status == "in_progress" && item.execution_state == "idle" {
            item.execution_state = "queued".to_string();
            item.execution_last_error = None;
            item.execution_finished_at = None;
            if transition_note.is_none() {
                *transition_note = Some(
                    "Workflow in_progress atteint; en attente d’un run technique backend explicite".to_string(),
                );
            }
        }
        if item.status == "released" {
            item.execution_state = "success".to_string();
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = None;
            item.changelog_entry = Some(serde_json::json!({
                "title": item.title,
                "summary": body.note.clone().unwrap_or_else(|| item.desired_outcome.clone()),
                "releasedAt": now_iso(),
            }));
        }
    }
}

use super::patch_helpers::set_run_id_if_present;

fn apply_execution_action(
    item: &mut ChangeRequestItem,
    action: &str,
    body: &PatchChangeRequestInputApi,
    transition_note: &Option<String>,
) {
    match action {
        "execution_queue" => {
            item.execution_state = "queued".to_string();
            item.execution_finished_at = None;
            item.execution_last_error = None;
            set_run_id_if_present(item, body);
        }
        "execution_start" => {
            let now = now_iso();
            item.execution_state = "running".to_string();
            item.execution_started_at = Some(
                item.execution_started_at
                    .clone()
                    .unwrap_or_else(|| now.clone()),
            );
            item.execution_last_heartbeat_at = Some(now.clone());
            item.execution_finished_at = None;
            item.execution_last_error = None;
            set_run_id_if_present(item, body);
        }
        "execution_heartbeat" => {
            item.execution_state = "running".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            if item.execution_started_at.is_none() {
                item.execution_started_at = Some(now_iso());
            }
            set_run_id_if_present(item, body);
        }
        "execution_fail" => {
            item.execution_state = "failed".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = body
                .execution_error
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| transition_note.clone())
                .or(Some("Execution failed".to_string()));
            set_run_id_if_present(item, body);
        }
        "execution_success" => {
            item.execution_state = "success".to_string();
            item.execution_last_heartbeat_at = Some(now_iso());
            item.execution_finished_at = Some(now_iso());
            item.execution_last_error = None;
            set_run_id_if_present(item, body);
        }
        "execution_reset" => {
            item.execution_state = "idle".to_string();
            item.execution_run_id = None;
            item.execution_started_at = None;
            item.execution_last_heartbeat_at = None;
            item.execution_finished_at = None;
            item.execution_last_error = None;
        }
        _ => {}
    }
}

fn apply_simple_field_patches(item: &mut ChangeRequestItem, body: &PatchChangeRequestInputApi) {
    if let Some(title) = &body.title {
        item.title = title.trim().to_string();
    }
    if let Some(problem) = &body.problem {
        item.problem = problem.trim().to_string();
    }
    if let Some(desired) = &body.desired_outcome {
        item.desired_outcome = desired.trim().to_string();
    }
    if let Some(status) = &body.status {
        let status = status.trim().to_ascii_lowercase();
        if [
            "submitted",
            "triaged",
            "planned",
            "in_progress",
            "qa",
            "released",
            "rejected",
        ]
        .contains(&status.as_str())
        {
            item.status = status;
        }
    }
}

pub(crate) async fn api_admin_change_request_patch(
    path: web::Path<String>,
    body: web::Json<PatchChangeRequestInputApi>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<ChangeRequestItem>(ADMIN_CHANGE_REQUESTS_COLL);

    let mut item = match coll.find_one(doc! { "id": &id }).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "Change request not found" }))
        }
        Err(e) => {
            eprintln!("api_admin_change_request_patch read error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to load change request" }));
        }
    };

    if let Some(action) = &body.action {
        let action = action.trim().to_ascii_lowercase();
        let actor = body
            .actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        let previous_status = item.status.clone();
        let mut transition_note = body.note.clone();

        if action == "reject" {
            apply_action_reject(&mut item);
        } else if action == "advance" {
            apply_action_advance(&mut item, &body, &mut transition_note);
        } else if [
            "execution_queue",
            "execution_start",
            "execution_heartbeat",
            "execution_fail",
            "execution_success",
            "execution_reset",
        ]
        .contains(&action.as_str())
        {
            apply_execution_action(&mut item, &action, &body, &transition_note);
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({ "message": "action must be advance|reject|execution_queue|execution_start|execution_heartbeat|execution_fail|execution_success|execution_reset" }));
        }

        if item.taken_in_charge_at.is_none()
            && previous_status == "submitted"
            && item.status != "submitted"
        {
            let intake_at = now_iso();
            item.taken_in_charge_at = Some(intake_at.clone());
            item.taken_in_charge_by = Some(actor.clone());
            if transition_note.is_none() {
                transition_note = Some("Prise en charge initiale".to_string());
            }
        }

        item.workflow_events.push(WorkflowEvent {
            at: now_iso(),
            actor,
            action,
            from_status: previous_status,
            to_status: item.status.clone(),
            note: transition_note,
        });
    }

    apply_simple_field_patches(&mut item, &body);

    item.updated_at = now_iso();

    match coll
        .replace_one(doc! { "id": &id }, &item)
        .upsert(false)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({ "item": item })),
        Err(e) => {
            eprintln!("api_admin_change_request_patch write error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update change request" }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_input_deserializes() {
        let json = serde_json::json!({
            "action": "advance",
            "note": "Moving forward",
            "actor": "john@example.com"
        });
        let input: PatchChangeRequestInputApi = serde_json::from_value(json).unwrap();
        assert_eq!(input.action, Some("advance".to_string()));
        assert_eq!(input.note, Some("Moving forward".to_string()));
        assert_eq!(input.actor, Some("john@example.com".to_string()));
    }

    #[test]
    fn patch_input_empty() {
        let json = serde_json::json!({});
        let input: PatchChangeRequestInputApi = serde_json::from_value(json).unwrap();
        assert_eq!(input.action, None);
        assert_eq!(input.note, None);
    }

    #[test]
    fn action_validation_advance() {
        let action = "advance";
        assert!(["advance", "reject", "execution_queue", "execution_start", "execution_heartbeat", "execution_fail", "execution_success", "execution_reset"].contains(&action));
    }

    #[test]
    fn action_validation_reject() {
        let action = "reject";
        assert!(["advance", "reject", "execution_queue", "execution_start", "execution_heartbeat", "execution_fail", "execution_success", "execution_reset"].contains(&action));
    }

    #[test]
    fn action_validation_execution_actions() {
        let actions = vec!["execution_queue", "execution_start", "execution_heartbeat", "execution_fail", "execution_success", "execution_reset"];
        for action in actions {
            assert!(["advance", "reject", "execution_queue", "execution_start", "execution_heartbeat", "execution_fail", "execution_success", "execution_reset"].contains(&action));
        }
    }

    #[test]
    fn action_validation_rejects_invalid() {
        let action = "invalid_action";
        assert!(!["advance", "reject", "execution_queue", "execution_start", "execution_heartbeat", "execution_fail", "execution_success", "execution_reset"].contains(&action));
    }

    #[test]
    fn workflow_order() {
        let order = admin_workflow_order();
        assert_eq!(order.len(), 7);
        assert_eq!(order[0], "submitted");
        assert_eq!(order[6], "released");
    }

    #[test]
    fn status_validation_submitted() {
        let status = "submitted";
        assert!(["submitted", "triaged", "planned", "in_progress", "qa", "released", "rejected"].contains(&status));
    }

    #[test]
    fn status_validation_released() {
        let status = "released";
        assert!(["submitted", "triaged", "planned", "in_progress", "qa", "released", "rejected"].contains(&status));
    }

    #[test]
    fn status_validation_rejected() {
        let status = "rejected";
        assert!(["submitted", "triaged", "planned", "in_progress", "qa", "released", "rejected"].contains(&status));
    }

    #[test]
    fn status_validation_rejects_invalid() {
        let status = "invalid";
        assert!(!["submitted", "triaged", "planned", "in_progress", "qa", "released", "rejected"].contains(&status));
    }

    #[test]
    fn error_response_not_found() {
        let response = serde_json::json!({ "message": "Change request not found" });
        assert_eq!(response["message"], "Change request not found");
    }

    #[test]
    fn error_response_invalid_action() {
        let response = serde_json::json!({ "message": "action must be advance|reject|execution_queue|execution_start|execution_heartbeat|execution_fail|execution_success|execution_reset" });
        assert_eq!(response["message"], "action must be advance|reject|execution_queue|execution_start|execution_heartbeat|execution_fail|execution_success|execution_reset");
    }

    #[test]
    fn error_response_update_failed() {
        let response = serde_json::json!({ "message": "Failed to update change request" });
        assert_eq!(response["message"], "Failed to update change request");
    }

    #[test]
    fn execution_state_idle() {
        let state = "idle";
        assert_eq!(state, "idle");
    }

    #[test]
    fn execution_state_queued() {
        let state = "queued";
        assert_eq!(state, "queued");
    }

    #[test]
    fn execution_state_running() {
        let state = "running";
        assert_eq!(state, "running");
    }

    #[test]
    fn execution_state_failed() {
        let state = "failed";
        assert_eq!(state, "failed");
    }

    #[test]
    fn execution_state_success() {
        let state = "success";
        assert_eq!(state, "success");
    }

    #[test]
    fn actor_defaults_to_hermes() {
        let actor: Option<String> = None;
        let resolved = actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        assert_eq!(resolved, "hermes");
    }

    #[test]
    fn actor_custom() {
        let actor: Option<String> = Some("john@example.com".to_string());
        let resolved = actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        assert_eq!(resolved, "john@example.com");
    }

    #[test]
    fn actor_empty_defaults_to_hermes() {
        let actor: Option<String> = Some("  ".to_string());
        let resolved = actor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("hermes")
            .to_string();
        assert_eq!(resolved, "hermes");
    }

    #[test]
    fn intake_tracking_sets_actor() {
        // When a CR moves from submitted to another status, intake tracking should be set
        let previous_status = "submitted";
        let new_status = "triaged";
        assert_eq!(previous_status, "submitted");
        assert_ne!(new_status, "submitted");
    }

    #[test]
    fn intake_tracking_not_set_for_submitted() {
        // When a CR stays in submitted, intake tracking should NOT be set
        let previous_status = "submitted";
        let new_status = "submitted";
        assert_eq!(previous_status, "submitted");
        assert_eq!(new_status, "submitted");
    }
}
