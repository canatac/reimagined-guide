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

    fn make_test_item() -> ChangeRequestItem {
        ChangeRequestItem {
            id: "cr_test".to_string(),
            title: "Original Title".to_string(),
            problem: "Original Problem".to_string(),
            desired_outcome: "Original Outcome".to_string(),
            scope: "backend".to_string(),
            priority: "P2".to_string(),
            status: "submitted".to_string(),
            requested_by: "tester".to_string(),
            linked_repo: "reimagined-guide".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            taken_in_charge_at: None,
            taken_in_charge_by: None,
            target_release_window: "next-72h".to_string(),
            acceptance_criteria: vec![],
            workflow: vec![],
            workflow_events: vec![],
            execution_state: "idle".to_string(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
            changelog_entry: None,
        }
    }

    fn make_patch_body(title: Option<&str>, problem: Option<&str>, desired: Option<&str>, status: Option<&str>) -> PatchChangeRequestInputApi {
        PatchChangeRequestInputApi {
            action: None,
            note: None,
            actor: None,
            title: title.map(|s| s.to_string()),
            problem: problem.map(|s| s.to_string()),
            desired_outcome: desired.map(|s| s.to_string()),
            status: status.map(|s| s.to_string()),
            execution_run_id: None,
            execution_error: None,
        }
    }

    #[test]
    fn apply_simple_field_patches_title() {
        let mut item = make_test_item();
        let body = make_patch_body(Some("Updated Title"), None, None, None);
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.title, "Updated Title");
        assert_eq!(item.problem, "Original Problem");
    }

    #[test]
    fn apply_simple_field_patches_problem() {
        let mut item = make_test_item();
        let body = make_patch_body(None, Some("Updated Problem"), None, None);
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.problem, "Updated Problem");
    }

    #[test]
    fn apply_simple_field_patches_desired_outcome() {
        let mut item = make_test_item();
        let body = make_patch_body(None, None, Some("Updated Outcome"), None);
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.desired_outcome, "Updated Outcome");
    }

    #[test]
    fn apply_simple_field_patches_valid_status() {
        let mut item = make_test_item();
        let body = make_patch_body(None, None, None, Some("triaged"));
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.status, "triaged");
    }

    #[test]
    fn apply_simple_field_patches_invalid_status_rejected() {
        let mut item = make_test_item();
        let body = make_patch_body(None, None, None, Some("not_a_real_status"));
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.status, "submitted");
    }

    #[test]
    fn apply_simple_field_patches_none_values_no_change() {
        let mut item = make_test_item();
        let body = make_patch_body(None, None, None, None);
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.title, "Original Title");
        assert_eq!(item.problem, "Original Problem");
        assert_eq!(item.desired_outcome, "Original Outcome");
        assert_eq!(item.status, "submitted");
    }

    #[test]
    fn apply_simple_field_patches_all_fields() {
        let mut item = make_test_item();
        let body = make_patch_body(Some("New Title"), Some("New Problem"), Some("New Outcome"), Some("planned"));
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.title, "New Title");
        assert_eq!(item.problem, "New Problem");
        assert_eq!(item.desired_outcome, "New Outcome");
        assert_eq!(item.status, "planned");
    }

    #[test]
    fn apply_simple_field_patches_whitespace_trimmed() {
        let mut item = make_test_item();
        let body = make_patch_body(Some("  Padded Title  "), None, None, None);
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.title, "Padded Title");
    }

    #[test]
    fn apply_simple_field_patches_status_case_insensitive() {
        let mut item = make_test_item();
        let body = make_patch_body(None, None, None, Some("Triaged"));
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.status, "triaged");
    }

    #[test]
    fn apply_simple_field_patches_all_valid_statuses() {
        for status in &["submitted", "triaged", "planned", "in_progress", "qa", "released", "rejected"] {
            let mut item = make_test_item();
            let body = make_patch_body(None, None, None, Some(status));
            apply_simple_field_patches(&mut item, &body);
            assert_eq!(item.status, *status, "failed for status: {}", status);
        }
    }
}
