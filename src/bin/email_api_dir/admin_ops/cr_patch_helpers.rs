#![allow(unused_imports, dead_code)]
use super::*;

pub(crate) fn apply_action_reject(item: &mut ChangeRequestItem) {
    item.status = "rejected".to_string();
    item.workflow = item
        .workflow
        .iter()
        .map(|stage| {
            if stage.status == "active" {
                let mut s = stage.clone();
                s.status = "done".to_string();
                s.done_at = Some(now_iso());
                s
            } else {
                stage.clone()
            }
        })
        .collect();
    item.execution_state = "idle".to_string();
    item.execution_run_id = None;
    item.execution_started_at = None;
    item.execution_last_heartbeat_at = None;
    item.execution_finished_at = Some(now_iso());
    item.execution_last_error = None;
}

pub(crate) fn apply_action_advance(
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

pub(crate) fn set_run_id_if_present(item: &mut ChangeRequestItem, body: &PatchChangeRequestInputApi) {
    if let Some(run_id) = body
        .execution_run_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        item.execution_run_id = Some(run_id.to_string());
    }
}

pub(crate) fn apply_execution_action(
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

pub(crate) fn apply_simple_field_patches(item: &mut ChangeRequestItem, body: &PatchChangeRequestInputApi) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item() -> ChangeRequestItem {
        ChangeRequestItem {
            id: "cr-1".to_string(),
            title: "Test".to_string(),
            problem: "Problem".to_string(),
            desired_outcome: "Outcome".to_string(),
            status: "submitted".to_string(),
            workflow: vec![
                WorkflowStage {
                    name: "Stage1".to_string(),
                    status: "active".to_string(),
                    done_at: None,
                },
            ],
            execution_state: "idle".to_string(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
            changelog_entry: None,
        }
    }

    #[test]
    fn apply_action_reject_sets_rejected() {
        let mut item = make_item();
        apply_action_reject(&mut item);
        assert_eq!(item.status, "rejected");
        assert_eq!(item.execution_state, "idle");
        assert!(item.execution_finished_at.is_some());
    }

    #[test]
    fn apply_action_reject_marks_active_stage_done() {
        let mut item = make_item();
        apply_action_reject(&mut item);
        assert_eq!(item.workflow[0].status, "done");
        assert!(item.workflow[0].done_at.is_some());
    }

    #[test]
    fn apply_action_advance_increments_status() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi::default();
        let mut note = None;
        apply_action_advance(&mut item, &body, &mut note);
        assert_eq!(item.status, "triaged");
    }

    #[test]
    fn apply_action_advance_to_in_progress_queues() {
        let mut item = ChangeRequestItem {
            status: "planned".to_string(),
            ..make_item()
        };
        let body = PatchChangeRequestInputApi::default();
        let mut note = None;
        apply_action_advance(&mut item, &body, &mut note);
        assert_eq!(item.status, "in_progress");
        assert_eq!(item.execution_state, "queued");
    }

    #[test]
    fn apply_action_advance_to_released_sets_success() {
        let mut item = ChangeRequestItem {
            status: "qa".to_string(),
            ..make_item()
        };
        let body = PatchChangeRequestInputApi::default();
        let mut note = None;
        apply_action_advance(&mut item, &body, &mut note);
        assert_eq!(item.status, "released");
        assert_eq!(item.execution_state, "success");
        assert!(item.changelog_entry.is_some());
    }

    #[test]
    fn apply_action_advance_at_last_status_noop() {
        let mut item = ChangeRequestItem {
            status: "released".to_string(),
            ..make_item()
        };
        let body = PatchChangeRequestInputApi::default();
        let mut note = None;
        apply_action_advance(&mut item, &body, &mut note);
        assert_eq!(item.status, "released");
    }

    #[test]
    fn set_run_id_if_present_sets_when_non_empty() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi {
            execution_run_id: Some("run-123".to_string()),
            ..Default::default()
        };
        set_run_id_if_present(&mut item, &body);
        assert_eq!(item.execution_run_id, Some("run-123".to_string()));
    }

    #[test]
    fn set_run_id_if_present_ignores_empty() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi {
            execution_run_id: Some("  ".to_string()),
            ..Default::default()
        };
        set_run_id_if_present(&mut item, &body);
        assert_eq!(item.execution_run_id, None);
    }

    #[test]
    fn apply_execution_action_queue() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi::default();
        apply_execution_action(&mut item, "execution_queue", &body, &None);
        assert_eq!(item.execution_state, "queued");
        assert!(item.execution_finished_at.is_none());
    }

    #[test]
    fn apply_execution_action_start() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi::default();
        apply_execution_action(&mut item, "execution_start", &body, &None);
        assert_eq!(item.execution_state, "running");
        assert!(item.execution_started_at.is_some());
        assert!(item.execution_last_heartbeat_at.is_some());
    }

    #[test]
    fn apply_execution_action_fail() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi {
            execution_error: Some("boom".to_string()),
            ..Default::default()
        };
        apply_execution_action(&mut item, "execution_fail", &body, &None);
        assert_eq!(item.execution_state, "failed");
        assert_eq!(item.execution_last_error, Some("boom".to_string()));
    }

    #[test]
    fn apply_execution_action_success() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi::default();
        apply_execution_action(&mut item, "execution_success", &body, &None);
        assert_eq!(item.execution_state, "success");
        assert!(item.execution_last_error.is_none());
    }

    #[test]
    fn apply_execution_action_reset() {
        let mut item = ChangeRequestItem {
            execution_state: "running".to_string(),
            execution_run_id: Some("run-1".to_string()),
            execution_started_at: Some("2026-01-01".to_string()),
            ..make_item()
        };
        let body = PatchChangeRequestInputApi::default();
        apply_execution_action(&mut item, "execution_reset", &body, &None);
        assert_eq!(item.execution_state, "idle");
        assert!(item.execution_run_id.is_none());
        assert!(item.execution_started_at.is_none());
    }

    #[test]
    fn apply_simple_field_patches_updates_fields() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi {
            title: Some("  New Title  ".to_string()),
            problem: Some("  New Problem  ".to_string()),
            desired_outcome: Some("  New Outcome  ".to_string()),
            status: Some("  IN_PROGRESS  ".to_string()),
            ..Default::default()
        };
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.title, "New Title");
        assert_eq!(item.problem, "New Problem");
        assert_eq!(item.desired_outcome, "New Outcome");
        assert_eq!(item.status, "in_progress");
    }

    #[test]
    fn apply_simple_field_patches_rejects_invalid_status() {
        let mut item = make_item();
        let body = PatchChangeRequestInputApi {
            status: Some("invalid_status".to_string()),
            ..Default::default()
        };
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.status, "submitted");
    }
}
