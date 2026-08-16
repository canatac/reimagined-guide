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
