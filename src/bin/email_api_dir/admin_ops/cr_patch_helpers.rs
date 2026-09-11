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
                    "Workflow in_progress atteint; en attente d'un run technique backend explicite".to_string(),
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

    #[test]
    fn apply_action_reject_sets_status() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "active".into(),
            workflow: vec![WorkflowStage {
                status: "active".into(),
                done_at: None,
            }],
            execution_state: "running".into(),
            execution_run_id: Some("run-1".into()),
            execution_started_at: Some("2026-01-01T00:00:00Z".into()),
            execution_last_heartbeat_at: Some("2026-01-01T00:00:00Z".into()),
            execution_finished_at: None,
            execution_last_error: None,
        };
        apply_action_reject(&mut item);
        assert_eq!(item.status, "rejected");
        assert_eq!(item.execution_state, "idle");
        assert_eq!(item.execution_run_id, None);
        assert_eq!(item.workflow[0].status, "done");
        assert!(item.workflow[0].done_at.is_some());
        assert!(item.execution_finished_at.is_some());
    }

    #[test]
    fn set_run_id_if_present_sets_when_present() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "active".into(),
            workflow: vec![],
            execution_state: "idle".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: Some("run-123".into()),
        };
        set_run_id_if_present(&mut item, &body);
        assert_eq!(item.execution_run_id, Some("run-123".to_string()));
    }

    #[test]
    fn set_run_id_if_present_skips_empty() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "active".into(),
            workflow: vec![],
            execution_state: "idle".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: Some("  ".into()),
        };
        set_run_id_if_present(&mut item, &body);
        assert_eq!(item.execution_run_id, None);
    }

    #[test]
    fn apply_execution_action_queue() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "in_progress".into(),
            workflow: vec![],
            execution_state: "idle".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: Some("run-1".into()),
        };
        apply_execution_action(&mut item, "execution_queue", &body, &None);
        assert_eq!(item.execution_state, "queued");
        assert_eq!(item.execution_finished_at, None);
        assert_eq!(item.execution_last_error, None);
        assert_eq!(item.execution_run_id, Some("run-1".to_string()));
    }

    #[test]
    fn apply_execution_action_start() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "in_progress".into(),
            workflow: vec![],
            execution_state: "queued".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: None,
        };
        apply_execution_action(&mut item, "execution_start", &body, &None);
        assert_eq!(item.execution_state, "running");
        assert!(item.execution_started_at.is_some());
        assert!(item.execution_last_heartbeat_at.is_some());
        assert_eq!(item.execution_finished_at, None);
        assert_eq!(item.execution_last_error, None);
    }

    #[test]
    fn apply_execution_action_heartbeat() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "in_progress".into(),
            workflow: vec![],
            execution_state: "running".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: None,
        };
        apply_execution_action(&mut item, "execution_heartbeat", &body, &None);
        assert_eq!(item.execution_state, "running");
        assert!(item.execution_last_heartbeat_at.is_some());
        assert!(item.execution_started_at.is_some());
    }

    #[test]
    fn apply_execution_action_fail() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "in_progress".into(),
            workflow: vec![],
            execution_state: "running".into(),
            execution_run_id: None,
            execution_started_at: Some("2026-01-01T00:00:00Z".into()),
            execution_last_heartbeat_at: Some("2026-01-01T00:00:00Z".into()),
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            execution_error: Some("Connection timeout".into()),
        };
        apply_execution_action(&mut item, "execution_fail", &body, &None);
        assert_eq!(item.execution_state, "failed");
        assert_eq!(item.execution_last_error, Some("Connection timeout".to_string()));
        assert!(item.execution_finished_at.is_some());
        assert!(item.execution_last_heartbeat_at.is_some());
    }

    #[test]
    fn apply_execution_action_success() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "released".into(),
            workflow: vec![],
            execution_state: "running".into(),
            execution_run_id: None,
            execution_started_at: Some("2026-01-01T00:00:00Z".into()),
            execution_last_heartbeat_at: Some("2026-01-01T00:00:00Z".into()),
            execution_finished_at: None,
            execution_last_error: Some("Previous error".into()),
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: None,
        };
        apply_execution_action(&mut item, "execution_success", &body, &None);
        assert_eq!(item.execution_state, "success");
        assert_eq!(item.execution_last_error, None);
        assert!(item.execution_finished_at.is_some());
    }

    #[test]
    fn apply_execution_action_reset() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            status: "in_progress".into(),
            workflow: vec![],
            execution_state: "failed".into(),
            execution_run_id: Some("run-1".into()),
            execution_started_at: Some("2026-01-01T00:00:00Z".into()),
            execution_last_heartbeat_at: Some("2026-01-01T00:00:00Z".into()),
            execution_finished_at: Some("2026-01-01T00:00:00Z".into()),
            execution_last_error: Some("Error".into()),
        };
        let body = PatchChangeRequestInputApi {
            execution_run_id: None,
        };
        apply_execution_action(&mut item, "execution_reset", &body, &None);
        assert_eq!(item.execution_state, "idle");
        assert_eq!(item.execution_run_id, None);
        assert_eq!(item.execution_started_at, None);
        assert_eq!(item.execution_last_heartbeat_at, None);
        assert_eq!(item.execution_finished_at, None);
        assert_eq!(item.execution_last_error, None);
    }

    #[test]
    fn apply_simple_field_patches_title() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            title: "Old Title".into(),
            status: "submitted".into(),
            workflow: vec![],
            execution_state: "idle".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            title: Some("  New Title  ".into()),
            ..Default::default()
        };
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.title, "New Title");
    }

    #[test]
    fn apply_simple_field_patches_status() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            title: "Title".into(),
            status: "submitted".into(),
            workflow: vec![],
            execution_state: "idle".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            status: Some("  TRIAGED  ".into()),
            ..Default::default()
        };
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.status, "triaged");
    }

    #[test]
    fn apply_simple_field_patches_rejects_invalid_status() {
        let mut item = ChangeRequestItem {
            id: "cr-1".into(),
            title: "Title".into(),
            status: "submitted".into(),
            workflow: vec![],
            execution_state: "idle".into(),
            execution_run_id: None,
            execution_started_at: None,
            execution_last_heartbeat_at: None,
            execution_finished_at: None,
            execution_last_error: None,
        };
        let body = PatchChangeRequestInputApi {
            status: Some("invalid".into()),
            ..Default::default()
        };
        apply_simple_field_patches(&mut item, &body);
        assert_eq!(item.status, "submitted");
    }
}
