#![allow(unused_imports, dead_code)]
use super::super::*;

pub(super) fn apply_action_reject(item: &mut ChangeRequestItem) {
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

pub(super) fn set_run_id_if_present(item: &mut ChangeRequestItem, body: &PatchChangeRequestInputApi) {
    if let Some(run_id) = body
        .execution_run_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        item.execution_run_id = Some(run_id.to_string());
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
}
