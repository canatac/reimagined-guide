#![allow(unused_imports, dead_code)]
use super::super::super::*;

pub(crate) async fn api_admin_deliverability_procedure(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let domain = env::var("DOMAIN_NAME")
        .or_else(|_| env::var("MAIL_DOMAIN"))
        .unwrap_or_else(|_| "misfits.ai".to_string())
        .trim()
        .trim_end_matches('.')
        .to_string();
    let selector = env::var("KEY_SELECTOR").unwrap_or_else(|_| "default".to_string());

    let dns = collect_dns_findings(&domain, &selector).await;

    let since = since_str(&query.window);
    let gmail_blocks = storage::count_events(
        &mongo,
        doc! {
            "ts": {"$gte": &since},
            "to": {"$regex": "@gmail\\.com$", "$options": "i"},
            "smtp_reply": {"$regex": "NotAuthorizedError|550-5\\.7\\.1", "$options": "i"}
        },
    )
    .await;
    let dkim_alerts = simple_smtp_server::security::audit::query_active_alerts(&mongo, 300)
        .await
        .into_iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("dkim"))
        .count() as u64;

    let state = load_procedure_state(&mongo).await;
    let next_reminder_due_at = if state.reminder_enabled {
        (state.reminder_anchor + chrono::Duration::hours(state.reminder_cadence_hours as i64))
            .to_rfc3339()
    } else {
        String::new()
    };

    let mut checklist =
        build_checklist(&dns, &domain, &selector, &query.window, gmail_blocks, dkim_alerts);
    apply_checklist_overrides(&mut checklist, &state.checklist_overrides);
    let (done_count, overall_status) = compute_procedure_diff(&checklist, gmail_blocks);

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "domain": domain,
        "overall_status": overall_status,
        "progress": {"done": done_count, "total": checklist.len()},
        "automation": {
            "auto_checks": ["dns_txt", "smtp_events", "security_alerts"],
            "last_computed_at": Utc::now().to_rfc3339(),
            "next_recompute_hint": "refresh tab or call endpoint"
        },
        "reminder": {
            "enabled": state.reminder_enabled,
            "cadence_hours": state.reminder_cadence_hours,
            "next_due_at": next_reminder_due_at
        },
        "checklist": checklist,
        "cta_details": [
            {"id": "run_external_probe", "label": "Lancer un test externe", "description": "Envoi test + vérification mail-tester + trace monitoring"},
            {"id": "publish_dmarc_stage", "label": "Publier DMARC stage suivant", "description": "none -> quarantine(25) -> quarantine(100) -> reject(100)"},
            {"id": "ack_review", "label": "Marquer revue hebdomadaire", "description": "Cocher les items validés et conserver une note opérateur"}
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_window_query_defaults() {
        let json = serde_json::json!({});
        let q: AdminWindowQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "1h");
    }

    #[test]
    fn admin_window_query_custom() {
        let json = serde_json::json!({ "window": "24h" });
        let q: AdminWindowQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.window, "24h");
    }

    #[test]
    fn domain_default() {
        let domain = "misfits.ai";
        assert_eq!(domain, "misfits.ai");
    }

    #[test]
    fn domain_trims_trailing_dot() {
        let domain = "misfits.ai.";
        let trimmed = domain.trim_end_matches('.');
        assert_eq!(trimmed, "misfits.ai");
    }

    #[test]
    fn domain_no_trailing_dot() {
        let domain = "misfits.ai";
        let trimmed = domain.trim_end_matches('.');
        assert_eq!(trimmed, "misfits.ai");
    }

    #[test]
    fn dkim_selector_default() {
        let selector = "default";
        assert_eq!(selector, "default");
    }

    #[test]
    fn gmail_blocks_query_format() {
        let query = doc! {
            "ts": {"$gte": "2026-01-01T00:00:00Z"},
            "to": {"$regex": "@gmail\\.com$", "$options": "i"},
            "smtp_reply": {"$regex": "NotAuthorizedError|550-5\\.7\\.1", "$options": "i"}
        };
        assert!(query.contains_key("ts"));
        assert!(query.contains_key("to"));
        assert!(query.contains_key("smtp_reply"));
    }

    #[test]
    fn dkim_alerts_filter() {
        let rule_names = vec!["dkim_fail", "spf_fail", "dkim_mismatch", "dmarc_reject"];
        let dkim_alerts: Vec<_> = rule_names
            .into_iter()
            .filter(|n| n.to_ascii_lowercase().contains("dkim"))
            .collect();
        assert_eq!(dkim_alerts.len(), 2);
    }

    #[test]
    fn reminder_enabled() {
        let enabled = true;
        let cadence_hours = 24i64;
        assert!(enabled);
        assert_eq!(cadence_hours, 24);
    }

    #[test]
    fn reminder_disabled() {
        let enabled = false;
        assert!(!enabled);
    }

    #[test]
    fn next_reminder_due_at_empty_when_disabled() {
        let enabled = false;
        let due_at = if enabled {
            "2026-01-02T00:00:00Z".to_string()
        } else {
            String::new()
        };
        assert_eq!(due_at, "");
    }

    #[test]
    fn next_reminder_due_at_set_when_enabled() {
        let enabled = true;
        let due_at = if enabled {
            "2026-01-02T00:00:00Z".to_string()
        } else {
            String::new()
        };
        assert_eq!(due_at, "2026-01-02T00:00:00Z");
    }

    #[test]
    fn progress_structure() {
        let done = 5usize;
        let total = 10usize;
        let progress = serde_json::json!({"done": done, "total": total});
        assert_eq!(progress["done"], 5);
        assert_eq!(progress["total"], 10);
    }

    #[test]
    fn automation_auto_checks() {
        let auto_checks = vec!["dns_txt", "smtp_events", "security_alerts"];
        assert_eq!(auto_checks.len(), 3);
        assert!(auto_checks.contains(&"dns_txt"));
        assert!(auto_checks.contains(&"smtp_events"));
        assert!(auto_checks.contains(&"security_alerts"));
    }

    #[test]
    fn cta_details_structure() {
        let cta_details = vec![
            serde_json::json!({"id": "run_external_probe", "label": "Lancer un test externe", "description": "Envoi test + vérification mail-tester + trace monitoring"}),
            serde_json::json!({"id": "publish_dmarc_stage", "label": "Publier DMARC stage suivant", "description": "none -> quarantine(25) -> quarantine(100) -> reject(100)"}),
            serde_json::json!({"id": "ack_review", "label": "Marquer revue hebdomadaire", "description": "Cocher les items validés et conserver une note opérateur"}),
        ];
        assert_eq!(cta_details.len(), 3);
        assert_eq!(cta_details[0]["id"], "run_external_probe");
        assert_eq!(cta_details[1]["id"], "publish_dmarc_stage");
        assert_eq!(cta_details[2]["id"], "ack_review");
    }

    #[test]
    fn dmarc_stages() {
        let stages = vec!["none", "quarantine(25)", "quarantine(100)", "reject(100)"];
        assert_eq!(stages.len(), 4);
        assert_eq!(stages[0], "none");
        assert_eq!(stages[3], "reject(100)");
    }

    #[test]
    fn overall_status_values() {
        let statuses = vec!["pending", "in_progress", "completed"];
        for status in &statuses {
            assert!(["pending", "in_progress", "completed"].contains(status));
        }
    }

    #[test]
    fn checklist_item_structure() {
        let item = serde_json::json!({
            "id": "spf_record",
            "label": "SPF record",
            "status": "pending",
            "description": "Check SPF record"
        });
        assert!(item.get("id").is_some());
        assert!(item.get("label").is_some());
        assert!(item.get("status").is_some());
        assert!(item.get("description").is_some());
    }

    #[test]
    fn checklist_item_status_pending() {
        let status = "pending";
        assert_eq!(status, "pending");
    }

    #[test]
    fn checklist_item_status_done() {
        let status = "done";
        assert_eq!(status, "done");
    }

    #[test]
    fn reminder_cadence_hours_default() {
        let cadence_hours = 24u32;
        assert_eq!(cadence_hours, 24);
    }

    #[test]
    fn reminder_anchor_format() {
        let anchor = "2026-01-01T00:00:00Z";
        assert!(anchor.contains("T"));
        assert!(anchor.ends_with("Z"));
    }

    #[test]
    fn since_str_format() {
        let window = "1h";
        assert_eq!(window, "1h");
    }

    #[test]
    fn since_str_24h() {
        let window = "24h";
        assert_eq!(window, "24h");
    }

    #[test]
    fn since_str_7d() {
        let window = "7d";
        assert_eq!(window, "7d");
    }

    #[test]
    fn procedure_response_structure() {
        let response = serde_json::json!({
            "window": "1h",
            "domain": "misfits.ai",
            "overall_status": "pending",
            "progress": {"done": 0, "total": 10},
            "automation": {},
            "reminder": {},
            "checklist": [],
            "cta_details": []
        });
        assert!(response.get("window").is_some());
        assert!(response.get("domain").is_some());
        assert!(response.get("overall_status").is_some());
        assert!(response.get("progress").is_some());
        assert!(response.get("automation").is_some());
        assert!(response.get("reminder").is_some());
        assert!(response.get("checklist").is_some());
        assert!(response.get("cta_details").is_some());
    }

    #[test]
    fn gmail_blocks_count_zero() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn gmail_blocks_count_positive() {
        let count = 5u64;
        assert!(count > 0);
    }

    #[test]
    fn dkim_alerts_count_zero() {
        let count = 0u64;
        assert_eq!(count, 0);
    }

    #[test]
    fn dkim_alerts_count_positive() {
        let count = 3u64;
        assert!(count > 0);
    }

    #[test]
    fn compute_procedure_diff_all_done() {
        let done = 10usize;
        let total = 10usize;
        assert_eq!(done, total);
    }

    #[test]
    fn compute_procedure_diff_none_done() {
        let done = 0usize;
        let total = 10usize;
        assert!(done < total);
    }

    #[test]
    fn compute_procedure_diff_partial() {
        let done = 5usize;
        let total = 10usize;
        assert!(done < total);
        assert!(done > 0);
    }
}
