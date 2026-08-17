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
