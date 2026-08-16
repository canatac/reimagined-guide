#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_admin_deliverability_diagnostics(
    query: web::Query<DeliverabilityDiagnosticsQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let since = since_str(&query.window);
    let mut filter = doc! { "ts": { "$gte": &since } };

    if let Some(domain) = query
        .domain
        .as_ref()
        .map(|d| d.trim())
        .filter(|d| !d.is_empty())
    {
        let safe_domain = domain.replace('.', "\\.");
        filter.insert(
            "to",
            doc! { "$regex": format!("@{}$", safe_domain), "$options": "i" },
        );
    }

    let total = storage::count_events(&mongo, filter.clone()).await;
    let bounces = storage::query_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "status": "bounced" },
        1,
        200,
    )
    .await;

    let mut bounce_reasons: HashMap<String, u32> = HashMap::new();
    for evt in &bounces {
        let key = evt
            .bounce_reason
            .clone()
            .or_else(|| evt.smtp_reply.clone())
            .unwrap_or_else(|| "unknown".to_string());
        *bounce_reasons.entry(key).or_insert(0) += 1;
    }

    let mut top_reasons: Vec<(String, u32)> = bounce_reasons.into_iter().collect();
    top_reasons.sort_by(|a, b| b.1.cmp(&a.1));

    let active_security_alerts = audit::query_active_alerts(&mongo, 300).await;
    let spf_failures = active_security_alerts
        .iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("spf"))
        .count() as u64;
    let dkim_failures = active_security_alerts
        .iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("dkim"))
        .count() as u64;
    let dmarc_failures = active_security_alerts
        .iter()
        .filter(|a| a.rule_name.to_ascii_lowercase().contains("dmarc"))
        .count() as u64;

    let auth_alerts = spf_failures + dkim_failures + dmarc_failures;

    let rbl_sources = env::var("RBL_CHECK_HOSTS")
        .unwrap_or_else(|_| "zen.spamhaus.org,bl.spamcop.net".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let rbl_listed_by = env::var("RBL_LISTED_BY")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let risk_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": filter.clone() },
            doc! { "$group": {
                "_id": null,
                "avg_risk": { "$avg": "$risk_score" },
                "high_risk_events": { "$sum": { "$cond": { "if": { "$gte": ["$risk_score", 70] }, "then": 1, "else": 0 } } }
            }},
        ],
    )
    .await;

    let avg_risk_score = risk_docs
        .first()
        .and_then(|d| d.get_f64("avg_risk").ok())
        .unwrap_or(0.0);
    let high_risk_events = risk_docs
        .first()
        .and_then(|d| d.get_i64("high_risk_events").ok())
        .unwrap_or(0);

    let denom = if total == 0 { 1.0 } else { total as f64 };

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "scope_domain": query.domain,
        "total_events": total,
        "bounces_total": bounces.len(),
        "auth_policy_alerts": auth_alerts,
        "spf": {
            "failures": spf_failures,
            "failure_rate": (spf_failures as f64 / denom)
        },
        "dkim": {
            "failures": dkim_failures,
            "failure_rate": (dkim_failures as f64 / denom)
        },
        "dmarc": {
            "failures": dmarc_failures,
            "failure_rate": (dmarc_failures as f64 / denom)
        },
        "reputation": {
            "avg_risk_score": (avg_risk_score * 10.0).round() / 10.0,
            "high_risk_events": high_risk_events,
            "ip_domain_status": if high_risk_events > 0 { "degraded" } else { "normal" }
        },
        "top_bounce_reasons": top_reasons.into_iter().take(10).map(|(reason, count)| serde_json::json!({"reason": reason, "count": count})).collect::<Vec<_>>(),
        "recent_delivery_failures": bounces.into_iter().take(15).map(|e| serde_json::json!({
            "ts": e.ts,
            "to": e.to,
            "mx_host": e.mx_host,
            "smtp_code": e.smtp_code,
            "smtp_reply": e.smtp_reply,
            "bounce_reason": e.bounce_reason,
            "risk_score": e.risk_score
        })).collect::<Vec<_>>(),
        "rbl": {
            "sources": rbl_sources,
            "listed_by": rbl_listed_by,
            "status": if !env::var("RBL_LISTED_BY").unwrap_or_default().trim().is_empty() { "listed" } else { "clean_or_unknown" },
            "note": "Renseigner RBL_LISTED_BY pour refléter les listes noires détectées par un probe DNS"
        },
        "diagnostics_hints": [
            "Vérifier SPF/DKIM/DMARC alignés pour le domaine expéditeur",
            "Comparer smtp_code/smtp_reply des bounces pour isoler policy vs reputation",
            "Analyser la latence DNS/TLS avant DATA pour détecter throttling provider"
        ]
    }))
}

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

pub(crate) async fn api_admin_deliverability_procedure_update(
    body: web::Json<DeliverabilityProcedureUpdateRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");

    let mut set_doc = doc! {
        "key": "deliverability_procedure",
        "updated_at": Utc::now().to_rfc3339(),
    };

    if let Some(reminder) = body.reminder.as_ref() {
        set_doc.insert(
            "reminder",
            doc! {
                "enabled": reminder.enabled,
                "cadence_hours": (reminder.cadence_hours.max(1) as i32),
                "updated_at": Utc::now().to_rfc3339(),
            },
        );
    }

    if let Some(items) = body.checklist.as_ref() {
        let mut overrides = bson::Document::new();
        for item in items {
            overrides.insert(
                item.id.clone(),
                bson::Bson::Document(doc! {
                    "checked": item.checked,
                    "note": item.note.clone().unwrap_or_default(),
                    "updated_at": Utc::now().to_rfc3339(),
                }),
            );
        }
        set_doc.insert("checklist_overrides", overrides);
    }

    match coll
        .update_one(
            doc! {"key": "deliverability_procedure"},
            doc! {"$set": set_doc},
        )
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "ok": false,
            "error": format!("deliverability_procedure_update_failed: {}", e)
        })),
    }
}
