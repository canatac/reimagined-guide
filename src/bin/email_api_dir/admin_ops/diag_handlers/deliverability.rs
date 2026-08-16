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

// --- Helpers privés pour api_admin_deliverability_procedure -----------------

struct DnsFindings {
    dmarc_policy: &'static str,
    spf_apex_ok: bool,
    dkim_dns_ok: bool,
    helo_spf_ok: bool,
    smtp_public_ip: String,
}

async fn collect_dns_findings(domain: &str, selector: &str) -> DnsFindings {
    let spf_rows = dns_txt_lookup(domain).await;
    let dmarc_rows = dns_txt_lookup(&format!("_dmarc.{}", domain)).await;
    let helo_rows = dns_txt_lookup(&format!("mail.{}", domain)).await;
    let dkim_rows = dns_txt_lookup(&format!("{}._domainkey.{}", selector, domain)).await;

    let spf_joined = spf_rows.join(" ").to_ascii_lowercase();
    let dmarc_joined = dmarc_rows.join(" ").to_ascii_lowercase();
    let helo_joined = helo_rows.join(" ").to_ascii_lowercase();

    let dmarc_policy = if dmarc_joined.contains("p=reject") {
        "reject"
    } else if dmarc_joined.contains("p=quarantine") {
        "quarantine"
    } else if dmarc_joined.contains("p=none") {
        "none"
    } else {
        "missing"
    };

    let smtp_public_ip =
        env::var("SMTP_PUBLIC_IP").unwrap_or_else(|_| "51.158.114.182".to_string());
    let spf_apex_ok = spf_joined.contains("v=spf1") && spf_joined.contains(&smtp_public_ip);
    let dkim_dns_ok = dkim_rows
        .iter()
        .any(|row| row.to_ascii_lowercase().contains("v=dkim1"));
    let helo_spf_ok = helo_joined.contains("v=spf1");

    DnsFindings { dmarc_policy, spf_apex_ok, dkim_dns_ok, helo_spf_ok, smtp_public_ip }
}

struct ProcedureState {
    reminder_enabled: bool,
    reminder_cadence_hours: u32,
    reminder_anchor: DateTime<Utc>,
    checklist_overrides: bson::Document,
}

async fn load_procedure_state(mongo: &Arc<mongodb::Client>) -> ProcedureState {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");
    let saved = coll
        .find_one(doc! {"key": "deliverability_procedure"})
        .await
        .ok()
        .flatten();

    let mut state = ProcedureState {
        reminder_enabled: true,
        reminder_cadence_hours: 24,
        reminder_anchor: Utc::now(),
        checklist_overrides: bson::Document::new(),
    };

    if let Some(saved_doc) = saved.as_ref() {
        if let Ok(reminder) = saved_doc.get_document("reminder") {
            state.reminder_enabled = reminder.get_bool("enabled").unwrap_or(true);
            state.reminder_cadence_hours = reminder
                .get_i32("cadence_hours")
                .ok()
                .map(|v| v.max(1) as u32)
                .unwrap_or(24);
            if let Ok(last_ack_at) = reminder.get_str("last_ack_at") {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(last_ack_at) {
                    state.reminder_anchor = parsed.with_timezone(&Utc);
                }
            }
        }
        if let Ok(updated_at) = saved_doc.get_str("updated_at") {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(updated_at) {
                state.reminder_anchor = parsed.with_timezone(&Utc);
            }
        }
        if let Ok(overrides) = saved_doc.get_document("checklist_overrides") {
            state.checklist_overrides = overrides.clone();
        }
    }
    state
}

fn build_checklist(
    dns: &DnsFindings,
    domain: &str,
    selector: &str,
    window: &str,
    gmail_blocks: u64,
    dkim_alerts: u64,
) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "id": "dmarc-enforcement",
            "title": "Activer DMARC enforcement progressif",
            "status": if dns.dmarc_policy == "reject" {"done"} else if dns.dmarc_policy == "quarantine" {"in_progress"} else {"todo"},
            "evidence": format!("policy actuelle: {}", dns.dmarc_policy),
            "cta": {
                "label": "Mettre à jour _dmarc",
                "kind": "dns",
                "details": "v=DMARC1; p=quarantine; pct=25; adkim=s; aspf=s; rua=mailto:dmarc@misfits.ai"
            }
        }),
        serde_json::json!({
            "id": "spf-helo",
            "title": "Corriger SPF_HELO_NONE",
            "status": if dns.helo_spf_ok {"done"} else {"todo"},
            "evidence": if dns.helo_spf_ok {"TXT SPF trouvé sur mail.<domain>"} else {"TXT SPF absent sur mail.<domain>"},
            "cta": {"label": "Ajouter TXT SPF HELO", "kind": "dns", "details": "host=mail value=v=spf1 a -all"}
        }),
        serde_json::json!({
            "id": "dkim-dns",
            "title": "Vérifier la clé DKIM publique",
            "status": if dns.dkim_dns_ok {"done"} else {"todo"},
            "evidence": format!("selector {}._domainkey.{}", selector, domain),
            "cta": {"label": "Valider la clé DKIM", "kind": "dns", "details": format!("dig +short TXT {}._domainkey.{}", selector, domain)}
        }),
        serde_json::json!({
            "id": "gmail-policy",
            "title": "Traiter les rejets policy Gmail",
            "status": if gmail_blocks == 0 {"done"} else {"blocked"},
            "evidence": format!("NotAuthorizedError sur fenêtre {}: {}", window, gmail_blocks),
            "cta": {"label": "Lancer plan warmup Gmail", "kind": "ops", "details": "Réputation IP/domain + Postmaster + ramp-up progressif"}
        }),
        serde_json::json!({
            "id": "dkim-runtime",
            "title": "Confirmer absence de régression DKIM",
            "status": if dkim_alerts == 0 {"done"} else {"todo"},
            "evidence": format!("alertes DKIM actives: {}", dkim_alerts),
            "cta": {"label": "Exécuter un probe externe", "kind": "probe", "details": "Envoyer un test mail-tester + vérifier DKIM/SPF/DMARC"}
        }),
        serde_json::json!({
            "id": "apex-spf",
            "title": "Conserver SPF apex aligné IP prod",
            "status": if dns.spf_apex_ok {"done"} else {"todo"},
            "evidence": format!("SPF apex contient {}: {}", dns.smtp_public_ip, dns.spf_apex_ok),
            "cta": {"label": "Mettre à jour SPF apex", "kind": "dns", "details": format!("v=spf1 ip4:{} -all", dns.smtp_public_ip)}
        }),
    ]
}

fn apply_checklist_overrides(checklist: &mut [serde_json::Value], overrides: &bson::Document) {
    for entry in checklist.iter_mut() {
        if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
            if let Ok(override_doc) = overrides.get_document(id) {
                if let Ok(checked) = override_doc.get_bool("checked") {
                    if checked {
                        entry["status"] = serde_json::json!("done_manual");
                    }
                }
                if let Ok(note) = override_doc.get_str("note") {
                    if !note.trim().is_empty() {
                        entry["operator_note"] = serde_json::json!(note);
                    }
                }
            }
        }
    }
}

fn compute_procedure_diff(checklist: &[serde_json::Value], gmail_blocks: u64) -> (usize, &'static str) {
    let done_count = checklist
        .iter()
        .filter(|item| {
            item.get("status")
                .and_then(|v| v.as_str())
                .map(|s| s == "done" || s == "done_manual")
                .unwrap_or(false)
        })
        .count();
    let overall_status = if gmail_blocks > 0 {
        "blocked_gmail_policy"
    } else if done_count == checklist.len() {
        "ready_for_reject"
    } else {
        "in_progress"
    };
    (done_count, overall_status)
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
