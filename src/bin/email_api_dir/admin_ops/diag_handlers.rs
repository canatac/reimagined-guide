#![allow(unused_imports, dead_code)]
use super::*;  // inherit all imports from mod.rs

pub(crate) async fn api_admin_security_posture(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let active_alerts = audit::query_active_alerts(&mongo, 300).await;

    let brute_force_alerts = active_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("bruteforce") || n.contains("brute") || n.contains("rate")
        })
        .count();

    let auth_fail_alerts = active_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("spf") || n.contains("dkim") || n.contains("dmarc")
        })
        .count();

    let domain = env::var("DOMAIN_NAME")
        .or_else(|_| env::var("MAIL_DOMAIN"))
        .unwrap_or_else(|_| "misfits.ai".to_string());
    let smtp_public_ip =
        env::var("SMTP_PUBLIC_IP").unwrap_or_else(|_| "51.158.114.182".to_string());
    let dkim_selector = env::var("KEY_SELECTOR").unwrap_or_else(|_| "default".to_string());

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "security": {
            "tls": {
                "smtp_starttls_required": env_bool("SMTP_REQUIRE_STARTTLS", true),
                "smtps_listener": env::var("SMTP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8465".to_string()),
                "imaps_listener": env::var("IMAP_TLS_ADDR").unwrap_or_else(|_| "0.0.0.0:8993".to_string()),
                "imap_starttls_required": env_bool("IMAP_REQUIRE_STARTTLS", true)
            },
            "authentication": {
                "sasl_mechanisms": ["PLAIN", "LOGIN"],
                "oauth2_enabled": env::var("GITHUB_CLIENT_ID").map(|v| !v.trim().is_empty()).unwrap_or(false),
                "admin_mfa_required": env_bool("ADMIN_MFA_REQUIRED", true)
            },
            "anti_abuse": {
                "rate_limit_enabled": env_bool("RATE_LIMIT_ENABLED", true),
                "rate_limit_per_minute": env::var("RATE_LIMIT_PER_MINUTE").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(120),
                "fail2ban_enabled": env_bool("FAIL2BAN_ENABLED", true),
                "bruteforce_signals_24h": brute_force_alerts,
                "auth_policy_signals_24h": auth_fail_alerts
            },
            "mail_auth_dns": {
                "domain": domain,
                "spf_expected": format!("v=spf1 ip4:{} -all", smtp_public_ip),
                "dkim_selector": dkim_selector,
                "dmarc_expected": "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=100",
                "ptr_rdns_note": "Configurer PTR/rDNS de l'IP publique vers un host mail stable (ex: mail.<domain>)"
            }
        }
    }))
}

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

    let spf_rows = dns_txt_lookup(&domain).await;
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

    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");
    let saved = coll
        .find_one(doc! {"key": "deliverability_procedure"})
        .await
        .ok()
        .flatten();

    let mut reminder_enabled = true;
    let mut reminder_cadence_hours = 24u32;
    let mut reminder_anchor = Utc::now();
    let mut checklist_overrides = bson::Document::new();

    if let Some(saved_doc) = saved.as_ref() {
        if let Ok(reminder) = saved_doc.get_document("reminder") {
            reminder_enabled = reminder.get_bool("enabled").unwrap_or(true);
            reminder_cadence_hours = reminder
                .get_i32("cadence_hours")
                .ok()
                .map(|v| v.max(1) as u32)
                .unwrap_or(24);

            if let Ok(last_ack_at) = reminder.get_str("last_ack_at") {
                if let Ok(parsed) = DateTime::parse_from_rfc3339(last_ack_at) {
                    reminder_anchor = parsed.with_timezone(&Utc);
                }
            }
        }

        if let Ok(updated_at) = saved_doc.get_str("updated_at") {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(updated_at) {
                reminder_anchor = parsed.with_timezone(&Utc);
            }
        }

        if let Ok(overrides) = saved_doc.get_document("checklist_overrides") {
            checklist_overrides = overrides.clone();
        }
    }

    let next_reminder_due_at = if reminder_enabled {
        (reminder_anchor + chrono::Duration::hours(reminder_cadence_hours as i64)).to_rfc3339()
    } else {
        String::new()
    };

    let mut checklist = vec![
        serde_json::json!({
            "id": "dmarc-enforcement",
            "title": "Activer DMARC enforcement progressif",
            "status": if dmarc_policy == "reject" {"done"} else if dmarc_policy == "quarantine" {"in_progress"} else {"todo"},
            "evidence": format!("policy actuelle: {}", dmarc_policy),
            "cta": {
                "label": "Mettre à jour _dmarc",
                "kind": "dns",
                "details": "v=DMARC1; p=quarantine; pct=25; adkim=s; aspf=s; rua=mailto:dmarc@misfits.ai"
            }
        }),
        serde_json::json!({
            "id": "spf-helo",
            "title": "Corriger SPF_HELO_NONE",
            "status": if helo_spf_ok {"done"} else {"todo"},
            "evidence": if helo_spf_ok {"TXT SPF trouvé sur mail.<domain>"} else {"TXT SPF absent sur mail.<domain>"},
            "cta": {
                "label": "Ajouter TXT SPF HELO",
                "kind": "dns",
                "details": "host=mail value=v=spf1 a -all"
            }
        }),
        serde_json::json!({
            "id": "dkim-dns",
            "title": "Vérifier la clé DKIM publique",
            "status": if dkim_dns_ok {"done"} else {"todo"},
            "evidence": format!("selector {}._domainkey.{}", selector, domain),
            "cta": {
                "label": "Valider la clé DKIM",
                "kind": "dns",
                "details": format!("dig +short TXT {}._domainkey.{}", selector, domain)
            }
        }),
        serde_json::json!({
            "id": "gmail-policy",
            "title": "Traiter les rejets policy Gmail",
            "status": if gmail_blocks == 0 {"done"} else {"blocked"},
            "evidence": format!("NotAuthorizedError sur fenêtre {}: {}", query.window, gmail_blocks),
            "cta": {
                "label": "Lancer plan warmup Gmail",
                "kind": "ops",
                "details": "Réputation IP/domain + Postmaster + ramp-up progressif"
            }
        }),
        serde_json::json!({
            "id": "dkim-runtime",
            "title": "Confirmer absence de régression DKIM",
            "status": if dkim_alerts == 0 {"done"} else {"todo"},
            "evidence": format!("alertes DKIM actives: {}", dkim_alerts),
            "cta": {
                "label": "Exécuter un probe externe",
                "kind": "probe",
                "details": "Envoyer un test mail-tester + vérifier DKIM/SPF/DMARC"
            }
        }),
        serde_json::json!({
            "id": "apex-spf",
            "title": "Conserver SPF apex aligné IP prod",
            "status": if spf_apex_ok {"done"} else {"todo"},
            "evidence": format!("SPF apex contient {}: {}", smtp_public_ip, spf_apex_ok),
            "cta": {
                "label": "Mettre à jour SPF apex",
                "kind": "dns",
                "details": format!("v=spf1 ip4:{} -all", smtp_public_ip)
            }
        }),
    ];

    for entry in &mut checklist {
        if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
            if let Ok(override_doc) = checklist_overrides.get_document(id) {
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

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "domain": domain,
        "overall_status": overall_status,
        "progress": {
            "done": done_count,
            "total": checklist.len()
        },
        "automation": {
            "auto_checks": ["dns_txt", "smtp_events", "security_alerts"],
            "last_computed_at": Utc::now().to_rfc3339(),
            "next_recompute_hint": "refresh tab or call endpoint"
        },
        "reminder": {
            "enabled": reminder_enabled,
            "cadence_hours": reminder_cadence_hours,
            "next_due_at": next_reminder_due_at
        },
        "checklist": checklist,
        "cta_details": [
            {
                "id": "run_external_probe",
                "label": "Lancer un test externe",
                "description": "Envoi test + vérification mail-tester + trace monitoring"
            },
            {
                "id": "publish_dmarc_stage",
                "label": "Publier DMARC stage suivant",
                "description": "none -> quarantine(25) -> quarantine(100) -> reject(100)"
            },
            {
                "id": "ack_review",
                "label": "Marquer revue hebdomadaire",
                "description": "Cocher les items validés et conserver une note opérateur"
            }
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

pub(crate) async fn api_admin_observability_overview(
    query: web::Query<AdminWindowQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    use simple_smtp_server::security::audit;

    let since = since_str(&query.window);
    let window_minutes = parse_window(&query.window).num_minutes().max(1) as f64;
    let base_filter = doc! { "ts": { "$gte": &since } };

    let total = storage::count_events(&mongo, base_filter.clone()).await;
    let by_status_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$group": { "_id": "$status", "count": { "$sum": 1 }, "avg_ms": { "$avg": "$total_ms" } } },
        ],
    )
    .await;

    let mut by_status = serde_json::Map::new();
    let mut delivered = 0u64;
    let mut bounced = 0u64;
    let mut failed = 0u64;
    let mut deferred = 0u64;

    for doc in &by_status_docs {
        let status = doc.get_str("_id").unwrap_or("unknown").to_string();
        let count = doc.get_i64("count").unwrap_or(0) as u64;
        match status.as_str() {
            "delivered" => delivered = count,
            "bounced" => bounced = count,
            "failed" => failed = count,
            "deferred" => deferred = count,
            _ => {}
        }
        by_status.insert(status, serde_json::json!(count));
    }

    let p95 = storage::p95_total_ms(&mongo, base_filter.clone(), 1000).await;

    let outcome_total = delivered + bounced + failed + deferred;
    let success_rate = if outcome_total == 0 {
        0.0
    } else {
        delivered as f64 / outcome_total as f64
    };

    // SMTP queue depth + oldest age
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let queue_coll = mongo
        .database(&db)
        .collection::<bson::Document>(SEND_QUEUE_COLL);
    let pending_queue_filter = doc! { "status": { "$in": ["pending", "scheduled", "sending"] } };
    let queue_depth = queue_coll
        .count_documents(pending_queue_filter.clone())
        .await
        .unwrap_or(0);

    let oldest_pending = queue_coll
        .find_one(pending_queue_filter.clone())
        .sort(doc! { "created_at": 1 })
        .await
        .ok()
        .flatten();
    let queue_oldest_age_seconds = oldest_pending
        .as_ref()
        .and_then(|d| d.get_datetime("created_at").ok())
        .map(|dt| (Utc::now().timestamp_millis() - dt.timestamp_millis()).max(0) as u64 / 1000);

    // Throughput and SMTP response classes
    let incoming_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "event_type": { "$in": ["accepted", "received"] } },
    )
    .await;
    let outgoing_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "status": { "$in": ["delivered", "bounced", "failed", "deferred"] } },
    )
    .await;

    let smtp_4xx = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "smtp_code": { "$gte": 400, "$lt": 500 } },
    )
    .await;
    let smtp_5xx = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "smtp_code": { "$gte": 500, "$lt": 600 } },
    )
    .await;

    let monitoring_alerts = monitoring::alerts::evaluate_alerts(
        &mongo,
        parse_window(&query.window).num_minutes(),
        &AlertConfig::default(),
    )
    .await;
    let security_alerts = audit::query_active_alerts(&mongo, 300).await;

    let queue_growth_alerts = monitoring_alerts
        .iter()
        .filter(|a| a.kind.contains("queue") || a.message.to_ascii_lowercase().contains("queue"))
        .count();
    let auth_failure_alerts = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("auth") || n.contains("brute") || n.contains("login")
        })
        .count();
    let anomaly_alerts = security_alerts
        .iter()
        .filter(|a| {
            let n = a.rule_name.to_ascii_lowercase();
            n.contains("volume")
                || n.contains("spike")
                || n.contains("anormal")
                || n.contains("anomaly")
        })
        .count();

    let dns_issue_events = storage::count_events(
        &mongo,
        doc! { "ts": { "$gte": &since }, "event_type": "dns_lookup", "status": { "$in": ["failed", "deferred"] } },
    )
    .await;

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

    let auth_events_coll = mongo
        .database(&db)
        .collection::<bson::Document>("auth_events");
    let suspicious_login_docs = match auth_events_coll
        .aggregate(vec![
            doc! { "$match": { "ts": { "$gte": &since }, "success": false } },
            doc! { "$group": { "_id": "$ip", "attempts": { "$sum": 1 } } },
            doc! { "$sort": { "attempts": -1 } },
            doc! { "$limit": 10 },
        ])
        .await
    {
        Ok(cursor) => cursor.try_collect::<Vec<_>>().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let suspicious_logins_top = suspicious_login_docs
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "ip": d.get_str("_id").unwrap_or("unknown"),
                "attempts": d.get_i64("attempts").unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();

    let by_domain_docs = storage::aggregate(
        &mongo,
        vec![
            doc! { "$match": base_filter.clone() },
            doc! { "$project": {
                "recipient_domain": { "$arrayElemAt": [ { "$split": ["$to", "@"] }, 1 ] },
                "status": "$status"
            }},
            doc! { "$group": {
                "_id": "$recipient_domain",
                "count": { "$sum": 1 },
                "delivered": { "$sum": { "$cond": { "if": { "$eq": ["$status", "delivered"] }, "then": 1, "else": 0 } } },
                "bounced": { "$sum": { "$cond": { "if": { "$eq": ["$status", "bounced"] }, "then": 1, "else": 0 } } }
            }},
            doc! { "$sort": { "count": -1 } },
            doc! { "$limit": 20 }
        ],
    )
    .await;

    let per_domain = by_domain_docs
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "domain": d.get_str("_id").unwrap_or("unknown"),
                "count": d.get_i64("count").unwrap_or(0),
                "delivered": d.get_i64("delivered").unwrap_or(0),
                "bounced": d.get_i64("bounced").unwrap_or(0)
            })
        })
        .collect::<Vec<_>>();

    HttpResponse::Ok().json(serde_json::json!({
        "window": query.window,
        "since": since,
        "smtp": {
            "total_events": total,
            "failure_events": failed + bounced,
            "p95_total_ms": p95,
            "by_status": by_status
        },
        "health_realtime": {
            "queue": {
                "depth": queue_depth,
                "oldest_age_seconds": queue_oldest_age_seconds
            },
            "throughput": {
                "incoming_per_min": ((incoming_events as f64 / window_minutes) * 100.0).round() / 100.0,
                "outgoing_per_min": ((outgoing_events as f64 / window_minutes) * 100.0).round() / 100.0
            },
            "delivery": {
                "success_rate": (success_rate * 10000.0).round() / 10000.0,
                "smtp_4xx_rate": if total == 0 { 0.0 } else { ((smtp_4xx as f64 / total as f64) * 10000.0).round() / 10000.0 },
                "smtp_5xx_rate": if total == 0 { 0.0 } else { ((smtp_5xx as f64 / total as f64) * 10000.0).round() / 10000.0 },
                "p95_total_ms": p95
            }
        },
        "proactive_alerting": {
            "threshold_alerts": {
                "queue_growth": queue_growth_alerts,
                "auth_failures": auth_failure_alerts,
                "imap_latency_alert": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok()).map(|v| v > env::var("IMAP_P95_MS_THRESHOLD").ok().and_then(|t| t.parse::<u64>().ok()).unwrap_or(4000)).unwrap_or(false)
            },
            "anomaly_detection": {
                "anomaly_alerts": anomaly_alerts,
                "spam_or_volume_spike": anomaly_alerts > 0,
                "sudden_bounce_signal": monitoring_alerts.iter().any(|a| a.kind == "bounce_rate")
            },
            "correlation": {
                "smtp": { "events": total, "smtp_4xx": smtp_4xx, "smtp_5xx": smtp_5xx },
                "imap": {
                    "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
                    "p95_ms": env::var("IMAP_P95_MS").ok().and_then(|v| v.parse::<u64>().ok())
                },
                "dns": { "lookup_issue_events": dns_issue_events },
                "blacklist": {
                    "sources": rbl_sources,
                    "listed_by": rbl_listed_by,
                    "listed": !env::var("RBL_LISTED_BY").unwrap_or_default().trim().is_empty()
                }
            }
        },
        "security_deliverability": {
            "suspicious_logins_top": suspicious_logins_top,
            "active_security_alerts": security_alerts.len(),
            "active_monitoring_alerts": monitoring_alerts.len()
        },
        "imap": {
            "active_connections": env::var("IMAP_ACTIVE_CONNECTIONS").ok().and_then(|v| v.parse::<u64>().ok()),
            "note": "Connecter un compteur runtime IMAP pour une métrique live fiable"
        },
        "realtime_alerts": {
            "monitoring_active": monitoring_alerts.len(),
            "security_active": security_alerts.len()
        },
        "per_domain": per_domain,
        "exports": {
            "prometheus_enabled": env_bool("PROMETHEUS_EXPORT_ENABLED", true),
            "prometheus_path": env::var("PROMETHEUS_EXPORT_PATH").unwrap_or_else(|_| "/metrics".to_string()),
            "siem_webhook_configured": env::var("SIEM_WEBHOOK_URL").map(|v| !v.trim().is_empty()).unwrap_or(false)
        }
    }))
}


