#![allow(unused_imports, dead_code)]
use super::super::super::*;

pub(crate) struct DnsFindings {
    pub(crate) dmarc_policy: &'static str,
    pub(crate) spf_apex_ok: bool,
    pub(crate) dkim_dns_ok: bool,
    pub(crate) helo_spf_ok: bool,
    pub(crate) smtp_public_ip: String,
}

pub(crate) async fn collect_dns_findings(domain: &str, selector: &str) -> DnsFindings {
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

pub(crate) struct ProcedureState {
    pub(crate) reminder_enabled: bool,
    pub(crate) reminder_cadence_hours: u32,
    pub(crate) reminder_anchor: DateTime<Utc>,
    pub(crate) checklist_overrides: bson::Document,
}

pub(crate) async fn load_procedure_state(mongo: &Arc<mongodb::Client>) -> ProcedureState {
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

pub(crate) fn build_checklist(
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

pub(crate) fn apply_checklist_overrides(checklist: &mut [serde_json::Value], overrides: &bson::Document) {
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

pub(crate) fn compute_procedure_diff(checklist: &[serde_json::Value], gmail_blocks: u64) -> (usize, &'static str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_findings_fields() {
        let findings = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "1.2.3.4".to_string(),
        };
        assert_eq!(findings.dmarc_policy, "reject");
        assert!(findings.spf_apex_ok);
        assert!(findings.dkim_dns_ok);
        assert!(findings.helo_spf_ok);
        assert_eq!(findings.smtp_public_ip, "1.2.3.4");
    }

    #[test]
    fn procedure_state_fields() {
        let state = ProcedureState {
            reminder_enabled: true,
            reminder_cadence_hours: 24,
            reminder_anchor: Utc::now(),
            checklist_overrides: bson::Document::new(),
        };
        assert!(state.reminder_enabled);
        assert_eq!(state.reminder_cadence_hours, 24);
    }

    #[test]
    fn procedure_state_with_overrides() {
        let mut overrides = bson::Document::new();
        overrides.insert("checklist_overrides", bson::Document::new());
        let state = ProcedureState {
            reminder_enabled: false,
            reminder_cadence_hours: 12,
            reminder_anchor: Utc::now(),
            checklist_overrides: overrides.clone(),
        };
        assert!(!state.reminder_enabled);
        assert_eq!(state.reminder_cadence_hours, 12);
        assert!(!state.checklist_overrides.is_empty());
    }

    #[test]
    fn build_checklist_returns_6_items() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        assert_eq!(checklist.len(), 6);
    }

    #[test]
    fn build_checklist_with_reject_policy() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let first = &checklist[0];
        assert_eq!(first.get("id").unwrap().as_str().unwrap(), "dmarc-enforcement");
        assert_eq!(first.get("status").unwrap().as_str().unwrap(), "done");
    }

    #[test]
    fn build_checklist_with_missing_policy() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let first = &checklist[0];
        assert_eq!(first.get("status").unwrap().as_str().unwrap(), "todo");
    }

    #[test]
    fn build_checklist_with_gmail_blocks() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 5, 0);
        let gmail_item = checklist.iter().find(|i| i.get("id").unwrap().as_str().unwrap() == "gmail-policy").unwrap();
        assert_eq!(gmail_item.get("status").unwrap().as_str().unwrap(), "blocked");
    }

    #[test]
    fn apply_checklist_overrides_checked() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", true);
        overrides.insert("dmarc-enforcement", dmarc_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0].get("status").unwrap().as_str().unwrap(), "done_manual");
    }

    #[test]
    fn apply_checklist_overrides_note() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("note", "Fixed DNS");
        overrides.insert("dmarc-enforcement", dmarc_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0].get("operator_note").unwrap().as_str().unwrap(), "Fixed DNS");
    }

    #[test]
    fn compute_procedure_diff_all_done() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let (done, status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done, 6);
        assert_eq!(status, "ready_for_reject");
    }

    #[test]
    fn compute_procedure_diff_in_progress() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let (done, status) = compute_procedure_diff(&checklist, 0);
        assert!(done < 6);
        assert_eq!(status, "in_progress");
    }

    #[test]
    fn compute_procedure_diff_blocked_by_gmail() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        let (_, status) = compute_procedure_diff(&checklist, 5);
        assert_eq!(status, "blocked_gmail_policy");
    }

    #[test]
    fn compute_procedure_diff_manual_done_counted() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "example.com", "default", "7d", 0, 0);
        // Override one item to done_manual
        checklist[0]["status"] = serde_json::json!("done_manual");
        let (done, _) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done, 1);
    }
}
