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
    fn dmarc_policy_reject() {
        let dmarc_joined = "v=dmarc1; p=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@misfits.ai";
        let policy = if dmarc_joined.contains("p=reject") {
            "reject"
        } else if dmarc_joined.contains("p=quarantine") {
            "quarantine"
        } else if dmarc_joined.contains("p=none") {
            "none"
        } else {
            "missing"
        };
        assert_eq!(policy, "reject");
    }

    #[test]
    fn dmarc_policy_quarantine() {
        let dmarc_joined = "v=dmarc1; p=quarantine; pct=25; adkim=s; aspf=s";
        let policy = if dmarc_joined.contains("p=reject") {
            "reject"
        } else if dmarc_joined.contains("p=quarantine") {
            "quarantine"
        } else if dmarc_joined.contains("p=none") {
            "none"
        } else {
            "missing"
        };
        assert_eq!(policy, "quarantine");
    }

    #[test]
    fn dmarc_policy_none() {
        let dmarc_joined = "v=dmarc1; p=none; pct=100; adkim=s; aspf=s";
        let policy = if dmarc_joined.contains("p=reject") {
            "reject"
        } else if dmarc_joined.contains("p=quarantine") {
            "quarantine"
        } else if dmarc_joined.contains("p=none") {
            "none"
        } else {
            "missing"
        };
        assert_eq!(policy, "none");
    }

    #[test]
    fn dmarc_policy_missing() {
        let dmarc_joined = "";
        let policy = if dmarc_joined.contains("p=reject") {
            "reject"
        } else if dmarc_joined.contains("p=quarantine") {
            "quarantine"
        } else if dmarc_joined.contains("p=none") {
            "none"
        } else {
            "missing"
        };
        assert_eq!(policy, "missing");
    }

    #[test]
    fn spf_apex_ok_true() {
        let spf_joined = "v=spf1 ip4:51.158.114.182 -all";
        let smtp_public_ip = "51.158.114.182".to_string();
        let spf_apex_ok = spf_joined.contains("v=spf1") && spf_joined.contains(&smtp_public_ip);
        assert!(spf_apex_ok);
    }

    #[test]
    fn spf_apex_ok_false_missing_ip() {
        let spf_joined = "v=spf1 a -all";
        let smtp_public_ip = "51.158.114.182".to_string();
        let spf_apex_ok = spf_joined.contains("v=spf1") && spf_joined.contains(&smtp_public_ip);
        assert!(!spf_apex_ok);
    }

    #[test]
    fn spf_apex_ok_false_no_spf() {
        let spf_joined = "no spf record";
        let smtp_public_ip = "51.158.114.182".to_string();
        let spf_apex_ok = spf_joined.contains("v=spf1") && spf_joined.contains(&smtp_public_ip);
        assert!(!spf_apex_ok);
    }

    #[test]
    fn dkim_dns_ok_true() {
        let dkim_rows = vec!["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"];
        let dkim_dns_ok = dkim_rows
            .iter()
            .any(|row| row.to_ascii_lowercase().contains("v=dkim1"));
        assert!(dkim_dns_ok);
    }

    #[test]
    fn dkim_dns_ok_false() {
        let dkim_rows = vec!["no dkim record"];
        let dkim_dns_ok = dkim_rows
            .iter()
            .any(|row| row.to_ascii_lowercase().contains("v=dkim1"));
        assert!(!dkim_dns_ok);
    }

    #[test]
    fn dkim_dns_ok_empty() {
        let dkim_rows: Vec<&str> = vec![];
        let dkim_dns_ok = dkim_rows
            .iter()
            .any(|row| row.to_ascii_lowercase().contains("v=dkim1"));
        assert!(!dkim_dns_ok);
    }

    #[test]
    fn helo_spf_ok_true() {
        let helo_joined = "v=spf1 a -all";
        let helo_spf_ok = helo_joined.contains("v=spf1");
        assert!(helo_spf_ok);
    }

    #[test]
    fn helo_spf_ok_false() {
        let helo_joined = "no spf record";
        let helo_spf_ok = helo_joined.contains("v=spf1");
        assert!(!helo_spf_ok);
    }

    #[test]
    fn dns_findings_default() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        assert_eq!(dns.dmarc_policy, "missing");
        assert!(!dns.spf_apex_ok);
        assert!(!dns.dkim_dns_ok);
        assert!(!dns.helo_spf_ok);
        assert_eq!(dns.smtp_public_ip, "51.158.114.182");
    }

    #[test]
    fn dns_findings_all_ok() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        assert_eq!(dns.dmarc_policy, "reject");
        assert!(dns.spf_apex_ok);
        assert!(dns.dkim_dns_ok);
        assert!(dns.helo_spf_ok);
    }

    #[test]
    fn procedure_state_default() {
        let state = ProcedureState {
            reminder_enabled: true,
            reminder_cadence_hours: 24,
            reminder_anchor: Utc::now(),
            checklist_overrides: bson::Document::new(),
        };
        assert!(state.reminder_enabled);
        assert_eq!(state.reminder_cadence_hours, 24);
        assert!(state.checklist_overrides.is_empty());
    }

    #[test]
    fn procedure_state_custom() {
        let state = ProcedureState {
            reminder_enabled: false,
            reminder_cadence_hours: 12,
            reminder_anchor: Utc::now(),
            checklist_overrides: bson::Document::new(),
        };
        assert!(!state.reminder_enabled);
        assert_eq!(state.reminder_cadence_hours, 12);
    }

    #[test]
    fn build_checklist_has_6_items() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        assert_eq!(checklist.len(), 6);
    }

    #[test]
    fn build_checklist_all_done_when_perfect() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        for item in &checklist {
            assert_eq!(item["status"], "done");
        }
    }

    #[test]
    fn build_checklist_all_todo_when_missing() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        for item in &checklist {
            assert_eq!(item["status"], "todo");
        }
    }

    #[test]
    fn build_checklist_gmail_blocked() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 5, 0);
        let gmail_item = &checklist[3];
        assert_eq!(gmail_item["id"], "gmail-policy");
        assert_eq!(gmail_item["status"], "blocked");
    }

    #[test]
    fn build_checklist_dkim_alerts() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 3);
        let dkim_item = &checklist[4];
        assert_eq!(dkim_item["id"], "dkim-runtime");
        assert_eq!(dkim_item["status"], "todo");
    }

    #[test]
    fn build_checklist_dmarc_in_progress() {
        let dns = DnsFindings {
            dmarc_policy: "quarantine",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let dmarc_item = &checklist[0];
        assert_eq!(dmarc_item["id"], "dmarc-enforcement");
        assert_eq!(dmarc_item["status"], "in_progress");
    }

    #[test]
    fn build_checklist_ids() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        assert_eq!(checklist[0]["id"], "dmarc-enforcement");
        assert_eq!(checklist[1]["id"], "spf-helo");
        assert_eq!(checklist[2]["id"], "dkim-dns");
        assert_eq!(checklist[3]["id"], "gmail-policy");
        assert_eq!(checklist[4]["id"], "dkim-runtime");
        assert_eq!(checklist[5]["id"], "apex-spf");
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
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", true);
        dmarc_override.insert("note", "Done manually");
        overrides.insert("dmarc-enforcement", dmarc_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0]["status"], "done_manual");
        assert_eq!(checklist[0]["operator_note"], "Done manually");
    }

    #[test]
    fn apply_checklist_overrides_unchecked() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", false);
        dmarc_override.insert("note", "Not done yet");
        overrides.insert("dmarc-enforcement", dmarc_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0]["status"], "todo");
        assert_eq!(checklist[0]["operator_note"], "Not done yet");
    }

    #[test]
    fn apply_checklist_overrides_empty_note() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", true);
        dmarc_override.insert("note", "");
        overrides.insert("dmarc-enforcement", dmarc_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0]["status"], "done_manual");
        assert!(checklist[0].get("operator_note").is_none());
    }

    #[test]
    fn apply_checklist_overrides_no_matching_id() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut unknown_override = bson::Document::new();
        unknown_override.insert("checked", true);
        overrides.insert("unknown-id", unknown_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0]["status"], "todo");
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
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 6);
        assert_eq!(overall_status, "ready_for_reject");
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
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 0);
        assert_eq!(overall_status, "in_progress");
    }

    #[test]
    fn compute_procedure_diff_blocked_gmail() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 5, 0);
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 5);
        assert_eq!(done_count, 5);
        assert_eq!(overall_status, "blocked_gmail_policy");
    }

    #[test]
    fn compute_procedure_diff_partial_done() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 4);
        assert_eq!(overall_status, "in_progress");
    }

    #[test]
    fn compute_procedure_diff_with_manual_done() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", true);
        overrides.insert("dmarc-enforcement", dmarc_override);
        apply_checklist_overrides(&mut checklist, &overrides);

        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 1);
        assert_eq!(overall_status, "in_progress");
    }

    #[test]
    fn build_checklist_evidence_format() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        assert!(checklist[0]["evidence"].to_string().contains("reject"));
        assert!(checklist[2]["evidence"].to_string().contains("default"));
        assert!(checklist[2]["evidence"].to_string().contains("misfits.ai"));
    }

    #[test]
    fn build_checklist_cta_format() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        for item in &checklist {
            assert!(item.get("cta").is_some());
            assert!(item["cta"].get("label").is_some());
            assert!(item["cta"].get("kind").is_some());
            assert!(item["cta"].get("details").is_some());
        }
    }

    #[test]
    fn build_checklist_cta_kinds() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        assert_eq!(checklist[0]["cta"]["kind"], "dns");
        assert_eq!(checklist[1]["cta"]["kind"], "dns");
        assert_eq!(checklist[2]["cta"]["kind"], "dns");
        assert_eq!(checklist[3]["cta"]["kind"], "ops");
        assert_eq!(checklist[4]["cta"]["kind"], "probe");
        assert_eq!(checklist[5]["cta"]["kind"], "dns");
    }

    #[test]
    fn procedure_state_reminder_cadence_min() {
        let cadence = 0i32;
        let clamped = cadence.max(1) as u32;
        assert_eq!(clamped, 1);
    }

    #[test]
    fn procedure_state_reminder_cadence_positive() {
        let cadence = 12i32;
        let clamped = cadence.max(1) as u32;
        assert_eq!(clamped, 12);
    }

    #[test]
    fn procedure_state_reminder_cadence_negative() {
        let cadence = -5i32;
        let clamped = cadence.max(1) as u32;
        assert_eq!(clamped, 1);
    }

    #[test]
    fn procedure_state_reminder_cadence_zero() {
        let cadence = 0i32;
        let clamped = cadence.max(1) as u32;
        assert_eq!(clamped, 1);
    }

    #[test]
    fn procedure_state_reminder_cadence_large() {
        let cadence = 1000i32;
        let clamped = cadence.max(1) as u32;
        assert_eq!(clamped, 1000);
    }

    #[test]
    fn dns_findings_clone() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let cloned = DnsFindings {
            dmarc_policy: dns.dmarc_policy,
            spf_apex_ok: dns.spf_apex_ok,
            dkim_dns_ok: dns.dkim_dns_ok,
            helo_spf_ok: dns.helo_spf_ok,
            smtp_public_ip: dns.smtp_public_ip.clone(),
        };
        assert_eq!(dns.dmarc_policy, cloned.dmarc_policy);
        assert_eq!(dns.spf_apex_ok, cloned.spf_apex_ok);
        assert_eq!(dns.dkim_dns_ok, cloned.dkim_dns_ok);
        assert_eq!(dns.helo_spf_ok, cloned.helo_spf_ok);
        assert_eq!(dns.smtp_public_ip, cloned.smtp_public_ip);
    }

    #[test]
    fn procedure_state_clone() {
        let state = ProcedureState {
            reminder_enabled: true,
            reminder_cadence_hours: 24,
            reminder_anchor: Utc::now(),
            checklist_overrides: bson::Document::new(),
        };
        let cloned = ProcedureState {
            reminder_enabled: state.reminder_enabled,
            reminder_cadence_hours: state.reminder_cadence_hours,
            reminder_anchor: state.reminder_anchor,
            checklist_overrides: state.checklist_overrides.clone(),
        };
        assert_eq!(state.reminder_enabled, cloned.reminder_enabled);
        assert_eq!(state.reminder_cadence_hours, cloned.reminder_cadence_hours);
    }

    #[test]
    fn build_checklist_with_different_domains() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "example.com", "selector1", "24h", 0, 0);
        assert!(checklist[2]["evidence"].to_string().contains("selector1"));
        assert!(checklist[2]["evidence"].to_string().contains("example.com"));
    }

    #[test]
    fn build_checklist_with_different_selectors() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "google", "1h", 0, 0);
        assert!(checklist[2]["evidence"].to_string().contains("google"));
    }

    #[test]
    fn build_checklist_with_different_windows() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "7d", 0, 0);
        assert!(checklist[3]["evidence"].to_string().contains("7d"));
    }

    #[test]
    fn build_checklist_with_different_gmail_blocks() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 10, 0);
        assert!(checklist[3]["evidence"].to_string().contains("10"));
    }

    #[test]
    fn build_checklist_with_different_dkim_alerts() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 5);
        assert!(checklist[4]["evidence"].to_string().contains("5"));
    }

    #[test]
    fn apply_checklist_overrides_multiple_items() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", true);
        dmarc_override.insert("note", "DMARC done");
        overrides.insert("dmarc-enforcement", dmarc_override);
        let mut spf_override = bson::Document::new();
        spf_override.insert("checked", true);
        spf_override.insert("note", "SPF done");
        overrides.insert("spf-helo", spf_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0]["status"], "done_manual");
        assert_eq!(checklist[0]["operator_note"], "DMARC done");
        assert_eq!(checklist[1]["status"], "done_manual");
        assert_eq!(checklist[1]["operator_note"], "SPF done");
    }

    #[test]
    fn apply_checklist_overrides_whitespace_note() {
        let dns = DnsFindings {
            dmarc_policy: "missing",
            spf_apex_ok: false,
            dkim_dns_ok: false,
            helo_spf_ok: false,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let mut checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        let mut overrides = bson::Document::new();
        let mut dmarc_override = bson::Document::new();
        dmarc_override.insert("checked", true);
        dmarc_override.insert("note", "   ");
        overrides.insert("dmarc-enforcement", dmarc_override);

        apply_checklist_overrides(&mut checklist, &overrides);
        assert_eq!(checklist[0]["status"], "done_manual");
        assert!(checklist[0].get("operator_note").is_none());
    }

    #[test]
    fn compute_procedure_diff_empty_checklist() {
        let checklist: Vec<serde_json::Value> = vec![];
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 0);
        assert_eq!(overall_status, "ready_for_reject");
    }

    #[test]
    fn compute_procedure_diff_single_item_done() {
        let checklist = vec![serde_json::json!({"status": "done"})];
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 1);
        assert_eq!(overall_status, "ready_for_reject");
    }

    #[test]
    fn compute_procedure_diff_single_item_todo() {
        let checklist = vec![serde_json::json!({"status": "todo"})];
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 0);
        assert_eq!(overall_status, "in_progress");
    }

    #[test]
    fn compute_procedure_diff_single_item_done_manual() {
        let checklist = vec![serde_json::json!({"status": "done_manual"})];
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 1);
        assert_eq!(overall_status, "ready_for_reject");
    }

    #[test]
    fn compute_procedure_diff_mixed_status() {
        let checklist = vec![
            serde_json::json!({"status": "done"}),
            serde_json::json!({"status": "todo"}),
            serde_json::json!({"status": "done_manual"}),
            serde_json::json!({"status": "in_progress"}),
        ];
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 0);
        assert_eq!(done_count, 2);
        assert_eq!(overall_status, "in_progress");
    }

    #[test]
    fn compute_procedure_diff_gmail_blocks_takes_precedence() {
        let checklist = vec![
            serde_json::json!({"status": "done"}),
            serde_json::json!({"status": "done"}),
        ];
        let (done_count, overall_status) = compute_procedure_diff(&checklist, 1);
        assert_eq!(done_count, 2);
        assert_eq!(overall_status, "blocked_gmail_policy");
    }

    #[test]
    fn build_checklist_titles() {
        let dns = DnsFindings {
            dmarc_policy: "reject",
            spf_apex_ok: true,
            dkim_dns_ok: true,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 0, 0);
        assert_eq!(checklist[0]["title"], "Activer DMARC enforcement progressif");
        assert_eq!(checklist[1]["title"], "Corriger SPF_HELO_NONE");
        assert_eq!(checklist[2]["title"], "Vérifier la clé DKIM publique");
        assert_eq!(checklist[3]["title"], "Traiter les rejets policy Gmail");
        assert_eq!(checklist[4]["title"], "Confirmer absence de régression DKIM");
        assert_eq!(checklist[5]["title"], "Conserver SPF apex aligné IP prod");
    }

    #[test]
    fn build_checklist_status_variants() {
        let dns = DnsFindings {
            dmarc_policy: "quarantine",
            spf_apex_ok: true,
            dkim_dns_ok: false,
            helo_spf_ok: true,
            smtp_public_ip: "51.158.114.182".to_string(),
        };
        let checklist = build_checklist(&dns, "misfits.ai", "default", "1h", 3, 2);
        assert_eq!(checklist[0]["status"], "in_progress");
        assert_eq!(checklist[1]["status"], "done");
        assert_eq!(checklist[2]["status"], "todo");
        assert_eq!(checklist[3]["status"], "blocked");
        assert_eq!(checklist[4]["status"], "todo");
        assert_eq!(checklist[5]["status"], "done");
    }
}
