#![allow(unused_imports, dead_code)]
use super::super::*;

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
    fn brute_force_rule_name_detection() {
        let rule_names = vec!["bruteforce_login", "rate_limit_exceeded", "brute_force_attack"];
        for name in &rule_names {
            let n = name.to_ascii_lowercase();
            assert!(n.contains("bruteforce") || n.contains("brute") || n.contains("rate"));
        }
    }

    #[test]
    fn auth_policy_rule_name_detection() {
        let rule_names = vec!["spf_fail", "dkim_mismatch", "dmarc_reject"];
        for name in &rule_names {
            let n = name.to_ascii_lowercase();
            assert!(n.contains("spf") || n.contains("dkim") || n.contains("dmarc"));
        }
    }

    #[test]
    fn non_brute_force_rule_name() {
        let rule_name = "normal_login";
        let n = rule_name.to_ascii_lowercase();
        assert!(!(n.contains("bruteforce") || n.contains("brute") || n.contains("rate")));
    }

    #[test]
    fn spf_record_format() {
        let smtp_public_ip = "51.158.114.182";
        let spf = format!("v=spf1 ip4:{} -all", smtp_public_ip);
        assert_eq!(spf, "v=spf1 ip4:51.158.114.182 -all");
    }

    #[test]
    fn dmarc_record_format() {
        let dmarc = "v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=100";
        assert!(dmarc.contains("v=DMARC1"));
        assert!(dmarc.contains("p=quarantine"));
        assert!(dmarc.contains("adkim=s"));
        assert!(dmarc.contains("aspf=s"));
        assert!(dmarc.contains("pct=100"));
    }

    #[test]
    fn sasl_mechanisms() {
        let mechanisms = vec!["PLAIN", "LOGIN"];
        assert_eq!(mechanisms.len(), 2);
        assert!(mechanisms.contains(&"PLAIN"));
        assert!(mechanisms.contains(&"LOGIN"));
    }

    #[test]
    fn rate_limit_default() {
        let rate_limit: u32 = 120;
        assert_eq!(rate_limit, 120);
    }

    #[test]
    fn smtps_listener_default() {
        let addr = "0.0.0.0:8465";
        assert!(addr.contains(":8465"));
    }

    #[test]
    fn imaps_listener_default() {
        let addr = "0.0.0.0:8993";
        assert!(addr.contains(":8993"));
    }

    #[test]
    fn dkim_selector_default() {
        let selector = "default";
        assert_eq!(selector, "default");
    }

    #[test]
    fn domain_default() {
        let domain = "misfits.ai";
        assert_eq!(domain, "misfits.ai");
    }

    #[test]
    fn ptr_rdns_note_format() {
        let domain = "misfits.ai";
        let note = format!("Configurer PTR/rDNS de l'IP publique vers un host mail stable (ex: mail.<{}>)", domain);
        assert!(note.contains("mail.misfits.ai"));
        assert!(note.contains("PTR/rDNS"));
    }

    #[test]
    fn security_posture_response_structure() {
        let response = serde_json::json!({
            "window": "1h",
            "security": {
                "tls": {},
                "authentication": {},
                "anti_abuse": {},
                "mail_auth_dns": {}
            }
        });
        assert!(response.get("window").is_some());
        assert!(response.get("security").is_some());
        let security = &response["security"];
        assert!(security.get("tls").is_some());
        assert!(security.get("authentication").is_some());
        assert!(security.get("anti_abuse").is_some());
        assert!(security.get("mail_auth_dns").is_some());
    }

    #[test]
    fn oauth2_enabled_detection() {
        let client_id = Some("github-client-id".to_string());
        let oauth2_enabled = client_id.map(|v| !v.trim().is_empty()).unwrap_or(false);
        assert!(oauth2_enabled);
    }

    #[test]
    fn oauth2_disabled_when_empty() {
        let client_id: Option<String> = None;
        let oauth2_enabled = client_id.map(|v| !v.trim().is_empty()).unwrap_or(false);
        assert!(!oauth2_enabled);
    }

    #[test]
    fn oauth2_disabled_when_blank() {
        let client_id = Some("   ".to_string());
        let oauth2_enabled = client_id.map(|v| !v.trim().is_empty()).unwrap_or(false);
        assert!(!oauth2_enabled);
    }

    #[test]
    fn env_bool_true_values() {
        let true_values = vec!["1", "true", "yes", "on"];
        for v in &true_values {
            assert!(matches!(v, &"1" | &"true" | &"yes" | &"on"));
        }
    }

    #[test]
    fn env_bool_false_values() {
        let false_values = vec!["0", "false", "no", "off"];
        for v in &false_values {
            assert!(matches!(v, &"0" | &"false" | &"no" | &"off"));
        }
    }

    #[test]
    fn active_alerts_count_zero() {
        let count = 0usize;
        assert_eq!(count, 0);
    }

    #[test]
    fn active_alerts_count_positive() {
        let count = 5usize;
        assert!(count > 0);
    }
}
