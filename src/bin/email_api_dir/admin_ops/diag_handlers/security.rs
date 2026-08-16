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

