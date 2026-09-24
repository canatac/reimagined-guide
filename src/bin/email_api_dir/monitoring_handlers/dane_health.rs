//! DANE (DNS-based Authentication of Named Entities) for outbound SMTP.
//!
//! Issue #679: DANE outbound TLS — TLSA record verification + TLS cert validation.
//!
//! This module provides:
//! 1. DANE health endpoint (GET /api/monitoring/dane-health)
//! 2. DANE pre-connection check for SMTP relay sends
//! 3. DANE status logging for observability

use actix_web::HttpResponse;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(serde::Serialize)]
struct DaneHealthResponse {
    status: &'static str,
    domain: String,
    tlsa_records_found: bool,
    message: String,
}

/// Counter for DANE checks performed (observability).
static DANE_CHECKS_TOTAL: AtomicUsize = AtomicUsize::new(0);
static DANE_ENFORCED_TOTAL: AtomicUsize = AtomicUsize::new(0);

/// Check DANE status for a given domain (optional `domain` query param).
/// Without query param, checks the SMTP relay host.
pub(crate) async fn api_monitoring_dane_health(
    actix_web::web::Query(params): actix_web::web::Query<std::collections::HashMap<String, String>>,
) -> impl actix_web::Responder {
    let domain = params
        .get("domain")
        .cloned()
        .or_else(|| std::env::var("SMTP_RELAY_HOST").ok())
        .unwrap_or_default();

    if domain.is_empty() {
        return HttpResponse::ServiceUnavailable().json(DaneHealthResponse {
            status: "misconfigured",
            domain: "(no domain or SMTP_RELAY_HOST)".to_string(),
            tlsa_records_found: false,
            message: "Set SMTP_RELAY_HOST or pass ?domain=".to_string(),
        });
    }

    DANE_CHECKS_TOTAL.fetch_add(1, Ordering::Relaxed);

    // Use the existing DANE module to check TLSA records
    match simple_smtp_server::smtp_client::dane::lookup_tlsa_records(&domain).await {
        Ok(records) if !records.is_empty() => {
            DANE_ENFORCED_TOTAL.fetch_add(1, Ordering::Relaxed);
            HttpResponse::Ok().json(DaneHealthResponse {
                status: "dane_enforced",
                domain,
                tlsa_records_found: true,
                message: format!(
                    "{} TLSA record(s) found — DANE validation active for outbound TLS",
                    records.len()
                ),
            })
        }
        Ok(_) => HttpResponse::Ok().json(DaneHealthResponse {
            status: "no_tlsa",
            domain,
            tlsa_records_found: false,
            message: "No TLSA records — opportunistic TLS (no DANE enforcement)".to_string(),
        }),
        Err(e) => HttpResponse::ServiceUnavailable().json(DaneHealthResponse {
            status: "lookup_failed",
            domain,
            tlsa_records_found: false,
            message: format!("TLSA lookup error: {}", e),
        }),
    }
}

/// Get DANE check statistics.
pub(crate) fn dane_check_stats() -> (usize, usize) {
    (
        DANE_CHECKS_TOTAL.load(Ordering::Relaxed),
        DANE_ENFORCED_TOTAL.load(Ordering::Relaxed),
    )
}

/// Check if DANE TLSA records exist for a domain (used by SMTP pipeline).
/// Returns true if DANE should be enforced (TLSA records present).
pub async fn should_enforce_dane(domain: &str) -> bool {
    if domain.is_empty() {
        return false;
    }
    simple_smtp_server::smtp_client::dane::has_tlsa_records(domain).await
}

/// Validate a server certificate against DANE TLSA records for a domain.
/// Returns Ok(()) if validation passes or no TLSA records exist.
/// Returns Err if TLSA records exist but cert doesn't match.
pub async fn validate_dane_for_domain(
    domain: &str,
    cert: &rustls::pki_types::CertificateDer<'_>,
) -> Result<(), String> {
    simple_smtp_server::smtp_client::dane::validate_server_cert_dane(domain, cert)
        .await
        .into()
}

impl From<simple_smtp_server::smtp_client::dane::DaneValidationResult> for Result<(), String> {
    fn from(result: simple_smtp_server::smtp_client::dane::DaneValidationResult) -> Self {
        use simple_smtp_server::smtp_client::dane::DaneValidationResult::*;
        match result {
            Valid | NoRecords => Ok(()),
            ValidationFailed(msg) => Err(msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dane_health_response_shape() {
        let resp = DaneHealthResponse {
            status: "dane_enforced",
            domain: "example.com".to_string(),
            tlsa_records_found: true,
            message: "2 TLSA record(s) found".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "dane_enforced");
        assert_eq!(json["tlsa_records_found"], true);
    }

    #[test]
    fn dane_health_no_tlsa_shape() {
        let resp = DaneHealthResponse {
            status: "no_tlsa",
            domain: "example.org".to_string(),
            tlsa_records_found: false,
            message: "No TLSA records".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "no_tlsa");
        assert_eq!(json["tlsa_records_found"], false);
    }

    #[test]
    fn dane_health_misconfigured_shape() {
        let resp = DaneHealthResponse {
            status: "misconfigured",
            domain: "(no domain)".to_string(),
            tlsa_records_found: false,
            message: "Set SMTP_RELAY_HOST".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "misconfigured");
    }

    #[test]
    fn dane_check_stats_initial() {
        let (total, enforced) = dane_check_stats();
        // Just verify the function doesn't panic
        assert!(total >= 0);
        assert!(enforced >= 0);
    }
}
