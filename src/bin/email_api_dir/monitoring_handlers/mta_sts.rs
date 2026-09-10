//! MTA-STS (Mail Transfer Agent Strict Transport Security) HTTP handlers
//! RFC 8461 — DNS-based TLS policy for outbound SMTP

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

use simple_smtp_server::monitoring::mta_sts::{
    generate_policy_text, parse_sts_policy_text, should_block_on_failure,
    should_enforce_tls, MtaStsManager, StsMode, StsValidationResult,
};

/// GET /api/v1/mta-sts/policy?domain=example.com
/// Fetch and return the MTA-STS policy for a domain
pub async fn api_mta_sts_policy(
    query: web::Query<PolicyQuery>,
) -> Result<HttpResponse> {
    let manager = MtaStsManager::new();
    match manager.fetch_policy(&query.domain).await {
        Ok(policy) => Ok(HttpResponse::Ok().json(policy)),
        Err(e) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": e,
            "domain": query.domain,
        }))),
    }
}

/// GET /api/v1/mta-sts/validate?domain=example.com&mx=mail.example.com
/// Validate MTA-STS policy for a destination domain + MX host
pub async fn api_mta_sts_validate(
    query: web::Query<ValidateQuery>,
) -> Result<HttpResponse> {
    let manager = MtaStsManager::new();
    let result = manager.validate(&query.domain, &query.mx).await;

    let response = ValidateResponse {
        domain: query.domain.clone(),
        mx: query.mx.clone(),
        result: format!("{:?}", result),
        enforce: should_enforce_tls(&result),
        block_on_failure: should_block_on_failure(&result),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// POST /api/v1/mta-sts/generate
/// Generate MTA-STS policy text for publication
pub async fn api_mta_sts_generate(
    body: web::Json<GenerateRequest>,
) -> Result<HttpResponse> {
    let mode = match body.mode.as_str() {
        "enforce" => StsMode::Enforce,
        "testing" => StsMode::Testing,
        "none" => StsMode::None,
        _ => {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid mode. Use 'enforce', 'testing', or 'none'",
            })));
        }
    };

    let policy_text = generate_policy_text(mode, body.max_age, &body.mx);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "policy": policy_text,
        "mode": body.mode,
        "max_age": body.max_age,
        "mx": body.mx,
    })))
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PolicyQuery {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateQuery {
    pub domain: String,
    pub mx: String,
}

#[derive(Debug, Serialize)]
pub struct ValidateResponse {
    pub domain: String,
    pub mx: String,
    pub result: String,
    pub enforce: bool,
    pub block_on_failure: bool,
}

#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    pub mode: String,
    pub max_age: u64,
    pub mx: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_response_serializes() {
        let resp = ValidateResponse {
            domain: "example.com".into(),
            mx: "mail.example.com".into(),
            result: "Valid".into(),
            enforce: true,
            block_on_failure: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["domain"], "example.com");
        assert_eq!(json["mx"], "mail.example.com");
        assert_eq!(json["enforce"], true);
        assert_eq!(json["block_on_failure"], false);
    }

    #[test]
    fn policy_query_deserializes() {
        let json = serde_json::json!({ "domain": "example.com" });
        let query: PolicyQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.domain, "example.com");
    }

    #[test]
    fn validate_query_deserializes() {
        let json = serde_json::json!({ "domain": "example.com", "mx": "mail.example.com" });
        let query: ValidateQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.domain, "example.com");
        assert_eq!(query.mx, "mail.example.com");
    }

    #[test]
    fn generate_request_deserializes() {
        let json = serde_json::json!({
            "mode": "enforce",
            "max_age": 86400,
            "mx": ["mail.example.com"]
        });
        let req: GenerateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.mode, "enforce");
        assert_eq!(req.max_age, 86400);
        assert_eq!(req.mx, vec!["mail.example.com"]);
    }
}
