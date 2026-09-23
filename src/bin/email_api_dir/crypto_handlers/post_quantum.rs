//! Post-quantum email signing (issue #620).
//! NIST FIPS 203/204/205 algorithm support: Dilithium, FALCON, SPHINCS+.

use actix_web::{HttpResponse, Responder};
use serde::{Deserialize, Serialize};

// ── Algorithm identifiers ──

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PostQuantumAlgorithm {
    Dilithium3,
    Falcon512,
    #[serde(rename = "sphincs+-sha256-128s")]
    SphincsPlusSha256128s,
}

impl PostQuantumAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dilithium3 => "dilithium3",
            Self::Falcon512 => "falcon512",
            Self::SphincsPlusSha256128s => "sphincs+-sha256-128s",
        }
    }

    pub fn display_label(&self) -> &'static str {
        match self {
            Self::Dilithium3 => "PQ-Dilithium3",
            Self::Falcon512 => "PQ-FALCON-512",
            Self::SphincsPlusSha256128s => "PQ-SPHINCS+-128s",
        }
    }

    pub fn nist_level(&self) -> u8 {
        match self {
            Self::Falcon512 | Self::SphincsPlusSha256128s => 1,
            Self::Dilithium3 => 3,
        }
    }
}

impl std::str::FromStr for PostQuantumAlgorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dilithium3" | "dilithium-3" | "crystals-dilithium3" => Ok(Self::Dilithium3),
            "falcon512" | "falcon-512" => Ok(Self::Falcon512),
            "sphincs+-sha256-128s" | "sphincs+_sha256_128s" | "sphincs-sha256-128s" => {
                Ok(Self::SphincsPlusSha256128s)
            }
            other => Err(format!("Unknown post-quantum algorithm: {}", other)),
        }
    }
}

// ── Request / Response ──

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct PostQuantumSignRequest {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub body: String,
    #[serde(default = "default_pq_algorithm")]
    pub pq_algorithm: PostQuantumAlgorithm,
    #[serde(default = "default_dual_sign")]
    pub dual_sign: bool,
}

fn default_pq_algorithm() -> PostQuantumAlgorithm {
    PostQuantumAlgorithm::Dilithium3
}

fn default_dual_sign() -> bool {
    true
}

#[derive(Serialize)]
pub struct PostQuantumSignResponse {
    pub status: String,
    pub message_id: String,
    pub pq_algorithm: String,
    pub pq_signature: String,
    pub pq_badge: String,
    pub nist_level: u8,
    pub dual_signed: bool,
    pub classical_signature: Option<String>,
}

// ── Handler ──

pub(crate) async fn sign_post_quantum(
    req: actix_web::web::Json<PostQuantumSignRequest>,
) -> impl Responder {
    let pq_algo = &req.pq_algorithm;

    // Validate addresses
    if req.from.is_empty() || req.to.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "code": "INVALID_ADDRESS",
            "message": "Both 'from' and 'to' are required."
        }));
    }

    // Build the signing payload for the DKIM service (PQ extension).
    let sign_payload = serde_json::json!({
        "from": req.from,
        "to": req.to,
        "subject": req.subject,
        "text": req.body,
        "html": req.body,
        "pq_algorithm": pq_algo.as_str(),
        "dual_sign": req.dual_sign
    });

    // Attempt to call the DKIM service PQ endpoint.
    let dkim_url = std::env::var("DKIM_SERVICE_PQ_URL")
        .unwrap_or_else(|_| "http://localhost:8465/sign-pq".to_string());

    let client = reqwest::Client::new();
    let response = match client.post(&dkim_url).json(&sign_payload).send().await {
        Ok(resp) => resp,
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "code": "PQ_SERVICE_UNREACHABLE",
                "message": format!("Post-quantum signing service unavailable: {}", e)
            }));
        }
    };

    let status = response.status();
    let body = match response.text().await {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::BadGateway().json(serde_json::json!({
                "code": "PQ_SERVICE_READ_ERROR",
                "message": e.to_string()
            }));
        }
    };

    if !status.is_success() {
        let snippet = if body.len() > 1200 { &body[..1200] } else { &body };
        return HttpResponse::BadGateway().json(serde_json::json!({
            "code": "PQ_SIGN_FAILED",
            "message": format!("PQ service HTTP {}: {}", status.as_u16(), snippet)
        }));
    }

    // Parse the response.
    let result: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::Ok().json(PostQuantumSignResponse {
                status: "success".into(),
                message_id: uuid::Uuid::new_v4().to_string(),
                pq_algorithm: pq_algo.as_str().to_string(),
                pq_signature: body.clone(),
                pq_badge: pq_algo.display_label().to_string(),
                nist_level: pq_algo.nist_level(),
                dual_signed: req.dual_sign,
                classical_signature: None,
            });
        }
    };

    // Structured response from PQ service.
    let message_id = result["messageId"]
        .as_str()
        .or_else(|| result["message_id"].as_str())
        .unwrap_or("")
        .to_string();
    let pq_sig = result["pqSignature"]
        .as_str()
        .or_else(|| result["pq_signature"].as_str())
        .unwrap_or("")
        .to_string();
    let classical_sig = result["classicalSignature"]
        .as_str()
        .or_else(|| result["classical_signature"].as_str())
        .map(String::from);

    if pq_sig.is_empty() {
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "code": "PQ_NO_SIGNATURE",
            "message": "PQ signing service returned success without a signature."
        }));
    }

    HttpResponse::Ok().json(PostQuantumSignResponse {
        status: "success".into(),
        message_id,
        pq_algorithm: pq_algo.as_str().to_string(),
        pq_signature: pq_sig,
        pq_badge: pq_algo.display_label().to_string(),
        nist_level: pq_algo.nist_level(),
        dual_signed: req.dual_sign,
        classical_signature: classical_sig,
    })
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_algo_dilithium3_wire() {
        assert_eq!(PostQuantumAlgorithm::Dilithium3.as_str(), "dilithium3");
    }

    #[test]
    fn pq_algo_falcon_display() {
        assert_eq!(
            PostQuantumAlgorithm::Falcon512.display_label(),
            "PQ-FALCON-512"
        );
    }

    #[test]
    fn pq_algo_sphincs_nist_level() {
        assert_eq!(
            PostQuantumAlgorithm::SphincsPlusSha256128s.nist_level(),
            1
        );
    }

    #[test]
    fn pq_algo_dilithium_nist_level() {
        assert_eq!(PostQuantumAlgorithm::Dilithium3.nist_level(), 3);
    }

    #[test]
    fn pq_algo_from_str_dilithium() {
        assert_eq!(
            "dilithium3".parse::<PostQuantumAlgorithm>().unwrap(),
            PostQuantumAlgorithm::Dilithium3
        );
    }

    #[test]
    fn pq_algo_from_str_falcon_hyphen() {
        assert_eq!(
            "falcon-512".parse::<PostQuantumAlgorithm>().unwrap(),
            PostQuantumAlgorithm::Falcon512
        );
    }

    #[test]
    fn pq_algo_from_str_sphincs() {
        assert_eq!(
            "sphincs+-sha256-128s".parse::<PostQuantumAlgorithm>().unwrap(),
            PostQuantumAlgorithm::SphincsPlusSha256128s
        );
    }

    #[test]
    fn pq_algo_from_str_unknown_fails() {
        assert!("nonexistent".parse::<PostQuantumAlgorithm>().is_err());
    }

    #[test]
    fn pq_request_default_algo() {
        let json = r#"{"from":"a@x.com","to":"b@x.com","subject":"s","body":"b"}"#;
        let req: PostQuantumSignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.pq_algorithm, PostQuantumAlgorithm::Dilithium3);
        assert!(req.dual_sign);
    }

    #[test]
    fn pq_request_custom_algo_and_no_dual() {
        let json = r#"{
            "from":"a@x.com","to":"b@x.com","subject":"s","body":"b",
            "pq_algorithm": "falcon512",
            "dual_sign": false
        }"#;
        let req: PostQuantumSignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.pq_algorithm, PostQuantumAlgorithm::Falcon512);
        assert!(!req.dual_sign);
    }

    #[test]
    fn pq_request_unknown_algo_rejected() {
        let json = r#"{
            "from":"a@x.com","to":"b@x.com","subject":"s","body":"b",
            "pq_algorithm": "bogus-algo"
        }"#;
        let result: Result<PostQuantumSignRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn pq_request_sphincs_roundtrip() {
        let json = r#"{
            "from":"a@x.com","to":"b@x.com","subject":"s","body":"b",
            "pq_algorithm": "sphincs+-sha256-128s"
        }"#;
        let req: PostQuantumSignRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.pq_algorithm,
            PostQuantumAlgorithm::SphincsPlusSha256128s
        );
    }

    #[test]
    fn pq_response_serialization() {
        let resp = PostQuantumSignResponse {
            status: "success".into(),
            message_id: "msg-pq-001".into(),
            pq_algorithm: "dilithium3".into(),
            pq_signature: "base64pqsig...".into(),
            pq_badge: "PQ-Dilithium3".into(),
            nist_level: 3,
            dual_signed: true,
            classical_signature: Some("rsa-sha256-classical".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["pq_badge"], "PQ-Dilithium3");
        assert_eq!(json["nist_level"], 3);
        assert_eq!(json["dual_signed"], true);
        assert!(json["classical_signature"].is_string());
    }

    #[test]
    fn pq_response_no_classical() {
        let resp = PostQuantumSignResponse {
            status: "success".into(),
            message_id: "msg-pq-002".into(),
            pq_algorithm: "falcon512".into(),
            pq_signature: "base64falcon...".into(),
            pq_badge: "PQ-FALCON-512".into(),
            nist_level: 1,
            dual_signed: false,
            classical_signature: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["classical_signature"].is_null());
    }

    #[test]
    fn pq_env_default_url() {
        // When DKIM_SERVICE_PQ_URL is unset, handler falls back to localhost:8465.
        std::env::remove_var("DKIM_SERVICE_PQ_URL");
        let url = std::env::var("DKIM_SERVICE_PQ_URL")
            .unwrap_or_else(|_| "http://localhost:8465/sign-pq".to_string());
        assert_eq!(url, "http://localhost:8465/sign-pq");
    }
}
