//! DKIM service health check endpoint (issue #691).
//! GET /api/monitoring/dkim-health — probes the Node.js DKIM signer service.

use actix_web::HttpResponse;
use std::time::Instant;

#[derive(serde::Serialize)]
struct DkimHealthResponse {
    status: &'static str,
    url: String,
    ping_ms: u64,
    reachable: bool,
}

pub(crate) async fn api_monitoring_dkim_health() -> impl actix_web::Responder {
    let dkim_url = std::env::var("DKIM_SERVICE_URL").unwrap_or_default();

    if dkim_url.is_empty() {
        return HttpResponse::ServiceUnavailable().json(DkimHealthResponse {
            status: "misconfigured",
            url: "(DKIM_SERVICE_URL not set)".to_string(),
            ping_ms: 0,
            reachable: false,
        });
    }

    // Probe via GET on the base URL (lightweight liveness check)
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build();

    let Ok(client) = client else {
        return HttpResponse::InternalServerError().json(DkimHealthResponse {
            status: "client_error",
            url: dkim_url,
            ping_ms: 0,
            reachable: false,
        });
    };

    let start = Instant::now();
    let result = client.get(&dkim_url.replace("/generate-dkim", "/health"))
        .send()
        .await;
    let ping_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(resp) if resp.status().is_success() => {
            HttpResponse::Ok().json(DkimHealthResponse {
                status: "healthy",
                url: dkim_url,
                ping_ms,
                reachable: true,
            })
        }
        Ok(resp) => {
            HttpResponse::ServiceUnavailable().json(DkimHealthResponse {
                status: "unhealthy",
                url: dkim_url,
                ping_ms,
                reachable: false,
            })
        }
        Err(_) => {
            HttpResponse::ServiceUnavailable().json(DkimHealthResponse {
                status: "unreachable",
                url: dkim_url,
                ping_ms,
                reachable: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkim_health_response_shape() {
        let resp = DkimHealthResponse {
            status: "healthy",
            url: "http://dkim-service:3000/generate-dkim".to_string(),
            ping_ms: 12,
            reachable: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["reachable"], true);
        assert_eq!(json["ping_ms"], 12);
    }

    #[test]
    fn dkim_health_unreachable_shape() {
        let resp = DkimHealthResponse {
            status: "unreachable",
            url: "http://dkim-service:3000/generate-dkim".to_string(),
            ping_ms: 3000,
            reachable: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "unreachable");
        assert_eq!(json["reachable"], false);
    }

    #[test]
    fn dkim_health_misconfigured_shape() {
        let resp = DkimHealthResponse {
            status: "misconfigured",
            url: "(DKIM_SERVICE_URL not set)".to_string(),
            ping_ms: 0,
            reachable: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["status"], "misconfigured");
    }
}
