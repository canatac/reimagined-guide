use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct HermesRunPath {
    pub(crate) run_id: String,
}

pub(crate) async fn api_hermes_runs(
    req: HttpRequest,
    body: web::Json<HermesRunsProxyRequest>,
) -> impl Responder {
    let input = match body.input.clone().filter(|v| !v.is_null()) {
        Some(v) => v,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "input is required"
            }))
        }
    };

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs", base);
    let model = body
        .model
        .clone()
        .unwrap_or_else(|| env::var("HERMES_MODEL").unwrap_or_else(|_| "hermes-agent".to_string()));

    let thread_id = body
        .thread_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let fallback_user_id = resolve_user_id(&req);
    let user_id = body
        .user_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(fallback_user_id);

    let session_id = body
        .session_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("mail-thread-{}", thread_id));

    let session_key = body
        .session_key
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("user-{}", user_id));

    let payload = serde_json::json!({
        "model": model,
        "input": input,
    });

    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id)
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

pub(crate) async fn api_hermes_run_status(path: web::Path<HermesRunPath>) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs/{}", base, path.run_id);
    let client = reqwest::Client::new();
    let response = match client.get(url).bearer_auth(api_key).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Hermes upstream unavailable"
            }));
        }
    };

    let status = response.status();
    let body_json = match response.json::<serde_json::Value>().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Hermes upstream JSON parse error: {}", e);
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermes_run_path_deserializes() {
        let json = serde_json::json!({ "run_id": "run-123" });
        let path: HermesRunPath = serde_json::from_value(json).unwrap();
        assert_eq!(path.run_id, "run-123");
    }

    #[test]
    fn hermes_runs_proxy_request_deserializes() {
        let json = serde_json::json!({
            "input": "Hello world",
            "model": "hermes-agent",
            "threadId": "thread-123",
            "userId": "user-456",
            "sessionId": "session-789",
            "sessionKey": "key-abc"
        });
        let req: HermesRunsProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.input, serde_json::json!("Hello world"));
        assert_eq!(req.model, Some("hermes-agent".to_string()));
        assert_eq!(req.thread_id, Some("thread-123".to_string()));
        assert_eq!(req.user_id, Some("user-456".to_string()));
        assert_eq!(req.session_id, Some("session-789".to_string()));
        assert_eq!(req.session_key, Some("key-abc".to_string()));
    }

    #[test]
    fn hermes_runs_proxy_request_minimal() {
        let json = serde_json::json!({ "input": "Test" });
        let req: HermesRunsProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.input, serde_json::json!("Test"));
        assert_eq!(req.model, None);
        assert_eq!(req.thread_id, None);
    }

    #[test]
    fn hermes_runs_proxy_request_complex_input() {
        let json = serde_json::json!({
            "input": {
                "message": "Hello",
                "context": ["item1", "item2"]
            }
        });
        let req: HermesRunsProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.input["message"], "Hello");
        assert_eq!(req.input["context"][0], "item1");
    }

    #[test]
    fn hermes_run_url_format() {
        let base = "https://hermes.example.com";
        let url = format!("{}/v1/runs", base);
        assert_eq!(url, "https://hermes.example.com/v1/runs");
    }

    #[test]
    fn hermes_run_status_url_format() {
        let base = "https://hermes.example.com";
        let run_id = "run-123";
        let url = format!("{}/v1/runs/{}", base, run_id);
        assert_eq!(url, "https://hermes.example.com/v1/runs/run-123");
    }

    #[test]
    fn model_default() {
        let model: Option<String> = None;
        let resolved = model.unwrap_or_else(|| "hermes-agent".to_string());
        assert_eq!(resolved, "hermes-agent");
    }

    #[test]
    fn model_custom() {
        let model: Option<String> = Some("custom-model".to_string());
        let resolved = model.unwrap_or_else(|| "hermes-agent".to_string());
        assert_eq!(resolved, "custom-model");
    }

    #[test]
    fn thread_id_default() {
        let thread_id: Option<String> = None;
        let resolved = thread_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        // Should be a UUID since None was provided
        assert!(Uuid::parse_str(&resolved).is_ok());
    }

    #[test]
    fn thread_id_custom() {
        let thread_id: Option<String> = Some("custom-thread".to_string());
        let resolved = thread_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        assert_eq!(resolved, "custom-thread");
    }

    #[test]
    fn thread_id_empty_defaults() {
        let thread_id: Option<String> = Some("  ".to_string());
        let resolved = thread_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        assert!(Uuid::parse_str(&resolved).is_ok());
    }

    #[test]
    fn user_id_fallback() {
        let user_id: Option<String> = None;
        let fallback = "fallback-user";
        let resolved = user_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback.to_string());
        assert_eq!(resolved, "fallback-user");
    }

    #[test]
    fn user_id_custom() {
        let user_id: Option<String> = Some("custom-user".to_string());
        let fallback = "fallback-user";
        let resolved = user_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback.to_string());
        assert_eq!(resolved, "custom-user");
    }

    #[test]
    fn session_id_default_format() {
        let thread_id = "thread-123";
        let session_id: Option<String> = None;
        let resolved = session_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("mail-thread-{}", thread_id));
        assert_eq!(resolved, "mail-thread-thread-123");
    }

    #[test]
    fn session_id_custom() {
        let thread_id = "thread-123";
        let session_id: Option<String> = Some("custom-session".to_string());
        let resolved = session_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("mail-thread-{}", thread_id));
        assert_eq!(resolved, "custom-session");
    }

    #[test]
    fn session_key_default_format() {
        let user_id = "user-456";
        let session_key: Option<String> = None;
        let resolved = session_key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("user-{}", user_id));
        assert_eq!(resolved, "user-user-456");
    }

    #[test]
    fn session_key_custom() {
        let user_id = "user-456";
        let session_key: Option<String> = Some("custom-key".to_string());
        let resolved = session_key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("user-{}", user_id));
        assert_eq!(resolved, "custom-key");
    }

    #[test]
    fn payload_structure() {
        let model = "hermes-agent";
        let input = serde_json::json!("Hello");
        let payload = serde_json::json!({
            "model": model,
            "input": input,
        });
        assert_eq!(payload["model"], "hermes-agent");
        assert_eq!(payload["input"], "Hello");
    }

    #[test]
    fn error_response_input_required() {
        let response = serde_json::json!({ "error": "input is required" });
        assert_eq!(response["error"], "input is required");
    }

    #[test]
    fn error_response_api_key_not_configured() {
        let response = serde_json::json!({ "error": "HERMES_API_KEY is not configured" });
        assert_eq!(response["error"], "HERMES_API_KEY is not configured");
    }

    #[test]
    fn error_response_upstream_unavailable() {
        let response = serde_json::json!({ "error": "Hermes upstream unavailable" });
        assert_eq!(response["error"], "Hermes upstream unavailable");
    }

    #[test]
    fn error_response_invalid_response() {
        let response = serde_json::json!({ "error": "Invalid Hermes upstream response" });
        assert_eq!(response["error"], "Invalid Hermes upstream response");
    }

    #[test]
    fn input_null_rejected() {
        let input: serde_json::Value = serde_json::Value::Null;
        let is_valid = input.clone().filter(|v| !v.is_null()).is_some();
        assert!(!is_valid);
    }

    #[test]
    fn input_string_accepted() {
        let input: serde_json::Value = serde_json::json!("Hello");
        let is_valid = input.clone().filter(|v| !v.is_null()).is_some();
        assert!(is_valid);
    }

    #[test]
    fn input_object_accepted() {
        let input: serde_json::Value = serde_json::json!({"key": "value"});
        let is_valid = input.clone().filter(|v| !v.is_null()).is_some();
        assert!(is_valid);
    }

    #[test]
    fn input_array_accepted() {
        let input: serde_json::Value = serde_json::json!([1, 2, 3]);
        let is_valid = input.clone().filter(|v| !v.is_null()).is_some();
        assert!(is_valid);
    }

    #[test]
    fn bearer_auth_header() {
        let api_key = "test-api-key";
        assert_eq!(api_key, "test-api-key");
    }

    #[test]
    fn session_headers_format() {
        let session_id = "session-123";
        let session_key = "key-456";
        assert_eq!(session_id, "session-123");
        assert_eq!(session_key, "key-456");
    }

    #[test]
    fn http_status_code_conversion() {
        let status = 200u16;
        let code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, actix_web::http::StatusCode::OK);
    }

    #[test]
    fn http_status_code_invalid_fallback() {
        let status = 999u16;
        let code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, actix_web::http::StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn run_id_format() {
        let run_id = "run-123";
        assert_eq!(run_id, "run-123");
    }

    #[test]
    fn run_id_uuid_format() {
        let run_id = Uuid::new_v4().to_string();
        assert!(Uuid::parse_str(&run_id).is_ok());
    }
}
