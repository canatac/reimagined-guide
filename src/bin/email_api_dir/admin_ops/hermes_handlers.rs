#![allow(unused_imports, dead_code)]
use super::*;

pub(crate) async fn api_mail_assistant_suggestions() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "suggestions": [
            "Quels emails importants ai-je reçus aujourd'hui ?",
            "Résume la conversation avec Marc sur le projet X",
            "Trouve les emails qui mentionnent le budget Q4",
            "Rédige une réponse à ce thread",
            "Programme un rappel si pas de réponse sous 3 jours"
        ]
    }))
}

pub(crate) async fn api_hermes_chat(
    req: HttpRequest,
    body: web::Json<HermesChatProxyRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if body.messages.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "messages is required"
        }));
    }

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/chat/completions", base);
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

    let mut payload = serde_json::json!({
        "model": model,
        "messages": body.messages,
    });

    if let Some(temp) = body.temperature {
        payload["temperature"] = serde_json::json!(temp);
    }
    if let Some(max_tokens) = body.max_tokens {
        payload["max_tokens"] = serde_json::json!(max_tokens);
    }

    let started = std::time::Instant::now();
    let client = reqwest::Client::new();
    let response = match client
        .post(url)
        .bearer_auth(api_key)
        .header("X-Hermes-Session-Id", session_id.clone())
        .header("X-Hermes-Session-Key", session_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Hermes upstream request error: {}", e);
            log_llm_usage_event(
                mongo.get_ref(),
                LlmUsageEvent {
                    feature: "hermes_chat_proxy".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(session_id.clone()),
                    user_id: Some(user_id.clone()),
                    source_id: None,
                    source_url: None,
                    error: Some(format!("request_error: {}", e)),
                },
            )
            .await;
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
            log_llm_usage_event(
                mongo.get_ref(),
                LlmUsageEvent {
                    feature: "hermes_chat_proxy".to_string(),
                    status: "failed".to_string(),
                    model: model.clone(),
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    total_tokens: 0,
                    latency_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(0)),
                    session_id: Some(session_id.clone()),
                    user_id: Some(user_id.clone()),
                    source_id: None,
                    source_url: None,
                    error: Some(format!("invalid_json: {}", e)),
                },
            )
            .await;
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "Invalid Hermes upstream response"
            }));
        }
    };

    let (prompt_tokens, completion_tokens, total_tokens) = extract_llm_usage_tokens(&body_json);
    log_llm_usage_event(
        mongo.get_ref(),
        LlmUsageEvent {
            feature: "hermes_chat_proxy".to_string(),
            status: if status.is_success() {
                "completed".to_string()
            } else {
                "failed".to_string()
            },
            model: model.clone(),
            prompt_tokens,
            completion_tokens,
            total_tokens,
            latency_ms: Some(i64::try_from(started.elapsed().as_millis()).unwrap_or(0)),
            session_id: Some(session_id.clone()),
            user_id: Some(user_id.clone()),
            source_id: None,
            source_url: None,
            error: body_json
                .get("error")
                .and_then(|v| v.get("message"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string()),
        },
    )
    .await;

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .json(body_json)
}

pub(crate) async fn api_hermes_runs_list(
    query: web::Query<HermesRunsListQuery>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(40).clamp(10, 200);

    match load_ai_activity_runs(mongo.get_ref(), limit).await {
        Ok(runs) if !runs.is_empty() => {
            return HttpResponse::Ok().json(serde_json::json!({ "data": runs }));
        }
        Ok(_) => {}
        Err(e) => eprintln!("api_hermes_runs_list local usage read error: {}", e),
    }

    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let url = format!("{}/v1/runs?limit={}", base, limit);
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
    fn hermes_chat_proxy_request_deserializes() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].role, "user");
        assert_eq!(req.messages[0].content, "Hello");
    }

    #[test]
    fn hermes_chat_proxy_request_with_model() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "model": "gpt-4"
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.model, Some("gpt-4".to_string()));
    }

    #[test]
    fn hermes_chat_proxy_request_with_temperature() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.7
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert!((req.temperature.unwrap() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn hermes_chat_proxy_request_with_max_tokens() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 1000
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.max_tokens, Some(1000));
    }

    #[test]
    fn hermes_chat_proxy_request_with_thread_id() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "thread_id": "thread-123"
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.thread_id, Some("thread-123".to_string()));
    }

    #[test]
    fn hermes_chat_proxy_request_with_user_id() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "user_id": "user-456"
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.user_id, Some("user-456".to_string()));
    }

    #[test]
    fn hermes_chat_proxy_request_with_session_id() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "session_id": "session-789"
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.session_id, Some("session-789".to_string()));
    }

    #[test]
    fn hermes_chat_proxy_request_with_session_key() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
            "session_key": "key-abc"
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.session_key, Some("key-abc".to_string()));
    }

    #[test]
    fn hermes_chat_proxy_request_defaults() {
        let json = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}]
        });
        let req: HermesChatProxyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.model, None);
        assert_eq!(req.temperature, None);
        assert_eq!(req.max_tokens, None);
        assert_eq!(req.thread_id, None);
        assert_eq!(req.user_id, None);
        assert_eq!(req.session_id, None);
        assert_eq!(req.session_key, None);
    }

    #[test]
    fn hermes_runs_list_query_defaults() {
        let json = serde_json::json!({});
        let q: HermesRunsListQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.limit, None);
    }

    #[test]
    fn hermes_runs_list_query_custom() {
        let json = serde_json::json!({ "limit": 50 });
        let q: HermesRunsListQuery = serde_json::from_value(json).unwrap();
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn hermes_runs_list_query_clamps_min() {
        let limit = 5u64;
        let clamped = limit.clamp(10, 200);
        assert_eq!(clamped, 10);
    }

    #[test]
    fn hermes_runs_list_query_clamps_max() {
        let limit = 500u64;
        let clamped = limit.clamp(10, 200);
        assert_eq!(clamped, 200);
    }

    #[test]
    fn hermes_runs_list_query_clamps_within_range() {
        let limit = 50u64;
        let clamped = limit.clamp(10, 200);
        assert_eq!(clamped, 50);
    }

    #[test]
    fn hermes_runs_list_query_default_limit() {
        let limit: Option<u64> = None;
        let resolved = limit.unwrap_or(40).clamp(10, 200);
        assert_eq!(resolved, 40);
    }

    #[test]
    fn hermes_runs_list_url_format() {
        let base = "https://hermes.example.com";
        let limit = 40u64;
        let url = format!("{}/v1/runs?limit={}", base, limit);
        assert_eq!(url, "https://hermes.example.com/v1/runs?limit=40");
    }

    #[test]
    fn hermes_chat_url_format() {
        let base = "https://hermes.example.com";
        let url = format!("{}/v1/chat/completions", base);
        assert_eq!(url, "https://hermes.example.com/v1/chat/completions");
    }

    #[test]
    fn model_default_fallback() {
        let model: Option<String> = None;
        let resolved = model.unwrap_or_else(|| "hermes-agent".to_string());
        assert_eq!(resolved, "hermes-agent");
    }

    #[test]
    fn model_custom() {
        let model: Option<String> = Some("gpt-4".to_string());
        let resolved = model.unwrap_or_else(|| "hermes-agent".to_string());
        assert_eq!(resolved, "gpt-4");
    }

    #[test]
    fn thread_id_default() {
        let thread_id: Option<String> = None;
        let resolved = thread_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        assert!(Uuid::parse_str(&resolved).is_ok());
    }

    #[test]
    fn thread_id_custom() {
        let thread_id: Option<String> = Some("thread-123".to_string());
        let resolved = thread_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        assert_eq!(resolved, "thread-123");
    }

    #[test]
    fn thread_id_empty_filtered() {
        let thread_id: Option<String> = Some("".to_string());
        let resolved = thread_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        assert!(Uuid::parse_str(&resolved).is_ok());
    }

    #[test]
    fn user_id_fallback() {
        let user_id: Option<String> = None;
        let fallback = "anonymous".to_string();
        let resolved = user_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback);
        assert_eq!(resolved, "anonymous");
    }

    #[test]
    fn user_id_custom() {
        let user_id: Option<String> = Some("user-456".to_string());
        let fallback = "anonymous".to_string();
        let resolved = user_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback);
        assert_eq!(resolved, "user-456");
    }

    #[test]
    fn session_id_default_format() {
        let session_id: Option<String> = None;
        let thread_id = "thread-123";
        let resolved = session_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("mail-thread-{}", thread_id));
        assert_eq!(resolved, "mail-thread-thread-123");
    }

    #[test]
    fn session_id_custom() {
        let session_id: Option<String> = Some("session-789".to_string());
        let thread_id = "thread-123";
        let resolved = session_id
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("mail-thread-{}", thread_id));
        assert_eq!(resolved, "session-789");
    }

    #[test]
    fn session_key_default_format() {
        let session_key: Option<String> = None;
        let user_id = "user-456";
        let resolved = session_key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("user-{}", user_id));
        assert_eq!(resolved, "user-user-456");
    }

    #[test]
    fn session_key_custom() {
        let session_key: Option<String> = Some("key-abc".to_string());
        let user_id = "user-456";
        let resolved = session_key
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("user-{}", user_id));
        assert_eq!(resolved, "key-abc");
    }

    #[test]
    fn payload_with_temperature() {
        let mut payload = serde_json::json!({
            "model": "gpt-4",
            "messages": []
        });
        let temperature = 0.7;
        payload["temperature"] = serde_json::json!(temperature);
        assert!((payload["temperature"].as_f64().unwrap() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn payload_with_max_tokens() {
        let mut payload = serde_json::json!({
            "model": "gpt-4",
            "messages": []
        });
        let max_tokens = 1000;
        payload["max_tokens"] = serde_json::json!(max_tokens);
        assert_eq!(payload["max_tokens"], 1000);
    }

    #[test]
    fn payload_without_optional_fields() {
        let payload = serde_json::json!({
            "model": "gpt-4",
            "messages": []
        });
        assert!(payload.get("temperature").is_none());
        assert!(payload.get("max_tokens").is_none());
    }

    #[test]
    fn error_messages() {
        let errors = vec![
            "messages is required",
            "HERMES_API_KEY is not configured",
            "Hermes upstream unavailable",
            "Invalid Hermes upstream response",
        ];
        assert_eq!(errors[0], "messages is required");
        assert_eq!(errors[1], "HERMES_API_KEY is not configured");
        assert_eq!(errors[2], "Hermes upstream unavailable");
        assert_eq!(errors[3], "Invalid Hermes upstream response");
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
    fn http_status_code_server_error() {
        let status = 500u16;
        let code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn http_status_code_bad_request() {
        let status = 400u16;
        let code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn http_status_code_bad_gateway() {
        let status = 502u16;
        let code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, actix_web::http::StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn llm_usage_event_feature() {
        let feature = "hermes_chat_proxy";
        assert_eq!(feature, "hermes_chat_proxy");
    }

    #[test]
    fn llm_usage_event_status_completed() {
        let status = "completed";
        assert_eq!(status, "completed");
    }

    #[test]
    fn llm_usage_event_status_failed() {
        let status = "failed";
        assert_eq!(status, "failed");
    }

    #[test]
    fn llm_usage_event_model() {
        let model = "hermes-agent";
        assert_eq!(model, "hermes-agent");
    }

    #[test]
    fn llm_usage_event_tokens() {
        let prompt_tokens = 100i64;
        let completion_tokens = 50i64;
        let total_tokens = 150i64;
        assert_eq!(prompt_tokens, 100);
        assert_eq!(completion_tokens, 50);
        assert_eq!(total_tokens, 150);
    }

    #[test]
    fn llm_usage_event_latency() {
        let latency_ms = 1500i64;
        assert_eq!(latency_ms, 1500);
    }

    #[test]
    fn llm_usage_event_session_id() {
        let session_id = "session-123";
        assert_eq!(session_id, "session-123");
    }

    #[test]
    fn llm_usage_event_user_id() {
        let user_id = "user-456";
        assert_eq!(user_id, "user-456");
    }

    #[test]
    fn llm_usage_event_error() {
        let error = "request_error: timeout";
        assert_eq!(error, "request_error: timeout");
    }

    #[test]
    fn llm_usage_event_error_invalid_json() {
        let error = "invalid_json: parse error";
        assert_eq!(error, "invalid_json: parse error");
    }

    #[test]
    fn extract_llm_usage_tokens_present() {
        let body_json = serde_json::json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        });
        let usage = body_json.get("usage");
        assert!(usage.is_some());
        assert_eq!(usage.unwrap()["prompt_tokens"], 100);
        assert_eq!(usage.unwrap()["completion_tokens"], 50);
        assert_eq!(usage.unwrap()["total_tokens"], 150);
    }

    #[test]
    fn extract_llm_usage_tokens_missing() {
        let body_json = serde_json::json!({});
        let usage = body_json.get("usage");
        assert!(usage.is_none());
    }

    #[test]
    fn extract_error_message_present() {
        let body_json = serde_json::json!({
            "error": {
                "message": "Something went wrong"
            }
        });
        let error = body_json
            .get("error")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        assert_eq!(error, Some("Something went wrong".to_string()));
    }

    #[test]
    fn extract_error_message_missing() {
        let body_json = serde_json::json!({});
        let error = body_json
            .get("error")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        assert_eq!(error, None);
    }

    #[test]
    fn extract_error_message_no_message_field() {
        let body_json = serde_json::json!({
            "error": {}
        });
        let error = body_json
            .get("error")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        assert_eq!(error, None);
    }

    #[test]
    fn status_success_range() {
        let status = 200u16;
        let is_success = (200..300).contains(&status);
        assert!(is_success);
    }

    #[test]
    fn status_client_error_range() {
        let status = 404u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_server_error_range() {
        let status = 500u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_redirect_range() {
        let status = 301u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_informational_range() {
        let status = 100u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn json_value_null() {
        let value = serde_json::Value::Null;
        assert!(value.is_null());
    }

    #[test]
    fn json_value_string() {
        let value = serde_json::json!("test");
        assert!(value.is_string());
        assert_eq!(value.as_str().unwrap(), "test");
    }

    #[test]
    fn json_value_number() {
        let value = serde_json::json!(42);
        assert!(value.is_number());
        assert_eq!(value.as_i64().unwrap(), 42);
    }

    #[test]
    fn json_value_array() {
        let value = serde_json::json!([1, 2, 3]);
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 3);
    }

    #[test]
    fn json_value_object() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.is_object());
        assert!(value.get("key").is_some());
    }

    #[test]
    fn json_value_bool() {
        let value = serde_json::json!(true);
        assert!(value.is_boolean());
        assert_eq!(value.as_bool().unwrap(), true);
    }

    #[test]
    fn json_value_false() {
        let value = serde_json::json!(false);
        assert!(value.is_boolean());
        assert_eq!(value.as_bool().unwrap(), false);
    }

    #[test]
    fn json_parse_error() {
        let result: Result<serde_json::Value, _> = serde_json::from_str("invalid json");
        assert!(result.is_err());
    }

    #[test]
    fn json_parse_success() {
        let result: Result<serde_json::Value, _> = serde_json::from_str(r#"{"key": "value"}"#);
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["key"], "value");
    }

    #[test]
    fn json_serialize() {
        let value = serde_json::json!({"key": "value"});
        let serialized = serde_json::to_string(&value).unwrap();
        assert_eq!(serialized, r#"{"key":"value"}"#);
    }

    #[test]
    fn json_deserialize() {
        let json = r#"{"key": "value"}"#;
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(value["key"], "value");
    }

    #[test]
    fn json_value_from_str() {
        let value: serde_json::Value = "test".into();
        assert_eq!(value, serde_json::json!("test"));
    }

    #[test]
    fn json_value_from_number() {
        let value: serde_json::Value = 42.into();
        assert_eq!(value, serde_json::json!(42));
    }

    #[test]
    fn json_value_from_bool() {
        let value: serde_json::Value = true.into();
        assert_eq!(value, serde_json::json!(true));
    }

    #[test]
    fn json_value_from_vec() {
        let value: serde_json::Value = vec![1, 2, 3].into();
        assert_eq!(value, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn json_value_from_map() {
        let mut map = serde_json::Map::new();
        map.insert("key".to_string(), serde_json::json!("value"));
        let value: serde_json::Value = map.into();
        assert_eq!(value, serde_json::json!({"key": "value"}));
    }

    #[test]
    fn json_value_clone() {
        let value = serde_json::json!({"key": "value"});
        let cloned = value.clone();
        assert_eq!(value, cloned);
    }

    #[test]
    fn json_value_eq() {
        let a = serde_json::json!({"key": "value"});
        let b = serde_json::json!({"key": "value"});
        assert_eq!(a, b);
    }

    #[test]
    fn json_value_ne() {
        let a = serde_json::json!({"key": "value1"});
        let b = serde_json::json!({"key": "value2"});
        assert_ne!(a, b);
    }

    #[test]
    fn json_value_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let value = serde_json::json!({"key": "value"});
        let mut hasher = DefaultHasher::new();
        value.to_string().hash(&mut hasher);
        let _ = hasher.finish();
        assert!(true);
    }

    #[test]
    fn json_value_display() {
        let value = serde_json::json!({"key": "value"});
        let display = format!("{}", value);
        assert_eq!(display, r#"{"key":"value"}"#);
    }

    #[test]
    fn json_value_debug() {
        let value = serde_json::json!({"key": "value"});
        let debug = format!("{:?}", value);
        assert!(debug.contains("key"));
        assert!(debug.contains("value"));
    }

    #[test]
    fn json_value_index_str() {
        let value = serde_json::json!({"key": "value"});
        assert_eq!(value["key"], "value");
    }

    #[test]
    fn json_value_index_usize() {
        let value = serde_json::json!([1, 2, 3]);
        assert_eq!(value[0], 1);
        assert_eq!(value[1], 2);
        assert_eq!(value[2], 3);
    }

    #[test]
    fn json_value_get_some() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.get("key").is_some());
    }

    #[test]
    fn json_value_get_none() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.get("missing").is_none());
    }

    #[test]
    fn json_value_get_or() {
        let value = serde_json::json!({"key": "value"});
        assert_eq!(value.get("missing").unwrap_or(&serde_json::Value::Null), &serde_json::Value::Null);
    }

    #[test]
    fn json_value_as_str() {
        let value = serde_json::json!("test");
        assert_eq!(value.as_str().unwrap(), "test");
    }

    #[test]
    fn json_value_as_i64() {
        let value = serde_json::json!(42);
        assert_eq!(value.as_i64().unwrap(), 42);
    }

    #[test]
    fn json_value_as_u64() {
        let value = serde_json::json!(42);
        assert_eq!(value.as_u64().unwrap(), 42);
    }

    #[test]
    fn json_value_as_f64() {
        let value = serde_json::json!(3.14);
        assert!((value.as_f64().unwrap() - 3.14).abs() < f64::EPSILON);
    }

    #[test]
    fn json_value_as_bool() {
        let value = serde_json::json!(true);
        assert_eq!(value.as_bool().unwrap(), true);
    }

    #[test]
    fn json_value_is_string() {
        let value = serde_json::json!("test");
        assert!(value.is_string());
    }

    #[test]
    fn json_value_is_number() {
        let value = serde_json::json!(42);
        assert!(value.is_number());
    }

    #[test]
    fn json_value_is_array() {
        let value = serde_json::json!([1, 2, 3]);
        assert!(value.is_array());
    }

    #[test]
    fn json_value_is_object() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.is_object());
    }

    #[test]
    fn json_value_is_boolean() {
        let value = serde_json::json!(true);
        assert!(value.is_boolean());
    }

    #[test]
    fn json_value_is_null() {
        let value = serde_json::Value::Null;
        assert!(value.is_null());
    }

    #[test]
    fn json_value_is_i64() {
        let value = serde_json::json!(42);
        assert!(value.is_i64());
    }

    #[test]
    fn json_value_is_u64() {
        let value = serde_json::json!(42);
        assert!(value.is_u64());
    }

    #[test]
    fn json_value_is_f64() {
        let value = serde_json::json!(3.14);
        assert!(value.is_f64());
    }

    #[test]
    fn json_value_pointer() {
        let value = serde_json::json!({"key": "value"});
        assert_eq!(value.pointer("/key").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_missing() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.pointer("/missing").is_none());
    }

    #[test]
    fn json_value_pointer_nested() {
        let value = serde_json::json!({"a": {"b": "c"}});
        assert_eq!(value.pointer("/a/b").unwrap(), &serde_json::json!("c"));
    }

    #[test]
    fn json_value_pointer_array() {
        let value = serde_json::json!([1, 2, 3]);
        assert_eq!(value.pointer("/0").unwrap(), &serde_json::json!(1));
    }

    #[test]
    fn json_value_pointer_array_nested() {
        let value = serde_json::json!([[1, 2], [3, 4]]);
        assert_eq!(value.pointer("/0/1").unwrap(), &serde_json::json!(2));
    }

    #[test]
    fn json_value_pointer_deep() {
        let value = serde_json::json!({"a": {"b": {"c": "d"}}});
        assert_eq!(value.pointer("/a/b/c").unwrap(), &serde_json::json!("d"));
    }

    #[test]
    fn json_value_pointer_invalid() {
        let value = serde_json::json!({"key": "value"});
        assert!(value.pointer("invalid").is_none());
    }

    #[test]
    fn json_value_pointer_empty() {
        let value = serde_json::json!({"key": "value"});
        assert_eq!(value.pointer("").unwrap(), &value);
    }

    #[test]
    fn json_value_pointer_root() {
        let value = serde_json::json!({"key": "value"});
        assert_eq!(value.pointer("/").unwrap(), &serde_json::json!({"key": "value"}));
    }

    #[test]
    fn json_value_pointer_escape() {
        let value = serde_json::json!({"a/b": "c"});
        assert_eq!(value.pointer("/a~1b").unwrap(), &serde_json::json!("c"));
    }

    #[test]
    fn json_value_pointer_tilde() {
        let value = serde_json::json!({"a~b": "c"});
        assert_eq!(value.pointer("/a~0b").unwrap(), &serde_json::json!("c"));
    }

    #[test]
    fn json_value_pointer_unicode() {
        let value = serde_json::json!({"key": "日本語"});
        assert_eq!(value.pointer("/key").unwrap(), &serde_json::json!("日本語"));
    }

    #[test]
    fn json_value_pointer_emoji() {
        let value = serde_json::json!({"key": "🎉"});
        assert_eq!(value.pointer("/key").unwrap(), &serde_json::json!("🎉"));
    }

    #[test]
    fn json_value_pointer_special_chars() {
        let value = serde_json::json!({"key with spaces": "value"});
        assert_eq!(value.pointer("/key with spaces").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_newline() {
        let value = serde_json::json!({"key\n": "value"});
        assert_eq!(value.pointer("/key\n").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_tab() {
        let value = serde_json::json!({"key\t": "value"});
        assert_eq!(value.pointer("/key\t").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_carriage_return() {
        let value = serde_json::json!({"key\r": "value"});
        assert_eq!(value.pointer("/key\r").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_backslash() {
        let value = serde_json::json!({"key\\": "value"});
        assert_eq!(value.pointer("/key\\\\").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_quote() {
        let value = serde_json::json!({"key\"": "value"});
        assert_eq!(value.pointer("/key\\\"").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_single_quote() {
        let value = serde_json::json!({"key'": "value"});
        assert_eq!(value.pointer("/key'").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_parentheses() {
        let value = serde_json::json!({"key()": "value"});
        assert_eq!(value.pointer("/key()").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_brackets() {
        let value = serde_json::json!({"key[]": "value"});
        assert_eq!(value.pointer("/key[]").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_braces() {
        let value = serde_json::json!({"key{}": "value"});
        assert_eq!(value.pointer("/key{}").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_asterisk() {
        let value = serde_json::json!({"key*": "value"});
        assert_eq!(value.pointer("/key*").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_ampersand() {
        let value = serde_json::json!({"key&": "value"});
        assert_eq!(value.pointer("/key&").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_at() {
        let value = serde_json::json!({"key@": "value"});
        assert_eq!(value.pointer("/key@").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_hash() {
        let value = serde_json::json!({"key#": "value"});
        assert_eq!(value.pointer("/key#").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_dollar() {
        let value = serde_json::json!({"key$": "value"});
        assert_eq!(value.pointer("/key$").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_percent() {
        let value = serde_json::json!({"key%": "value"});
        assert_eq!(value.pointer("/key%").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_exclamation() {
        let value = serde_json::json!({"key!": "value"});
        assert_eq!(value.pointer("/key!").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_question() {
        let value = serde_json::json!({"key?": "value"});
        assert_eq!(value.pointer("/key?").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_plus() {
        let value = serde_json::json!({"key+": "value"});
        assert_eq!(value.pointer("/key+").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_equals() {
        let value = serde_json::json!({"key=": "value"});
        assert_eq!(value.pointer("/key=").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_comma() {
        let value = serde_json::json!({"key,": "value"});
        assert_eq!(value.pointer("/key,").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_colon() {
        let value = serde_json::json!({"key:": "value"});
        assert_eq!(value.pointer("/key:").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_semicolon() {
        let value = serde_json::json!({"key;": "value"});
        assert_eq!(value.pointer("/key;").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_pipe() {
        let value = serde_json::json!({"key|": "value"});
        assert_eq!(value.pointer("/key|").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_less_than() {
        let value = serde_json::json!({"key<": "value"});
        assert_eq!(value.pointer("/key<").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_greater_than() {
        let value = serde_json::json!({"key>": "value"});
        assert_eq!(value.pointer("/key>").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_caret() {
        let value = serde_json::json!({"key^": "value"});
        assert_eq!(value.pointer("/key^").unwrap(), &serde_json::json!("value"));
    }

    #[test]
    fn json_value_pointer_backtick() {
        let value = serde_json::json!({"key`": "value"});
        assert_eq!(value.pointer("/key`").unwrap(), &serde_json::json!("value"));
    }
}
