use super::super::super::*;
use actix_web::{test, web, App};

#[actix_web::test]
async fn test_api_hermes_chat_requires_messages() {
    let app = test::init_service(
        App::new().route("/api/hermes/chat", web::post().to(api_hermes_chat)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/hermes/chat")
        .set_json(serde_json::json!({ "messages": [] }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
}

#[test]
fn test_hermes_chat_request_accepts_explicit_session_overrides() {
    let parsed: HermesChatProxyRequest = serde_json::from_value(serde_json::json!({
        "messages": [{"role":"user","content":"hello"}],
        "threadId": "thread-123",
        "userId": "admin",
        "sessionId": "mail-thread-explicit",
        "sessionKey": "user-explicit",
        "maxTokens": 1200
    }))
    .expect("HermesChatProxyRequest should deserialize");

    assert_eq!(parsed.thread_id.as_deref(), Some("thread-123"));
    assert_eq!(parsed.user_id.as_deref(), Some("admin"));
    assert_eq!(parsed.session_id.as_deref(), Some("mail-thread-explicit"));
    assert_eq!(parsed.session_key.as_deref(), Some("user-explicit"));
    assert_eq!(parsed.max_tokens, Some(1200));
}

#[actix_web::test]
async fn test_api_hermes_runs_requires_input() {
    let app = test::init_service(
        App::new().route("/api/hermes/runs", web::post().to(api_hermes_runs)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/hermes/runs")
        .set_json(serde_json::json!({}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
}

#[test]
fn test_hermes_runs_request_accepts_explicit_session_overrides() {
    let parsed: HermesRunsProxyRequest = serde_json::from_value(serde_json::json!({
        "input": [{"role":"user","content":"hello"}],
        "threadId": "thread-123",
        "userId": "admin",
        "sessionId": "mail-thread-explicit",
        "sessionKey": "user-explicit",
        "model": "hermes-agent"
    }))
    .expect("HermesRunsProxyRequest should deserialize");

    assert!(parsed.input.is_some());
    assert_eq!(parsed.thread_id.as_deref(), Some("thread-123"));
    assert_eq!(parsed.user_id.as_deref(), Some("admin"));
    assert_eq!(parsed.session_id.as_deref(), Some("mail-thread-explicit"));
    assert_eq!(parsed.session_key.as_deref(), Some("user-explicit"));
    assert_eq!(parsed.model.as_deref(), Some("hermes-agent"));
}

#[test]
fn test_normalize_hermes_base_url_strips_v1_and_slashes() {
    assert_eq!(
        normalize_hermes_base_url("http://172.16.12.2:8642/v1/"),
        "http://172.16.12.2:8642"
    );
    assert_eq!(
        normalize_hermes_base_url("http://172.16.12.2:8642/v1"),
        "http://172.16.12.2:8642"
    );
    assert_eq!(
        normalize_hermes_base_url("http://172.16.12.2:8642"),
        "http://172.16.12.2:8642"
    );
}
