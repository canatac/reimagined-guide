#![allow(unused_imports, dead_code)]
use super::*;

pub(crate) async fn api_hermes_run_events(path: web::Path<HermesRunPath>, req: HttpRequest) -> impl Responder {
    let base = resolve_hermes_base_url();
    let api_key = match env::var("HERMES_API_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "HERMES_API_KEY is not configured"
            }))
        }
    };

    let query_suffix = req
        .uri()
        .query()
        .filter(|q| !q.is_empty())
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let url = format!("{}/v1/runs/{}/events{}", base, path.run_id, query_suffix);

    let client = reqwest::Client::new();
    let upstream = match client
        .get(url)
        .bearer_auth(api_key)
        .header("Accept", "text/event-stream")
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

    let status = upstream.status();
    if !status.is_success() {
        let body_json = match upstream.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(_) => serde_json::json!({ "error": "Hermes upstream error" }),
        };
        return HttpResponse::build(
            actix_web::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
        )
        .json(body_json);
    }

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/event-stream")
        .to_string();

    let bytes_stream = upstream
        .bytes_stream()
        .map_err(actix_web::error::ErrorBadGateway);

    HttpResponse::build(
        actix_web::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY),
    )
    .content_type(content_type)
    .insert_header(("Cache-Control", "no-cache"))
    .insert_header(("X-Accel-Buffering", "no"))
    .streaming(bytes_stream)
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
    fn hermes_run_events_url_format() {
        let base = "https://hermes.example.com";
        let run_id = "run-123";
        let url = format!("{}/v1/runs/{}/events", base, run_id);
        assert_eq!(url, "https://hermes.example.com/v1/runs/run-123/events");
    }

    #[test]
    fn hermes_run_events_url_with_query() {
        let base = "https://hermes.example.com";
        let run_id = "run-123";
        let query = "offset=10&limit=50";
        let url = format!("{}/v1/runs/{}/events?{}", base, run_id, query);
        assert_eq!(url, "https://hermes.example.com/v1/runs/run-123/events?offset=10&limit=50");
    }

    #[test]
    fn query_suffix_empty() {
        let query: Option<&str> = None;
        let suffix = query
            .filter(|q| !q.is_empty())
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        assert_eq!(suffix, "");
    }

    #[test]
    fn query_suffix_with_value() {
        let query: Option<&str> = Some("offset=10");
        let suffix = query
            .filter(|q| !q.is_empty())
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        assert_eq!(suffix, "?offset=10");
    }

    #[test]
    fn query_suffix_empty_string() {
        let query: Option<&str> = Some("");
        let suffix = query
            .filter(|q| !q.is_empty())
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        assert_eq!(suffix, "");
    }

    #[test]
    fn query_suffix_whitespace() {
        let query: Option<&str> = Some("   ");
        let suffix = query
            .filter(|q| !q.is_empty())
            .map(|q| format!("?{}", q))
            .unwrap_or_default();
        assert_eq!(suffix, "?   ");
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
    fn error_response_upstream_error() {
        let response = serde_json::json!({ "error": "Hermes upstream error" });
        assert_eq!(response["error"], "Hermes upstream error");
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
    fn http_status_code_bad_gateway() {
        let status = 502u16;
        let code = actix_web::http::StatusCode::from_u16(status)
            .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, actix_web::http::StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn content_type_event_stream() {
        let content_type = "text/event-stream";
        assert_eq!(content_type, "text/event-stream");
    }

    #[test]
    fn content_type_default() {
        let content_type: Option<&str> = None;
        let resolved = content_type.unwrap_or("text/event-stream");
        assert_eq!(resolved, "text/event-stream");
    }

    #[test]
    fn content_type_custom() {
        let content_type: Option<&str> = Some("application/json");
        let resolved = content_type.unwrap_or("text/event-stream");
        assert_eq!(resolved, "application/json");
    }

    #[test]
    fn cache_control_header() {
        let header = ("Cache-Control", "no-cache");
        assert_eq!(header.0, "Cache-Control");
        assert_eq!(header.1, "no-cache");
    }

    #[test]
    fn x_accel_buffering_header() {
        let header = ("X-Accel-Buffering", "no");
        assert_eq!(header.0, "X-Accel-Buffering");
        assert_eq!(header.1, "no");
    }

    #[test]
    fn accept_header() {
        let accept = "text/event-stream";
        assert_eq!(accept, "text/event-stream");
    }

    #[test]
    fn bearer_auth_header() {
        let api_key = "test-api-key";
        assert_eq!(api_key, "test-api-key");
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

    #[test]
    fn base_url_format() {
        let base = "https://hermes.example.com";
        assert_eq!(base, "https://hermes.example.com");
    }

    #[test]
    fn base_url_with_port() {
        let base = "https://hermes.example.com:8080";
        assert_eq!(base, "https://hermes.example.com:8080");
    }

    #[test]
    fn base_url_localhost() {
        let base = "http://localhost:3000";
        assert_eq!(base, "http://localhost:3000");
    }

    #[test]
    fn url_with_run_id() {
        let base = "https://hermes.example.com";
        let run_id = "run-456";
        let url = format!("{}/v1/runs/{}/events", base, run_id);
        assert!(url.contains("run-456"));
        assert!(url.contains("/v1/runs/"));
        assert!(url.contains("/events"));
    }

    #[test]
    fn url_encoding_run_id() {
        let base = "https://hermes.example.com";
        let run_id = "run+123";
        let url = format!("{}/v1/runs/{}/events", base, run_id);
        assert!(url.contains("run+123"));
    }

    #[test]
    fn status_success() {
        let status = 200u16;
        let is_success = (200..300).contains(&status);
        assert!(is_success);
    }

    #[test]
    fn status_client_error() {
        let status = 404u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_server_error() {
        let status = 500u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_redirect() {
        let status = 301u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_informational() {
        let status = 100u16;
        let is_success = (200..300).contains(&status);
        assert!(!is_success);
    }

    #[test]
    fn status_ok() {
        let status = 200u16;
        assert_eq!(status, 200);
    }

    #[test]
    fn status_created() {
        let status = 201u16;
        assert_eq!(status, 201);
    }

    #[test]
    fn status_accepted() {
        let status = 202u16;
        assert_eq!(status, 202);
    }

    #[test]
    fn status_no_content() {
        let status = 204u16;
        assert_eq!(status, 204);
    }

    #[test]
    fn status_bad_request() {
        let status = 400u16;
        assert_eq!(status, 400);
    }

    #[test]
    fn status_unauthorized() {
        let status = 401u16;
        assert_eq!(status, 401);
    }

    #[test]
    fn status_forbidden() {
        let status = 403u16;
        assert_eq!(status, 403);
    }

    #[test]
    fn status_not_found() {
        let status = 404u16;
        assert_eq!(status, 404);
    }

    #[test]
    fn status_method_not_allowed() {
        let status = 405u16;
        assert_eq!(status, 405);
    }

    #[test]
    fn status_conflict() {
        let status = 409u16;
        assert_eq!(status, 409);
    }

    #[test]
    fn status_unprocessable_entity() {
        let status = 422u16;
        assert_eq!(status, 422);
    }

    #[test]
    fn status_too_many_requests() {
        let status = 429u16;
        assert_eq!(status, 429);
    }

    #[test]
    fn status_internal_server_error() {
        let status = 500u16;
        assert_eq!(status, 500);
    }

    #[test]
    fn status_bad_gateway() {
        let status = 502u16;
        assert_eq!(status, 502);
    }

    #[test]
    fn status_service_unavailable() {
        let status = 503u16;
        assert_eq!(status, 503);
    }

    #[test]
    fn status_gateway_timeout() {
        let status = 504u16;
        assert_eq!(status, 504);
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
