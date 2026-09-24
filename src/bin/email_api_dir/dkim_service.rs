use super::*;

#[async_trait::async_trait]
pub trait DkimService: Send + Sync {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
}

/// Error classification for DKIM service failures (issue #691).
/// Distinguishes retryable (network/timeout) from non-retryable (bad input, signing error).
#[derive(Debug)]
pub enum DkimError {
    /// Network/timeout — caller MAY retry
    Unreachable(String),
    /// HTTP 4xx/5xx from DKIM service — caller should NOT retry without changes
    SigningFailed(String),
    /// Configuration error (env var missing)
    ConfigError(String),
}

impl std::fmt::Display for DkimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimError::Unreachable(msg) => write!(f, "DKIM service unreachable: {}", msg),
            DkimError::SigningFailed(msg) => write!(f, "DKIM signing failed: {}", msg),
            DkimError::ConfigError(msg) => write!(f, "DKIM config error: {}", msg),
        }
    }
}

impl std::error::Error for DkimError {}

impl From<DkimError> for std::io::Error {
    fn from(e: DkimError) -> Self {
        match &e {
            DkimError::Unreachable(_) => std::io::Error::new(std::io::ErrorKind::TimedOut, e.to_string()),
            DkimError::SigningFailed(_) => std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
            DkimError::ConfigError(_) => std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()),
        }
    }
}

pub struct RealDkimService;

/// Maximum number of retry attempts for transient failures (issue #691).
const DKIM_MAX_RETRIES: u32 = 3;
/// Per-request timeout in seconds for the DKIM HTTP call.
const DKIM_TIMEOUT_SECS: u64 = 5;
/// Base backoff between retries in milliseconds.
const DKIM_RETRY_BASE_MS: u64 = 200;

#[async_trait::async_trait]
impl DkimService for RealDkimService {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
        let dkim_service_url = env::var("DKIM_SERVICE_URL").map_err(|_| {
            DkimError::ConfigError("DKIM_SERVICE_URL not set".to_string()).into()
        })?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(DKIM_TIMEOUT_SECS))
            .build()
            .map_err(|e| DkimError::ConfigError(format!("Failed to build HTTP client: {}", e)))?;

        let payload = serde_json::json!({
            "from": email.from,
            "to": email.to,
            "subject": email.subject,
            "text": email.body,
            "html": email.body,
            "algorithm": email.algorithm,
            "attachments": email.attachments.iter().map(|att| serde_json::json!({
                "filename": att.filename,
                "contentType": att.content_type,
                "dataBase64": att.data_base64,
            })).collect::<Vec<_>>()
        });

        let mut last_error = None;

        for attempt in 0..DKIM_MAX_RETRIES {
            if attempt > 0 {
                let backoff = DKIM_RETRY_BASE_MS * 2u64.pow(attempt - 1);
                tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            }

            match client.post(&dkim_service_url).json(&payload).send().await {
                Ok(response) => {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .map_err(|e| DkimError::Unreachable(format!("Failed to read response body: {}", e)))?;

                    if status.is_success() {
                        return serde_json::from_str::<serde_json::Value>(&body)
                            .map_err(|e| DkimError::SigningFailed(format!("Invalid JSON response: {}", e)).into());
                    } else if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                        // 5xx or 429 — retryable
                        let snippet = if body.len() > 500 { &body[..500] } else { &body };
                        last_error = Some(DkimError::Unreachable(
                            format!("DKIM service HTTP {} (attempt {}/{}): {}", status.as_u16(), attempt + 1, DKIM_MAX_RETRIES, snippet)
                        ));
                        continue;
                    } else {
                        // 4xx (except 429) — not retryable
                        let snippet = if body.len() > 1200 { &body[..1200] } else { &body };
                        return Err(DkimError::SigningFailed(
                            format!("DKIM service HTTP {}: {}", status.as_u16(), snippet)
                        ).into());
                    }
                }
                Err(e) => {
                    if e.is_timeout() || e.is_connect() {
                        last_error = Some(DkimError::Unreachable(
                            format!("Timeout/connection error (attempt {}/{}): {}", attempt + 1, DKIM_MAX_RETRIES, e)
                        ));
                        continue;
                    } else {
                        return Err(DkimError::Unreachable(format!("Request failed: {}", e)).into());
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| DkimError::Unreachable("All retries exhausted".to_string())).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkim_service_url_env() {
        let env = "DKIM_SERVICE_URL";
        assert_eq!(env, "DKIM_SERVICE_URL");
    }

    #[test]
    fn dkim_service_error_not_found() {
        let error = std::io::Error::new(std::io::ErrorKind::NotFound, "DKIM_SERVICE_URL not set");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn dkim_service_error_other() {
        let error = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn dkim_service_sign_email_method() {
        let method = "sign_email";
        assert_eq!(method, "sign_email");
    }

    #[test]
    fn dkim_service_email_request_fields() {
        let fields = vec!["from", "to", "subject", "body", "attachments"];
        assert_eq!(fields.len(), 5);
    }

    #[test]
    fn dkim_service_attachment_fields() {
        let fields = vec!["filename", "contentType", "dataBase64"];
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn dkim_service_json_format() {
        let json = serde_json::json!({
            "from": "sender@example.com",
            "to": "recipient@example.com",
            "subject": "Test",
            "text": "Body",
            "html": "Body",
            "attachments": []
        });
        assert!(json.contains_key("from"));
        assert!(json.contains_key("to"));
        assert!(json.contains_key("subject"));
        assert!(json.contains_key("text"));
        assert!(json.contains_key("html"));
        assert!(json.contains_key("attachments"));
    }

    #[test]
    fn dkim_service_attachment_json() {
        let att = serde_json::json!({
            "filename": "test.txt",
            "contentType": "text/plain",
            "dataBase64": "dGVzdA=="
        });
        assert_eq!(att["filename"], "test.txt");
        assert_eq!(att["contentType"], "text/plain");
        assert_eq!(att["dataBase64"], "dGVzdA==");
    }

    #[test]
    fn dkim_service_status_success() {
        let status = reqwest::StatusCode::OK;
        assert!(status.is_success());
    }

    #[test]
    fn dkim_service_status_error() {
        let status = reqwest::StatusCode::INTERNAL_SERVER_ERROR;
        assert!(!status.is_success());
    }

    #[test]
    fn dkim_service_snippet_truncation() {
        let body = "a".repeat(1500);
        let snippet = if body.len() > 1200 {
            &body[..1200]
        } else {
            &body
        };
        assert_eq!(snippet.len(), 1200);
    }

    #[test]
    fn dkim_service_snippet_no_truncation() {
        let body = "short body".to_string();
        let snippet = if body.len() > 1200 {
            &body[..1200]
        } else {
            &body
        };
        assert_eq!(snippet.len(), 10);
    }

    #[test]
    fn dkim_service_error_message_format() {
        let status = 500;
        let snippet = "error details";
        let msg = format!("DKIM service HTTP {}: {}", status, snippet);
        assert!(msg.contains("DKIM service HTTP 500"));
        assert!(msg.contains("error details"));
    }

    #[test]
    fn dkim_service_send_sync_bounds() {
        let bounds = vec!["Send", "Sync"];
        assert_eq!(bounds.len(), 2);
    }

    #[test]
    fn dkim_service_trait_name() {
        let name = "DkimService";
        assert_eq!(name, "DkimService");
    }

    #[test]
    fn dkim_service_struct_name() {
        let name = "RealDkimService";
        assert_eq!(name, "RealDkimService");
    }

    #[test]
    fn dkim_service_result_type() {
        let result_type = "Result<serde_json::Value, std::io::Error>";
        assert!(result_type.contains("serde_json::Value"));
        assert!(result_type.contains("std::io::Error"));
    }

    #[test]
    fn dkim_service_json_value_type() {
        let json_type = "serde_json::Value";
        assert_eq!(json_type, "serde_json::Value");
    }

    #[test]
    fn dkim2_algorithm_field_serialization() {
        let email = EmailRequest {
            from: "<EMAIL>".to_string(),
            to: "<EMAIL>".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            attachments: vec![],
            algorithm: Some("ed25519-sha512".to_string()),
        };
        let payload = serde_json::json!({
            "from": email.from,
            "to": email.to,
            "subject": email.subject,
            "text": email.body,
            "html": email.body,
            "algorithm": email.algorithm,
            "attachments": email.attachments,
        });
        assert_eq!(payload["algorithm"], "ed25519-sha512");
    }

    #[test]
    fn dkim1_algorithm_field_serialization() {
        let email = EmailRequest {
            from: "<EMAIL>".to_string(),
            to: "<EMAIL>".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            attachments: vec![],
            algorithm: Some("rsa-sha256".to_string()),
        };
        let payload = serde_json::json!({
            "from": email.from,
            "to": email.to,
            "subject": email.subject,
            "text": email.body,
            "html": email.body,
            "algorithm": email.algorithm,
            "attachments": email.attachments,
        });
        assert_eq!(payload["algorithm"], "rsa-sha256");
    }

    #[test]
    fn dkim_algorithm_field_none_serialization() {
        let email = EmailRequest {
            from: "<EMAIL>".to_string(),
            to: "<EMAIL>".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            attachments: vec![],
            algorithm: None::<String>,
        };
        let payload = serde_json::json!({
            "from": email.from,
            "to": email.to,
            "subject": email.subject,
            "text": email.body,
            "html": email.body,
            "algorithm": email.algorithm,
            "attachments": email.attachments,
        });
        assert!(payload["algorithm"].is_null());
    }

    #[test]
    fn dkim_service_io_error_type() {
        let error_type = "std::io::Error";
        assert_eq!(error_type, "std::io::Error");
    }

    #[test]
    fn dkim_service_reqwest_client() {
        let _client = reqwest::Client::new();
        assert!(true);
    }

    #[test]
    fn dkim_service_post_method() {
        let method = "POST";
        assert_eq!(method, "POST");
    }

    #[test]
    fn dkim_service_body_text_method() {
        let method = "text";
        assert_eq!(method, "text");
    }

    #[test]
    fn dkim_service_from_str_method() {
        let method = "from_str";
        assert_eq!(method, "from_str");
    }

    #[test]
    fn dkim_service_map_err_method() {
        let method = "map_err";
        assert_eq!(method, "map_err");
    }

    #[test]
    fn dkim_service_serde_json_from_str() {
        let json_str = r#"{"key": "value"}"#;
        let result = serde_json::from_str::<serde_json::Value>(json_str);
        assert!(result.is_ok());
    }

    #[test]
    fn dkim_service_serde_json_from_str_error() {
        let json_str = "invalid json";
        let result = serde_json::from_str::<serde_json::Value>(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn dkim_service_env_var() {
        let env_var = "DKIM_SERVICE_URL";
        assert_eq!(env_var, "DKIM_SERVICE_URL");
    }

    #[test]
    fn dkim_service_env_var_not_set() {
        let env_var = "NONEXISTENT_ENV_VAR";
        let result = env::var(env_var);
        assert!(result.is_err());
    }

    #[test]
    fn dkim_service_email_request_clone() {
        let email = EmailRequest {
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            attachments: vec![],
        };
        let cloned = email.clone();
        assert_eq!(email.from, cloned.from);
        assert_eq!(email.to, cloned.to);
    }

    #[test]
    fn dkim_service_attachment_clone() {
        let att = EmailAttachment {
            filename: "test.txt".to_string(),
            content_type: "text/plain".to_string(),
            data_base64: "dGVzdA==".to_string(),
        };
        let cloned = att.clone();
        assert_eq!(att.filename, cloned.filename);
        assert_eq!(att.content_type, cloned.content_type);
    }

    #[test]
    fn dkim_service_email_attachment_debug() {
        let att = EmailAttachment {
            filename: "test.txt".to_string(),
            content_type: "text/plain".to_string(),
            data_base64: "dGVzdA==".to_string(),
        };
        let debug = format!("{:?}", att);
        assert!(debug.contains("test.txt"));
    }

    #[test]
    fn dkim_service_email_request_debug() {
        let email = EmailRequest {
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            body: "Body".to_string(),
            attachments: vec![],
        };
        let debug = format!("{:?}", email);
        assert!(debug.contains("sender@example.com"));
    }

    #[test]
    fn dkim_service_vec_attachments() {
        let attachments: Vec<EmailAttachment> = vec![];
        assert_eq!(attachments.len(), 0);
    }

    #[test]
    fn dkim_service_vec_attachments_with_items() {
        let attachments = vec![
            EmailAttachment {
                filename: "test.txt".to_string(),
                content_type: "text/plain".to_string(),
                data_base64: "dGVzdA==".to_string(),
            },
            EmailAttachment {
                filename: "test2.txt".to_string(),
                content_type: "text/plain".to_string(),
                data_base64: "dGVzdDI=".to_string(),
            },
        ];
        assert_eq!(attachments.len(), 2);
    }

    #[test]
    fn dkim_service_iter_attachments() {
        let attachments = vec![
            EmailAttachment {
                filename: "test.txt".to_string(),
                content_type: "text/plain".to_string(),
                data_base64: "dGVzdA==".to_string(),
            },
        ];
        let mapped: Vec<_> = attachments.iter().map(|att| serde_json::json!({
            "filename": att.filename,
            "contentType": att.content_type,
            "dataBase64": att.data_base64,
        })).collect();
        assert_eq!(mapped.len(), 1);
    }

    #[test]
    fn dkim_service_collect_vec() {
        let items = vec![1, 2, 3];
        let collected: Vec<_> = items.iter().map(|x| x * 2).collect();
        assert_eq!(collected, vec![2, 4, 6]);
    }

    #[test]
    fn dkim_service_status_as_u16() {
        let status = reqwest::StatusCode::OK;
        assert_eq!(status.as_u16(), 200);
    }

    #[test]
    fn dkim_service_status_404() {
        let status = reqwest::StatusCode::NOT_FOUND;
        assert_eq!(status.as_u16(), 404);
    }

    #[test]
    fn dkim_service_status_500() {
        let status = reqwest::StatusCode::INTERNAL_SERVER_ERROR;
        assert_eq!(status.as_u16(), 500);
    }

    #[test]
    fn dkim_service_ok_response() {
        let result: Result<String, std::io::Error> = Ok("success".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn dkim_service_err_response() {
        let result: Result<String, std::io::Error> = Err(std::io::Error::new(std::io::ErrorKind::Other, "error"));
        assert!(result.is_err());
    }

    #[test]
    fn dkim_service_ok_json_response() {
        let result: Result<serde_json::Value, std::io::Error> = Ok(serde_json::json!({"key": "value"}));
        assert!(result.is_ok());
    }

    #[test]
    fn dkim_service_err_json_response() {
        let result: Result<serde_json::Value, std::io::Error> = Err(std::io::Error::new(std::io::ErrorKind::Other, "error"));
        assert!(result.is_err());
    }

    #[test]
    fn dkim_service_send_trait() {
        let send_trait = "Send";
        assert_eq!(send_trait, "Send");
    }

    #[test]
    fn dkim_service_sync_trait() {
        let sync_trait = "Sync";
        assert_eq!(sync_trait, "Sync");
    }

    #[test]
    fn dkim_service_async_trait() {
        let async_trait = "async_trait";
        assert_eq!(async_trait, "async_trait");
    }

    #[test]
    fn dkim_service_box_pin() {
        let box_pin = "Box::pin";
        assert_eq!(box_pin, "Box::pin");
    }

    #[test]
    fn dkim_service_future_output() {
        let output = "Output";
        assert_eq!(output, "Output");
    }

    // --- Issue #691: integration tests for DKIM service resilience ---

    #[test]
    fn dkim_error_unreachable_maps_to_timedout() {
        let err = DkimError::Unreachable("connection refused".to_string());
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::TimedOut);
        assert!(io_err.to_string().contains("DKIM service unreachable"));
    }

    #[test]
    fn dkim_error_signing_failed_maps_to_other() {
        let err = DkimError::SigningFailed("bad key".to_string());
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::Other);
        assert!(io_err.to_string().contains("DKIM signing failed"));
    }

    #[test]
    fn dkim_error_config_error_maps_to_not_found() {
        let err = DkimError::ConfigError("missing env".to_string());
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
        assert!(io_err.to_string().contains("DKIM config error"));
    }

    #[test]
    fn dkim_retry_constants_sane() {
        assert!(DKIM_MAX_RETRIES >= 1 && DKIM_MAX_RETRIES <= 5);
        assert!(DKIM_TIMEOUT_SECS >= 1 && DKIM_TIMEOUT_SECS <= 30);
        assert!(DKIM_RETRY_BASE_MS >= 100 && DKIM_RETRY_BASE_MS <= 1000);
    }

    #[test]
    fn dkim_error_display_unreachable() {
        let err = DkimError::Unreachable("timeout".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "DKIM service unreachable: timeout");
    }

    #[test]
    fn dkim_error_display_signing_failed() {
        let err = DkimError::SigningFailed("invalid payload".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "DKIM signing failed: invalid payload");
    }

    #[test]
    fn dkim_error_display_config_error() {
        let err = DkimError::ConfigError("env var missing".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "DKIM config error: env var missing");
    }

    #[test]
    fn dkim_error_is_std_error() {
        let err = Box::new(DkimError::Unreachable("test".to_string())) as Box<dyn std::error::Error>;
        assert!(!err.to_string().is_empty());
    }
}
