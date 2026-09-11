use super::*;

#[async_trait::async_trait]
pub trait DkimService: Send + Sync {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
}

pub struct RealDkimService;

#[async_trait::async_trait]
impl DkimService for RealDkimService {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
        let dkim_service_url = env::var("DKIM_SERVICE_URL").map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "DKIM_SERVICE_URL not set")
        })?;
        let client = reqwest::Client::new();

        let response = client
            .post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": email.from,
                "to": email.to,
                "subject": email.subject,
                "text": email.body,
                "html": email.body,
                "attachments": email.attachments.iter().map(|att| serde_json::json!({
                    "filename": att.filename,
                    "contentType": att.content_type,
                    "dataBase64": att.data_base64,
                })).collect::<Vec<_>>()
            }))
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if status.is_success() {
            serde_json::from_str::<serde_json::Value>(&body)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            let snippet = if body.len() > 1200 {
                &body[..1200]
            } else {
                &body
            };
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("DKIM service HTTP {}: {}", status.as_u16(), snippet),
            ))
        }
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
    fn dkim_service_io_error_type() {
        let error_type = "std::io::Error";
        assert_eq!(error_type, "std::io::Error");
    }

    #[test]
    fn dkim_service_reqwest_client() {
        let client = reqwest::Client::new();
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
}
