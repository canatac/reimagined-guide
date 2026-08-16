#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use dotenv::dotenv;
    use mockall::mock;
    use mockall::predicate::eq;

    mock! {
        pub DkimService {
            pub async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
        }
    }

    #[async_trait::async_trait]
    impl DkimService for MockDkimService {
        async fn sign_email(
            &self,
            email: &EmailRequest,
        ) -> Result<serde_json::Value, std::io::Error> {
            self.sign_email(email).await
        }
    }

    #[actix_web::test]
    async fn test_send_email() {
        dotenv::from_filename(".env.test").ok();

        let mut mock_dkim_service = MockDkimService::new();
        mock_dkim_service
            .expect_sign_email()
            .with(eq(EmailRequest {
                from: "sender@example.com".to_string(),
                to: "recipient@example.com".to_string(),
                subject: "Test Email".to_string(),
                body: "This is a test email.".to_string(),
            }))
            .times(1)
            .returning(|_| Ok(serde_json::json!({"status": "success", "messageId": "12345"})));

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(
                    Box::new(mock_dkim_service) as Box<dyn DkimService>
                ))
                .route("/send-email", web::post().to(send_email_handler)),
        )
        .await;

        let email_request = EmailRequest {
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test Email".to_string(),
            body: "This is a test email.".to_string(),
        };
        println!("Sending test request to /send-email");

        let req = test::TestRequest::post()
            .uri("/send-email")
            .set_json(&email_request)
            .to_request();
        let resp = test::call_service(&app, req).await;
        println!("Response status: {:?}", resp.status());
        assert!(resp.status().is_success());
    }

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

    // ─── Sprint 1: Integration tests on critical flows ────────────────────────
    //
    // These tests exercise the HTTP handler shape (status codes, response
    // structure) without a live MongoDB or SMTP server. They verify:
    //  - Correct 4xx on bad / missing input
    //  - Response JSON shape on valid input (where the handler does not
    //    require a DB connection at the validation stage)
    //
    // Flow 1: POST /api/auth/login — rejects empty password
    #[actix_web::test]
    async fn test_auth_login_rejects_empty_password() {
        let app = test::init_service(
            App::new()
                .app_data(
                    web::JsonConfig::default()
                        .error_handler(|err, req| {
                            let resp = actix_web::HttpResponse::BadRequest()
                                .json(serde_json::json!({ "code": "INVALID_JSON", "message": err.to_string() }));
                            actix_web::error::InternalError::from_response(err, resp).into()
                        })
                )
                .route("/api/auth/login", web::post().to(auth_login)),
        )
        .await;

        // Missing password field → JSON parse error → 400
        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(serde_json::json!({ "email": "test@misfits.ai" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    // Flow 1b: POST /api/auth/login — correct shape → 200 or 401 (never 500)
    #[actix_web::test]
    async fn test_auth_login_valid_shape_returns_200_or_401() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return, // Skip if no test DB
        };
        let logic = web::Data::new(Arc::new(Logic::new(mongo.clone())));
        let mongo_data = web::Data::new(mongo);
        let bus_data = web::Data::new(EventBus::new());

        let app = test::init_service(
            App::new()
                .app_data(logic)
                .app_data(mongo_data)
                .app_data(bus_data)
                .route("/api/auth/login", web::post().to(auth_login)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(serde_json::json!({
                "email": "nonexistent@misfits.ai",
                "password": "wrongpassword"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 401,
            "Expected 200 or 401, got {}",
            status
        );
    }

    // Flow 2: POST /api/auth/2fa/verify — rejects missing fields
    #[actix_web::test]
    async fn test_2fa_verify_rejects_missing_fields() {
        let app = test::init_service(
            App::new()
                .app_data(
                    web::JsonConfig::default().error_handler(|err, _req| {
                        let resp = actix_web::HttpResponse::BadRequest()
                            .json(serde_json::json!({ "verified": false, "error": err.to_string() }));
                        actix_web::error::InternalError::from_response(err, resp).into()
                    })
                )
                .route("/api/auth/2fa/verify", web::post().to(api_2fa_verify)),
        )
        .await;

        // Missing code → 400
        let req = test::TestRequest::post()
            .uri("/api/auth/2fa/verify")
            .set_json(serde_json::json!({ "email": "test@misfits.ai", "method": "email" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    // Flow 3: GET /api/emails — rejects request with no user identity (empty folder)
    #[actix_web::test]
    async fn test_api_emails_empty_folder_returns_empty_list() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let logic = web::Data::new(Arc::new(Logic::new(mongo.clone())));

        let app = test::init_service(
            App::new()
                .app_data(logic)
                .route("/api/emails", web::get().to(api_emails)),
        )
        .await;

        // No x-user-id header → resolve_user_id returns empty string → returns empty list
        let req = test::TestRequest::get()
            .uri("/api/emails?folder=inbox&page=1&page_size=5")
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Handler always returns 200 (empty list for unknown user)
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["emails"].is_array(), "Expected emails array");
    }

    // Flow 4: POST /api/send — rejects missing recipients
    #[actix_web::test]
    async fn test_api_send_rejects_empty_recipients() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let logic = web::Data::new(Arc::new(Logic::new(mongo.clone())));
        let mongo_data = web::Data::new(mongo);
        let bus_data = web::Data::new(EventBus::new());

        let app = test::init_service(
            App::new()
                .app_data(logic)
                .app_data(mongo_data)
                .app_data(bus_data)
                .route("/api/send", web::post().to(api_send)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/send")
            .set_json(serde_json::json!({
                "to": [],
                "subject": "Test",
                "body": "Hello"
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["sent"], false);
        assert!(body["message"].is_string());
    }

    // Flow 5: GET /api/monitoring/summary — returns required fields
    #[actix_web::test]
    async fn test_monitoring_summary_shape() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let mongo_data = web::Data::new(mongo);

        let app = test::init_service(
            App::new()
                .app_data(mongo_data)
                .route("/api/monitoring/summary", web::get().to(api_monitoring_summary)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/monitoring/summary?window=1h")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        // Shape assertions: all required fields present
        assert!(body["total"].is_number(), "Expected total field");
        assert!(body["deliveryRate"].is_number(), "Expected deliveryRate field");
        assert!(body["bounceRate"].is_number(), "Expected bounceRate field");
        assert!(body["byStatus"].is_object(), "Expected byStatus object");
    }

    // Flow 6: GET /api/admin/users — returns 200 with users array (RBAC flag off)
    #[actix_web::test]
    async fn test_admin_users_list_shape() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let mongo_data = web::Data::new(mongo);

        let app = test::init_service(
            App::new()
                .app_data(mongo_data)
                .route("/api/admin/users", web::get().to(api_admin_users_list)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/admin/users")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(body["users"].is_array(), "Expected users array");
        assert!(body["generatedAt"].is_string(), "Expected generatedAt");
    }

    // Flow 6b: GET /api/admin/whoami — returns enforced flag
    #[actix_web::test]
    async fn test_admin_whoami_returns_enforced_flag() {
        dotenv::from_filename(".env.test").ok();
        use std::sync::Arc;
        let mongo_url = std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        let mongo = match mongodb::Client::with_uri_str(&mongo_url).await {
            Ok(c) => Arc::new(c),
            Err(_) => return,
        };
        let mongo_data = web::Data::new(mongo);

        let app = test::init_service(
            App::new()
                .app_data(mongo_data)
                .route("/api/admin/whoami", web::get().to(api_admin_whoami)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/api/admin/whoami")
            .insert_header(("Authorization", "Bearer test-token"))
            .to_request();
        let resp = test::call_service(&app, req).await;
        // Either 200 (flag off, system user) or 401 (flag on, token unknown)
        let status = resp.status().as_u16();
        assert!(
            status == 200 || status == 401,
            "Expected 200 or 401, got {}",
            status
        );
    }
} // end mod tests
