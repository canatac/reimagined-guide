use super::super::super::*;
use actix_web::{test, web, App};
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

    let req = test::TestRequest::post()
        .uri("/send-email")
        .set_json(&email_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
