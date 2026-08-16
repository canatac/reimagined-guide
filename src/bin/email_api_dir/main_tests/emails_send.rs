use super::super::super::*;
use actix_web::{test, web, App};

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

    let req = test::TestRequest::get()
        .uri("/api/emails?folder=inbox&page=1&page_size=5")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["emails"].is_array(), "Expected emails array");
}

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
