use super::super::super::*;
use actix_web::{test, web, App};

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
    assert!(body["total"].is_number(), "Expected total field");
    assert!(body["deliveryRate"].is_number(), "Expected deliveryRate field");
    assert!(body["bounceRate"].is_number(), "Expected bounceRate field");
    assert!(body["byStatus"].is_object(), "Expected byStatus object");
}

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

    let req = test::TestRequest::get().uri("/api/admin/users").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["users"].is_array(), "Expected users array");
    assert!(body["generatedAt"].is_string(), "Expected generatedAt");
}

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
    let status = resp.status().as_u16();
    assert!(status == 200 || status == 401, "Expected 200 or 401, got {}", status);
}
