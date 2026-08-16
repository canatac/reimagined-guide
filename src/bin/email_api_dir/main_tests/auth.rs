use super::super::super::*;
use actix_web::{test, web, App};

#[actix_web::test]
async fn test_auth_login_rejects_empty_password() {
    let app = test::init_service(
        App::new()
            .app_data(
                web::JsonConfig::default()
                    .error_handler(|err, _req| {
                        let resp = actix_web::HttpResponse::BadRequest()
                            .json(serde_json::json!({ "code": "INVALID_JSON", "message": err.to_string() }));
                        actix_web::error::InternalError::from_response(err, resp).into()
                    })
            )
            .route("/api/auth/login", web::post().to(auth_login)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({ "email": "test@misfits.ai" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_auth_login_valid_shape_returns_200_or_401() {
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
    assert!(status == 200 || status == 401, "Expected 200 or 401, got {}", status);
}

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

    let req = test::TestRequest::post()
        .uri("/api/auth/2fa/verify")
        .set_json(serde_json::json!({ "email": "test@misfits.ai", "method": "email" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
}
