use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};

mod client;
use client::{Email, send_outgoing_email};

#[derive(Deserialize, Serialize)]
struct EmailRequest {
    from: String,
    to: String,
    subject: String,
    body: String,
}

async fn send_email_handler(email_req: web::Json<EmailRequest>) -> impl Responder {
    let email = Email {
        from: email_req.from.clone(),
        to: email_req.to.clone(),
        subject: email_req.subject.clone(),
        body: email_req.body.clone(),
        headers: vec![],
    };

    match send_outgoing_email(&email).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": "Email sent successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/send-email", web::post().to(send_email_handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}