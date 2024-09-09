use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

mod client;
use client::{Email, send_outgoing_email};

use std::fs::{File, create_dir_all};
use std::io::{Write,BufRead, BufReader};
use std::path::Path;

#[derive(Deserialize, Serialize)]
struct EmailRequest {
    from: String,
    to: String,
    subject: String,
    body: String,
}


#[derive(Deserialize)]
struct MailingListRequest {
    label: String,
    emails: Vec<String>,
}

#[derive(Deserialize)]
struct MailingListEmailRequest {
    from: String,
    subject: String,
    body: String,
    mailing_list: String,
}

async fn create_mailing_list(mailing_list: web::Json<MailingListRequest>) -> impl Responder {
    let mailing_list_dir = Path::new("mailing-lists");
    if !mailing_list_dir.exists() {
        if let Err(e) = create_dir_all(mailing_list_dir) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create mailing list directory: {}", e)
            }));
        }
    }

    let file_path = mailing_list_dir.join(format!("{}.csv", mailing_list.label));
    let mut file = match File::create(&file_path) {
        Ok(file) => file,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to create file: {}", e)
        })),
    };

    for email in &mailing_list.emails {
        if let Err(e) = writeln!(file, "{}", email) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to write to file: {}", e)
            }));
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Mailing list '{}' created successfully", mailing_list.label)
    }))
}

async fn send_to_mailing_list(email_req: web::Json<MailingListEmailRequest>) -> impl Responder {
    let mailing_list_path = Path::new("mailing-lists").join(format!("{}.csv", email_req.mailing_list));
    
    if !mailing_list_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "status": "error",
            "message": format!("Mailing list '{}' not found", email_req.mailing_list)
        }));
    }

    let file = match File::open(&mailing_list_path) {
        Ok(file) => file,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": format!("Failed to open mailing list file: {}", e)
        })),
    };

    let reader = BufReader::new(file);
    let mut success_count = 0;
    let mut failure_count = 0;

    for line in reader.lines() {
        let to_email = match line {
            Ok(email) => email.trim().to_string(),
            Err(e) => {
                failure_count += 1;
                continue;
            }
        };

        let email = Email {
            from: email_req.from.clone(),
            to: to_email,
            subject: email_req.subject.clone(),
            body: email_req.body.clone(),
            headers: vec![],
        };

        match send_outgoing_email(&email).await {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Emails sent to mailing list '{}'. Successful: {}, Failed: {}", 
                           email_req.mailing_list, success_count, failure_count)
    }))
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
    // Load SSL keys
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("privkey.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("fullchain.pem").unwrap();

    HttpServer::new(|| {
        App::new()
            .route("/send-email", web::post().to(send_email_handler))
            .route("/create-mailing-list", web::post().to(create_mailing_list))
            .route("/send-to-mailing-list", web::post().to(send_to_mailing_list))
    })
    .bind_openssl("0.0.0.0:8443", builder)?
    .run()
    .await
}