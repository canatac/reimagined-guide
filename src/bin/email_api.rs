/*
This is an API server implementation for the SMTP service.

To run this API server, use the following command from the project root:

cargo run --bin api_server

Make sure you have set the necessary environment variables in your .env file:
    API_SERVER_ADDR: The address and port for the API server (e.g., "127.0.0.1:3000")
    SMTP_USERNAME: Your SMTP username
    SMTP_PASSWORD: Your SMTP password
    FULLCHAIN_PATH: Path to your SSL certificate chain file

The API server provides the following endpoint:

POST /send_email
    Accepts JSON payload with the following structure:
    {
        "from": "sender@example.com",
        "to": "recipient@example.com",
        "subject": "Test Email",
        "body": "This is a test email sent via the API server."
    }

Example usage with curl:
curl -X POST http://localhost:3000/send_email \
     -H "Content-Type: application/json" \
     -d '{
         "from": "sender@example.com",
         "to": "recipient@example.com",
         "subject": "Test Email",
         "body": "This is a test email sent via the API server."
     }'

The API server will attempt to send the email using the SMTP client and return the result.
*/

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

mod smtp_client;
use smtp_client::send_outgoing_email;

use std::fs::{File, create_dir_all};
use std::io::{Write, BufRead, BufReader};
use std::path::Path;
use dotenv::dotenv;
use std::env;
use chrono::Utc;
use reqwest;

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
    
        let from = email_req.from.clone();
        let to = to_email;
        let subject = email_req.subject.clone();
        let body = email_req.body.clone();
    
        let email_content = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
            from, to, subject, body
        );

        match send_outgoing_email(&email_content).await {
            Ok(_) => success_count += 1,
            Err(_) => {
                failure_count += 1;
            }        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Emails sent to mailing list '{}'. Successful: {}, Failed: {}", 
                           email_req.mailing_list, success_count, failure_count)
    }))
}

async fn send_email_handler(email_req: web::Json<EmailRequest>) -> impl Responder {
    let dkim_service_url = env::var("DKIM_SERVICE_URL").expect("DKIM_SERVICE_URL not set");
    
    let date = Utc::now().to_rfc2822();
    let body = if email_req.body.ends_with("\r\n") {
        email_req.body.clone()
    } else {
        format!("{}\r\n", email_req.body)
    };
    let email_content = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\n\r\n{}",
        email_req.from, email_req.to, email_req.subject, date, body
    );

    let client = reqwest::Client::new();
    let dkim_response = match client.post(&dkim_service_url)
        .json(&serde_json::json!({
            "from": email_req.from,
            "to": email_req.to,
            "subject": email_req.subject,
            "text": email_req.body
        }))
        .send()
        .await {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("Failed to call DKIM service: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": "Failed to generate DKIM signature"
                }));
            }
        };

    if !dkim_response.status().is_success() {
        eprintln!("DKIM service returned an error: {:?}", dkim_response.status());
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": "DKIM service error"
        }));
    }

    let dkim_result: serde_json::Value = match dkim_response.json().await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to parse DKIM service response: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": "Failed to parse DKIM signature"
            }));
        }
    };

    let dkim_signature = dkim_result["dkimSignature"].as_str().unwrap_or("");
    let email_content_with_dkim = format!("{}\r\n{}", dkim_signature, email_content);

    match send_outgoing_email(&email_content_with_dkim).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": "Email sent successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(env::var("PRIVKEY_PATH").expect("PRIVKEY_PATH must be set"), SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set")).unwrap();

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