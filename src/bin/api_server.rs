use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

mod client;
use client::{Email, send_outgoing_email};

use std::fs::{File, create_dir_all};
use std::io::{Write,BufRead, BufReader};
use std::path::Path;
use simple_smtp_server::auth::email_auth::EmailAuthenticator;
use dotenv::dotenv;
use std::env;
use chrono::Utc;

fn read_private_key(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}


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
    // TODO: Implement authentication to ensure only authorized users can send to mailing lists

    // TODO: Implement rate limiting to prevent API abuse and comply with email sending limits

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

    // TODO: Implement this as a background job or use a task queue for large mailing lists

    // TODO: Implement batch sending for very large lists to avoid overloading the email server

    for line in reader.lines() {
        let to_email = match line {
            Ok(email) => email.trim().to_string(),
            Err(e) => {
                failure_count += 1;
                continue;
            }
        };
       // TODO: Add an unsubscribe link to the email body

        let email = Email {
            from: email_req.from.clone(),
            to: to_email,
            subject: email_req.subject.clone(),
            body: email_req.body.clone(),
            headers: vec![],
        };
        // TODO: Implement more detailed logging for auditing and troubleshooting

        match send_outgoing_email(&email).await {
            Ok(_) => success_count += 1,
            Err(_) => {
                // TODO: Decide on the appropriate error handling strategy
                // (e.g., stop sending after a certain number of failures)
                failure_count += 1;
            }        }
    }
    // TODO: For very large lists, consider returning a job ID and implementing a status check endpoint

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Emails sent to mailing list '{}'. Successful: {}, Failed: {}", 
                           email_req.mailing_list, success_count, failure_count)
    }))
}

async fn send_email_handler(email_req: web::Json<EmailRequest>) -> impl Responder {
    let private_key_path = env::var("DKIM_PRIVATE_KEY_PATH").expect("DKIM_PRIVATE_KEY_PATH not set");
    let private_key = match read_private_key(&private_key_path) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to read DKIM private key: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": "Failed to read DKIM private key"
            }));
        }
    };

    let authenticator = match EmailAuthenticator::new(
        &private_key,
        env::var("DKIM_SELECTOR").expect("DKIM_SELECTOR not set").as_str(),
        env::var("DKIM_DOMAIN").expect("DKIM_DOMAIN not set").as_str()
    ) {
        Ok(auth) => auth,
        Err(e) => {
            eprintln!("Failed to create EmailAuthenticator: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": format!("Failed to create EmailAuthenticator: {}", e)
            }));
        }
    };

    let date = Utc::now().to_rfc2822();
    let body = if email_req.body.ends_with("\r\n") {
        email_req.body.clone()
    } else {
        format!("{}\r\n", email_req.body)
    };
    // Create the email content for DKIM signing
    /* */
    let email_content = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nDate: {}\r\n\r\n{}",
        email_req.from, email_req.to, email_req.subject, date, body
    );
    
        let dkim_signature = match authenticator.sign_with_dkim(&email_content) {
            Ok(signature) => signature,
            Err(e) => {
                eprintln!("Failed to sign email with DKIM: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "message": format!("Failed to sign email with DKIM: {}", e)
                }));
            }
        };

    
    let email_content_with_dkim = format!("DKIM-Signature: {}\r\n{}", dkim_signature, email_content);

    println!("Email content with DKIM:\n{}", email_content_with_dkim);

    let email = Email {
        from: email_req.from.clone(),
        to: email_req.to.clone(),
        subject: email_req.subject.clone(),
        body: body,
        headers: vec![
            ("DKIM-Signature".to_string(), dkim_signature),
            ("From".to_string(), email_req.from.clone()),
            ("To".to_string(), email_req.to.clone()),
            ("Subject".to_string(), email_req.subject.clone()),
            ("Date".to_string(), date),
        ],
    };

    println!("Email content: {}", email_content_with_dkim);
    println!("DKIM-Signature: {}", email.headers[0].1);

    match send_outgoing_email(&email).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": "Email sent successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
}

// TODO: Implement proper error handling throughout the application
// TODO: Add comprehensive logging for debugging and monitoring
// TODO: Implement input validation for all API endpoints
// TODO: Consider implementing CORS if the API will be accessed from web browsers
// TODO: Implement API versioning for future-proofing


// Advanced Security and Native Encryption
// TODO: Implement end-to-end encryption for complete email privacy
// TODO: Add native support for DKIM, SPF, and DMARC to reduce spam and identity spoofing
// TODO: Integrate machine learning tools for real-time fraud and phishing prevention

// Performance and Scalability
// TODO: Optimize multithreading for high-load environments
// TODO: Design architecture to support containers and microservices (e.g., Kubernetes, Docker)

// Email Analytics and Insights
// TODO: Develop real-time statistics and dashboards for email performance
// TODO: Implement email campaign optimization tools with automatic recommendations

// Privacy and Compliance
// TODO: Ensure native GDPR compliance and support for other international privacy regulations
// TODO: Add feature for automatic email deletion based on time or specific rules

// Integration with Other Tools and Services
// TODO: Develop a flexible RESTful API for integration with third-party platforms
// TODO: Create plugins for instant messaging systems (e.g., Slack, Microsoft Teams)

// User-focused Features
// TODO: Implement smart filters and automatic inbox management
// TODO: Design an intuitive UI for managing email flows
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    // Load SSL keys
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(env::var("PRIVKEY_PATH").expect("PRIVKEY_PATH must be set"), SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set")).unwrap();
    
    // TODO: Load configuration from environment variables or a config file
    // TODO: Set up a connection pool for any databases used
    // TODO: Initialize any required external services or APIs

    HttpServer::new(|| {
        App::new()
            // TODO: Add middleware for logging, error handling, etc.
            .route("/send-email", web::post().to(send_email_handler))
            .route("/create-mailing-list", web::post().to(create_mailing_list))
            .route("/send-to-mailing-list", web::post().to(send_to_mailing_list))
            // TODO: Group routes under a common path (e.g., /api/v1)
        })
    .bind_openssl("0.0.0.0:8443", builder)?
    .run()
    .await
}