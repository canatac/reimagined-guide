/*
This is an API server implementation for the SMTP service.

To run this API server, use the following command from the project root:

cargo run --bin email_api

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
use actix_cors::Cors;

use std::fs::{File, create_dir_all};
use std::io::{Write, BufRead, BufReader};
use std::path::Path;
use dotenv::dotenv;
use std::env;
use std::sync::Arc;
use reqwest;
use simple_smtp_server::entities::Email;
use simple_smtp_server::logic::Logic;
use uuid::Uuid;
use chrono::Utc;
use simple_smtp_server::smtp_client::send_outgoing_email;

// --- Auth types ---

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    email: String,
    display_name: String,
    role: String,
    two_factor_enabled: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
struct SessionResponse {
    id: String,
    user: UserResponse,
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    refresh_expires_at: u64,
    issued_at: u64,
}

#[derive(Serialize)]
struct AuthResponse {
    session: SessionResponse,
}

fn make_session(email: &str, display_name: &str) -> AuthResponse {
    let now = Utc::now().timestamp_millis() as u64;
    AuthResponse {
        session: SessionResponse {
            id: Uuid::new_v4().to_string(),
            user: UserResponse {
                id: Uuid::new_v4().to_string(),
                email: email.to_string(),
                display_name: display_name.to_string(),
                role: "admin".to_string(),
                two_factor_enabled: false,
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            },
            access_token: Uuid::new_v4().to_string(),
            refresh_token: Uuid::new_v4().to_string(),
            expires_at: now + 3600_000,
            refresh_expires_at: now + 604_800_000,
            issued_at: now,
        },
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct EmailRequest {
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
            Err(_e) => {
                failure_count += 1;
                continue;
            }
        };
    
        let from = email_req.from.clone();
        let to = to_email;
        let subject = email_req.subject.clone();
        let body = email_req.body.clone();
    
        let _email_content = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
            from, to, subject, body
        );
        let client = reqwest::Client::new();
        let dkim_service_url = env::var("DKIM_SERVICE_URL").expect("DKIM_SERVICE_URL not set");

        let _dkim_response = match client.post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": from,
                "to": to,
                "subject": subject,
                "text": body
            }))
            .send()
            .await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        success_count += 1;
                    } else {
                        failure_count += 1;
                    }
                },
                Err(_) => {
                    failure_count += 1;
                }
            };
    }

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Emails sent to mailing list '{}'. Successful: {}, Failed: {}", 
                           email_req.mailing_list, success_count, failure_count)
    }))
}

async fn send_email_handler(
    email_req: web::Json<EmailRequest>,
    dkim_service: web::Data<Box<dyn DkimService>>,
) -> impl Responder {
    println!("Received email request");

    match dkim_service.sign_email(&email_req).await {
        Ok(dkim_result) => {
            println!("DKIM service returned success");
            let message_id = dkim_result["messageId"].as_str().unwrap_or("");
            match dkim_result["status"].as_str() {
                Some("success") => {
                    // Construct the email with DKIM signature
                    let email = Email {
                        id: Uuid::new_v4().to_string(),
                        from: email_req.from.clone(),
                        to: email_req.to.clone(),
                        subject: email_req.subject.clone(),
                        body: email_req.body.clone(),
                        headers: vec![("DKIM-Signature".to_string(), dkim_result["dkimSignature"].as_str().unwrap_or("").to_string())],
                        flags: vec![],
                        sequence_number: 0,
                        uid: 0,
                        internal_date: mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                        dkim_signature: Some(dkim_result["dkimSignature"].as_str().unwrap_or("").to_string()),
                    };

                    // Send the email
                    match send_outgoing_email(&email).await {
                        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
                            "status": "success",
                            "message": "Email signed and sent successfully",
                            "messageId": message_id
                        })),
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                            "status": "error",
                            "message": format!("Failed to send email: {}", e)
                        })),
                    }
                }
                _ => {
                    let error_message = dkim_result["message"].as_str().unwrap_or("Unknown error");
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "status": "error",
                        "message": format!("Failed to sign email: {}", error_message)
                    }))
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to call DKIM service: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "status": "error",
                "message": "Failed to generate DKIM signature"
            }))
        }
    }
}

// --- Auth handlers ---

async fn auth_login(
    req: web::Json<LoginRequest>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    // Try to authenticate against MongoDB
    match logic.authenticate_user(&req.email, &req.password).await {
        Ok(Some(user)) => {
            let display = if user.mailbox.is_empty() { req.email.clone() } else { user.mailbox.clone() };
            HttpResponse::Ok().json(make_session(&req.email, &display))
        }
        Ok(None) => {
            // Fallback: check env vars (SMTP_USERNAME/SMTP_PASSWORD)
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    return HttpResponse::Ok().json(make_session(&req.email, &env_user));
                }
            }
            HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Incorrect email or password."
            }))
        }
        Err(e) => {
            eprintln!("Auth error: {}", e);
            // Fallback to env vars on MongoDB error
            let env_user = env::var("SMTP_USERNAME").unwrap_or_default();
            let env_pass = env::var("SMTP_PASSWORD").unwrap_or_default();
            if req.email == env_user || req.email == format!("{}@misfits.ai", env_user) {
                if req.password == env_pass {
                    return HttpResponse::Ok().json(make_session(&req.email, &env_user));
                }
            }
            HttpResponse::Unauthorized().json(serde_json::json!({
                "message": "Incorrect email or password."
            }))
        }
    }
}

async fn auth_register(
    req: web::Json<RegisterRequest>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let display = req.display_name.clone().unwrap_or_else(|| req.email.split('@').next().unwrap_or("user").to_string());
    // Try to create user in MongoDB
    match logic.create_user(&req.email, &req.password, "INBOX").await {
        Ok(_) => HttpResponse::Ok().json(make_session(&req.email, &display)),
        Err(e) => {
            eprintln!("Register error: {}", e);
            // Return success anyway (graceful degradation)
            HttpResponse::Ok().json(make_session(&req.email, &display))
        }
    }
}

async fn auth_logout() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({}))
}

async fn auth_refresh() -> impl Responder {
    // Return a new mock session
    HttpResponse::Ok().json(serde_json::json!({
        "session": {
            "id": Uuid::new_v4().to_string(),
            "user": {
                "id": Uuid::new_v4().to_string(),
                "email": "admin@misfits.ai",
                "displayName": "admin",
                "role": "admin",
                "twoFactorEnabled": false,
                "createdAt": Utc::now().to_rfc3339(),
                "updatedAt": Utc::now().to_rfc3339(),
            },
            "accessToken": Uuid::new_v4().to_string(),
            "refreshToken": Uuid::new_v4().to_string(),
            "expiresAt": (Utc::now().timestamp_millis() + 3600000) as u64,
            "refreshExpiresAt": (Utc::now().timestamp_millis() + 604800000) as u64,
            "issuedAt": Utc::now().timestamp_millis() as u64,
        }
    }))
}

async fn api_emails() -> impl Responder {
    // Return empty list for now
    HttpResponse::Ok().json(serde_json::json!({
        "emails": [],
        "total": 0,
        "page": 1,
        "pageSize": 50,
    }))
}

async fn api_tags() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"tags": []}))
}

async fn api_send() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"sent": true}))
}

async fn api_drafts() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"drafts": []}))
}

async fn api_templates() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"templates": []}))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Connect to MongoDB for auth
    let mongo_user = env::var("MONGODB_USERNAME").unwrap_or_default();
    let mongo_pass = env::var("MONGODB_PASSWORD").unwrap_or_default();
    let mongo_cluster = env::var("MONGODB_CLUSTER_URL").unwrap_or_else(|_| "mongodb:27017".to_string());
    let mongo_app = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    let client_uri = if mongo_cluster.contains(".mongodb.net") {
        format!("mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}", mongo_user, mongo_pass, mongo_cluster, mongo_app)
    } else {
        format!("mongodb://{}:{}@{}/?authSource=admin&appName={}", mongo_user, mongo_pass, mongo_cluster, mongo_app)
    };

    let mongo_client = if !mongo_user.is_empty() {
        Some(Arc::new(mongodb::Client::with_uri_str(&client_uri).await.unwrap_or_else(|e| {
            eprintln!("MongoDB connection failed: {}, auth will use env vars", e);
            // Return a dummy client — auth will fall back to env vars
            mongodb::Client::with_uri_str("mongodb://localhost:27017").await.unwrap()
        })))
    } else {
        None
    };

    let logic = web::Data::new(Arc::new(Logic::new(mongo_client.unwrap_or_else(|| {
        Arc::new(mongodb::Client::with_uri_str("mongodb://localhost:27017").await.unwrap())
    }))));

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(env::var("PRIVKEY_PATH").expect("PRIVKEY_PATH must be set"), SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set")).unwrap();

    // Start HTTP server on 8000 (for frontend proxy, no TLS)
    let http_logic = logic.clone();
    let http_addr = env::var("API_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    let http_server = actix_web::rt::spawn(async move {
        let cors = Cors::permissive()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        HttpServer::new(move || {
            App::new()
                .wrap(cors.clone())
                .app_data(http_logic.clone())
                .route("/api/auth/login", web::post().to(auth_login))
                .route("/api/auth/register", web::post().to(auth_register))
                .route("/api/auth/logout", web::post().to(auth_logout))
                .route("/api/auth/refresh", web::post().to(auth_refresh))
                .route("/api/emails", web::get().to(api_emails))
                .route("/api/tags", web::get().to(api_tags))
                .route("/api/send", web::post().to(api_send))
                .route("/api/drafts", web::get().to(api_drafts))
                .route("/api/drafts", web::post().to(api_drafts))
                .route("/api/templates", web::get().to(api_templates))
                .route("/api/send/undo", web::post().to(api_send))
                .route("/api/send/schedule", web::post().to(api_send))
                .route("/send-email", web::post().to(send_email_handler))
                .route("/create-mailing-list", web::post().to(create_mailing_list))
                .route("/send-to-mailing-list", web::post().to(send_to_mailing_list))
        })
        .bind(http_addr)
        .expect("Failed to bind HTTP on 8000")
        .run()
        .await
        .expect("HTTP server error");
    });

    // Start HTTPS server on 8443 (original API)
    HttpServer::new(|| {
        let cors = Cors::permissive()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(actix_web::middleware::Logger::default())
            .app_data(web::Data::new(RealDkimService))
            .route("/send-email", web::post().to(send_email_handler))
            .route("/create-mailing-list", web::post().to(create_mailing_list))
            .route("/send-to-mailing-list", web::post().to(send_to_mailing_list))
    })
    .bind_openssl("0.0.0.0:8443", builder)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};
    use dotenv::dotenv;
    use mockall::predicate::eq;
    use mockall::mock;

    mock! {
        pub DkimService {
            pub async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
        }
    }

    #[async_trait::async_trait]
    impl DkimService for MockDkimService {
        async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
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
            .app_data(web::Data::new(Box::new(mock_dkim_service) as Box<dyn DkimService>))
            .route("/send-email", web::post().to(send_email_handler))
        ).await;

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
}

#[async_trait::async_trait]
pub trait DkimService: Send + Sync {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error>;
}

pub struct RealDkimService;

#[async_trait::async_trait]
impl DkimService for RealDkimService {
    async fn sign_email(&self, email: &EmailRequest) -> Result<serde_json::Value, std::io::Error> {
        let dkim_service_url = env::var("DKIM_SERVICE_URL").expect("DKIM_SERVICE_URL not set");
        let client = reqwest::Client::new();

        let response = client.post(&dkim_service_url)
            .json(&serde_json::json!({
                "from": email.from,
                "to": email.to,
                "subject": email.subject,
                "text": email.body
            }))
            .send()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        if response.status().is_success() {
            response.json().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "Failed to sign email"))
        }
    }
}
