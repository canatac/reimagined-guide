use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use openssl::rsa::Padding;
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
use std::collections::LinkedList;

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
/*
        let email = Email {
            from: email_req.from.clone(),
            to: to_email,
            subject: email_req.subject.clone(),
            body: email_req.body.clone(),
            headers: vec![],
        };
   */
        let from = email_req.from.clone();
        let to = to_email;
        let subject = email_req.subject.clone();
        let body = email_req.body.clone();
    
        // Create the email content
        let email_content = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\n\r\n{}",
            from, to, subject, body
        );

        // TODO: Implement more detailed logging for auditing and troubleshooting

        match send_outgoing_email(&email_content).await {
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
        Ok(signature) => {
            println!("DKIM signature: {}", signature);
            signature
        },
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
/*
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
 */
// Validate DKIM signature before sending

    let public_key_pem = authenticator.get_dkim_public_key().await.expect("Failed to get DKIM public key");
let validator = DKIMValidator::new(public_key_pem).expect("Failed to create DKIM validator");
match validator.validate(&email_content_with_dkim) {
    Ok(true) => println!("DKIM validation passed"),
    Ok(false) => {
        eprintln!("DKIM validation failed");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": "DKIM validation failed"
        }));
    },
    Err(e) => {
        eprintln!("DKIM validation error: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": format!("DKIM validation error: {}", e)
        }));
    }
}
/*
    match send_outgoing_email(&email).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": "Email sent successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
 */
    match send_outgoing_email(&email_content_with_dkim).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "success", "message": "Email sent successfully"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"status": "error", "message": e.to_string()})),
    }
}

use base64;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;
use std::error::Error;

pub struct DKIMValidator {
    public_key: PKey<Public>,
}

impl DKIMValidator {
    pub fn new(public_key: PKey<Public>) -> Result<Self, DKIMError> {
        Ok(Self { public_key })
    }

    fn validate(&self, email_content: &str) -> Result<bool, DKIMError> {
        println!("+++++++++++++++++++++++++V A L I D A T E+++++++++++++++++++++++++++++");

        let (headers, body) = email_content.split_once("\r\n\r\n").ok_or(DKIMError::InvalidEmailFormat)?;
        println!("validate - OUTPUT - Headers: {}", headers);

        println!("validate - OUTPUT - Body: {}", body);

        let dkim_signature = self.extract_dkim_signature(headers)?;
        println!("validate - OUTPUT - Extracted DKIM signature: {}", dkim_signature);
        
        let (signed_headers, signature, dkim_params) = self.parse_dkim_signature(&dkim_signature)?;
        println!("validate - OUTPUT - Parsed DKIM signature: {:?}", (&signed_headers, &signature, &dkim_params));

        let canonicalized_headers = self.canonicalize_headers(headers, &signed_headers);
        println!("validate - OUTPUT - Canonicalized headers: {}", canonicalized_headers);

        let computed_body_hash = self.compute_body_hash(body);
    
        println!("validate - OUTPUT - Computed body hash: {}", computed_body_hash);

        // Check if the computed body hash matches the one in the DKIM signature
        let bh_param = dkim_params.iter()
            .find_map(|(k, v)| if k == "bh" { Some(v) } else { None })
            .ok_or_else(|| DKIMError::InvalidSignatureFormat("Missing bh parameter".to_string()))?;

        if computed_body_hash != *bh_param {
            return Err(DKIMError::BodyHashMismatch);
        }
        println!("validate - OUTPUT - Computed body hash matches the one in the DKIM signature");

        let signature_base = self.construct_signature_base(&dkim_params, &canonicalized_headers, &computed_body_hash);
        println!("validate - OUTPUT - Validator signature_base as bytes: {:?}", signature_base.as_bytes());
        println!("validate - OUTPUT - Validator signature_base as string: {}", signature_base);

        let signature_bytes = base64::decode(signature)
            .map_err(|e| DKIMError::Base64DecodeError(e.to_string()))?;
        println!("validate - OUTPUT - Sent Signature bytes: {:?}", signature_bytes);

        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.public_key)
            .map_err(|e| DKIMError::OpenSSLError(e.to_string()))?;
        //        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.public_key)?;
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();

        // Met à jour le vérificateur avec la base de signature (chaîne à vérifier)
        verifier.update(signature_base.as_bytes())
        .map_err(|e| DKIMError::OpenSSLError(e.to_string()))?;
        println!("Verifier updated with base signature string");

        // Vérifie la signature avec les bytes décodés de la signature
        match verifier.verify(&signature_bytes) {
            Ok(true) => {
                println!("Signature verification succeeded");
                Ok(true)
            },
            Ok(false) => {
                println!("Signature verification failed");
                Err(DKIMError::SignatureVerificationFailed)
            },
            Err(e) => Err(DKIMError::OpenSSLError(format!("Verification error: {}", e)))
        }
    }

    fn extract_dkim_signature(&self, headers: &str) -> Result<String, DKIMError> {
        println!("Extracting DKIM signature from headers: {}", headers);
        headers
            .lines()
            .find(|line| line.starts_with("DKIM-Signature:"))
            .ok_or(DKIMError::SignatureNotFound)
            .map(|line| line.trim_start_matches("DKIM-Signature:").trim().to_string())
    }


fn parse_dkim_signature(&self, dkim_signature: &str) -> Result<(Vec<String>, String, LinkedList<(String, String)>), DKIMError> {
    let mut signed_headers = Vec::new();
    let mut signature = String::new();
    let mut dkim_params = LinkedList::new();

    for part in dkim_signature.split(';') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            match key.as_str() {
                "h" => {
                    signed_headers = value.split(':').map(|s| s.trim().to_lowercase()).collect();
                    dkim_params.push_back((key, value)); },
                "b" => {
                    signature = value;
                 },
                _ => { dkim_params.push_back((key, value)); }
            }
        }
    }

    if signed_headers.is_empty() || signature.is_empty() {
        return Err(DKIMError::InvalidSignatureFormat("Missing required parameters".to_string()));
    }

    Ok((signed_headers, signature, dkim_params))
}

    fn canonicalize_headers(&self, headers: &str, signed_headers: &[String]) -> String {
        let mut canonicalized = String::new();
        for header_name in signed_headers {
            if let Some(header_value) = self.get_header_value(headers, header_name) {
                let canonical_header = self.relaxed_canonicalization(header_name, header_value);
                canonicalized.push_str(&canonical_header);
                canonicalized.push_str("\r\n");
            }
        }
        canonicalized
    }

    fn relaxed_canonicalization(&self, name: &str, value: &str) -> String {
        let name = name.to_lowercase();
        let value = value.split_whitespace().collect::<Vec<&str>>().join(" ");
        format!("{}:{}", name, value.trim())
    }

    fn get_header_value<'a>(&self, headers: &'a str, header_name: &str) -> Option<&'a str> {
        headers.lines()
            .find(|line| line.to_lowercase().starts_with(&format!("{}:", header_name.to_lowercase())))
            .and_then(|line| line.splitn(2, ':').nth(1))
            .map(|value| value.trim())
    }

    fn compute_body_hash(&self, body: &str) -> String {
        let body = if body.is_empty() { "\r\n" } else { body };
        let hash = hash(MessageDigest::sha256(), body.as_bytes()).unwrap();
        base64::encode(hash)
    }

    fn construct_signature_base(&self, dkim_params: &LinkedList<(String, String)>, canonicalized_headers: &str, body_hash: &str) -> String {
        println!("Constructing signature base");
        let mut base = String::new();

     /*
     let dkim_header = format!(
            "v=1; a=rsa-sha256; c=relaxed/simple; d={}; s={}; t={}; bh={}; h={}",
            self.dkim_domain, 
            self.dkim_selector, 
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            body_hash, 
            headers_to_sign.join(":")
        );

        let signature_base = format!("{}\r\n{}", dkim_header, canonicalized_headers.trim_end());
      */

        // Add all parameters, including 'b' but without its value
        for (key, value) in dkim_params {
            base.push_str(&format!("{}={};", key, value));
        }
        base.push_str("b=;");
        base.push_str("\r\n");
        base.push_str(canonicalized_headers);

        
        println!("Signature base 1 :\n{}", base);
        base
    }
}
#[derive(Debug)]
pub enum DKIMError {
    SignatureNotFound,
    InvalidSignatureFormat(String),
    BodyHashMismatch,
    SignatureVerificationFailed,
    InvalidEmailFormat,
    PublicKeyError(String),
    Base64DecodeError(String),
    OpenSSLError(String),
    IOError(std::io::Error),
    KeyRetrievalError(String),
    DNSError(String),
}

impl std::fmt::Display for DKIMError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DKIMError::SignatureNotFound => write!(f, "DKIM-Signature not found in headers"),
            DKIMError::InvalidSignatureFormat(msg) => write!(f, "Invalid DKIM signature format: {}", msg),
            DKIMError::BodyHashMismatch => write!(f, "Body hash in DKIM signature does not match computed body hash"),
            DKIMError::SignatureVerificationFailed => write!(f, "DKIM signature verification failed"),
            DKIMError::InvalidEmailFormat => write!(f, "Invalid email format"),
            DKIMError::PublicKeyError(msg) => write!(f, "Public key error: {}", msg),
            DKIMError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            DKIMError::OpenSSLError(msg) => write!(f, "OpenSSL error: {}", msg),
            DKIMError::IOError(e) => write!(f, "IO error: {}", e),
            DKIMError::KeyRetrievalError(msg) => write!(f, "Key retrieval error: {}", msg),
            DKIMError::DNSError(msg) => write!(f, "DNS error: {}", msg),
        }
    }
}

impl std::error::Error for DKIMError {}
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