// Email export .eml batch — POST /api/emails/export
// Accepts a list of email IDs, fetches them from MongoDB, generates .eml files,
// and returns a .zip archive containing all selected emails.
#![allow(unused_imports)]
use super::*;
use std::io::Write;

/// Request body for email export.
#[derive(Debug, Deserialize)]
pub struct EmailExportRequest {
    #[serde(default)]
    pub email_ids: Vec<String>,
    #[serde(default)]
    pub folder: Option<String>,
}

/// Maximum number of emails allowed per export batch.
const MAX_EXPORT_BATCH: usize = 200;

/// Convert an Email entity into RFC 5322 .eml format.
fn email_to_eml(email: &Email) -> String {
    let mut eml = String::new();
    // Headers
    eml.push_str(&format!("Message-ID: <{}>\r\n", email.id));
    eml.push_str(&format!("From: {}\r\n", email.from));
    eml.push_str(&format!("To: {}\r\n", email.to));
    eml.push_str(&format!("Subject: {}\r\n", email.subject));
    eml.push_str(&format!(
        "Date: {}\r\n",
        email.internal_date.format("%a, %d %b %Y %H:%M:%S %z")
    ));
    // Custom headers
    for (key, value) in &email.headers {
        eml.push_str(&format!("{}: {}\r\n", key, value));
    }
    // DKIM-Signature if present
    if let Some(ref dkim) = email.dkim_signature {
        eml.push_str(&format!("DKIM-Signature: {}\r\n", dkim));
    }
    // Blank line separates headers from body
    eml.push_str("\r\n");
    // Body
    eml.push_str(&email.body);
    eml
}

/// Sanitize a string for use in a filename.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .take(80)
        .collect()
}

/// Build a .zip archive containing .eml files for the given emails.
fn build_eml_zip(emails: Vec<Email>) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut zip_writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        for email in &emails {
            let filename = format!(
                "{}_{}.eml",
                sanitize_filename(&email.id),
                sanitize_filename(&email.subject)
            );
            zip_writer
                .start_file(&filename, options)
                .map_err(|e| format!("zip start_file error: {}", e))?;
            let eml_content = email_to_eml(email);
            zip_writer
                .write_all(eml_content.as_bytes())
                .map_err(|e| format!("zip write error: {}", e))?;
        }

        zip_writer
            .finish()
            .map_err(|e| format!("zip finish error: {}", e))?;
    }
    Ok(buf)
}

/// POST /api/emails/export — export selected emails as .eml files in a .zip archive.
pub(crate) async fn api_emails_export(
    body: web::Json<EmailExportRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);

    // Validate batch size
    if body.email_ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "No email_ids provided"
        }));
    }
    if body.email_ids.len() > MAX_EXPORT_BATCH {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": format!("Too many emails: {} (max {})", body.email_ids.len(), MAX_EXPORT_BATCH)
        }));
    }

    // Fetch emails by IDs
    let mut emails: Vec<Email> = Vec::new();
    for email_id in &body.email_ids {
        match logic.fetch_email(&user_id, email_id).await {
            Ok(Some(email)) => emails.push(email),
            Ok(None) => {
                eprintln!("export: email {} not found", email_id);
            }
            Err(e) => {
                eprintln!("export: fetch_email error for {}: {}", email_id, e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "message": format!("Failed to fetch email {}", email_id)
                }));
            }
        }
    }

    if emails.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "message": "No emails found for the given IDs"
        }));
    }

    // Build zip
    match build_eml_zip(emails) {
        Ok(zip_bytes) => HttpResponse::Ok()
            .insert_header(("Content-Type", "application/zip"))
            .insert_header((
                "Content-Disposition",
                "attachment; filename=\"emails_export.zip\"",
            ))
            .body(zip_bytes),
        Err(e) => {
            eprintln!("export: zip build error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to build export archive"
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::Email;
    use chrono::TimeZone;

    fn test_email(id: &str, subject: &str) -> Email {
        Email {
            id: id.to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: subject.to_string(),
            body: "Test body content".to_string(),
            headers: vec![("X-Custom".to_string(), "test-value".to_string())],
            flags: vec!["\\Seen".to_string()],
            sequence_number: 1,
            uid: 1,
            internal_date: Utc.with_ymd_and_hms(2026, 1, 15, 10, 30, 0).unwrap(),
            dkim_signature: None,
        }
    }

    #[test]
    fn email_to_eml_contains_headers() {
        let email = test_email("abc123", "Test Subject");
        let eml = email_to_eml(&email);
        assert!(eml.contains("From: sender@example.com"));
        assert!(eml.contains("To: recipient@example.com"));
        assert!(eml.contains("Subject: Test Subject"));
        assert!(eml.contains("Message-ID: <abc123>"));
        assert!(eml.contains("Test body content"));
    }

    #[test]
    fn email_to_eml_separates_headers_and_body() {
        let email = test_email("id1", "Hello");
        let eml = email_to_eml(&email);
        assert!(eml.contains("\r\n\r\n"));
        let parts: Vec<&str> = eml.split("\r\n\r\n").collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1], "Test body content");
    }

    #[test]
    fn sanitize_filename_removes_special_chars() {
        assert_eq!(sanitize_filename("hello world!"), "hello_world_");
        assert_eq!(sanitize_filename("test/file:name"), "test_file_name");
        assert_eq!(sanitize_filename("normal-name_123"), "normal-name_123");
    }

    #[test]
    fn sanitize_filename_truncates_long() {
        let long = "a".repeat(200);
        assert_eq!(sanitize_filename(&long).len(), 80);
    }

    #[test]
    fn build_eml_zip_creates_valid_zip() {
        let emails = vec![
            test_email("id1", "First Email"),
            test_email("id2", "Second Email"),
        ];
        let zip_bytes = build_eml_zip(emails).expect("zip should build");
        // ZIP files start with "PK" magic bytes
        assert_eq!(&zip_bytes[0..2], b"PK");
        assert!(zip_bytes.len() > 100);
    }

    #[test]
    fn build_eml_zip_empty_list() {
        let zip_bytes = build_eml_zip(vec![]).expect("zip should build");
        assert_eq!(&zip_bytes[0..2], b"PK");
    }

    #[test]
    fn email_to_eml_with_dkim() {
        let mut email = test_email("id3", "DKIM test");
        email.dkim_signature = Some("v=1; a=rsa-sha256;".to_string());
        let eml = email_to_eml(&email);
        assert!(eml.contains("DKIM-Signature: v=1; a=rsa-sha256;"));
    }
}
