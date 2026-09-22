// gdpr_export.rs — GDPR data portability + export (EML/ZIP) for issue #552
#![allow(unused_imports)]
use super::*;
use super::send_pipeline::*;

/// Collection for tracking export jobs.
const EXPORT_JOBS_COLL: &str = "export_jobs";

/// Request body for POST /api/v1/export/emails
#[derive(Debug, Deserialize)]
pub(crate) struct ExportEmailsRequest {
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub format: Option<String>, // "eml" | "mbox" | "json"
    #[serde(default)]
    pub date_from: Option<String>,
    #[serde(default)]
    pub date_to: Option<String>,
}

/// Export job document stored in MongoDB.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ExportJob {
    pub id: String,
    pub user_id: String,
    pub status: String, // "pending" | "processing" | "completed" | "failed"
    pub format: String,
    pub folder: Option<String>,
    pub email_count: i64,
    pub file_path: Option<String>,
    pub error: Option<String>,
    pub created_at: bson::DateTime,
    pub completed_at: Option<bson::DateTime>,
}

/// POST /api/v1/export/emails — initiate async email export.
pub(crate) async fn api_export_emails(
    body: Option<web::Json<ExportEmailsRequest>>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let body = body.map(|b| b.into_inner()).unwrap_or(ExportEmailsRequest {
        folder: None,
        format: None,
        date_from: None,
        date_to: None,
    });
    let format = body.format.unwrap_or_else(|| "eml".to_string());
    let job_id = Uuid::new_v4().to_string();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(EXPORT_JOBS_COLL);

    let job = ExportJob {
        id: job_id.clone(),
        user_id: user_id.clone(),
        status: "pending".to_string(),
        format: format.clone(),
        folder: body.folder.clone(),
        email_count: 0,
        file_path: None,
        error: None,
        created_at: bson::DateTime::from_millis(Utc::now().timestamp_millis()),
        completed_at: None,
    };

    let doc = match bson::to_document(&job) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": format!("serialize failed: {}", e) }));
        }
    };

    if let Err(e) = coll.insert_one(doc).await {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": format!("insert failed: {}", e) }));
    }

    // Spawn background processing.
    let logic_clone = logic.get_ref().clone();
    let mongo_clone = mongo.get_ref().clone();
    let folder_clone = body.folder.clone();
    let job_id_clone = job_id.clone();
    let user_id_clone = user_id.clone();
    let format_clone = format.clone();
    tokio::spawn(async move {
        process_export_job(
            &job_id_clone,
            &user_id_clone,
            &format_clone,
            folder_clone.as_deref(),
            &logic_clone,
            &mongo_clone,
        )
        .await;
    });

    HttpResponse::Accepted().json(serde_json::json!({
        "job_id": job_id,
        "status": "pending",
        "message": "Export job created. Check status at /api/v1/export/{job_id}/status"
    }))
}

/// GET /api/v1/export/{job_id}/status — check export job status.
pub(crate) async fn api_export_status(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let job_id = path.into_inner();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(EXPORT_JOBS_COLL);

    match coll
        .find_one(doc! { "id": &job_id, "user_id": &user_id })
        .await
    {
        Ok(Some(doc)) => {
            let status: String = doc.get_str("status").unwrap_or("unknown").to_string();
            let email_count = doc.get_i64("email_count").unwrap_or(0);
            let error: Option<String> = doc.get_str("err").ok().map(|s| s.to_string());
            HttpResponse::Ok().json(serde_json::json!({
                "job_id": job_id,
                "status": status,
                "email_count": email_count,
                "error": error,
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Export job not found"
        })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": e.to_string() })),
    }
}

/// GET /api/v1/export/{job_id}/download — download completed export ZIP.
pub(crate) async fn api_export_download(
    path: web::Path<String>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let job_id = path.into_inner();
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(EXPORT_JOBS_COLL);

    let job = match coll
        .find_one(doc! { "id": &job_id, "user_id": &user_id })
        .await
    {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "error": "Export job not found" }));
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": e.to_string() }));
        }
    };

    let status = job.get_str("status").unwrap_or("unknown");
    if status != "completed" {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Export job is {} — not ready for download", status)
        }));
    }

    let file_path = match job.get_str("file_path") {
        Ok(p) => p.to_string(),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "file_path missing" }));
        }
    };

    // Read file from disk.
    let data = match std::fs::read(&file_path) {
        Ok(d) => d,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": format!("read failed: {}", e) }));
        }
    };

    HttpResponse::Ok()
        .content_type("application/zip")
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"emails-export-{}.zip\"", job_id),
        ))
        .body(data)
}

/// Background job processor: exports emails to EML files in a ZIP archive.
async fn process_export_job(
    job_id: &str,
    user_id: &str,
    format: &str,
    folder: Option<&str>,
    logic: &Arc<Logic>,
    mongo: &Arc<mongodb::Client>,
) {
    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(EXPORT_JOBS_COLL);

    // Mark as processing.
    let _ = coll
        .update_one(
            doc! { "id": job_id },
            doc! { "$set": { "status": "processing" } },
        )
        .await;

    // Collect mailboxes to export.
    let mailboxes: Vec<String> = match folder {
        Some(f) => folder_to_mailboxes(f),
        None => vec!["inbox".to_string(), "sent".to_string(), "archive".to_string()],
    };

    // Fetch all emails from all mailboxes.
    let mut all_emails: Vec<Email> = Vec::new();
    for mailbox in &mailboxes {
        match logic.get_emails_page(user_id, mailbox, 1000, 0).await {
            Ok(emails) => all_emails.extend(emails),
            Err(e) => {
                let _ = coll
                    .update_one(
                        doc! { "id": job_id },
                        doc! { "$set": {
                            "status": "failed",
                            "error": format!("fetch failed for {}: {}", mailbox, e),
                            "completed_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                        }},
                    )
                    .await;
                return;
            }
        }
    }

    let email_count = all_emails.len() as i64;

    // Create temp directory for export.
    let export_dir = format!("/tmp/export-{}", job_id);
    if let Err(e) = std::fs::create_dir_all(&export_dir) {
        let _ = coll
            .update_one(
                doc! { "id": job_id },
                doc! { "$set": {
                    "status": "failed",
                    "error": format!("create_dir failed: {}", e),
                    "completed_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                }},
            )
            .await;
        return;
    }

    // Write EML files.
    for (idx, email) in all_emails.iter().enumerate() {
        let eml_content = build_eml(email);
        let filename = format!("{}/{:04}-{}.eml", export_dir, idx + 1, email.id);
        if let Err(e) = std::fs::write(&filename, eml_content) {
            let _ = coll
                .update_one(
                    doc! { "id": job_id },
                    doc! { "$set": {
                        "status": "failed",
                        "error": format!("write failed for {}: {}", filename, e),
                        "completed_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                    }},
                )
                .await;
            return;
        }
    }

    // Create ZIP archive.
    let zip_path = format!("/tmp/emails-export-{}.zip", job_id);
    if let Err(e) = create_zip(&export_dir, &zip_path) {
        let _ = coll
            .update_one(
                doc! { "id": job_id },
                doc! { "$set": {
                    "status": "failed",
                    "error": format!("zip failed: {}", e),
                    "completed_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                }},
            )
            .await;
        return;
    }

    // Clean up temp dir.
    let _ = std::fs::remove_dir_all(&export_dir);

    // Mark as completed.
    let _ = coll
        .update_one(
            doc! { "id": job_id },
            doc! { "$set": {
                "status": "completed",
                "email_count": email_count,
                "file_path": &zip_path,
                "completed_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
            }},
        )
        .await;
}

/// Build RFC 5322 EML content from an Email struct.
fn build_eml(email: &Email) -> String {
    let mut out = String::new();
    out.push_str(&format!("Message-ID: <{}>\n", email.id));
    out.push_str(&format!("Date: {}\n", email.internal_date.to_rfc2822()));
    out.push_str(&format!("From: {}\n", email.from));
    out.push_str(&format!("To: {}\n", email.to));
    out.push_str(&format!("Subject: {}\n", email.subject));
    out.push_str("Content-Type: text/plain; charset=\"utf-8\"\n");
    out.push_str("MIME-Version: 1.0\n");
    for (key, val) in &email.headers {
        out.push_str(&format!("{}: {}\n", key, val));
    }
    out.push('\n');
    out.push_str(&email.body);
    out.push('\n');
    out
}

/// Create a ZIP archive from a directory.
fn create_zip(src_dir: &str, dest_path: &str) -> std::io::Result<()> {
    let file = std::fs::File::create(dest_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let entries = std::fs::read_dir(src_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file());
    for entry in entries {
        let path = entry.path();
        let name = path.file_name().unwrap().to_string_lossy();
        zip.start_file(name.as_ref(), options)?;
        let data = std::fs::read(&path)?;
        zip.write_all(&data)?;
    }
    zip.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_eml_contains_headers() {
        let email = Email {
            id: "test-1".to_string(),
            from: "<EMAIL>".to_string(),
            to: "<EMAIL>".to_string(),
            subject: "Hello".to_string(),
            body: "World".to_string(),
            headers: vec![("X-Custom".to_string(), "value".to_string())],
            flags: vec![],
            sequence_number: 0,
            uid: 1,
            internal_date: Utc::now(),
            dkim_signature: None,
        };
        let eml = build_eml(&email);
        assert!(eml.contains("From: <EMAIL>"));
        assert!(eml.contains("To: <EMAIL>"));
        assert!(eml.contains("Subject: Hello"));
        assert!(eml.contains("World"));
        assert!(eml.contains("X-Custom: value"));
    }

    #[test]
    fn export_emails_request_deserializes() {
        let json = serde_json::json!({
            "folder": "inbox",
            "format": "eml"
        });
        let req: ExportEmailsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.folder, Some("inbox".to_string()));
        assert_eq!(req.format, Some("eml".to_string()));
    }

    #[test]
    fn export_emails_request_defaults() {
        let json = serde_json::json!({});
        let req: ExportEmailsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.folder, None);
        assert_eq!(req.format, None);
    }
}
