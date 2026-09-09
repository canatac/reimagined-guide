#![allow(unused_imports, dead_code)]
use super::super::*;
use serde::Deserialize;

/// Input for POST /api/v1/import/configure — Email import wizard.
///
/// Supports OAuth2 for Gmail / Outlook / Yahoo and generic IMAP/SMTP.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportConfigureInput {
    pub provider: String,
    pub email: String,
    #[serde(default)]
    pub auth_type: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub imap_host: Option<String>,
    #[serde(default)]
    pub imap_port: Option<u16>,
    #[serde(default = "default_true")]
    pub imap_tls: bool,
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default)]
    pub smtp_port: Option<u16>,
    #[serde(default)]
    pub smtp_tls: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    /// Incremental sync: only import emails newer than this ISO-8601 date.
    #[serde(default)]
    pub since: Option<String>,
    /// Max emails to import (rate-limit guard). Default 1000, max 10000.
    #[serde(default = "default_max_emails")]
    pub max_emails: u64,
}

fn default_max_emails() -> u64 {
    1000
}

fn default_true() -> bool {
    true
}

/// POST /api/v1/import/configure — configure an email import wizard job.
///
/// Flow:
/// 1. Validate provider (gmail / outlook / yahoo / generic).
/// 2. Create external IMAP account record.
/// 3. Discover folders (auto-mapping).
/// 4. Start incremental sync.
/// 5. Return sync run ID + progress endpoint.
pub(crate) async fn api_import_configure(
    req: HttpRequest,
    payload: web::Json<ImportConfigureInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let input = payload.into_inner();

    // 1. Validate provider.
    let provider = match normalize_import_provider(&input.provider) {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": {
                    "code": "IMPORT_UNSUPPORTED_PROVIDER",
                    "message": format!("Unsupported provider: {}", input.provider),
                    "supported": ["gmail", "outlook", "yahoo", "generic"]
                }
            }));
        }
    };

    // Clamp max_emails to avoid provider rate-limit bans.
    let max_emails = input.max_emails.min(10_000);

    // 2. Build CreateExternalAccountInput.
    let create_input = build_create_account_input(&provider, &input);

    let account = match svc.create_account(&user_id, create_input).await {
        Ok(a) => a,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "IMPORT_ACCOUNT_CREATE_FAILED", "message": e.to_string() }
            }));
        }
    };

    // 3. Discover folders (best-effort; non-blocking on failure).
    let folders_result = svc.discover_folders(&user_id, &account).await;
    let discovered_folders = match &folders_result {
        Ok(r) => r.folders.clone(),
        Err(_) => Vec::new(),
    };

    // 4. Start incremental sync.
    let sync_input = StartSyncInput {
        mode: "incremental".to_string(),
        folders: discovered_folders.clone(),
        since: input.since.clone(),
    };

    let sync_run = match svc.start_sync_run(&user_id, &account.id, &sync_input).await {
        Ok(run) => run,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": { "code": "IMPORT_SYNC_START_FAILED", "message": e.to_string() }
            }));
        }
    };

    // 5. Return configuration result with progress endpoint.
    HttpResponse::Ok().json(serde_json::json!({
        "status": "configured",
        "accountId": account.id,
        "provider": provider,
        "email": input.email,
        "syncRunId": sync_run.id,
        "discoveredFolders": discovered_folders,
        "maxEmails": max_emails,
        "progressUrl": format!("/api/external-accounts/{}/sync/status", account.id),
        "folderMappingUrl": format!("/api/external-accounts/{}/folders/discover", account.id)
    }))
}

/// Normalize provider slug for the import wizard.
/// Accepts common aliases (google→gmail, office365/outlook365→outlook).
fn normalize_import_provider(provider: &str) -> Option<String> {
    let p = provider.trim().to_ascii_lowercase();
    match p.as_str() {
        "gmail" | "google" => Some("gmail".to_string()),
        "outlook" | "office365" | "outlook365" | "hotmail" | "live" => Some("outlook".to_string()),
        "yahoo" | "ymail" => Some("yahoo".to_string()),
        "generic" | "imap" => Some("generic".to_string()),
        _ => None,
    }
}

/// Build CreateExternalAccountInput from import wizard input.
fn build_create_account_input(
    provider: &str,
    input: &ImportConfigureInput,
) -> CreateExternalAccountInput {
    let auth_type = if input.auth_type.is_empty() {
        match provider {
            "gmail" | "outlook" | "yahoo" => "oauth2".to_string(),
            _ => "password".to_string(),
        }
    } else {
        input.auth_type.clone()
    };

    let imap = ExternalImapServerConfig {
        host: input
            .imap_host
            .clone()
            .unwrap_or_else(|| default_imap_host(provider)),
        port: input.imap_port.unwrap_or_else(|| default_imap_port(provider, input.imap_tls)),
        tls: input.imap_tls,
    };

    let smtp = Some(ExternalSmtpServerConfig {
        host: input.smtp_host.clone().or_else(|| default_smtp_host(provider)),
        port: input.smtp_port.or_else(|| default_smtp_port(provider)),
        tls: input.smtp_tls,
    });

    let credentials = Some(ExternalAccountCredentials {
        secret_value: input.password.clone(),
        secret_ref: input.access_token.clone(),
    });

    CreateExternalAccountInput {
        provider: provider.to_string(),
        email: input.email.clone(),
        auth_type,
        imap,
        smtp,
        credentials,
    }
}

fn default_imap_host(provider: &str) -> String {
    match provider {
        "gmail" => "imap.gmail.com".to_string(),
        "outlook" => "outlook.office365.com".to_string(),
        "yahoo" => "imap.mail.yahoo.com".to_string(),
        _ => String::new(),
    }
}

fn default_imap_port(provider: &str, tls: bool) -> u16 {
    match provider {
        "generic" => {
            if tls {
                993
            } else {
                143
            }
        }
        _ => 993,
    }
}

fn default_smtp_host(provider: &str) -> Option<String> {
    match provider {
        "gmail" => Some("smtp.gmail.com".to_string()),
        "outlook" => Some("smtp.office365.com".to_string()),
        "yahoo" => Some("smtp.mail.yahoo.com".to_string()),
        _ => None,
    }
}

fn default_smtp_port(provider: &str) -> Option<u16> {
    match provider {
        "gmail" => Some(587),
        "outlook" => Some(587),
        "yahoo" => Some(587),
        _ => None,
    }
}
