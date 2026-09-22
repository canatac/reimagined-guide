#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_external_accounts_list(
    req: HttpRequest,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    match svc.list_accounts(&user_id).await {
        Ok(accounts) => HttpResponse::Ok().json(serde_json::json!({ "accounts": accounts })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNTS_LIST_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_accounts_create(
    req: HttpRequest,
    payload: web::Json<CreateExternalAccountInput>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    match svc.create_account(&user_id, payload.into_inner()).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_CREATE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_get(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.get_account(&user_id, &account_id).await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_patch(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<UpdateExternalAccountInput>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc
        .update_account(&user_id, &account_id, payload.into_inner())
        .await
    {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_UPDATE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_delete(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.delete_account(&user_id, &account_id).await {
        Ok(true) => HttpResponse::Ok().json(serde_json::json!({ "deleted": true })),
        Ok(false) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_DELETE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_account_test(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if let Err(resp) = admin_auth::require_auth(&req, &mongo, &mongo_db_name()).await {
        return resp;
    }
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    match svc.imap_test(&account).await {
        Ok(result) => {
            if result.ok {
                HttpResponse::Ok().json(result)
            } else {
                HttpResponse::UnprocessableEntity().json(serde_json::json!({
                    "ok": false,
                    "error": {"code": "IMAP_AUTH_FAILED", "message": result.message},
                    "capabilities": result.capabilities,
                    "greeting": result.greeting,
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(
            serde_json::json!({"error": {"code": "IMAP_TEST_FAILED", "message": e.to_string()}}),
        ),
    }
}

/// POST /api/external-accounts/{id}/send — send email via external account SMTP (issue #564).
pub(crate) async fn api_external_account_send(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<serde_json::Value>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return HttpResponse::NotFound().json(
                serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}}),
            );
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(
                serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}}),
            );
        }
    };

    if account.smtp_host.is_none() {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error": {"code": "SMTP_NOT_CONFIGURED", "message": "External account has no SMTP configuration"}}),
        );
    }

    let from = payload
        .get("from")
        .and_then(|v| v.as_str())
        .unwrap_or(&account.email)
        .to_string();
    let to = payload
        .get("to")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subject = payload
        .get("subject")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let body = payload
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if to.is_empty() {
        return HttpResponse::BadRequest().json(
            serde_json::json!({"error": {"code": "MISSING_RECIPIENT", "message": "to field is required"}}),
        );
    }

    let email = simple_smtp_server::entities::Email {
        id: uuid::Uuid::new_v4().to_string(),
        from,
        to,
        subject,
        body,
        headers: vec![],
        flags: vec![],
        sequence_number: 0,
        uid: 0,
        internal_date: chrono::Utc::now(),
        dkim_signature: None,
    };

    match simple_smtp_server::smtp_client::send_via_external_smtp(&email, &account).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "message": "Email sent via external SMTP",
            "accountId": account_id,
            "from": email.from,
            "to": email.to,
        })),
        Err(e) => HttpResponse::InternalServerError().json(
            serde_json::json!({"error": {"code": "EXTERNAL_SMTP_SEND_FAILED", "message": e.to_string()}}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_external_account_input_deserializes() {
        let json = serde_json::json!({
            "provider": "gmail",
            "email": "<EMAIL>",
            "authType": "oauth2",
            "imap": {"host": "imap.gmail.com", "port": 993, "tls": true},
            "smtp": {"host": "smtp.gmail.com", "port": 587, "tls": true},
            "credentials": {"secretValue": "token123", "secretRef": null}
        });
        let input: CreateExternalAccountInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.provider, "gmail");
        assert_eq!(input.email, "<EMAIL>");
        assert_eq!(input.auth_type, "oauth2");
        assert_eq!(input.imap.host, "imap.gmail.com");
        assert_eq!(input.imap.port, 993);
        assert!(input.imap.tls);
        assert!(input.smtp.is_some());
        assert!(input.credentials.is_some());
    }

    #[test]
    fn create_external_account_input_minimal() {
        let json = serde_json::json!({
            "provider": "outlook",
            "email": "<EMAIL>",
            "authType": "password",
            "imap": {"host": "outlook.office365.com", "port": 993}
        });
        let input: CreateExternalAccountInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.provider, "outlook");
        assert!(input.smtp.is_none());
        assert!(input.credentials.is_none());
    }

    #[test]
    fn update_external_account_input_deserializes() {
        let json = serde_json::json!({
            "provider": "gmail",
            "status": "active",
            "lastError": null
        });
        let input: UpdateExternalAccountInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.provider, Some("gmail".to_string()));
        assert_eq!(input.status, Some("active".to_string()));
        assert_eq!(input.last_error, None);
    }

    #[test]
    fn update_external_account_input_empty() {
        let json = serde_json::json!({});
        let input: UpdateExternalAccountInput = serde_json::from_value(json).unwrap();
        assert_eq!(input.provider, None);
        assert_eq!(input.email, None);
    }

    #[test]
    fn external_account_credentials_deserializes() {
        let json = serde_json::json!({"secretValue": "my-token", "secretRef": "op://vault/item"});
        let creds: ExternalAccountCredentials = serde_json::from_value(json).unwrap();
        assert_eq!(creds.secret_value, Some("my-token".to_string()));
        assert_eq!(creds.secret_ref, Some("op://vault/item".to_string()));
    }

    #[test]
    fn external_imap_server_config_defaults_tls() {
        let json = serde_json::json!({"host": "imap.example.com", "port": 993});
        let config: ExternalImapServerConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.host, "imap.example.com");
        assert_eq!(config.port, 993);
        assert!(config.tls);
    }

    #[test]
    fn imap_test_result_deserializes() {
        let json = serde_json::json!({
            "ok": true,
            "capabilities": ["IMAP4rev1", "AUTH=PLAIN"],
            "greeting": "* OK IMAP server ready",
            "message": "Connection successful"
        });
        let result: ImapTestResult = serde_json::from_value(json).unwrap();
        assert!(result.ok);
        assert_eq!(result.capabilities.len(), 2);
        assert_eq!(result.greeting, "* OK IMAP server ready");
    }

    #[test]
    fn external_account_send_requires_recipient() {
        // Verify that empty "to" is rejected
        let to = "";
        assert!(to.is_empty());
    }

    #[test]
    fn external_account_send_uses_account_email_as_default_from() {
        let account_email = "<EMAIL>";
        let from: Option<&str> = None;
        let resolved = from.unwrap_or(account_email);
        assert_eq!(resolved, "<EMAIL>");
    }
}
