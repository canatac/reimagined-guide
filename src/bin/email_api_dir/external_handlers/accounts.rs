#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_external_accounts_list(
    req: HttpRequest,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
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
) -> impl Responder {
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
) -> impl Responder {
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
) -> impl Responder {
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
) -> impl Responder {
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
) -> impl Responder {
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
}
