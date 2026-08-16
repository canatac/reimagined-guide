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
