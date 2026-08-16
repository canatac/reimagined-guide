#![allow(unused_imports, dead_code)]
use super::super::*;

pub(crate) async fn api_external_folders_list(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.list_folders(&user_id, &account_id).await {
        Ok(folders) => HttpResponse::Ok().json(serde_json::json!({ "folders": folders })),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDERS_LIST_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_folders_discover(
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

    match svc.discover_folders(&user_id, &account).await {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDERS_DISCOVER_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_folder_mapping_put(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    payload: web::Json<ExternalFolderMappingInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let (account_id, folder_id) = path.into_inner();
    match svc
        .upsert_folder_mapping(&user_id, &account_id, &folder_id, &payload.local_role)
        .await
    {
        Ok(Some(folder)) => HttpResponse::Ok().json(folder),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDER_NOT_FOUND", "message": "Folder not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_FOLDER_MAPPING_FAILED", "message": e.to_string()}})),
    }
}
