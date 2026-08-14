// external_handlers.rs — Sprint 2: extracted api_external_*, api_openapi_json, api_swagger_ui
// Recovered from git (ef79505) — handlers that were beyond the original extraction boundary

use super::*;

pub(crate) async fn api_openapi_json() -> impl Responder {
    static SPEC_JSON: &str = r#"{
        "openapi": "3.0.3",
        "info": {
            "title": "Email API",
            "version": "1.0.0",
            "description": "Backend API for the mail server"
        },
        "paths": {
            "/api/auth/login": { "post": { "tags": ["Auth"], "summary": "Login", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/register": { "post": { "tags": ["Auth"], "summary": "Register", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/logout": { "post": { "tags": ["Auth"], "summary": "Logout", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/refresh": { "post": { "tags": ["Auth"], "summary": "Refresh token", "responses": { "200": { "description": "OK" } } } },
            "/api/user/locale": { "patch": { "tags": ["Auth"], "summary": "Update user locale", "responses": { "200": { "description": "OK" } } } },
            "/api/auth/oauth/{provider}": { "get": { "tags": ["Auth"], "summary": "Start OAuth flow", "parameters": [{ "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "302": { "description": "Redirect" } } } },
            "/api/auth/oauth/{provider}/callback": { "get": { "tags": ["Auth"], "summary": "OAuth callback", "parameters": [{ "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "302": { "description": "Redirect" } } } },
            "/api/emails": { "get": { "tags": ["Emails"], "summary": "List emails", "responses": { "200": { "description": "OK" } } } },
            "/api/emails/{id}": {
                "get": { "tags": ["Emails"], "summary": "Get email by ID", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/emails/{id}/action": {
                "post": { "tags": ["Emails"], "summary": "Perform action on email (move, delete, read, unread, star, unstar)", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/tags": { "get": { "tags": ["Emails"], "summary": "List tags", "responses": { "200": { "description": "OK" } } } },
            "/api/send": { "post": { "tags": ["Send"], "summary": "Send an email", "responses": { "200": { "description": "OK" } } } },
            "/api/send/{id}/status": { "get": { "tags": ["Send"], "summary": "Get send status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/drafts": {
                "get": { "tags": ["Drafts"], "summary": "List drafts", "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["Drafts"], "summary": "Create or update draft", "responses": { "200": { "description": "OK" } } }
            },
            "/api/drafts/{id}": { "delete": { "tags": ["Drafts"], "summary": "Delete draft", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/templates": { "get": { "tags": ["Templates"], "summary": "List templates", "responses": { "200": { "description": "OK" } } } },
            "/api/settings/ai": {
                "get": { "tags": ["AI"], "summary": "Get AI settings", "responses": { "200": { "description": "OK" } } },
                "put": { "tags": ["AI"], "summary": "Update AI settings", "responses": { "200": { "description": "OK" } } }
            },
            "/api/hermes/chat": { "post": { "tags": ["Hermes"], "summary": "Chat completions proxy", "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs": { "post": { "tags": ["Hermes"], "summary": "Create run", "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs/{run_id}": { "get": { "tags": ["Hermes"], "summary": "Get run status", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/hermes/runs/{run_id}/events": { "get": { "tags": ["Hermes"], "summary": "Stream run events (SSE)", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "SSE stream" } } } },
            "/api/calendar/events": {
                "get": { "tags": ["Calendar"], "summary": "List calendar events", "parameters": [{ "name": "start", "in": "query", "schema": { "type": "string", "format": "date-time" } }, { "name": "end", "in": "query", "schema": { "type": "string", "format": "date-time" } }], "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["Calendar"], "summary": "Create calendar event", "responses": { "201": { "description": "Created" } } }
            },
            "/api/calendar/events/{id}": {
                "get": { "tags": ["Calendar"], "summary": "Get calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "put": { "tags": ["Calendar"], "summary": "Update calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "tags": ["Calendar"], "summary": "Delete calendar event", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/events": { "get": { "tags": ["Events"], "summary": "List events", "responses": { "200": { "description": "OK" } } } },
            "/api/events/stream": { "get": { "tags": ["Events"], "summary": "SSE event stream", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/monitoring/summary": { "get": { "tags": ["Monitoring"], "summary": "SMTP monitoring summary", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/events": { "get": { "tags": ["Monitoring"], "summary": "SMTP monitoring events", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/messages/{message_id}/trace": { "get": { "tags": ["Monitoring"], "summary": "Message delivery trace", "parameters": [{ "name": "message_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/bounces": { "get": { "tags": ["Monitoring"], "summary": "Bounce list", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/providers/top": { "get": { "tags": ["Monitoring"], "summary": "Top providers", "responses": { "200": { "description": "OK" } } } },
            "/api/monitoring/live": { "get": { "tags": ["Monitoring"], "summary": "Live SMTP events (SSE)", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/monitoring/alerts/active": { "get": { "tags": ["Monitoring"], "summary": "Active monitoring alerts", "responses": { "200": { "description": "OK" } } } },
            "/api/security/alerts/active": { "get": { "tags": ["Security"], "summary": "Active security alerts", "responses": { "200": { "description": "OK" } } } },
            "/api/security/incidents": { "get": { "tags": ["Security"], "summary": "Security incidents", "responses": { "200": { "description": "OK" } } } },
            "/api/security/live": { "get": { "tags": ["Security"], "summary": "Live security events (SSE)", "responses": { "200": { "description": "SSE stream" } } } },
            "/api/security/tenant/{id}/status": { "get": { "tags": ["Security"], "summary": "Tenant security status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/security/remediation/{alert_id}/rollback": { "post": { "tags": ["Security"], "summary": "Rollback remediation", "parameters": [{ "name": "alert_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts": {
                "get": { "tags": ["External IMAP"], "summary": "List external accounts", "responses": { "200": { "description": "OK" } } },
                "post": { "tags": ["External IMAP"], "summary": "Create external account", "responses": { "200": { "description": "OK" } } }
            },
            "/api/external-accounts/{id}": {
                "get": { "tags": ["External IMAP"], "summary": "Get external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "patch": { "tags": ["External IMAP"], "summary": "Update external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } },
                "delete": { "tags": ["External IMAP"], "summary": "Delete external account", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } }
            },
            "/api/external-accounts/{id}/test": { "post": { "tags": ["External IMAP"], "summary": "Test IMAP connection", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders": { "get": { "tags": ["External IMAP"], "summary": "List folders", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders/discover": { "post": { "tags": ["External IMAP"], "summary": "Discover folders", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/folders/{folder_id}/mapping": { "put": { "tags": ["External IMAP"], "summary": "Set folder mapping", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }, { "name": "folder_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync": { "post": { "tags": ["External IMAP"], "summary": "Start sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/status": { "get": { "tags": ["External IMAP"], "summary": "Get sync status", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/pause": { "post": { "tags": ["External IMAP"], "summary": "Pause sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-accounts/{id}/sync/resume": { "post": { "tags": ["External IMAP"], "summary": "Resume sync", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-sync-runs/{run_id}": { "get": { "tags": ["External IMAP"], "summary": "Get sync run", "parameters": [{ "name": "run_id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-messages": { "get": { "tags": ["External IMAP"], "summary": "List external messages", "parameters": [{ "name": "account_id", "in": "query", "required": true, "schema": { "type": "string" } }, { "name": "folder", "in": "query", "schema": { "type": "string" } }, { "name": "page", "in": "query", "schema": { "type": "integer" } }, { "name": "page_size", "in": "query", "schema": { "type": "integer" } }], "responses": { "200": { "description": "OK" } } } },
            "/api/external-messages/{id}/action": { "post": { "tags": ["External IMAP"], "summary": "Apply action on external message", "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }], "responses": { "200": { "description": "OK" } } } }
        }
    }"#;
    let spec: serde_json::Value = serde_json::from_str(SPEC_JSON).unwrap_or_default();
    HttpResponse::Ok().json(spec)
}

pub(crate) async fn api_swagger_ui() -> impl Responder {
    let html = r##"<!DOCTYPE html>
<html>
<head>
  <title>Email API — Swagger UI</title>
  <meta charset="utf-8"/>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger-ui", presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset] });
</script>
</body>
</html>"##;
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

pub(crate) async fn api_external_openapi() -> impl Responder {
    static OPENAPI_YAML: &str = include_str!("../../ops/openapi/external-imap-v1.yaml");
    HttpResponse::Ok()
        .content_type("application/yaml; charset=utf-8")
        .body(OPENAPI_YAML)
}

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

pub(crate) async fn api_external_sync_start(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<StartSyncInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();

    let account = match svc.get_account_raw(&user_id, &account_id).await {
        Ok(Some(a)) => a,
        Ok(None) => return HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_FETCH_FAILED", "message": e.to_string()}})),
    };

    let run = match svc.start_sync_run(&user_id, &account_id, &payload).await {
        Ok(run) => run,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_START_FAILED", "message": e.to_string()}})),
    };

    match svc.run_sync_now(&user_id, &account, &run).await {
        Ok(stats) => {
            let updated = svc
                .complete_sync_run(&user_id, &run.id, "success", stats, None)
                .await
                .ok()
                .flatten();
            HttpResponse::Ok()
                .json(serde_json::json!({ "runId": run.id, "status": "success", "run": updated }))
        }
        Err(e) => {
            let _ = svc
                .complete_sync_run(
                    &user_id,
                    &run.id,
                    "failed",
                    simple_smtp_server::external_imap::SyncExecutionResult {
                        fetched: 0,
                        updated: 0,
                        deleted: 0,
                        discovered_folders: 0,
                    },
                    Some(e.to_string()),
                )
                .await;
            HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_EXECUTION_FAILED", "message": e.to_string()}, "runId": run.id}))
        }
    }
}

pub(crate) async fn api_external_sync_run_get(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let run_id = path.into_inner();
    match svc.get_sync_run(&user_id, &run_id).await {
        Ok(Some(run)) => HttpResponse::Ok().json(run),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RUN_NOT_FOUND", "message": "Sync run not found"}})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RUN_FETCH_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_status(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.get_sync_status(&user_id, &account_id).await {
        Ok(Some(run)) => HttpResponse::Ok().json(run),
        Ok(None) => HttpResponse::Ok().json(serde_json::json!({"status": "idle"})),
        Err(e) => HttpResponse::InternalServerError()
            .json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_STATUS_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_pause(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.set_account_status(&user_id, &account_id, "paused").await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_PAUSE_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_sync_resume(
    req: HttpRequest,
    path: web::Path<String>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let account_id = path.into_inner();
    match svc.set_account_status(&user_id, &account_id, "active").await {
        Ok(Some(account)) => HttpResponse::Ok().json(account),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_ACCOUNT_NOT_FOUND", "message": "External account not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_SYNC_RESUME_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_messages_list(
    req: HttpRequest,
    query: web::Query<ExternalMessagesQuery>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(50).min(200);
    match svc
        .list_messages(
            &user_id,
            &query.account_id,
            query.folder.as_deref(),
            page,
            page_size,
        )
        .await
    {
        Ok(messages) => HttpResponse::Ok().json(serde_json::json!({ "messages": messages, "page": page, "pageSize": page_size })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGES_LIST_FAILED", "message": e.to_string()}})),
    }
}

pub(crate) async fn api_external_message_action(
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<ExternalMessageActionInput>,
    svc: web::Data<Arc<ExternalImapService>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let message_id = path.into_inner();
    match svc
        .apply_message_action(&user_id, &message_id, &payload)
        .await
    {
        Ok(Some(message)) => HttpResponse::Ok().json(message),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGE_NOT_FOUND", "message": "Message not found"}})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": {"code": "EXTERNAL_MESSAGE_ACTION_FAILED", "message": e.to_string()}})),
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateCalendarEventRequest {
    title: String,
    #[serde(default)]
    description: String,
    start: String, // ISO 8601
    end: String,   // ISO 8601
    #[serde(default = "default_event_type_str")]
    event_type: String,
    #[serde(default = "default_color_str")]
    color: String,
    #[serde(default)]
    location: String,
}

pub(crate) fn default_event_type_str() -> String {
    "default".to_string()
}
pub(crate) fn default_color_str() -> String {
    "#3788d8".to_string()
}

#[derive(Deserialize)]
pub(crate) struct UpdateCalendarEventRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    color: Option<String>,
    #[serde(default)]
    location: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CalendarQueryParams {
    #[serde(default)]
    start: Option<String>, // ISO 8601
    #[serde(default)]
    end: Option<String>, // ISO 8601
}

pub(crate) fn parse_iso_to_bson(s: &str) -> Option<bson::DateTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()))
}

pub(crate) fn get_user_from_headers(req: &actix_web::HttpRequest) -> String {
    // Try x-user-email header, fallback to query param, fallback to env SMTP_USERNAME
    if let Some(email) = req
        .headers()
        .get("x-user-email")
        .and_then(|v| v.to_str().ok())
    {
        return email.to_string();
    }
    // Fallback: use SMTP_USERNAME env var
    env::var("SMTP_USERNAME").unwrap_or_else(|_| "admin@misfits.ai".to_string())
}

// --- Calendar handlers ---

pub(crate) async fn calendar_create_event(
    req_body: web::Json<CreateCalendarEventRequest>,
    req: actix_web::HttpRequest,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start = match parse_iso_to_bson(&req_body.start) {
        Some(dt) => dt,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid start date format, use ISO 8601"}))
        }
    };
    let end = match parse_iso_to_bson(&req_body.end) {
        Some(dt) => dt,
        None => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"error": "Invalid end date format, use ISO 8601"}))
        }
    };

    let mut event = CalendarEvent::new(&user, &req_body.title, start, end);
    event.description = req_body.description.clone();
    event.event_type = req_body.event_type.clone();
    event.color = req_body.color.clone();
    event.location = req_body.location.clone();

    match logic.create_calendar_event(&event).await {
        Ok(_) => HttpResponse::Created().json(&event),
        Err(e) => {
            eprintln!("Calendar create error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to create event"}))
        }
    }
}

pub(crate) async fn calendar_list_events(
    req: actix_web::HttpRequest,
    query: web::Query<CalendarQueryParams>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);

    let start_after = query.start.as_ref().and_then(|s| parse_iso_to_bson(s));
    let start_before = query.end.as_ref().and_then(|s| parse_iso_to_bson(s));

    match logic
        .get_calendar_events(&user, start_after, start_before)
        .await
    {
        Ok(events) => {
            HttpResponse::Ok().json(serde_json::json!({"events": events, "total": events.len()}))
        }
        Err(e) => {
            eprintln!("Calendar list error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to list events"}))
        }
    }
}

pub(crate) async fn calendar_get_event(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    match logic.get_calendar_event(&user, &event_id).await {
        Ok(Some(event)) => HttpResponse::Ok().json(&event),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Event not found"})),
        Err(e) => {
            eprintln!("Calendar get error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to get event"}))
        }
    }
}

pub(crate) async fn calendar_update_event(
    req_body: web::Json<UpdateCalendarEventRequest>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    let mut update = bson::Document::new();
    if let Some(title) = &req_body.title {
        update.insert("title", title.clone());
    }
    if let Some(desc) = &req_body.description {
        update.insert("description", desc.clone());
    }
    if let Some(start) = &req_body.start {
        match parse_iso_to_bson(start) {
            Some(dt) => {
                update.insert("start", dt);
            }
            None => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Invalid start date format"}))
            }
        }
    }
    if let Some(end) = &req_body.end {
        match parse_iso_to_bson(end) {
            Some(dt) => {
                update.insert("end", dt);
            }
            None => {
                return HttpResponse::BadRequest()
                    .json(serde_json::json!({"error": "Invalid end date format"}))
            }
        }
    }
    if let Some(et) = &req_body.event_type {
        update.insert("event_type", et.clone());
    }
    if let Some(color) = &req_body.color {
        update.insert("color", color.clone());
    }
    if let Some(loc) = &req_body.location {
        update.insert("location", loc.clone());
    }

    if update.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "No fields to update"}));
    }

    match logic.update_calendar_event(&user, &event_id, update).await {
        Ok(Some(event)) => HttpResponse::Ok().json(&event),
        Ok(None) => HttpResponse::NotFound().json(serde_json::json!({"error": "Event not found"})),
        Err(e) => {
            eprintln!("Calendar update error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to update event"}))
        }
    }
}

pub(crate) async fn calendar_delete_event(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    logic: web::Data<Arc<Logic>>,
) -> impl Responder {
    let user = get_user_from_headers(&req);
    let event_id = path.into_inner();

    match logic.delete_calendar_event(&user, &event_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"deleted": true})),
        Err(e) => {
            eprintln!("Calendar delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "Failed to delete event"}))
        }
    }
}

#[actix_web::main]
pub(crate) async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // rustls 0.23 requires an explicit process-level CryptoProvider.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    // Connect to MongoDB for auth
    let mongo_user = env::var("MONGODB_USERNAME").unwrap_or_default();
    let mongo_pass = env::var("MONGODB_PASSWORD").unwrap_or_default();
    let mongo_cluster =
        env::var("MONGODB_CLUSTER_URL").unwrap_or_else(|_| "mongodb:27017".to_string());
    let mongo_app = env::var("MONGODB_APP_NAME").unwrap_or_else(|_| "mailserver".to_string());

    // If MONGODB_CLUSTER_URL is already a full URI (e.g. from 1Password), use it directly.
    let client_uri = if mongo_cluster.starts_with("mongodb://")
        || mongo_cluster.starts_with("mongodb+srv://")
    {
        let base = mongo_cluster.trim_end_matches('&').trim_end_matches('?');
        // Use ? or & depending on whether query params already exist
        let sep = if base.contains('?') { "&" } else { "?" };
        format!(
            "{}{}appName={}&serverSelectionTimeoutMS=5000",
            base, sep, mongo_app
        )
    } else if mongo_cluster.contains(".mongodb.net") {
        format!("mongodb+srv://{}:{}@{}/?retryWrites=true&w=majority&appName={}&serverSelectionTimeoutMS=5000", mongo_user, mongo_pass, mongo_cluster, mongo_app)
    } else {
        format!(
            "mongodb://{}:{}@{}/?authSource=admin&appName={}&serverSelectionTimeoutMS=5000",
            mongo_user, mongo_pass, mongo_cluster, mongo_app
        )
    };

    let use_mongodb = env::var("USE_MONGODB").unwrap_or_else(|_| "false".to_string()) == "true";

    let mongo_client = if use_mongodb && !mongo_user.is_empty() {
        match mongodb::Client::with_uri_str(&client_uri).await {
            Ok(c) => {
                let c = Arc::new(c);
                // Warm-up: force DNS resolution + TLS + MongoDB handshake at startup
                // so the first user login is not delayed by 10-30s.
                if let Err(e) = c
                    .database("admin")
                    .run_command(mongodb::bson::doc! {"ping": 1})
                    .await
                {
                    eprintln!("MongoDB warm-up ping failed (non-fatal): {}", e);
                } else {
                    println!("MongoDB connection ready.");
                }
                Some(c)
            }
            Err(e) => {
                eprintln!("MongoDB connection failed: {}, auth will use env vars", e);
                None
            }
        }
    } else {
        None
    };

    let fallback_client = Arc::new(
        mongodb::Client::with_uri_str("mongodb://localhost:27017")
            .await
            .unwrap(),
    );
    let shared_mongo = mongo_client
        .clone()
        .unwrap_or_else(|| fallback_client.clone());
    let logic = web::Data::new(Arc::new(Logic::new(
        mongo_client.unwrap_or(fallback_client),
    )));
    let mongo_data = web::Data::new(shared_mongo.clone());
    let external_imap_service =
        web::Data::new(Arc::new(ExternalImapService::new(shared_mongo.clone())));

    let (event_tx, _) = broadcast::channel::<MailEvent>(256);
    let event_bus = web::Data::new(event_tx);

    // Init global SMTP monitoring bus + background persistence task
    monitoring::init_bus();
    monitoring::storage::start_persistence_task(shared_mongo.clone());
    let shared_mongo_idx = shared_mongo.clone();
    tokio::spawn(async move {
        monitoring::storage::ensure_indexes(&shared_mongo_idx).await;
    });

    // Init security monitoring bus + background evaluation engine
    security::init_bus();
    let sec_mongo = shared_mongo.clone();
    tokio::spawn(async move {
        security::audit::ensure_indexes(&sec_mongo).await;
    });
    security::audit::start_engine(shared_mongo.clone());

    // Start send queue background worker
    let sq_mongo = shared_mongo.clone();
    tokio::spawn(send_queue_worker(sq_mongo));

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(
            env::var("PRIVKEY_PATH").expect("PRIVKEY_PATH must be set"),
            SslFiletype::PEM,
        )
        .unwrap();
    builder
        .set_certificate_chain_file(env::var("FULLCHAIN_PATH").expect("FULLCHAIN_PATH must be set"))
        .unwrap();

    // Start HTTP server on 8000 (for frontend proxy, no TLS)
    let http_logic = logic.clone();
    let http_mongo = mongo_data.clone();
    let http_event_bus = event_bus.clone();
    let http_external_imap = external_imap_service.clone();
    let http_addr = env::var("API_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    let http_server = actix_web::rt::spawn(async move {
        HttpServer::new(move || {
            let cors = Cors::permissive()
                .allow_any_origin()
                .allow_any_method()
                .allow_any_header()
                .supports_credentials()
                .max_age(3600);

            App::new()
                .wrap(cors)
                .app_data(http_logic.clone())
                .app_data(http_mongo.clone())
                .app_data(http_event_bus.clone())
                .app_data(http_external_imap.clone())
                .route("/api/openapi.json", web::get().to(api_openapi_json))
                .route("/api/docs", web::get().to(api_swagger_ui))
                .route(
                    "/api/openapi/external-imap.yaml",
                    web::get().to(api_external_openapi),
                )
                .route(
                    "/api/external-accounts",
                    web::get().to(api_external_accounts_list),
                )
                .route(
                    "/api/external-accounts",
                    web::post().to(api_external_accounts_create),
                )
                .route(
                    "/api/external-accounts/{id}",
                    web::get().to(api_external_account_get),
                )
                .route(
                    "/api/external-accounts/{id}",
                    web::patch().to(api_external_account_patch),
                )
                .route(
                    "/api/external-accounts/{id}",
                    web::delete().to(api_external_account_delete),
                )
                .route(
                    "/api/external-accounts/{id}/test",
                    web::post().to(api_external_account_test),
                )
                .route(
                    "/api/external-accounts/{id}/folders",
                    web::get().to(api_external_folders_list),
                )
                .route(
                    "/api/external-accounts/{id}/folders/discover",
                    web::post().to(api_external_folders_discover),
                )
                .route(
                    "/api/external-accounts/{id}/folders/{folder_id}/mapping",
                    web::put().to(api_external_folder_mapping_put),
                )
                .route(
                    "/api/external-accounts/{id}/sync",
                    web::post().to(api_external_sync_start),
                )
                .route(
                    "/api/external-accounts/{id}/sync/status",
                    web::get().to(api_external_sync_status),
                )
                .route(
                    "/api/external-accounts/{id}/sync/pause",
                    web::post().to(api_external_sync_pause),
                )
                .route(
                    "/api/external-accounts/{id}/sync/resume",
                    web::post().to(api_external_sync_resume),
                )
                .route(
                    "/api/external-sync-runs/{run_id}",
                    web::get().to(api_external_sync_run_get),
                )
                .route(
                    "/api/external-messages",
                    web::get().to(api_external_messages_list),
                )
                .route(
                    "/api/external-messages/{id}/action",
                    web::post().to(api_external_message_action),
                )
                .route("/api/auth/login", web::post().to(auth_login))
                .route("/api/auth/register", web::post().to(auth_register))
                .route("/api/auth/logout", web::post().to(auth_logout))
                .route("/api/auth/refresh", web::post().to(auth_refresh))
                .route("/api/auth/2fa/verify", web::post().to(api_2fa_verify))
                .route(
                    "/api/auth/password-reset/request",
                    web::post().to(api_password_reset_request),
                )
                .route(
                    "/api/auth/password-reset/confirm",
                    web::post().to(api_password_reset_confirm),
                )
                .route("/api/user/locale", web::patch().to(api_patch_user_locale))
                .route(
                    "/api/auth/oauth/{provider}",
                    web::get().to(auth_oauth_start),
                )
                .route(
                    "/api/auth/oauth/{provider}/start",
                    web::get().to(auth_oauth_start),
                )
                .route(
                    "/api/auth/oauth/{provider}/callback",
                    web::get().to(auth_oauth_callback),
                )
                .route("/api/emails", web::get().to(api_emails))
                .route("/api/emails/{id}", web::get().to(api_email_by_id))
                .route("/api/emails/{id}/action", web::post().to(api_email_action))
                .route("/api/tags", web::get().to(api_tags))
                .route("/api/send", web::post().to(api_send))
                .route("/api/send/{id}/status", web::get().to(api_send_status))
                .route("/api/drafts", web::get().to(api_drafts_list))
                .route("/api/drafts", web::post().to(api_drafts_upsert))
                .route("/api/drafts/{id}", web::delete().to(api_drafts_delete))
                .route("/api/templates", web::get().to(api_templates))
                .route("/api/settings/ai", web::get().to(api_get_ai_settings))
                .route("/api/settings/ai", web::put().to(api_put_ai_settings))
                .route("/api/hermes/chat", web::post().to(api_hermes_chat))
                .route("/api/hermes/runs", web::get().to(api_hermes_runs_list))
                .route("/api/hermes/runs", web::post().to(api_hermes_runs))
                .route(
                    "/api/hermes/runs/{run_id}",
                    web::get().to(api_hermes_run_status),
                )
                .route(
                    "/api/hermes/runs/{run_id}/events",
                    web::get().to(api_hermes_run_events),
                )
                .route("/api/send/undo", web::post().to(api_send_undo))
                .route("/api/send/schedule", web::post().to(api_send_schedule))
                .route(
                    "/api/calendar/events",
                    web::post().to(calendar_create_event),
                )
                .route("/api/calendar/events", web::get().to(calendar_list_events))
                .route(
                    "/api/calendar/events/{id}",
                    web::get().to(calendar_get_event),
                )
                .route(
                    "/api/calendar/events/{id}",
                    web::put().to(calendar_update_event),
                )
                .route(
                    "/api/calendar/events/{id}",
                    web::delete().to(calendar_delete_event),
                )
                .route("/send-email", web::post().to(send_email_handler))
                .route("/create-mailing-list", web::post().to(create_mailing_list))
                .route(
                    "/send-to-mailing-list",
                    web::post().to(send_to_mailing_list),
                )
                .route("/api/events", web::get().to(api_events))
                .route("/api/events/stream", web::get().to(api_events_stream))
                // SMTP monitoring
                .route(
                    "/api/monitoring/summary",
                    web::get().to(api_monitoring_summary),
                )
                .route(
                    "/api/monitoring/events",
                    web::get().to(api_monitoring_events),
                )
                .route(
                    "/api/monitoring/messages/{message_id}/trace",
                    web::get().to(api_monitoring_trace),
                )
                .route(
                    "/api/monitoring/bounces",
                    web::get().to(api_monitoring_bounces),
                )
                .route(
                    "/api/monitoring/providers/top",
                    web::get().to(api_monitoring_providers_top),
                )
                .route("/api/monitoring/live", web::get().to(api_monitoring_live))
                .route(
                    "/api/monitoring/alerts/active",
                    web::get().to(api_monitoring_alerts_active),
                )
                // Security endpoints
                .route(
                    "/api/security/alerts/active",
                    web::get().to(api_security_alerts_active),
                )
                .route(
                    "/api/security/incidents",
                    web::get().to(api_security_incidents),
                )
                .route("/api/security/live", web::get().to(api_security_live))
                .route(
                    "/api/security/tenant/{id}/status",
                    web::get().to(api_security_tenant_status),
                )
                .route(
                    "/api/security/remediation/{alert_id}/rollback",
                    web::post().to(api_security_rollback),
                )
                .route("/api/admin/users", web::get().to(api_admin_users_list))
                .route("/api/admin/users", web::post().to(api_admin_user_create))
                .route("/api/admin/whoami", web::get().to(api_admin_whoami))
                .route("/api/admin/audit-log", web::get().to(api_admin_audit_log))
                .route(
                    "/api/admin/users/{id}/invite",
                    web::post().to(api_admin_user_invite),
                )
                .route(
                    "/api/admin/users/{id}/reset-password",
                    web::post().to(api_admin_user_reset_password),
                )
                .route(
                    "/api/admin/users/{id}/revoke-sessions",
                    web::post().to(api_admin_user_revoke_sessions),
                )
                .route("/api/admin/users/{id}", web::get().to(api_admin_user_get))
                .route(
                    "/api/admin/users/{id}",
                    web::patch().to(api_admin_user_patch),
                )
                .route(
                    "/api/admin/users/{id}",
                    web::delete().to(api_admin_user_delete),
                )
                .route(
                    "/api/admin/change-requests",
                    web::get().to(api_admin_change_requests_list),
                )
                .route(
                    "/api/admin/change-requests",
                    web::post().to(api_admin_change_request_create),
                )
                .route(
                    "/api/admin/change-requests/{id}",
                    web::get().to(api_admin_change_request_get),
                )
                .route(
                    "/api/admin/change-requests/{id}",
                    web::patch().to(api_admin_change_request_patch),
                )
                .route(
                    "/api/admin/change-requests/{id}",
                    web::delete().to(api_admin_change_request_delete),
                )
                .route(
                    "/api/admin/security/posture",
                    web::get().to(api_admin_security_posture),
                )
                .route(
                    "/api/admin/deliverability/diagnostics",
                    web::get().to(api_admin_deliverability_diagnostics),
                )
                .route(
                    "/api/admin/deliverability/procedure",
                    web::get().to(api_admin_deliverability_procedure),
                )
                .route(
                    "/api/admin/deliverability/procedure",
                    web::post().to(api_admin_deliverability_procedure_update),
                )
                .route(
                    "/api/admin/observability/overview",
                    web::get().to(api_admin_observability_overview),
                )
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
            .route(
                "/send-to-mailing-list",
                web::post().to(send_to_mailing_list),
            )
    })
    .bind_openssl("0.0.0.0:8443", builder)?
    .run()
    .await
}

