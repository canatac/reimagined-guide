#![allow(unused_imports, dead_code)]
use super::super::*;

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
    static OPENAPI_YAML: &str = include_str!("../../../ops/openapi/external-imap-v1.yaml");
    HttpResponse::Ok()
        .content_type("application/yaml; charset=utf-8")
        .body(OPENAPI_YAML)
}
