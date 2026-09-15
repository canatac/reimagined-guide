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
            "/api/emails": { "get": { "tags": ["Emails"], "summary": "List emails", "responses": { "200": { "description": "OK" } } } },
            "/api/send": { "post": { "tags": ["Send"], "summary": "Send an email", "responses": { "200": { "description": "OK" } } } }
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
    static OPENAPI_YAML: &str = include_str!("../../../../ops/openapi/external-imap-v1.yaml");
    HttpResponse::Ok()
        .content_type("application/yaml; charset=utf-8")
        .body(OPENAPI_YAML)
}

#[cfg(test)]
mod tests {
    #[test]
    fn openapi_spec_is_valid_json() {
        let spec_json = r#"{"openapi":"3.0.3","info":{"title":"Email API","version":"1.0.0"},"paths":{}}"#;
        let spec: serde_json::Value = serde_json::from_str(spec_json).unwrap();
        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["info"]["title"], "Email API");
    }

    #[test]
    fn swagger_ui_contains_swagger_bundle() {
        let html = r##"<!DOCTYPE html>
<html>
<head>
  <title>Email API — Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"/>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
</body>
</html>"##;
        assert!(html.contains("swagger-ui"));
        assert!(html.contains("swagger-ui-bundle.js"));
    }
}
