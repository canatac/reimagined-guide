//! Email template CRUD handlers with variable substitution.
//!
//! Implements issue #588: POST/GET/PUT/DELETE /api/templates
//! and POST /api/templates/preview for variable substitution.

use std::env;

use actix_web::web;
use actix_web::HttpRequest;
use actix_web::Responder;
use bson;
use bson::doc;
use chrono::Utc;
use futures::TryStreamExt;
use mongodb;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailTemplate {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub variables: Vec<String>,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplateCreateRequest {
    pub name: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub variables: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplateUpdateRequest {
    pub name: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub variables: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplatePreviewRequest {
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub variables: Vec<TemplateVar>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplateVar {
    pub key: String,
    pub value: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn templates_coll(mongo: &Arc<mongodb::Client>) -> mongodb::Collection<bson::Document> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    mongo.database(&db).collection::<bson::Document>("email_templates")
}

fn resolve_user_id(req: &HttpRequest) -> String {
    if let Some(id) = req
        .headers()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return id.to_string();
    }
    if let Some(email) = req
        .headers()
        .get("x-user-email")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return email.split('@').next().unwrap_or(email).to_string();
    }
    env::var("SMTP_USERNAME").unwrap_or_else(|_| "admin".to_string())
}

/// Extract variable names from a template string like "Hello {{name}}, from {{company}}"
fn extract_variables(text: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let mut remaining = text;
    while let Some(start) = remaining.find("{{") {
        if let Some(end) = remaining[start..].find("}}") {
            let var_name = &remaining[start + 2..start + end];
            let trimmed = var_name.trim().to_string();
            if !trimmed.is_empty() && !vars.contains(&trimmed) {
                vars.push(trimmed);
            }
            remaining = &remaining[start + end + 2..];
        } else {
            break;
        }
    }
    vars
}

/// Replace {{key}} placeholders in template with provided variable values
fn apply_substitution(template: &str, variables: &[TemplateVar]) -> String {
    let mut result = template.to_string();
    for var in variables {
        let placeholder = format!("{{{{{}}}}}", var.key);
        result = result.replace(&placeholder, &var.value);
    }
    result
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /api/templates — list user templates
pub(crate) async fn api_templates_list(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = templates_coll(&mongo);
    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "name": 1 })
        .await
    {
        Ok(cursor) => {
            let docs: Vec<bson::Document> = cursor.try_collect().await.unwrap_or_default();
            let templates: Vec<EmailTemplate> = docs
                .into_iter()
                .filter_map(|doc| bson::from_document::<EmailTemplate>(doc).ok())
                .collect();
            actix_web::HttpResponse::Ok().json(serde_json::json!({ "templates": templates }))
        }
        Err(e) => {
            eprintln!("api_templates_list error: {}", e);
            actix_web::HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to list templates" }))
        }
    }
}

/// POST /api/templates — create template
pub(crate) async fn api_templates_create(
    body: web::Json<TemplateCreateRequest>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "message": "name is required"
        }));
    }
    let subject = body.subject.trim().to_string();
    if subject.is_empty() {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "message": "subject is required"
        }));
    }
    let body_text = body.body.trim().to_string();
    if body_text.is_empty() {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "message": "body is required"
        }));
    }

    // Auto-extract variables from subject+body if not provided
    let mut variables = if body.variables.is_empty() {
        let mut v = extract_variables(&subject);
        v.extend(extract_variables(&body_text));
        v.dedup();
        v
    } else {
        body.variables.clone()
    };

    let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
    let template = EmailTemplate {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.clone(),
        name,
        subject,
        body: body_text,
        variables,
        created_at: now,
        updated_at: now,
    };

    let coll = templates_coll(&mongo);
    let payload = match bson::to_document(&template) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("api_templates_create serialize error: {}", e);
            return actix_web::HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create template" }));
        }
    };

    match coll.insert_one(payload).await {
        Ok(_) => actix_web::HttpResponse::Created().json(serde_json::json!({ "template": template })),
        Err(e) => {
            eprintln!("api_templates_create error: {}", e);
            actix_web::HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to create template" }))
        }
    }
}

/// PUT /api/templates/{id} — update template
pub(crate) async fn api_templates_update(
    path: web::Path<String>,
    body: web::Json<TemplateUpdateRequest>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = path.into_inner();
    let mut set_doc = doc! {};

    if let Some(name) = body.name.as_ref() {
        let normalized = name.trim().to_string();
        if normalized.is_empty() {
            return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                "message": "name must not be empty"
            }));
        }
        set_doc.insert("name", normalized);
    }
    if let Some(subject) = body.subject.as_ref() {
        let normalized = subject.trim().to_string();
        if normalized.is_empty() {
            return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                "message": "subject must not be empty"
            }));
        }
        set_doc.insert("subject", normalized);
    }
    if let Some(body_text) = body.body.as_ref() {
        let normalized = body_text.trim().to_string();
        if normalized.is_empty() {
            return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
                "message": "body must not be empty"
            }));
        }
        set_doc.insert("body", normalized);
    }
    if let Some(variables) = body.variables.as_ref() {
        set_doc.insert("variables", variables);
    }

    if set_doc.is_empty() {
        return actix_web::HttpResponse::BadRequest().json(serde_json::json!({
            "message": "No fields to update"
        }));
    }

    set_doc.insert("updated_at", bson::DateTime::from_millis(Utc::now().timestamp_millis()));

    let coll = templates_coll(&mongo);
    match coll
        .update_one(doc! { "user_id": &user_id, "id": &id }, doc! { "$set": set_doc })
        .await
    {
        Ok(result) if result.matched_count == 0 => actix_web::HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "Template not found" })),
        Ok(_) => actix_web::HttpResponse::Ok().json(serde_json::json!({ "ok": true, "id": id })),
        Err(e) => {
            eprintln!("api_templates_update error: {}", e);
            actix_web::HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to update template" }))
        }
    }
}

/// DELETE /api/templates/{id} — delete template
pub(crate) async fn api_templates_delete(
    path: web::Path<String>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let id = path.into_inner();
    let coll = templates_coll(&mongo);
    match coll
        .delete_one(doc! { "user_id": &user_id, "id": &id })
        .await
    {
        Ok(result) if result.deleted_count == 0 => actix_web::HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "Template not found" })),
        Ok(_) => actix_web::HttpResponse::Ok().json(serde_json::json!({ "ok": true, "id": id })),
        Err(e) => {
            eprintln!("api_templates_delete error: {}", e);
            actix_web::HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "Failed to delete template" }))
        }
    }
}

/// POST /api/templates/preview — variable substitution preview
pub(crate) async fn api_templates_preview(
    body: web::Json<TemplatePreviewRequest>,
) -> impl Responder {
    let subject = apply_substitution(&body.subject, &body.variables);
    let body_text = apply_substitution(&body.body, &body.variables);
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "subject": subject,
        "body": body_text,
    }))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_variables_simple() {
        let text = "Hello {{name}}, welcome to {{company}}!";
        let vars = extract_variables(text);
        assert_eq!(vars, vec!["name", "company"]);
    }

    #[test]
    fn extract_variables_dedup() {
        let text = "{{name}} and {{name}} again";
        let vars = extract_variables(text);
        assert_eq!(vars, vec!["name"]);
    }

    #[test]
    fn extract_variables_empty() {
        let vars = extract_variables("no variables here");
        assert!(vars.is_empty());
    }

    #[test]
    fn extract_variables_nested_braces() {
        let vars = extract_variables("{{ a }} and {{b}}");
        assert_eq!(vars, vec!["a", "b"]);
    }

    #[test]
    fn apply_substitution_replaces_all() {
        let template = "Hello {{name}}, from {{company}}";
        let result = apply_substitution(
            template,
            &[
                TemplateVar { key: "name".into(), value: "Alice".into() },
                TemplateVar { key: "company".into(), value: "Acme".into() },
            ],
        );
        assert_eq!(result, "Hello Alice, from Acme");
    }

    #[test]
    fn apply_substitution_missing_var_untouched() {
        let template = "Hello {{name}}, from {{missing}}";
        let result = apply_substitution(
            template,
            &[TemplateVar { key: "name".into(), value: "Alice".into() }],
        );
        assert_eq!(result, "Hello Alice, from {{missing}}");
    }

    #[test]
    fn template_create_request_default() {
        let req = TemplateCreateRequest::default();
        assert!(req.name.is_empty());
        assert!(req.subject.is_empty());
        assert!(req.body.is_empty());
        assert!(req.variables.is_empty());
    }

    #[test]
    fn template_update_request_default() {
        let req = TemplateUpdateRequest::default();
        assert!(req.name.is_none());
        assert!(req.subject.is_none());
        assert!(req.body.is_none());
        assert!(req.variables.is_none());
    }
}
