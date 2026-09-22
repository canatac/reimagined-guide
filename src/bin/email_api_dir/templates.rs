// templates.rs — Email template CRUD API with variable substitution.
// Endpoints: POST/GET/PUT/DELETE /api/templates, POST /api/templates/preview
#![allow(unused_imports, dead_code)]

use actix_web::{web, HttpResponse, Responder};
use bson::{doc, oid::ObjectId, Document};
use chrono::Utc;
use mongodb::Collection;
use serde::{Deserialize, Serialize};

// ── Request / Response types ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailTemplate {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub user_id: String,
    pub name: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub variables: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub variables: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub variables: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct PreviewTemplateRequest {
    pub subject: String,
    pub body: String,
    pub variables: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct TemplateResponse {
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub subject: String,
    pub body: String,
    pub variables: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct TemplatesListResponse {
    pub templates: Vec<TemplateResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn templates_collection() -> Collection<Document> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let mongo_url = std::env::var("MONGODB_URI")
        .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
    let client = mongodb::Client::with_uri_str(&mongo_url)
        .expect("Failed to connect to MongoDB");
    client.database(&db_name).collection("email_templates")
}

fn to_template_response(doc: &Document) -> Option<TemplateResponse> {
    let id = doc.get_object_id("_id").ok()?.to_hex();
    let user_id = doc.get_str("user_id").ok()?.to_string();
    let name = doc.get_str("name").ok()?.to_string();
    let subject = doc.get_str("subject").ok()?.to_string();
    let body = doc.get_str("body").ok()?.to_string();
    let variables = doc
        .get_array("variables")
        .ok()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let created_at = doc.get_str("created_at").ok()?.to_string();
    let updated_at = doc.get_str("updated_at").ok()?.to_string();
    Some(TemplateResponse {
        id,
        user_id,
        name,
        subject,
        body,
        variables,
        created_at,
        updated_at,
    })
}

/// Replace {{variable}} placeholders in template string with values from JSON map.
fn substitute_variables(template: String, vars: &serde_json::Value) -> String {
    let mut result = template;
    if let serde_json::Value::Object(map) = vars {
        for (key, val) in map {
            let placeholder = format!("{{{{{}}}}}", key);
            let replacement = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            result = result.replace(&placeholder, &replacement);
        }
    }
    result
}

/// Extract {{variable}} names from a string without regex.
fn extract_vars_from_str(s: &str) -> Vec<String> {
    let mut vars = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Found {{, look for }}
            let start = i + 2;
            if let Some(end) = s[start..].find("}}") {
                let var_name = &s[start..start + end];
                if !var_name.is_empty() && !vars.contains(&var_name.to_string()) {
                    vars.push(var_name.to_string());
                }
                i = start + end + 2;
                continue;
            }
        }
        i += 1;
    }
    vars
}

fn extract_variables(subject: &str, body: &str) -> Vec<String> {
    let mut vars = extract_vars_from_str(subject);
    let body_vars = extract_vars_from_str(body);
    for v in body_vars {
        if !vars.contains(&v) {
            vars.push(v);
        }
    }
    vars
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// POST /api/templates — Create a new template
pub(crate) async fn create_template(
    req: web::Json<CreateTemplateRequest>,
) -> impl Responder {
    let coll = templates_collection();
    let now = Utc::now().to_rfc3339();
    let variables = if req.variables.is_empty() {
        extract_variables(&req.subject, &req.body)
    } else {
        req.variables.clone()
    };
    let doc = doc! {
        "user_id": "anonymous",
        "name": &req.name,
        "subject": &req.subject,
        "body": &req.body,
        "variables": &variables,
        "created_at": &now,
        "updated_at": &now,
    };
    match coll.insert_one(doc).await {
        Ok(insert_result) => {
            let id = insert_result
                .inserted_id
                .as_object_id()
                .map(|o| o.to_hex())
                .unwrap_or_default();
            HttpResponse::Created().json(TemplateResponse {
                id,
                user_id: "anonymous".to_string(),
                name: req.name.clone(),
                subject: req.subject.clone(),
                body: req.body.clone(),
                variables,
                created_at: now.clone(),
                updated_at: now,
            })
        }
        Err(e) => {
            eprintln!("create_template error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Failed to create template: {}", e),
            })
        }
    }
}

/// GET /api/templates — List all templates
pub(crate) async fn list_templates() -> impl Responder {
    let coll = templates_collection();
    match coll.find(doc! {}).await {
        Ok(mut cursor) => {
            let mut templates = Vec::new();
            use futures_util::stream::TryStreamExt;
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let Some(t) = to_template_response(&doc) {
                    templates.push(t);
                }
            }
            let total = templates.len();
            HttpResponse::Ok().json(TemplatesListResponse { templates, total })
        }
        Err(e) => {
            eprintln!("list_templates error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Failed to list templates: {}", e),
            })
        }
    }
}

/// GET /api/templates/:id — Get a single template
pub(crate) async fn get_template(path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    let coll = templates_collection();
    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid template ID format".to_string(),
            })
        }
    };
    match coll.find_one(doc! { "_id": obj_id }).await {
        Ok(Some(doc)) => {
            if let Some(template) = to_template_response(&doc) {
                HttpResponse::Ok().json(template)
            } else {
                HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "Failed to parse template document".to_string(),
                })
            }
        }
        Ok(None) => HttpResponse::NotFound().json(ErrorResponse {
            error: format!("Template {} not found", id),
        }),
        Err(e) => {
            eprintln!("get_template error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Failed to get template: {}", e),
            })
        }
    }
}

/// PUT /api/templates/:id — Update a template
pub(crate) async fn update_template(
    path: web::Path<String>,
    req: web::Json<UpdateTemplateRequest>,
) -> impl Responder {
    let id = path.into_inner();
    let coll = templates_collection();
    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid template ID format".to_string(),
            })
        }
    };
    let now = Utc::now().to_rfc3339();
    let mut update_doc = doc! { "updated_at": &now };
    if let Some(ref name) = req.name {
        update_doc.insert("name", name);
    }
    if let Some(ref subject) = req.subject {
        update_doc.insert("subject", subject);
    }
    if let Some(ref body) = req.body {
        update_doc.insert("body", body);
    }
    if let Some(ref variables) = req.variables {
        update_doc.insert("variables", variables);
    }
    match coll.update_one(doc! { "_id": obj_id }, doc! { "$set": update_doc }).await {
        Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Template updated"
        })),
        Ok(_) => HttpResponse::NotFound().json(ErrorResponse {
            error: format!("Template {} not found", id),
        }),
        Err(e) => {
            eprintln!("update_template error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Failed to update template: {}", e),
            })
        }
    }
}

/// DELETE /api/templates/:id — Delete a template
pub(crate) async fn delete_template(path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    let coll = templates_collection();
    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                error: "Invalid template ID format".to_string(),
            })
        }
    };
    match coll.delete_one(doc! { "_id": obj_id }).await {
        Ok(result) if result.deleted_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Template deleted"
        })),
        Ok(_) => HttpResponse::NotFound().json(ErrorResponse {
            error: format!("Template {} not found", id),
        }),
        Err(e) => {
            eprintln!("delete_template error: {}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Failed to delete template: {}", e),
            })
        }
    }
}

/// POST /api/templates/preview — Preview template with variable substitution
pub(crate) async fn preview_template(
    req: web::Json<PreviewTemplateRequest>,
) -> impl Responder {
    let subject = substitute_variables(req.subject.clone(), &req.variables);
    let body = substitute_variables(req.body.clone(), &req.variables);
    HttpResponse::Ok().json(PreviewResponse { subject, body })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_variables_replaces_placeholders() {
        let template = "Hello {{name}}, welcome to {{company}}!".to_string();
        let vars = serde_json::json!({ "name": "Alice", "company": "Acme" });
        let result = substitute_variables(template, &vars);
        assert_eq!(result, "Hello Alice, welcome to Acme!");
    }

    #[test]
    fn substitute_variables_missing_key_leaves_placeholder() {
        let template = "Hello {{name}}, from {{company}}".to_string();
        let vars = serde_json::json!({ "name": "Bob" });
        let result = substitute_variables(template, &vars);
        assert_eq!(result, "Hello Bob, from {{company}}");
    }

    #[test]
    fn substitute_variables_empty_vars() {
        let template = "Static text".to_string();
        let vars = serde_json::json!({});
        let result = substitute_variables(template, &vars);
        assert_eq!(result, "Static text");
    }

    #[test]
    fn extract_variables_from_subject_and_body() {
        let subject = "Re: {{topic}}";
        let body = "Hi {{name}},\n\nRegarding {{topic}}...";
        let vars = extract_variables(subject, body);
        assert!(vars.contains(&"name".to_string()));
        assert!(vars.contains(&"topic".to_string()));
        assert_eq!(vars.len(), 2);
    }

    #[test]
    fn extract_variables_no_duplicates() {
        let subject = "{{greeting}} {{greeting}}";
        let body = "{{greeting}}";
        let vars = extract_variables(subject, body);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0], "greeting");
    }

    #[test]
    fn extract_variables_empty_string() {
        let vars = extract_variables("", "");
        assert!(vars.is_empty());
    }

    #[test]
    fn create_template_request_deserializes() {
        let json = serde_json::json!({
            "name": "Welcome",
            "subject": "Welcome {{name}}",
            "body": "Hi {{name}}, thanks for joining!",
            "variables": ["name"]
        });
        let req: CreateTemplateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "Welcome");
        assert_eq!(req.variables, vec!["name"]);
    }

    #[test]
    fn update_template_request_deserializes_partial() {
        let json = serde_json::json!({ "name": "Updated" });
        let req: UpdateTemplateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, Some("Updated".to_string()));
        assert!(req.body.is_none());
    }

    #[test]
    fn preview_request_deserializes() {
        let json = serde_json::json!({
            "subject": "Hello {{name}}",
            "body": "Welcome to {{company}}",
            "variables": { "name": "Alice", "company": "Acme" }
        });
        let req: PreviewTemplateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.subject, "Hello {{name}}");
    }

    #[test]
    fn substitute_variables_numeric_values() {
        let template = "Order #{{order_id}}: \${{amount}}".to_string();
        let vars = serde_json::json!({ "order_id": 42, "amount": "99.99" });
        let result = substitute_variables(template, &vars);
        assert_eq!(result, "Order #42: $99.99");
    }
}
