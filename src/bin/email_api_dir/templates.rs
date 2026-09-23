// templates.rs — Email template CRUD API with variable substitution.
// Endpoints: POST/GET/PUT/DELETE /api/templates, POST /api/templates/preview
#![allow(unused_imports, dead_code)]

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use bson::doc;
use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;

// ── Request types ─────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────

/// Replace {{variable}} placeholders in template string with values from JSON map.
pub(crate) fn substitute_variables(template: String, vars: &serde_json::Value) -> String {
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

pub(crate) fn extract_variables(subject: &str, body: &str) -> Vec<String> {
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
pub(crate) async fn api_templates_create(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<CreateTemplateRequest>,
) -> impl Responder {
    let user_id = crate::resolve_user_id(&req);
    let coll = mongo
        .database(&crate::mongo_db_name())
        .collection::<bson::Document>("email_templates");

    let now = Utc::now().to_rfc3339();
    let variables = if body.variables.is_empty() {
        extract_variables(&body.subject, &body.body)
    } else {
        body.variables.clone()
    };

    let doc = doc! {
        "user_id": &user_id,
        "name": &body.name,
        "subject": &body.subject,
        "body": &body.body,
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
            HttpResponse::Created().json(serde_json::json!({
                "id": id,
                "user_id": user_id,
                "name": body.name,
                "subject": body.subject,
                "body": body.body,
                "variables": variables,
                "created_at": now,
                "updated_at": now,
            }))
        }
        Err(e) => {
            eprintln!("api_templates_create error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": format!("Failed to create template: {}", e),
            }))
        }
    }
}

/// GET /api/templates — List all templates for the current user
pub(crate) async fn api_templates(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::resolve_user_id(&req);
    let coll = mongo
        .database(&crate::mongo_db_name())
        .collection::<bson::Document>("email_templates");

    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "updated_at": -1 })
        .limit(200)
        .await
    {
        Ok(cursor) => {
            let mut templates: Vec<serde_json::Value> = Vec::new();
            for mut docu in cursor
                .try_collect::<Vec<bson::Document>>()
                .await
                .unwrap_or_default()
            {
                docu.remove("_id");
                docu.remove("user_id");
                if let Ok(v) = bson::from_bson::<serde_json::Value>(bson::Bson::Document(docu)) {
                    templates.push(v);
                }
            }
            HttpResponse::Ok().json(serde_json::json!({ "templates": templates }))
        }
        Err(e) => {
            eprintln!("api_templates error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to load templates",
            }))
        }
    }
}

/// GET /api/templates/:id — Get a single template
pub(crate) async fn api_templates_get(
    path: web::Path<String>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::resolve_user_id(&req);
    let id = path.into_inner();
    let coll = mongo
        .database(&crate::mongo_db_name())
        .collection::<bson::Document>("email_templates");

    match bson::oid::ObjectId::parse_str(&id) {
        Ok(obj_id) => match coll
            .find_one(doc! { "_id": obj_id, "user_id": &user_id })
            .await
        {
            Ok(Some(doc)) => {
                let mut doc = doc;
                doc.remove("_id");
                doc.remove("user_id");
                match bson::from_bson::<serde_json::Value>(bson::Bson::Document(doc)) {
                    Ok(v) => HttpResponse::Ok().json(v),
                    Err(e) => {
                        eprintln!("api_templates_get parse error: {}", e);
                        HttpResponse::InternalServerError().json(serde_json::json!({
                            "message": "Failed to parse template",
                        }))
                    }
                }
            }
            Ok(None) => HttpResponse::NotFound().json(serde_json::json!({
                "message": format!("Template {} not found", id),
            })),
            Err(e) => {
                eprintln!("api_templates_get error: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "message": format!("Failed to get template: {}", e),
                }))
            }
        },
        Err(_) => HttpResponse::BadRequest().json(serde_json::json!({
            "message": "Invalid template ID format",
        })),
    }
}

/// PUT /api/templates/:id — Update a template
pub(crate) async fn api_templates_update(
    path: web::Path<String>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<UpdateTemplateRequest>,
) -> impl Responder {
    let user_id = crate::resolve_user_id(&req);
    let id = path.into_inner();
    let coll = mongo
        .database(&crate::mongo_db_name())
        .collection::<bson::Document>("email_templates");

    let obj_id = match bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Invalid template ID format",
            }))
        }
    };

    let now = Utc::now().to_rfc3339();
    let mut set_doc = bson::Document::new();
    set_doc.insert("updated_at", now);
    if let Some(ref name) = body.name {
        set_doc.insert("name", name);
    }
    if let Some(ref subject) = body.subject {
        set_doc.insert("subject", subject);
    }
    if let Some(ref body_text) = body.body {
        set_doc.insert("body", body_text);
    }
    if let Some(ref variables) = body.variables {
        set_doc.insert("variables", variables);
    }

    if set_doc.len() <= 1 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "message": "No fields to update",
        }));
    }

    match coll
        .update_one(doc! { "_id": obj_id, "user_id": &user_id }, doc! { "$set": set_doc })
        .await
    {
        Ok(result) if result.matched_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "updated": true,
            "id": id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "message": format!("Template {} not found", id),
        })),
        Err(e) => {
            eprintln!("api_templates_update error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": format!("Failed to update template: {}", e),
            }))
        }
    }
}

/// DELETE /api/templates/:id — Delete a template
pub(crate) async fn api_templates_delete(
    path: web::Path<String>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = crate::resolve_user_id(&req);
    let id = path.into_inner();
    let coll = mongo
        .database(&crate::mongo_db_name())
        .collection::<bson::Document>("email_templates");

    let obj_id = match bson::oid::ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "message": "Invalid template ID format",
            }))
        }
    };

    match coll
        .delete_one(doc! { "_id": obj_id, "user_id": &user_id })
        .await
    {
        Ok(result) if result.deleted_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "deleted": true,
            "id": id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "message": format!("Template {} not found", id),
        })),
        Err(e) => {
            eprintln!("api_templates_delete error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": format!("Failed to delete template: {}", e),
            }))
        }
    }
}

/// POST /api/templates/preview — Preview template with variable substitution
pub(crate) async fn api_templates_preview(
    body: web::Json<PreviewTemplateRequest>,
) -> impl Responder {
    let subject = substitute_variables(body.subject.clone(), &body.variables);
    let body_text = substitute_variables(body.body.clone(), &body.variables);
    HttpResponse::Ok().json(serde_json::json!({
        "subject": subject,
        "body": body_text,
    }))
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
    fn substitute_variables_numeric_values() {
        let template = "Order #{{order_id}}: ${{amount}}".to_string();
        let vars = serde_json::json!({ "order_id": 42, "amount": "99.99" });
        let result = substitute_variables(template, &vars);
        assert_eq!(result, "Order #42: $99.99");
    }
}
