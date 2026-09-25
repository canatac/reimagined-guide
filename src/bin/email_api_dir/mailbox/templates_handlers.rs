//! Email templates CRUD + variable substitution (Issue #588).
//!
//! Templates stored in MongoDB `templates` collection, scoped by user_id.
//! Variable substitution: `{{name}}`, `{{company}}`, etc. replaced at send/preview time.

use super::*;
use actix_web::{web, HttpResponse, Responder};
use bson::doc;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

// ─────────────────────────────── LIST ───────────────────────────────

pub(crate) async fn api_templates_list(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    // Auth guard: require valid session when RBAC is enforced (issue #729)
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("templates");

    match coll
        .find(doc! { "user_id": &user_id })
        .sort(doc! { "updatedAt": -1 })
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
            eprintln!("api_templates_list error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to load templates",
            }))
        }
    }
}

// ─────────────────────────────── CREATE ─────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplateCreateRequest {
    pub name: String,
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub category: Option<String>,
}

pub(crate) async fn api_templates_create(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<TemplateCreateRequest>,
) -> impl Responder {
    // Auth guard: require valid session when RBAC is enforced (issue #729)
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("templates");

    let template_id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let doc = doc! {
        "id": &template_id,
        "user_id": &user_id,
        "name": &body.name,
        "subject": &body.subject,
        "body": &body.body,
        "category": body.category.as_deref().unwrap_or("general"),
        "createdAt": &now,
        "updatedAt": &now,
    };

    match coll.insert_one(doc).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "id": template_id,
            "name": &body.name,
            "subject": &body.subject,
            "body": &body.body,
            "category": body.category.as_deref().unwrap_or("general"),
            "createdAt": &now,
            "updatedAt": &now,
        })),
        Err(e) => {
            eprintln!("api_templates_create error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to create template",
            }))
        }
    }
}

// ─────────────────────────────── UPDATE ─────────────────────────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplateUpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

pub(crate) async fn api_templates_update(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<TemplateUpdateRequest>,
) -> impl Responder {
    // Auth guard: require valid session when RBAC is enforced (issue #729)
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let template_id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("templates");

    // Ensure ownership
    let filter = doc! { "id": &template_id, "user_id": &user_id };
    match coll.find_one(filter.clone()).await {
        Ok(None) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "message": "Template not found",
            }));
        }
        Ok(Some(_)) => {} // ownership confirmed
        Err(e) => {
            eprintln!("api_templates_update find error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to fetch template",
            }));
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut update_doc = doc! { "updatedAt": &now };
    if let Some(name) = &body.name {
        update_doc.insert("name", name);
    }
    if let Some(subject) = &body.subject {
        update_doc.insert("subject", subject);
    }
    if let Some(body_text) = &body.body {
        update_doc.insert("body", body_text);
    }
    if let Some(category) = &body.category {
        update_doc.insert("category", category);
    }

    match coll.update_one(filter, doc! { "$set": update_doc }).await {
        Ok(result) if result.modified_count > 0 || result.matched_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({
                "id": template_id,
                "updatedAt": &now,
            }))
        }
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Template not found",
        })),
        Err(e) => {
            eprintln!("api_templates_update error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to update template",
            }))
        }
    }
}

// ─────────────────────────────── DELETE ─────────────────────────────

pub(crate) async fn api_templates_delete(
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    // Auth guard: require valid session when RBAC is enforced (issue #729)
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let template_id = path.into_inner();
    let coll = mongo
        .database(&mongo_db_name())
        .collection::<bson::Document>("templates");

    match coll
        .delete_one(doc! { "id": &template_id, "user_id": &user_id })
        .await
    {
        Ok(result) if result.deleted_count > 0 => HttpResponse::Ok().json(serde_json::json!({
            "message": "Template deleted",
            "id": template_id,
        })),
        Ok(_) => HttpResponse::NotFound().json(serde_json::json!({
            "message": "Template not found",
        })),
        Err(e) => {
            eprintln!("api_templates_delete error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "message": "Failed to delete template",
            }))
        }
    }
}

// ─────────────────────────── PREVIEW (variable substitution) ───────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TemplatePreviewRequest {
    pub subject: String,
    pub body: String,
    #[serde(default)]
    pub variables: HashMap<String, String>,
}

/// Simple `{{var}}` substitution. Escaped: `\{{` → literal `{{`.
pub(crate) fn substitute_variables(text: &str, vars: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'{') {
            chars.next(); // consume first {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume second {
                result.push_str("{{");
                continue;
            }
            result.push('\\');
            result.push('{');
        } else if c == '{' && chars.peek() == Some(&'{') {
            chars.next(); // consume second {
            // Read variable name until }}
            let mut var_name = String::new();
            let mut closed = false;
            while let Some(c2) = chars.next() {
                if c2 == '}' && chars.peek() == Some(&'}') {
                    chars.next();
                    closed = true;
                    break;
                }
                var_name.push(c2);
            }
            if closed {
                let key = var_name.trim();
                if let Some(val) = vars.get(key) {
                    result.push_str(val);
                } else {
                    result.push_str("{{");
                    result.push_str(&var_name);
                    result.push_str("}}");
                }
            } else {
                result.push_str("{{");
                result.push_str(&var_name);
            }
        } else {
            result.push(c);
        }
    }
    result
}

pub(crate) async fn api_templates_preview(
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    body: web::Json<TemplatePreviewRequest>,
) -> impl Responder {
    // Auth guard: require valid session when RBAC is enforced (issue #729)
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let subject = substitute_variables(&body.subject, &body.variables);
    let body_text = substitute_variables(&body.body, &body.variables);
    HttpResponse::Ok().json(serde_json::json!({
        "subject": subject,
        "body": body_text,
    }))
}

// ─────────────────────────────── TESTS ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_variables_replaces_known() {
        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Alice".to_string());
        vars.insert("company".to_string(), "Acme".to_string());
        let input = "Hello {{name}}, welcome to {{company}}!";
        assert_eq!(
            substitute_variables(input, &vars),
            "Hello Alice, welcome to Acme!"
        );
    }

    #[test]
    fn substitute_variables_keeps_unknown() {
        let vars = HashMap::new();
        let input = "Hello {{unknown}}";
        assert_eq!(substitute_variables(input, &vars), "Hello {{unknown}}");
    }

    #[test]
    fn substitute_variables_escapes_literal() {
        let vars = HashMap::new();
        let input = r"\{{not_a_var}}";
        assert_eq!(substitute_variables(input, &vars), "{{not_a_var}}");
    }

    #[test]
    fn substitute_variables_no_vars() {
        let vars = HashMap::new();
        let input = "Plain text without templates";
        assert_eq!(substitute_variables(input, &vars), "Plain text without templates");
    }
}
