//! Email templates API handlers (issue #588).
//! CRUD for user email templates with variable substitution.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use mongodb::bson;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use uuid::Uuid;

use super::*;

const TEMPLATES_COLL: &str = "email_templates";

fn templates_coll(mongo: &Arc<mongodb::Client>) -> mongodb::Collection<bson::Document> {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    mongo.database(&db).collection::<bson::Document>(TEMPLATES_COLL)
}

/// Substitute variables in template content.
/// Replaces {{varname}} with the provided value.
fn substitute_variables(template: &str, variables: &serde_json::Value) -> String {
    let mut result = template.to_string();
    if let serde_json::Value::Object(map) = variables {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EmailTemplate {
    #[serde(rename = "_id")]
    pub id: String,
    pub user_id: String,
    pub name: String,
    pub subject: String,
    pub body: String,
    pub created_at: bson::DateTime,
    pub updated_at: bson::DateTime,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateTemplateRequest {
    pub name: String,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreviewTemplateRequest {
    pub variables: Option<serde_json::Value>,
}

/// GET /api/templates — list all templates for the current user
pub(crate) async fn api_templates_list(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let coll = templates_coll(&mongo);

    let filter = doc! { "user_id": &user_id };
    let mut cursor = match coll.find(filter).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("api_templates_list find error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "database error" }));
        }
    };

    let mut templates: Vec<bson::Document> = Vec::new();
    while let Ok(true) = cursor.advance().await {
        match cursor.deserialize_current() {
            Ok(doc) => templates.push(doc),
            Err(e) => {
                eprintln!("api_templates_list deserialize error: {}", e);
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({ "templates": templates }))
}

/// POST /api/templates — create a new template
pub(crate) async fn api_templates_create(
    body: web::Json<CreateTemplateRequest>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);

    let name = body.name.trim().to_string();
    if name.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "name is required" }));
    }
    let subject = body.subject.trim().to_string();
    if subject.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "subject is required" }));
    }
    let body_text = body.body.trim().to_string();
    if body_text.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "body is required" }));
    }

    let now = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
    let template = EmailTemplate {
        id: Uuid::new_v4().to_string(),
        user_id,
        name,
        subject,
        body: body_text,
        created_at: now,
        updated_at: now,
    };

    let doc = match bson::to_document(&template) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("api_templates_create serialize error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "serialization error" }));
        }
    };

    let coll = templates_coll(&mongo);
    match coll.insert_one(doc).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "message": "template created",
            "id": template.id,
        })),
        Err(e) => {
            eprintln!("api_templates_create insert error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "database error" }))
        }
    }
}

/// PUT /api/templates/:id — update a template
pub(crate) async fn api_templates_update(
    path: web::Path<String>,
    body: web::Json<UpdateTemplateRequest>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let template_id = path.inner().trim().to_string();

    if template_id.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "template id is required" }));
    }

    let coll = templates_coll(&mongo);
    let filter = doc! { "_id": &template_id, "user_id": &user_id };

    // Check ownership
    let existing = match coll.find_one(filter.clone()).await {
        Ok(opt) => opt,
        Err(e) => {
            eprintln!("api_templates_update find error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "database error" }));
        }
    };

    if existing.is_none() {
        return HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "template not found" }));
    }

    let now = bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
    let mut update_doc = bson::doc! { "updated_at": now };

    if let Some(name) = &body.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "name cannot be empty" }));
        }
        update_doc.insert("name", name);
    }
    if let Some(subject) = &body.subject {
        let subject = subject.trim().to_string();
        if subject.is_empty() {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "subject cannot be empty" }));
        }
        update_doc.insert("subject", subject);
    }
    if let Some(body_text) = &body.body {
        let body_text = body_text.trim().to_string();
        if body_text.is_empty() {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({ "message": "body cannot be empty" }));
        }
        update_doc.insert("body", body_text);
    }

    match coll.update_one(filter, doc! { "$set": update_doc }).await {
        Ok(result) if result.modified_count > 0 || result.matched_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "message": "template updated" }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "template not found" })),
        Err(e) => {
            eprintln!("api_templates_update error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "database error" }))
        }
    }
}

/// DELETE /api/templates/:id — delete a template
pub(crate) async fn api_templates_delete(
    path: web::Path<String>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let template_id = path.inner().trim().to_string();

    if template_id.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "message": "template id is required" }));
    }

    let coll = templates_coll(&mongo);
    let filter = doc! { "_id": &template_id, "user_id": &user_id };

    match coll.delete_one(filter).await {
        Ok(result) if result.deleted_count > 0 => {
            HttpResponse::Ok().json(serde_json::json!({ "message": "template deleted" }))
        }
        Ok(_) => HttpResponse::NotFound()
            .json(serde_json::json!({ "message": "template not found" })),
        Err(e) => {
            eprintln!("api_templates_delete error: {}", e);
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "database error" }))
        }
    }
}

/// POST /api/templates/:id/preview — preview template with variable substitution
pub(crate) async fn api_templates_preview(
    path: web::Path<String>,
    body: web::Json<PreviewTemplateRequest>,
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = resolve_user_id(&req);
    let template_id = path.inner().trim().to_string();

    let coll = templates_coll(&mongo);
    let filter = doc! { "_id": &template_id, "user_id": &user_id };

    let doc = match coll.find_one(filter).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(serde_json::json!({ "message": "template not found" }));
        }
        Err(e) => {
            eprintln!("api_templates_preview find error: {}", e);
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "message": "database error" }));
        }
    };

    let subject = doc.get_str("subject").unwrap_or("").to_string();
    let body_text = doc.get_str("body").unwrap_or("").to_string();

    let variables = body.variables.clone().unwrap_or(serde_json::json!({}));

    let preview_subject = substitute_variables(&subject, &variables);
    let preview_body = substitute_variables(&body_text, &variables);

    HttpResponse::Ok().json(serde_json::json!({
        "subject": preview_subject,
        "body": preview_body,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_variables_replaces_single() {
        let template = "Hello {{name}}, welcome to {{company}}!";
        let variables = serde_json::json!({ "name": "Alice", "company": "Acme" });
        let result = substitute_variables(template, &variables);
        assert_eq!(result, "Hello Alice, welcome to Acme!");
    }

    #[test]
    fn substitute_variables_missing_var_unchanged() {
        let template = "Hello {{name}}, your code is {{code}}";
        let variables = serde_json::json!({ "name": "Bob" });
        let result = substitute_variables(template, &variables);
        assert_eq!(result, "Hello Bob, your code is {{code}}");
    }

    #[test]
    fn substitute_variables_empty_vars() {
        let template = "Static content";
        let variables = serde_json::json!({});
        let result = substitute_variables(template, &variables);
        assert_eq!(result, "Static content");
    }

    #[test]
    fn substitute_variables_multiple_occurrences() {
        let template = "{{greeting}} {{name}}! {{greeting}} again!";
        let variables = serde_json::json!({ "greeting": "Hi", "name": "World" });
        let result = substitute_variables(template, &variables);
        assert_eq!(result, "Hi World! Hi again!");
    }
}
