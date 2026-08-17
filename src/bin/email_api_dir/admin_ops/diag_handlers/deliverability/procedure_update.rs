#![allow(unused_imports, dead_code)]
use super::super::super::*;

pub(crate) async fn api_admin_deliverability_procedure_update(
    body: web::Json<DeliverabilityProcedureUpdateRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let db = env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>("admin_runbooks");

    let mut set_doc = doc! {
        "key": "deliverability_procedure",
        "updated_at": Utc::now().to_rfc3339(),
    };

    if let Some(reminder) = body.reminder.as_ref() {
        set_doc.insert(
            "reminder",
            doc! {
                "enabled": reminder.enabled,
                "cadence_hours": (reminder.cadence_hours.max(1) as i32),
                "updated_at": Utc::now().to_rfc3339(),
            },
        );
    }

    if let Some(items) = body.checklist.as_ref() {
        let mut overrides = bson::Document::new();
        for item in items {
            overrides.insert(
                item.id.clone(),
                bson::Bson::Document(doc! {
                    "checked": item.checked,
                    "note": item.note.clone().unwrap_or_default(),
                    "updated_at": Utc::now().to_rfc3339(),
                }),
            );
        }
        set_doc.insert("checklist_overrides", overrides);
    }

    match coll
        .update_one(
            doc! {"key": "deliverability_procedure"},
            doc! {"$set": set_doc},
        )
        .upsert(true)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"ok": true})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "ok": false,
            "error": format!("deliverability_procedure_update_failed: {}", e)
        })),
    }
}
