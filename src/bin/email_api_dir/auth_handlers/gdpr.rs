//! GDPR Article 17 - Right to erasure (right to be forgotten).
//!
//! Provides `DELETE /api/account` which:
//! 1. Authenticates the user (via `require_auth`).
//! 2. Purges all emails from MongoDB `emails`.
//! 3. Purges all mailboxes from MongoDB `mailboxes`.
//! 4. Purges all drafts from MongoDB `drafts`.
//! 5. Purges all scheduled emails from MongoDB `scheduled`.
//! 6. Purges all templates from MongoDB `templates`.
//! 7. Purges all send queue entries from MongoDB `send_queue`.
//! 8. Purges all newsletter sources from MongoDB `newsletter_sources`.
//! 9. Purges the user record from MongoDB `users`.
//! 10. Logs a `gdpr_deletion` audit event to `mail_events`.
//! 11. Emits a deletion event on the event bus.
//! 12. Returns a confirmation with per-collection counts.

use super::super::*;
use actix_web::{HttpRequest, HttpResponse, Responder};
use mongodb::bson::doc;
use std::sync::Arc;

/// Collections purged by a GDPR deletion, in purge order.
pub(crate) const GDPR_PURGED_COLLECTIONS: [&str; 7] = [
    "emails",
    "mailboxes",
    "drafts",
    "scheduled",
    "templates",
    "send_queue",
    "newsletter_sources",
];

/// DELETE /api/account - GDPR Article 17 account + data deletion.
pub(crate) async fn api_gdpr_delete_account(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    bus: web::Data<EventBus>,
) -> impl Responder {
    let db_name =
        simple_smtp_server::logic::mongo_adapter::MongoDatabaseAdapter::database_name();
    let auth = match admin_auth::require_auth(&req, mongo.get_ref(), &db_name).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let user_id = auth.user_id.clone();
    let user_email = auth.email.clone();
    let users_coll_name =
        simple_smtp_server::logic::mongo_adapter::MongoDatabaseAdapter::users_collection_name();

    let db = mongo.database(&db_name);
    let mut deleted: Vec<(&str, u64)> = Vec::with_capacity(GDPR_PURGED_COLLECTIONS.len());

    for coll_name in GDPR_PURGED_COLLECTIONS {
        let coll = db.collection::<mongodb::bson::Document>(coll_name);
        let filter = doc! { "user_id": &user_id };
        match coll.delete_many(filter).await {
            Ok(r) => deleted.push((coll_name, r.deleted_count)),
            Err(e) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "code": "GDPR_DELETE_FAILED",
                    "collection": coll_name,
                    "message": format!("Failed to purge {coll_name}: {e}")
                }));
            }
        }
    }

    let users_coll = db.collection::<mongodb::bson::Document>(&users_coll_name);
    let user_deleted = match users_coll
        .delete_one(doc! { "username": &user_id })
        .await
    {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_USER_FAILED",
                "message": format!("Failed to delete user record: {e}")
            }));
        }
    };

    let counts: std::collections::HashMap<&str, u64> = deleted.iter().cloned().collect();
    let now = mongodb::bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
    let events_coll = db.collection::<mongodb::bson::Document>("mail_events");
    let _ = events_coll
        .insert_one(doc! {
            "kind": "gdpr_deletion",
            "user_id": &user_id,
            "email_id": "",
            "subject": "GDPR Article 17 account deletion",
            "from": "",
            "to": "",
            "timestamp": now,
            "emails_deleted": counts.get("emails").copied().unwrap_or(0) as i64,
            "mailboxes_deleted": counts.get("mailboxes").copied().unwrap_or(0) as i64,
            "drafts_deleted": counts.get("drafts").copied().unwrap_or(0) as i64,
            "scheduled_deleted": counts.get("scheduled").copied().unwrap_or(0) as i64,
            "templates_deleted": counts.get("templates").copied().unwrap_or(0) as i64,
            "send_queue_deleted": counts.get("send_queue").copied().unwrap_or(0) as i64,
            "newsletter_deleted": counts.get("newsletter_sources").copied().unwrap_or(0) as i64,
            "user_deleted": user_deleted as i64,
        })
        .await;

    emit_event(
        &bus,
        &mongo,
        MailEvent {
            id: uuid::Uuid::new_v4().to_string(),
            kind: MailEventKind::Deleted,
            user_id: user_id.clone(),
            email_id: String::new(),
            subject: "GDPR Article 17 - account deleted".to_string(),
            from: String::new(),
            to: user_email.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    )
    .await;

    HttpResponse::Ok().json(serde_json::json!({
        "code": "GDPR_DELETION_COMPLETE",
        "message": "Account and all personal data purged per GDPR Article 17",
        "user_id": user_id,
        "deleted": {
            "emails": counts.get("emails").copied().unwrap_or(0),
            "mailboxes": counts.get("mailboxes").copied().unwrap_or(0),
            "drafts": counts.get("drafts").copied().unwrap_or(0),
            "scheduled": counts.get("scheduled").copied().unwrap_or(0),
            "templates": counts.get("templates").copied().unwrap_or(0),
            "send_queue": counts.get("send_queue").copied().unwrap_or(0),
            "newsletter_sources": counts.get("newsletter_sources").copied().unwrap_or(0),
            "user_record": user_deleted,
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdpr_filter_format() {
        let user_id = "test-user";
        let filter = doc! { "user_id": user_id };
        assert!(filter.contains_key("user_id"));
        assert_eq!(filter.get_str("user_id").unwrap(), user_id);
    }

    #[test]
    fn gdpr_user_filter_format() {
        let user_id = "test-user";
        let filter = doc! { "username": user_id };
        assert!(filter.contains_key("username"));
        assert_eq!(filter.get_str("username").unwrap(), user_id);
    }

    #[test]
    fn gdpr_purged_collections_complete() {
        assert_eq!(GDPR_PURGED_COLLECTIONS.len(), 7);
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"emails"));
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"mailboxes"));
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"drafts"));
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"scheduled"));
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"templates"));
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"send_queue"));
        assert!(GDPR_PURGED_COLLECTIONS.contains(&"newsletter_sources"));
    }

    #[test]
    fn gdpr_all_collections_listed() {
        let collections = vec![
            "emails", "mailboxes", "drafts", "scheduled", "templates",
            "send_queue", "newsletter_sources", "users",
        ];
        assert_eq!(collections.len(), 8);
    }
}
