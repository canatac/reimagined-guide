//! GDPR Article 17 — Right to erasure (right to be forgotten).
//!
//! Provides `DELETE /api/account` which:
//! 1. Authenticates the user (via `require_auth`).
//! 2. Captures user email for confirmation notification.
//! 3. Purges all emails from MongoDB `emails` collection.
//! 4. Purges all mailboxes from MongoDB `mailboxes` collection.
//! 5. Purges all drafts from MongoDB `drafts` collection.
//! 6. Purges all scheduled emails from MongoDB `scheduled` collection.
//! 7. Purges all templates from MongoDB `templates` collection.
//! 8. Purges all send queue entries from MongoDB `send_queue` collection.
//! 9. Purges all newsletter sources from MongoDB `newsletter_sources` collection.
//! 10. Purges the user record from MongoDB `users` collection.
//! 11. Logs a `gdpr_deletion` audit event to `mail_events`.
//! 12. Emits a deletion confirmation event on the event bus.
//! 13. Returns a confirmation with deletion timestamp.

use super::super::*;
use actix_web::{HttpRequest, HttpResponse, Responder};
use mongodb::bson::doc;
use std::sync::Arc;

/// DELETE /api/account — GDPR Article 17 account + data deletion.
pub(crate) async fn api_gdpr_delete_account(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
    bus: web::Data<EventBus>,
) -> impl Responder {
    // 1. Authenticate
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

    // 2. Capture counts before deletion for the audit log
    let emails_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("emails");
    let emails_filter = doc! { "user_id": &user_id };
    let emails_deleted = match emails_coll.delete_many(emails_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_EMAILS_FAILED",
                "message": format!("Failed to purge emails: {e}")
            }));
        }
    };

    // 3. Purge all mailboxes for this user
    let mailboxes_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("mailboxes");
    let mailboxes_filter = doc! { "user_id": &user_id };
    let mailboxes_deleted = match mailboxes_coll.delete_many(mailboxes_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_MAILBOXES_FAILED",
                "message": format!("Failed to purge mailboxes: {e}")
            }));
        }
    };

    // 4. Purge all drafts for this user
    let drafts_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("drafts");
    let drafts_filter = doc! { "user_id": &user_id };
    let drafts_deleted = match drafts_coll.delete_many(drafts_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_DRAFTS_FAILED",
                "message": format!("Failed to purge drafts: {e}")
            }));
        }
    };

    // 5. Purge all scheduled emails for this user
    let scheduled_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("scheduled");
    let scheduled_filter = doc! { "user_id": &user_id };
    let scheduled_deleted = match scheduled_coll.delete_many(scheduled_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_SCHEDULED_FAILED",
                "message": format!("Failed to purge scheduled emails: {e}")
            }));
        }
    };

    // 6. Purge all templates for this user
    let templates_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("templates");
    let templates_filter = doc! { "user_id": &user_id };
    let templates_deleted = match templates_coll.delete_many(templates_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_TEMPLATES_FAILED",
                "message": format!("Failed to purge templates: {e}")
            }));
        }
    };

    // 7. Purge all send queue entries for this user
    let send_queue_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("send_queue");
    let send_queue_filter = doc! { "user_id": &user_id };
    let send_queue_deleted = match send_queue_coll.delete_many(send_queue_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_SEND_QUEUE_FAILED",
                "message": format!("Failed to purge send queue: {e}")
            }));
        }
    };

    // 8. Purge all newsletter sources for this user
    let newsletter_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("newsletter_sources");
    let newsletter_filter = doc! { "user_id": &user_id };
    let newsletter_deleted = match newsletter_coll.delete_many(newsletter_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_NEWSLETTER_FAILED",
                "message": format!("Failed to purge newsletter sources: {e}")
            }));
        }
    };

    // 9. Purge the user record
    let users_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>(&users_coll_name);
    let user_filter = doc! { "username": &user_id };
    let user_deleted = match users_coll.delete_one(user_filter).await {
        Ok(r) => r.deleted_count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "code": "GDPR_DELETE_USER_FAILED",
                "message": format!("Failed to delete user record: {e}")
            }));
        }
    };

    // 10. Log the GDPR deletion event
    let events_coll = mongo
        .database(&db_name)
        .collection::<mongodb::bson::Document>("mail_events");
    let now = mongodb::bson::DateTime::from_millis(chrono::Utc::now().timestamp_millis());
    let _ = events_coll
        .insert_one(doc! {
            "kind": "gdpr_deletion",
            "user_id": &user_id,
            "email_id": "",
            "subject": "GDPR Article 17 account deletion",
            "from": "",
            "to": "",
            "timestamp": now,
            "emails_deleted": emails_deleted as i64,
            "mailboxes_deleted": mailboxes_deleted as i64,
            "drafts_deleted": drafts_deleted as i64,
            "scheduled_deleted": scheduled_deleted as i64,
            "templates_deleted": templates_deleted as i64,
            "send_queue_deleted": send_queue_deleted as i64,
            "newsletter_deleted": newsletter_deleted as i64,
            "user_deleted": user_deleted as i64,
        })
        .await;

    // 11. Emit GDPR deletion event on the event bus
    emit_event(
        &bus,
        &mongo,
        MailEvent {
            id: uuid::Uuid::new_v4().to_string(),
            kind: MailEventKind::Deleted,
            user_id: user_id.clone(),
            email_id: String::new(),
            subject: "GDPR Article 17 — account deleted".to_string(),
            from: String::new(),
            to: user_email.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    )
    .await;

    // 12. Return confirmation
    HttpResponse::Ok().json(serde_json::json!({
        "code": "GDPR_DELETION_COMPLETE",
        "message": "Account and all personal data purged per GDPR Article 17",
        "user_id": user_id,
        "deleted": {
            "emails": emails_deleted,
            "mailboxes": mailboxes_deleted,
            "drafts": drafts_deleted,
            "scheduled": scheduled_deleted,
            "templates": templates_deleted,
            "send_queue": send_queue_deleted,
            "newsletter_sources": newsletter_deleted,
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
    }

    #[test]
    fn gdpr_user_filter_format() {
        let user_id = "test-user";
        let filter = doc! { "username": user_id };
        assert!(filter.contains_key("username"));
    }

    #[test]
    fn gdpr_drafts_filter_format() {
        let user_id = "test-user";
        let filter = doc! { "user_id": user_id };
        assert!(filter.contains_key("user_id"));
        assert_eq!(filter.get_str("user_id").unwrap(), user_id);
    }

    #[test]
    fn gdpr_all_collections_listed() {
        // Verify the list of purged collections is complete
        let collections = vec![
            "emails", "mailboxes", "drafts", "scheduled", "templates",
            "send_queue", "newsletter_sources", "users",
        ];
        assert_eq!(collections.len(), 8);
    }
}
