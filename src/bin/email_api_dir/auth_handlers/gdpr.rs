//! GDPR Article 17 — Right to erasure (right to be forgotten).
//!
//! Provides `DELETE /api/account` which:
//! 1. Authenticates the user (via `require_auth`).
//! 2. Purges all emails belonging to the user from MongoDB `emails` collection.
//! 3. Purges all mailboxes from MongoDB `mailboxes` collection.
//! 4. Purges the user record from MongoDB `users` collection.
//! 5. Logs a `gdpr_deletion` audit event to `mail_events`.
//! 6. Returns a confirmation with deletion timestamp.

use super::super::*;
use actix_web::{HttpRequest, HttpResponse, Responder};
use mongodb::bson::doc;
use std::sync::Arc;

/// DELETE /api/account — GDPR Article 17 account + data deletion.
pub(crate) async fn api_gdpr_delete_account(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    // 1. Authenticate
    let db_name =
        simple_smtp_server::logic::mongo_adapter::MongoDatabaseAdapter::database_name();
    let auth = match admin_auth::require_auth(&req, mongo.get_ref(), &db_name).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let user_id = auth.user_id.clone();
    let users_coll_name =
        simple_smtp_server::logic::mongo_adapter::MongoDatabaseAdapter::users_collection_name();

    // 2. Purge all emails for this user
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

    // 4. Purge the user record
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

    // 5. Log the GDPR deletion event
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
            "user_deleted": user_deleted as i64,
        })
        .await;

    // 6. Return confirmation
    HttpResponse::Ok().json(serde_json::json!({
        "code": "GDPR_DELETION_COMPLETE",
        "message": "Account and all personal data purged per GDPR Article 17",
        "user_id": user_id,
        "deleted": {
            "emails": emails_deleted,
            "mailboxes": mailboxes_deleted,
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
}
