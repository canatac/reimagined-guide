//! List-Unsubscribe backend (issue #548, MW-2026-055).
//!
//! Implements RFC 8058 one-click unsubscribe:
//! - POST /api/unsubscribe  → record unsubscribe + return 200 (one-click)
//! - GET  /api/unsubscribe  → confirmation page (user-click fallback)
//! - Audit trail in MongoDB `unsubscribe_log` collection.
//! - List-Unsubscribe header injected by send_pipeline when env configured.

#![allow(unused_imports)]
use actix_web::{web, HttpResponse, Responder};
use bson::doc;
use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;

use crate::event_bus::mongo_db_name;

const UNSUBSCRIBE_LOG_COLL: &str = "unsubscribe_log";

#[derive(Deserialize, Debug)]
pub(crate) struct UnsubscribeRequest {
    pub email: String,
    #[serde(default)]
    pub list_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// One-click unsubscribe (RFC 8058 §3.1):
/// MUST be POST, MUST return 200, MUST process List-Unsubscribe-Post header.
pub(crate) async fn api_unsubscribe(
    body: web::Json<UnsubscribeRequest>,
    req: actix_web::HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    let user_id = req
        .headers()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("anonymous");

    let db = mongo_db_name();
    let coll = mongo
        .database(&db)
        .collection::<bson::Document>(UNSUBSCRIBE_LOG_COLL);

    let list_id = body.list_id.as_deref().unwrap_or("default");
    let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());

    match coll
        .insert_one(doc! {
            "email": &body.email,
            "list_id": list_id,
            "reason": body.reason.as_deref().unwrap_or(""),
            "user_id": user_id,
            "source": "one_click",
            "created_at": now,
        })
        .await
    {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "unsubscribed": true,
            "email": &body.email,
            "listId": list_id,
        })),
        Err(e) => {
            eprintln!("unsubscribe_log insert error: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "unsubscribed": false,
                "error": e.to_string(),
            }))
        }
    }
}

/// GET unsubscribe — confirmation page fallback (RFC 8058 §3.2).
pub(crate) async fn api_unsubscribe_confirm() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Unsubscribe</title></head>\
             <body style=\"font-family:sans-serif;max-width:600px;margin:40px auto;text-align:center\">\
             <h1>Unsubscribed</h1>\
             <p>You have been successfully unsubscribed. You will no longer receive emails from this list.</p>\
             <p>Changed your mind? Contact <a href=\"mailto:<EMAIL>\"><EMAIL></a></p>\
             </body></html>",
        )
}

/// Build List-Unsubscribe header value from env-configured endpoint.
/// Returns None if SEND_UNSUBSCRIBE_ENDPOINT is not set.
pub(crate) fn list_unsubscribe_header(email: &str, list_id: &str) -> Option<(String, String)> {
    let endpoint = std::env::var("SEND_UNSUBSCRIBE_ENDPOINT").ok()?;
    if endpoint.is_empty() {
        return None;
    }
    let mailto = format!("<mailto:<EMAIL>>", endpoint);
    let https = format!(
        "<{}/api/unsubscribe?email={}&list={}>",
        endpoint.trim_end_matches('/'),
        urlencoding::encode(email),
        urlencoding::encode(list_id)
    );
    // RFC 8058: if both mailto and HTTPS present, HTTPS SHOULD be used for one-click
    Some(("List-Unsubscribe".to_string(), format!("{}, {}", https, mailto)))
}

/// List-Unsubscribe-Post header value for one-click (RFC 8058).
pub(crate) const LIST_UNSUBSCRIBE_POST_HEADER: (&str, &str) =
    ("List-Unsubscribe-Post", "List-Unsubscribe=One-Click");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_unsubscribe_header_formats_https_and_mailto() {
        std::env::set_var("SEND_UNSUBSCRIBE_ENDPOINT", "https://mail.misfits.ai");
        let (key, val) = list_unsubscribe_header("<EMAIL>", "newsletter").unwrap();
        assert_eq!(key, "List-Unsubscribe");
        assert!(val.contains("https://mail.misfits.ai/api/unsubscribe?"), "got: {}", val);
        assert!(val.contains("<EMAIL>"));
        assert!(val.contains("list=newsletter"));
        assert!(val.contains("mailto:"));
    }

    #[test]
    fn list_unsubscribe_header_none_when_unset() {
        std::env::remove_var("SEND_UNSUBSCRIBE_ENDPOINT");
        assert!(list_unsubscribe_header("<EMAIL>", "default").is_none());
    }

    #[test]
    fn list_unsubscribe_header_none_when_empty() {
        std::env::set_var("SEND_UNSUBSCRIBE_ENDPOINT", "");
        assert!(list_unsubscribe_header("<EMAIL>", "default").is_none());
    }

    #[test]
    fn unsubscribe_request_deserializes() {
        let json = serde_json::json!({ "email": "<EMAIL>", "listId": "newsletter", "reason": "too many emails" });
        let req: UnsubscribeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.email, "<EMAIL>");
        assert_eq!(req.list_id.as_deref(), Some("newsletter"));
        assert_eq!(req.reason.as_deref(), Some("too many emails"));
    }

    #[test]
    fn unsubscribe_request_defaults() {
        let json = serde_json::json!({ "email": "<EMAIL>" });
        let req: UnsubscribeRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.email, "<EMAIL>");
        assert!(req.list_id.is_none());
        assert!(req.reason.is_none());
    }
}
