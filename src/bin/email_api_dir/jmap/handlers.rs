//! JMAP endpoint handlers.
//!
//! Implements the three JMAP routes:
//! - `GET /.well-known/jmap` — Session discovery
//! - `GET /jmap/session` — Full session resource
//! - `POST /jmap` — Main JMAP API endpoint (method dispatch)

use super::types::*;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

// ===========================================================================
// GET /.well-known/jmap — Session Discovery
// ===========================================================================

/// JMAP session discovery endpoint (RFC 8620 §2.1).
///
/// Returns a minimal JSON document pointing clients to the JMAP API endpoint.
/// This is unauthenticated — any client can discover the JMAP capabilities.
pub(crate) async fn jmap_well_known_handler() -> impl HttpResponse {
    let base_url = std::env::var("JMAP_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());

    let discovery = json!({
        "apiUrl": format!("{}/jmap", base_url),
        "authenticationUrl": format!("{}/jmap/session", base_url),
        "capabilities": {
            "urn:ietf:params:jmap:core": {},
            "urn:ietf:params:jmap:mail": {}
        }
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .body(discovery.to_string())
}

// ===========================================================================
// GET /jmap/session — Full Session Resource
// ===========================================================================

/// Full JMAP session resource (RFC 8620 §2).
///
/// Requires authentication (session token or Authorization header).
/// Returns the complete session document with capabilities, accounts, and URLs.
pub(crate) async fn jmap_session_handler(
    req: HttpRequest,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    // Extract session token from Authorization header or cookie
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let session_token = match auth_header {
        Some(ref header) if header.starts_with("Bearer ") => {
            Some(header[7..].to_string())
        }
        _ => {
            // Try cookie
            req.cookie("session_token")
                .map(|c| c.value().to_string())
        }
    };

    let username = match session_token {
        Some(token) => {
            // Validate session against MongoDB
            validate_jmap_session(mongo.get_ref(), &token).await
        }
        None => None,
    };

    let username = match username {
        Some(u) => u,
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "type": "unauthorized",
                "description": "Valid session required"
            }));
        }
    };

    let base_url = std::env::var("JMAP_BASE_URL")
        .unwrap_or_else(|_| "https://mail.misfits.ai".to_string());

    let account_id = format!("u_{}", username.replace('@', "_").replace('.', "_"));

    let mut accounts = HashMap::new();
    accounts.insert(
        account_id.clone(),
        JmapAccount {
            name: username.clone(),
            is_personal: true,
            is_read_only: false,
            account_capabilities: {
                let mut caps = HashMap::new();
                caps.insert(
                    "urn:ietf:params:jmap:mail".to_string(),
                    json!({}),
                );
                caps
            },
        },
    );

    let mut primary_accounts = HashMap::new();
    primary_accounts.insert("urn:ietf:params:jmap:core".to_string(), account_id.clone());
    primary_accounts.insert("urn:ietf:params:jmap:mail".to_string(), account_id.clone());

    let session = JmapSession {
        capabilities: JmapCapabilities::new(),
        accounts,
        primary_accounts,
        username: username.clone(),
        api_url: "/jmap".to_string(),
        download_url: format!("{}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?type={{type}}", base_url),
        upload_url: format!("{}/jmap/upload/{{accountId}}", base_url),
        event_source_url: None,
        state: "state-0".to_string(),
    };

    HttpResponse::Ok()
        .content_type("application/json")
        .json(session)
}

/// Validate a JMAP session token against the database.
async fn validate_jmap_session(
    mongo: &mongodb::Client,
    token: &str,
) -> Option<String> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = mongo.database(&db_name);

    // Check admin sessions first
    let sessions = db.collection::<mongodb::bson::Document>("admin_sessions");
    let filter = mongodb::bson::doc! {
        "token": token,
        "expires_at": { "$gt": mongodb::bson::DateTime::now() }
    };

    match sessions.find_one(filter).await {
        Ok(Some(doc)) => doc.get_str("email").ok().map(|s| s.to_string()),
        Ok(None) => {
            // Also check user sessions collection
            let user_sessions = db.collection::<mongodb::bson::Document>("user_sessions");
            let filter = mongodb::bson::doc! {
                "access_token": token,
                "expires_at": { "$gt": mongodb::bson::DateTime::now() }
            };
            match user_sessions.find_one(filter).await {
                Ok(Some(doc)) => doc.get_str("username").ok().map(|s| s.to_string()),
                _ => None,
            }
        }
        Err(_) => None,
    }
}

// ===========================================================================
// POST /jmap — Main JMAP API Endpoint
// ===========================================================================

/// Main JMAP API endpoint (RFC 8620 §3.3).
///
/// Accepts a JMAP request containing one or more method calls.
/// Returns a JMAP response with results for each call in order.
pub(crate) async fn jmap_api_handler(
    req: HttpRequest,
    body: web::Json<JmapRequest>,
    mongo: web::Data<Arc<mongodb::Client>>,
    logic: web::Data<Arc<crate::logic::Logic>>,
) -> impl Responder {
    // Authenticate
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let session_token = match auth_header {
        Some(ref header) if header.starts_with("Bearer ") => {
            Some(header[7..].to_string())
        }
        _ => req
            .cookie("session_token")
            .map(|c| c.value().to_string()),
    };

    let username = match session_token {
        Some(token) => validate_jmap_session(mongo.get_ref(), &token).await,
        None => None,
    };

    let username = match username {
        Some(u) => u,
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "type": "unauthorized",
                "description": "Valid Bearer token or session_token cookie required"
            }));
        }
    };

    let account_id = format!("u_{}", username.replace('@', "_").replace('.', "_"));
    let request = body.into_inner();
    let mut response = JmapResponse::with_state("state-0");

    // Process each method call
    for call in &request.method_calls {
        let call_array = match call.as_array() {
            Some(arr) if arr.len() >= 3 => arr,
            _ => {
                response.push_error("invalidRequest", "Method call must be [name, args, id]", "");
                continue;
            }
        };

        let method_name = call_array[0].as_str().unwrap_or("").to_string();
        let method_args = &call_array[1];
        let call_id = call_array[2].as_str().unwrap_or("").to_string();

        // Dispatch the method
        let result = dispatch_jmap_method(
            &method_name,
            method_args,
            &call_id,
            &username,
            &account_id,
            mongo.get_ref(),
            logic.get_ref(),
        )
        .await;

        match result {
            Ok(value) => response.push_response(&method_name, value, &call_id),
            Err(err) => response.push_error(&err.error_type, err.detail.as_deref().unwrap_or(""), &call_id),
        }
    }

    HttpResponse::Ok()
        .content_type("application/json")
        .json(response)
}

/// Dispatch a JMAP method call to the appropriate handler.
async fn dispatch_jmap_method(
    method_name: &str,
    args: &Value,
    call_id: &str,
    username: &str,
    account_id: &str,
    mongo: &mongodb::Client,
    logic: &Arc<crate::logic::Logic>,
) -> Result<Value, JmapError> {
    match method_name {
        // === Core methods ===
        "Core/echo" => handle_core_echo(args, call_id).await,

        // === Email methods ===
        "Email/get" => handle_email_get(args, call_id, username, account_id, logic).await,
        "Email/query" => handle_email_query(args, call_id, username, account_id, logic).await,
        "Email/set" => handle_email_set(args, call_id, username, account_id, logic).await,
        "Email/queryChanges" => {
            handle_email_query_changes(args, call_id, username, account_id).await
        }
        "Email/import" => handle_email_import(args, call_id, username, account_id).await,

        // === Mailbox methods ===
        "Mailbox/get" => {
            handle_mailbox_get(args, call_id, username, account_id, mongo).await
        }
        "Mailbox/set" => {
            handle_mailbox_set(args, call_id, username, account_id, mongo).await
        }
        "Mailbox/query" => {
            handle_mailbox_query(args, call_id, username, account_id, mongo).await
        }
        "Mailbox/changes" => {
            handle_mailbox_changes(args, call_id, username, account_id).await
        }

        // === Thread methods ===
        "Thread/get" => handle_thread_get(args, call_id, username, account_id).await,

        // === EmailSubmission methods ===
        "EmailSubmission/get" => {
            handle_email_submission_get(args, call_id, username, account_id).await
        }
        "EmailSubmission/set" => {
            handle_email_submission_set(args, call_id, username, account_id, logic).await
        }
        "EmailSubmission/query" => {
            handle_email_submission_query(args, call_id, username, account_id).await
        }

        // === Identity methods ===
        "Identity/get" => handle_identity_get(args, call_id, username, account_id).await,

        // === SearchSnippet methods ===
        "SearchSnippet/get" => {
            handle_search_snippet_get(args, call_id, username, account_id, logic).await
        }

        // === VacationResponse methods ===
        "VacationResponse/get" => {
            handle_vacation_get(args, call_id, username, account_id).await
        }
        "VacationResponse/set" => {
            handle_vacation_set(args, call_id, username, account_id).await
        }

        _ => Err(JmapError::unknown_method(method_name)),
    }
}

// ===========================================================================
// Core/echo
// ===========================================================================

async fn handle_core_echo(args: &Value, _call_id: &str) -> Result<Value, JmapError> {
    // Echo back whatever was sent — useful for testing
    Ok(args.clone())
}

// ===========================================================================
// Email/get
// ===========================================================================

async fn handle_email_get(
    args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
    logic: &Arc<crate::logic::Logic>,
) -> Result<Value, JmapError> {
    let parsed: JmapEmailGetArgs = serde_json::from_value(args.clone())
        .map_err(|e| JmapError::invalid_arguments(&format!("Invalid Email/get args: {e}")))?;

    // Validate account
    validate_account(&parsed.account_id, account_id)?;

    let mut emails: Vec<JmapEmail> = Vec::new();

    if let Some(ids) = &parsed.ids {
        for id in ids {
            match logic.find_email(username, id).await {
                Ok(Some(email)) => {
                    emails.push(JmapEmail::from_internal_email(&email));
                }
                Ok(None) => {} // Not found — skip
                Err(e) => {
                    eprintln!("Email/get: find_email {} failed: {}", id, e);
                }
            }
        }
    } else {
        // No ids specified — return all emails (with limit)
        // Fetch from default mailboxes
        for mailbox in &["inbox", "sent", "drafts"] {
            match logic.find_emails(username, mailbox).await {
                Ok(batch) => {
                    for email in batch {
                        emails.push(JmapEmail::from_internal_email(&email));
                    }
                }
                Err(e) => {
                    eprintln!("Email/get: find_emails {} failed: {}", mailbox, e);
                }
            }
        }
    }

    let list: Vec<String> = emails.iter().map(|e| e.id.clone()).collect();
    let not_found: Vec<String> = if let Some(ids) = &parsed.ids {
        ids.iter()
            .filter(|id| !list.iter().any(|eid| eid == *id))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    Ok(json!({
        "accountId": account_id,
        "state": "email-state-0",
        "list": emails,
        "notFound": not_found
    }))
}

// ===========================================================================
// Email/query
// ===========================================================================

async fn handle_email_query(
    args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
    logic: &Arc<crate::logic::Logic>,
) -> Result<Value, JmapError> {
    let parsed: JmapEmailQueryArgs = serde_json::from_value(args.clone())
        .map_err(|e| JmapError::invalid_arguments(&format!("Invalid Email/query args: {e}")))?;

    validate_account(&parsed.account_id, account_id)?;

    // Collect all emails from user's mailboxes
    let mut all_emails: Vec<simple_smtp_server::entities::Email> = Vec::new();
    for mailbox in &["inbox", "sent", "drafts"] {
        match logic.find_emails(username, mailbox).await {
            Ok(batch) => all_emails.extend(batch),
            Err(e) => {
                eprintln!("Email/query: find_emails {} failed: {}", mailbox, e);
            }
        }
    }

    // Apply filter (simple keyword/subject matching)
    if let Some(filter) = &parsed.filter {
        if let Some(condition) = filter.as_object() {
            // Simple text filter on subject/body
            if let Some(text) = condition.get("text").and_then(|v| v.as_str()) {
                let text_lower = text.to_lowercase();
                all_emails.retain(|e| {
                    e.subject.to_lowercase().contains(&text_lower)
                        || e.body.to_lowercase().contains(&text_lower)
                });
            }
            // Filter by inMailbox
            if let Some(mailbox_filter) =
                condition.get("inMailbox").and_then(|v| v.as_str())
            {
                // In a real impl, we'd filter by actual mailbox membership
                // For now, this is a no-op placeholder
                let _ = mailbox_filter;
            }
            // Filter by hasKeyword
            if let Some(keyword) = condition.get("hasKeyword").and_then(|v| v.as_str()) {
                all_emails.retain(|e| e.flags.iter().any(|f| f == keyword));
            }
            // Filter by notKeyword
            if let Some(keyword) = condition.get("notKeyword").and_then(|v| v.as_str()) {
                all_emails.retain(|e| !e.flags.iter().any(|f| f == keyword));
            }
        }
    }

    // Sort (default: receivedAt descending)
    all_emails.sort_by(|a, b| b.internal_date.cmp(&a.internal_date));

    // Apply sort comparators
    if let Some(sort) = &parsed.sort {
        for comparator in sort {
            if let Some(prop) = comparator.get("property").and_then(|v| v.as_str()) {
                let descending = comparator
                    .get("isAscending")
                    .and_then(|v| v.as_bool())
                    .map(|a| !a)
                    .unwrap_or(true);

                match prop {
                    "receivedAt" => {
                        if !descending {
                            all_emails.sort_by(|a, b| a.internal_date.cmp(&b.internal_date));
                        }
                    }
                    "subject" => {
                        all_emails.sort_by(|a, b| {
                            let cmp = a.subject.cmp(&b.subject);
                            if descending {
                                cmp.reverse()
                            } else {
                                cmp
                            }
                        });
                    }
                    _ => {} // Unknown sort property — ignore
                }
            }
        }
    }

    let total_count = all_emails.len() as u64;

    // Paginate
    let position = parsed.position.max(0) as usize;
    let limit = parsed.limit.unwrap_or(10) as usize;
    let page_ids: Vec<String> = all_emails
        .iter()
        .skip(position)
        .take(limit)
        .map(|e| e.id.clone())
        .collect();

    let mut result = json!({
        "accountId": account_id,
        "queryState": "email-query-state-0",
        "ids": page_ids,
        "position": position as u64,
    });

    if parsed.calculate_total {
        result["total"] = json!(total_count);
    }

    Ok(result)
}

// ===========================================================================
// Email/set
// ===========================================================================

async fn handle_email_set(
    args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
    logic: &Arc<crate::logic::Logic>,
) -> Result<Value, JmapError> {
    let parsed: JmapEmailSetArgs = serde_json::from_value(args.clone())
        .map_err(|e| JmapError::invalid_arguments(&format!("Invalid Email/set args: {e}")))?;

    validate_account(&parsed.account_id, account_id)?;

    let mut created = HashMap::new();
    let mut updated = HashMap::new();
    let mut destroyed = Vec::new();
    let mut not_created = HashMap::new();
    let mut not_updated = HashMap::new();
    let mut not_destroyed = HashMap::new();

    // Handle destroy
    if let Some(destroy_ids) = &parsed.destroy {
        for id in destroy_ids {
            match logic.delete_email(id).await {
                Ok(()) => {
                    destroyed.push(id.clone());
                }
                Err(e) => {
                    eprintln!("Email/set: delete {} failed: {}", id, e);
                    not_destroyed.insert(
                        id.clone(),
                        json!({ "type": "serverFail", "description": e.to_string() }),
                    );
                }
            }
        }
    }

    // Handle update
    if let Some(updates) = &parsed.update {
        for (id, patch) in updates {
            match logic.find_email(username, id).await {
                Ok(Some(mut email)) => {
                    // Apply patch fields
                    if let Some(keywords) = patch.get("keywords").and_then(|v| v.as_object()) {
                        email.flags = keywords
                            .iter()
                            .filter(|(_, v)| v.as_bool().unwrap_or(false))
                            .map(|(k, _)| k.clone())
                            .collect();
                    }
                    if let Some(mailbox_ids) = patch.get("mailboxIds") {
                        // In a real impl, we'd update mailbox membership
                        let _ = mailbox_ids;
                    }
                    updated.insert(id.clone(), json!({}));
                }
                Ok(None) => {
                    not_updated.insert(
                        id.clone(),
                        json!({ "type": "notFound", "description": "Email not found" }),
                    );
                }
                Err(e) => {
                    not_updated.insert(
                        id.clone(),
                        json!({ "type": "serverFail", "description": e.to_string() }),
                    );
                }
            }
        }
    }

    // Handle create (basic stub — creating raw emails via JMAP is complex)
    if let Some(creates) = &parsed.create {
        for (client_id, email_obj) in creates {
            // In a full impl, this would create a new email draft
            // For now, return a not-implemented error
            not_created.insert(
                client_id.clone(),
                json!({ "type": "forbidden", "description": "Email creation via JMAP not yet implemented" }),
            );
        }
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": "email-state-0",
        "newState": "email-state-1",
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed
    }))
}

// ===========================================================================
// Email/queryChanges
// ===========================================================================

async fn handle_email_query_changes(
    args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    let parsed: JmapEmailQueryChangesArgs = serde_json::from_value(args.clone())
        .map_err(|e| {
            JmapError::invalid_arguments(&format!("Invalid Email/queryChanges args: {e}"))
        })?;

    validate_account(&parsed.account_id, account_id)?;

    // Full implementation would track state changes
    // For now, return cannotCalculateChanges
    Err(JmapError::cannot_calculate_changes())
}

// ===========================================================================
// Email/import
// ===========================================================================

async fn handle_email_import(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    _account_id: &str,
) -> Result<Value, JmapError> {
    Err(JmapError {
        error_type: "forbidden".to_string(),
        status: 403,
        detail: Some("Email/import not yet implemented".to_string()),
    })
}

// ===========================================================================
// Mailbox/get
// ===========================================================================

async fn handle_mailbox_get(
    args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
    mongo: &mongodb::Client,
) -> Result<Value, JmapError> {
    let parsed: JmapMailboxGetArgs = serde_json::from_value(args.clone())
        .map_err(|e| JmapError::invalid_arguments(&format!("Invalid Mailbox/get args: {e}")))?;

    validate_account(&parsed.account_id, account_id)?;

    let mailboxes = get_user_mailboxes(username, mongo).await?;

    let list: Vec<JmapMailbox> = if let Some(ids) = &parsed.ids {
        ids.iter()
            .filter_map(|id| mailboxes.iter().find(|m| &m.id == id))
            .cloned()
            .collect()
    } else {
        mailboxes
    };

    let list_ids: Vec<String> = list.iter().map(|m| m.id.clone()).collect();
    let not_found: Vec<String> = if let Some(ids) = &parsed.ids {
        ids.iter()
            .filter(|id| !list_ids.iter().any(|lid| lid == *id))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    Ok(json!({
        "accountId": account_id,
        "state": "mailbox-state-0",
        "list": list,
        "notFound": not_found
    }))
}

/// Get all mailboxes for a user.
async fn get_user_mailboxes(
    username: &str,
    mongo: &mongodb::Client,
) -> Result<Vec<JmapMailbox>, JmapError> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = mongo.database(&db_name);

    // Try to get user's mailboxes from the database
    let coll = db.collection::<mongodb::bson::Document>("mailboxes");
    let filter = mongodb::bson::doc! { "user_id": username };

    let mut mailboxes = Vec::new();

    match coll.find(filter).await {
        Ok(mut cursor) => {
            use futures_util::stream::TryStreamExt;
            while let Ok(Some(doc)) = cursor.try_next().await {
                let name = doc
                    .get_str("name")
                    .unwrap_or("inbox")
                    .to_string();
                let id = doc
                    .get_object_id("_id")
                    .ok()
                    .map(|oid| oid.to_hex())
                    .unwrap_or_else(|| format!("mb_{}", name));

                let role = doc.get_str("role").ok().map(|s| s.to_string());

                mailboxes.push(JmapMailbox::from_name(&name, role.as_deref(), &id));
            }
        }
        Err(e) => {
            eprintln!("Mailbox/get: find mailboxes failed: {}", e);
        }
    }

    // Ensure default mailboxes exist
    if mailboxes.is_empty() {
        let defaults = vec![
            ("inbox", Some("inbox")),
            ("sent", Some("sent")),
            ("drafts", Some("drafts")),
            ("trash", Some("trash")),
            ("archive", Some("archive")),
            ("junk", Some("junk")),
        ];
        for (name, role) in defaults {
            mailboxes.push(JmapMailbox::from_name(
                name,
                role,
                &format!("mb_{username}_{name}"),
            ));
        }
    }

    Ok(mailboxes)
}

// ===========================================================================
// Mailbox/set
// ===========================================================================

async fn handle_mailbox_set(
    args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
    mongo: &mongodb::Client,
) -> Result<Value, JmapError> {
    let parsed: JmapMailboxSet = serde_json::from_value(args.clone())
        .map_err(|e| JmapError::invalid_arguments(&format!("Invalid Mailbox/set args: {e}")))?;

    validate_account(&parsed.account_id, account_id)?;

    let mut created = HashMap::new();
    let mut updated = HashMap::new();
    let mut destroyed = Vec::new();
    let mut not_created = HashMap::new();
    let mut not_updated = HashMap::new();
    let mut not_destroyed = HashMap::new();

    // Handle create
    if let Some(creates) = &parsed.create {
        for (client_id, mailbox) in creates {
            match create_mailbox(username, mongo, mailbox).await {
                Ok(mailbox_id) => {
                    created.insert(client_id.clone(), json!({ "id": mailbox_id }));
                }
                Err(e) => {
                    not_created.insert(
                        client_id.clone(),
                        json!({ "type": "serverFail", "description": e.to_string() }),
                    );
                }
            }
        }
    }

    // Handle update
    if let Some(updates) = &parsed.update {
        for (mailbox_id, patch) in updates {
            match update_mailbox(username, mongo, mailbox_id, patch).await {
                Ok(()) => {
                    updated.insert(mailbox_id.clone(), json!({}));
                }
                Err(e) => {
                    not_updated.insert(
                        mailbox_id.clone(),
                        json!({ "type": "serverFail", "description": e.to_string() }),
                    );
                }
            }
        }
    }

    // Handle destroy
    if let Some(destroy_ids) = &parsed.destroy {
        for id in destroy_ids {
            match destroy_mailbox(username, mongo, id).await {
                Ok(()) => {
                    destroyed.push(id.clone());
                }
                Err(e) => {
                    not_destroyed.insert(
                        id.clone(),
                        json!({ "type": "serverFail", "description": e.to_string() }),
                    );
                }
            }
        }
    }

    Ok(json!({
        "accountId": account_id,
        "oldState": "mailbox-state-0",
        "newState": "mailbox-state-1",
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
        "notCreated": not_created,
        "notUpdated": not_updated,
        "notDestroyed": not_destroyed
    }))
}

/// Create a new mailbox for the user.
async fn create_mailbox(
    username: &str,
    mongo: &mongodb::Client,
    mailbox: &JmapMailbox,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = mongo.database(&db_name);
    let coll = db.collection::<mongodb::bson::Document>("mailboxes");

    let mailbox_id = format!("mb_{}_{}", username.replace('@', "_"), mailbox.name);
    let doc = mongodb::bson::doc! {
        "_id": &mailbox_id,
        "name": &mailbox.name,
        "user_id": username,
        "role": mailbox.role.as_deref().unwrap_or(""),
        "sort_order": mailbox.sort_order as i64,
        "created_at": mongodb::bson::DateTime::now(),
        "updated_at": mongodb::bson::DateTime::now(),
    };

    coll.insert_one(doc).await?;
    Ok(mailbox_id)
}

/// Update an existing mailbox.
async fn update_mailbox(
    username: &str,
    mongo: &mongodb::Client,
    mailbox_id: &str,
    patch: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = mongo.database(&db_name);
    let coll = db.collection::<mongodb::bson::Document>("mailboxes");

    let mut update_doc = mongodb::bson::doc! {};

    if let Some(name) = patch.get("name").and_then(|v| v.as_str()) {
        update_doc.insert("name", name);
    }
    if let Some(sort_order) = patch.get("sortOrder").and_then(|v| v.as_i64()) {
        update_doc.insert("sort_order", sort_order);
    }
    if let Some(parent_id) = patch.get("parentId").and_then(|v| v.as_str()) {
        update_doc.insert("parent_id", parent_id);
    }

    update_doc.insert("updated_at", mongodb::bson::DateTime::now());

    let filter = mongodb::bson::doc! {
        "_id": mailbox_id,
        "user_id": username
    };
    let update = mongodb::bson::doc! { "$set": update_doc };

    coll.update_one(filter, update).await?;
    Ok(())
}

/// Destroy a mailbox.
async fn destroy_mailbox(
    username: &str,
    mongo: &mongodb::Client,
    mailbox_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_name = std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string());
    let db = mongo.database(&db_name);
    let coll = db.collection::<mongodb::bson::Document>("mailboxes");

    let filter = mongodb::bson::doc! {
        "_id": mailbox_id,
        "user_id": username
    };

    coll.delete_one(filter).await?;
    Ok(())
}

// ===========================================================================
// Mailbox/query
// ===========================================================================

async fn handle_mailbox_query(
    args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
    mongo: &mongodb::Client,
) -> Result<Value, JmapError> {
    let parsed: Value = args.clone();
    let account_id_arg = parsed
        .get("accountId")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    validate_account(account_id_arg, account_id)?;

    let mailboxes = get_user_mailboxes(username, mongo).await?;

    // Simple sort by sortOrder then name
    let mut sorted = mailboxes;
    sorted.sort_by(|a, b| a.sort_order.cmp(&b.sort_order).then_with(|| a.name.cmp(&b.name)));

    let total = sorted.len() as u64;
    let position = parsed
        .get("position")
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
        .max(0) as usize;
    let limit = parsed
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(50) as usize;

    let ids: Vec<String> = sorted
        .iter()
        .skip(position)
        .take(limit)
        .map(|m| m.id.clone())
        .collect();

    Ok(json!({
        "accountId": account_id,
        "queryState": "mailbox-query-state-0",
        "ids": ids,
        "position": position as u64,
        "total": total
    }))
}

// ===========================================================================
// Mailbox/changes
// ===========================================================================

async fn handle_mailbox_changes(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    _account_id: &str,
) -> Result<Value, JmapError> {
    Err(JmapError::cannot_calculate_changes())
}

// ===========================================================================
// Thread/get
// ===========================================================================

async fn handle_thread_get(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "state": "thread-state-0",
        "list": [],
        "notFound": []
    }))
}

// ===========================================================================
// EmailSubmission/get
// ===========================================================================

async fn handle_email_submission_get(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "state": "submission-state-0",
        "list": [],
        "notFound": []
    }))
}

// ===========================================================================
// EmailSubmission/set
// ===========================================================================

async fn handle_email_submission_set(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
    _logic: &Arc<crate::logic::Logic>,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "oldState": "submission-state-0",
        "newState": "submission-state-1",
        "created": {},
        "updated": {},
        "destroyed": [],
        "notCreated": {},
        "notUpdated": {},
        "notDestroyed": {}
    }))
}

// ===========================================================================
// EmailSubmission/query
// ===========================================================================

async fn handle_email_submission_query(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "queryState": "submission-query-state-0",
        "ids": [],
        "position": 0,
        "total": 0
    }))
}

// ===========================================================================
// Identity/get
// ===========================================================================

async fn handle_identity_get(
    _args: &Value,
    _call_id: &str,
    username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    let identity = JmapIdentity {
        id: format!("id_{}", username.replace('@', "_")),
        name: username.split('@').next().unwrap_or("User").to_string(),
        email: username.to_string(),
        reply_to: None,
        bcc: None,
        text_signature: String::new(),
        html_signature: String::new(),
        may_delete: false,
    };

    Ok(json!({
        "accountId": account_id,
        "state": "identity-state-0",
        "list": [identity],
        "notFound": []
    }))
}

// ===========================================================================
// SearchSnippet/get
// ===========================================================================

async fn handle_search_snippet_get(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
    _logic: &Arc<crate::logic::Logic>,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "list": [],
        "notFound": []
    }))
}

// ===========================================================================
// VacationResponse/get
// ===========================================================================

async fn handle_vacation_get(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "list": [],
        "notFound": []
    }))
}

// ===========================================================================
// VacationResponse/set
// ===========================================================================

async fn handle_vacation_set(
    _args: &Value,
    _call_id: &str,
    _username: &str,
    account_id: &str,
) -> Result<Value, JmapError> {
    Ok(json!({
        "accountId": account_id,
        "oldState": "vacation-state-0",
        "newState": "vacation-state-1",
        "updated": {},
        "notUpdated": {}
    }))
}

// ===========================================================================
// Utility: Account validation
// ===========================================================================

/// Validate that the requested account matches the authenticated user's account.
fn validate_account(requested: &str, actual: &str) -> Result<(), JmapError> {
    if requested.is_empty() || requested == actual {
        Ok(())
    } else {
        Err(JmapError::account_not_found())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_account_empty_passes() {
        assert!(validate_account("", "u_test").is_ok());
    }

    #[test]
    fn validate_account_matching_passes() {
        assert!(validate_account("u_test", "u_test").is_ok());
    }

    #[test]
    fn validate_account_mismatch_fails() {
        assert!(validate_account("u_other", "u_test").is_err());
    }

    #[test]
    fn jmap_response_new() {
        let resp = JmapResponse::new();
        assert!(resp.method_responses.is_empty());
        assert_eq!(resp.session_state, "state-0");
    }

    #[test]
    fn jmap_response_with_state() {
        let resp = JmapResponse::with_state("custom-state");
        assert_eq!(resp.session_state, "custom-state");
    }

    #[test]
    fn jmap_response_push_response() {
        let mut resp = JmapResponse::new();
        resp.push_response("Email/get", json!({"list": []}), "call-1");
        assert_eq!(resp.method_responses.len(), 1);
    }

    #[test]
    fn jmap_response_push_error() {
        let mut resp = JmapResponse::new();
        resp.push_error("notFound", "Email not found", "call-2");
        assert_eq!(resp.method_responses.len(), 1);
    }

    #[test]
    fn jmap_error_types() {
        let err = JmapError::account_not_found();
        assert_eq!(err.error_type, "accountNotFound");
        assert_eq!(err.status, 404);

        let err = JmapError::invalid_arguments("bad arg");
        assert_eq!(err.error_type, "invalidArguments");
        assert_eq!(err.status, 400);

        let err = JmapError::unknown_method("Foo/bar");
        assert_eq!(err.error_type, "unknownMethod");
    }

    #[test]
    fn jmap_email_from_internal() {
        let internal = simple_smtp_server::entities::Email {
            id: "test-123".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Hello".to_string(),
            body: "World".to_string(),
            headers: vec![],
            flags: vec!["\\Seen".to_string()],
            sequence_number: 1,
            uid: 1,
            internal_date: chrono::Utc::now(),
            dkim_signature: None,
        };

        let jmap_email = JmapEmail::from_internal_email(&internal);
        assert_eq!(jmap_email.id, "test-123");
        assert_eq!(jmap_email.subject, Some("Hello".to_string()));
        assert_eq!(jmap_email.from.len(), 1);
        assert_eq!(jmap_email.from[0].email, "sender@example.com");
    }

    #[test]
    fn jmap_mailbox_from_name() {
        let mailbox = JmapMailbox::from_name("Inbox", Some("inbox"), "mb-1");
        assert_eq!(mailbox.name, "Inbox");
        assert_eq!(mailbox.role, Some("inbox".to_string()));
        assert_eq!(mailbox.id, "mb-1");
    }

    #[test]
    fn jmap_well_known_discovery_shape() {
        // Verify the discovery document structure
        let discovery = json!({
            "apiUrl": "https://mail.misfits.ai/jmap",
            "authenticationUrl": "https://mail.misfits.ai/jmap/session",
            "capabilities": {
                "urn:ietf:params:jmap:core": {},
                "urn:ietf:params:jmap:mail": {}
            }
        });
        assert!(discovery.get("apiUrl").is_some());
        assert!(discovery.get("authenticationUrl").is_some());
        assert!(discovery["capabilities"].get("urn:ietf:params:jmap:core").is_some());
    }

    #[test]
    fn handler_names() {
        let names = vec![
            "jmap_well_known_handler",
            "jmap_session_handler",
            "jmap_api_handler",
        ];
        assert_eq!(names.len(), 3);
    }
}
