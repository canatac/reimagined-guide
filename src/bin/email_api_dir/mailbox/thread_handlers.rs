//! Conversation thread grouping (issue #544).
//!
//! Groups emails into threads using References / In-Reply-To headers.
//! Falls back to subject-based grouping (Re: / Fwd:) when headers absent.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use bson::doc;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use super::super::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ThreadDto {
    pub thread_id: String,
    pub subject: String,
    pub participants: Vec<String>,
    pub message_count: u32,
    pub last_activity: String,
    pub is_read: bool,
    pub is_starred: bool,
    pub preview: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ThreadDetailDto {
    pub thread_id: String,
    pub subject: String,
    pub messages: Vec<EmailDto>,
}

#[derive(Deserialize)]
pub(crate) struct ThreadsQuery {
    #[serde(default = "default_folder")]
    pub folder: String,
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

fn default_folder() -> String {
    "inbox".to_string()
}
fn default_page() -> u32 {
    1
}
fn default_page_size() -> u32 {
    25
}

fn extract_message_id(email: &Email) -> Option<String> {
    email.headers.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("message-id") {
            let val = v.trim();
            if val.is_empty() {
                None
            } else {
                Some(val.trim_matches(|c| c == '<' || c == '>').to_string())
            }
        } else {
            None
        }
    })
}

fn extract_references(email: &Email) -> Vec<String> {
    email
        .headers
        .iter()
        .find_map(|(k, v)| {
            if k.eq_ignore_ascii_case("references") {
                let ids: Vec<String> = v
                    .split_whitespace()
                    .map(|s| s.trim_matches(|c| c == '<' || c == '>').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                Some(ids)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn extract_in_reply_to(email: &Email) -> Option<String> {
    email.headers.iter().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case("in-reply-to") {
            let val = v.trim_matches(|c| c == '<' || c == '>').to_string();
            if val.is_empty() {
                None
            } else {
                Some(val)
            }
        } else {
            None
        }
    })
}

fn normalize_subject(subject: &str) -> String {
    subject
        .trim()
        .replacen("Re:", "", 10)
        .replacen("RE:", "", 10)
        .replacen("Fwd:", "", 10)
        .replacen("FWD:", "", 10)
        .trim()
        .to_string()
}

/// Group emails into threads. Returns map of thread_id -> Vec<email indices>.
fn group_into_threads(emails: &[Email]) -> Vec<Vec<usize>> {
    let mut message_to_idx: HashMap<String, usize> = HashMap::new();
    for (idx, email) in emails.iter().enumerate() {
        if let Some(mid) = extract_message_id(email) {
            message_to_idx.insert(mid, idx);
        }
    }

    // Union-Find for thread grouping
    let n = emails.len();
    let mut parent: Vec<usize> = (0..n).collect();
    let mut rank: Vec<u32> = vec![0; n];

    fn find(parent: &mut Vec<usize>, x: usize) -> usize {
        if parent[x] != x {
            parent[x] = find(parent, parent[x]);
        }
        parent[x]
    }
    fn union(parent: &mut Vec<usize>, rank: &mut Vec<u32>, a: usize, b: usize) {
        let ra = find(parent, a);
        let rb = find(parent, b);
        if ra == rb {
            return;
        }
        if rank[ra] < rank[rb] {
            parent[ra] = rb;
        } else if rank[ra] > rank[rb] {
            parent[rb] = ra;
        } else {
            parent[rb] = ra;
            rank[ra] += 1;
        }
    }

    // Link emails via References / In-Reply-To
    for (idx, email) in emails.iter().enumerate() {
        let refs = extract_references(email);
        for ref_id in &refs {
            if let Some(&parent_idx) = message_to_idx.get(ref_id) {
                union(&mut parent, &mut rank, idx, parent_idx);
            }
        }
        if let Some(ref_id) = extract_in_reply_to(email) {
            if let Some(&parent_idx) = message_to_idx.get(&ref_id) {
                union(&mut parent, &mut rank, idx, parent_idx);
            }
        }
    }

    // Fallback: group by normalized subject if no header-based link found
    let mut subject_groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, email) in emails.iter().enumerate() {
        let root = find(&mut parent, idx);
        if root == idx && rank[root] == 0 {
            // Isolated email — try subject grouping
            let norm_subj = normalize_subject(&email.subject);
            if !norm_subj.is_empty() {
                subject_groups.entry(norm_subj).or_default().push(idx);
            }
        }
    }
    for (_, group) in subject_groups {
        for window in group.windows(2) {
            union(&mut parent, &mut rank, window[0], window[1]);
        }
    }

    // Collect groups
    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for idx in 0..n {
        let root = find(&mut parent, idx);
        groups.entry(root).or_default().push(idx);
    }

    groups.into_values().collect()
}

pub(crate) async fn api_threads(
    query: web::Query<ThreadsQuery>,
    req: HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let folder = query.folder.trim().to_ascii_lowercase();
    let page = query.page.max(1);
    let page_size = query.page_size.clamp(1, 50);

    let fetch_limit = 500i64;
    let mut emails: Vec<Email> = Vec::new();
    for mailbox in folder_to_mailboxes(&folder) {
        match logic.get_emails_page(&user_id, &mailbox, fetch_limit, 0).await {
            Ok(mut batch) => emails.append(&mut batch),
            Err(e) => {
                eprintln!("api_threads mailbox={}: {}", mailbox, e);
            }
        }
    }

    emails.sort_by(|a, b| b.internal_date.cmp(&a.internal_date));

    let thread_groups = group_into_threads(&emails);

    let mut thread_dtos: Vec<ThreadDto> = thread_groups
        .into_iter()
        .filter_map(|indices| {
            let mut thread_emails: Vec<&Email> = indices.iter().map(|&i| &emails[i]).collect();
            thread_emails.sort_by(|a, b| b.internal_date.cmp(&a.internal_date));
            let latest = thread_emails.first()?;
            let all_read = thread_emails.iter().all(|e| {
                e.flags
                    .iter()
                    .any(|f| f == "\\Seen" || f == "seen")
            });
            let any_starred = thread_emails.iter().any(|e| {
                e.flags
                    .iter()
                    .any(|f| f == "\\Flagged" || f == "flagged" || f == "starred")
            });
            let mut participants: Vec<String> = thread_emails
                .iter()
                .map(|e| e.from.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            participants.sort();
            let last_ms = latest.internal_date.timestamp_millis();
            let last_activity = chrono::DateTime::from_timestamp_millis(last_ms)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| Utc::now().to_rfc3339());
            let thread_id = extract_message_id(latest)
                .unwrap_or_else(|| latest.id.clone());
            Some(ThreadDto {
                thread_id,
                subject: latest.subject.clone(),
                participants,
                message_count: thread_emails.len() as u32,
                last_activity,
                is_read: all_read,
                is_starred: any_starred,
                preview: latest.body.chars().take(120).collect(),
            })
        })
        .collect();

    thread_dtos.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

    let total = thread_dtos.len() as u32;
    let start = ((page - 1) * page_size) as usize;
    let page_items: Vec<ThreadDto> = thread_dtos
        .into_iter()
        .skip(start)
        .take(page_size as usize)
        .collect();
    let has_more = start + page_items.len() < total as usize;

    HttpResponse::Ok().json(serde_json::json!({
        "threads": page_items,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "hasMore": has_more,
    }))
}

pub(crate) async fn api_thread_detail(
    path: web::Path<String>,
    req: HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let thread_id = path.into_inner();

    let fetch_limit = 500i64;
    let mut emails: Vec<Email> = Vec::new();
    for mailbox in folder_to_mailboxes("inbox") {
        match logic.get_emails_page(&user_id, &mailbox, fetch_limit, 0).await {
            Ok(mut batch) => emails.append(&mut batch),
            Err(e) => {
                eprintln!("api_thread_detail mailbox={}: {}", mailbox, e);
            }
        }
    }

    let thread_groups = group_into_threads(&emails);
    for indices in thread_groups {
        let mut thread_emails: Vec<Email> = indices.iter().map(|&i| emails[i].clone()).collect();
        let has_match = thread_emails.iter().any(|e| {
            extract_message_id(e)
                .map(|mid| mid == thread_id)
                .unwrap_or(false) || e.id == thread_id
        });
        if has_match {
            thread_emails.sort_by(|a, b| a.internal_date.cmp(&b.internal_date));
            let messages: Vec<EmailDto> = thread_emails
                .iter()
                .map(|e| email_to_detail_dto(e, "inbox"))
                .collect();
            let subject = messages
                .first()
                .map(|m| m.subject.clone())
                .unwrap_or_default();
            return HttpResponse::Ok().json(serde_json::json!({
                "threadId": thread_id,
                "subject": subject,
                "messages": messages,
            }));
        }
    }

    HttpResponse::NotFound().json(serde_json::json!({
        "message": "Thread not found",
    }))
}

/// Batch action on a thread (delete, archive, mark read).
pub(crate) async fn api_thread_action(
    path: web::Path<String>,
    body: web::Json<ThreadActionBody>,
    req: HttpRequest,
    logic: web::Data<Arc<Logic>>,
    mongo: web::Data<Arc<mongodb::Client>>,
) -> impl Responder {
    if admin_auth::rbac_enabled() {
        if let Err(resp) = admin_auth::require_auth(&req, mongo.get_ref(), &mongo_db_name()).await {
            return resp;
        }
    }
    let user_id = resolve_user_id(&req);
    let thread_id = path.into_inner();

    let fetch_limit = 500i64;
    let mut emails: Vec<Email> = Vec::new();
    for mailbox in folder_to_mailboxes("inbox") {
        match logic.get_emails_page(&user_id, &mailbox, fetch_limit, 0).await {
            Ok(mut batch) => emails.append(&mut batch),
            Err(e) => {
                eprintln!("api_thread_action mailbox={}: {}", mailbox, e);
            }
        }
    }

    let thread_groups = group_into_threads(&emails);
    let mut affected = 0u32;
    for indices in thread_groups {
        let has_match = indices.iter().any(|&i| {
            extract_message_id(&emails[i])
                .map(|mid| mid == thread_id)
                .unwrap_or(false) || emails[i].id == thread_id
        });
        if has_match {
            for &idx in &indices {
                match body.action.as_str() {
                    "delete" => {
                        if logic.delete_email(&user_id, &emails[idx].id).await.is_ok() {
                            affected += 1;
                        }
                    }
                    "archive" => {
                        if logic.archive_email(&user_id, &emails[idx].id).await.is_ok() {
                            affected += 1;
                        }
                    }
                    "mark_read" => {
                        if logic
                            .set_email_read(&user_id, &emails[idx].id, true)
                            .await
                            .is_ok()
                        {
                            affected += 1;
                        }
                    }
                    _ => {}
                }
            }
            break;
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Thread action '{}' applied to {} messages", body.action, affected),
        "affected": affected,
    }))
}

#[derive(Deserialize)]
pub(crate) struct ThreadActionBody {
    pub action: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_email(id: &str, subject: &str, headers: Vec<(String, String)>) -> Email {
        Email {
            id: id.to_string(),
            from: "test@example.com".to_string(),
            to: "recv@example.com".to_string(),
            subject: subject.to_string(),
            body: "body".to_string(),
            headers,
            flags: vec![],
            sequence_number: 0,
            uid: 0,
            internal_date: Utc::now(),
            dkim_signature: None,
        }
    }

    #[test]
    fn extract_message_id_basic() {
        let email = make_email(
            "1",
            "test",
            vec![("Message-ID".to_string(), "<abc@example.com>".to_string())],
        );
        assert_eq!(extract_message_id(&email), Some("abc@example.com".to_string()));
    }

    #[test]
    fn extract_references_multiple() {
        let email = make_email(
            "2",
            "re: test",
            vec![(
                "References".to_string(),
                "<a@example.com> <b@example.com>".to_string(),
            )],
        );
        let refs = extract_references(&email);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], "a@example.com");
        assert_eq!(refs[1], "b@example.com");
    }

    #[test]
    fn group_threads_by_references() {
        let emails = vec![
            make_email(
                "1",
                "Original",
                vec![("Message-ID".to_string(), "<orig@example.com>".to_string())],
            ),
            make_email(
                "2",
                "Re: Original",
                vec![
                    ("Message-ID".to_string(), "<reply@example.com>".to_string()),
                    ("References".to_string(), "<orig@example.com>".to_string()),
                ],
            ),
            make_email(
                "3",
                "Unrelated",
                vec![("Message-ID".to_string(), "<other@example.com>".to_string())],
            ),
        ];
        let groups = group_into_threads(&emails);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn normalize_subject_strips_re() {
        assert_eq!(normalize_subject("Re: Hello"), "Hello");
        assert_eq!(normalize_subject("RE: Fwd: Hello"), "Hello");
        assert_eq!(normalize_subject("Hello"), "Hello");
    }

    #[test]
    fn group_threads_by_subject_fallback() {
        let emails = vec![
            make_email("1", "Same topic", vec![]),
            make_email("2", "Re: Same topic", vec![]),
        ];
        let groups = group_into_threads(&emails);
        assert_eq!(groups.len(), 1);
    }
}
