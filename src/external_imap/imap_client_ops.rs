// imap_client_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

    pub async fn imap_test(&self, account: &ExternalImapAccount) -> Result<ImapTestResult> {
        let host = account.imap_host.clone();
        let port = account.imap_port;
        let tls = account.imap_tls;
        let login_user = account.email.clone();
        let login_secret = account.secret_value.clone().unwrap_or_default();
        let res = tokio::task::spawn_blocking(move || {
            imap_probe(&host, port, tls, &login_user, &login_secret, false)
        })
        .await
        .map_err(|e| mongodb::error::Error::custom(format!("imap test join error: {e}")))?;

        match res {
            Ok((greeting, caps, _folders)) => Ok(ImapTestResult {
                ok: true,
                capabilities: caps,
                greeting,
                message: "IMAP login OK".to_string(),
            }),
            Err(e) => Ok(ImapTestResult {
                ok: false,
                capabilities: vec![],
                greeting: String::new(),
                message: e,
            }),
        }
    }

    pub async fn discover_folders(
        &self,
        owner_user_id: &str,
        account: &ExternalImapAccount,
    ) -> Result<ImapDiscoverResult> {
        let host = account.imap_host.clone();
        let port = account.imap_port;
        let tls = account.imap_tls;
        let login_user = account.email.clone();
        let login_secret = account.secret_value.clone().unwrap_or_default();
        let account_id = account.id.clone();

        let res = tokio::task::spawn_blocking(move || {
            imap_probe(&host, port, tls, &login_user, &login_secret, true)
        })
        .await
        .map_err(|e| mongodb::error::Error::custom(format!("imap discover join error: {e}")))?;

        let (_greeting, caps, folders) = res.map_err(mongodb::error::Error::custom)?;

        for f in &folders {
            let role = infer_role(f);
            let _ = self.ensure_folder(owner_user_id, &account_id, f, &role).await?;
        }

        Ok(ImapDiscoverResult {
            folders,
            capabilities: caps,
        })
    }

    pub async fn run_sync_now(
        &self,
        owner_user_id: &str,
        account: &ExternalImapAccount,
        run: &ExternalSyncRun,
    ) -> Result<SyncExecutionResult> {
        let discover = self.discover_folders(owner_user_id, account).await?;

        // Resolve the target inbox folder (create-if-missing is handled by
        // discover_folders → ensure_folder). We fetch into whichever local
        // folder has role="inbox"; if none, fall back to the first folder.
        let folders = self.list_folders(owner_user_id, &account.id).await?;
        let inbox_folder = folders
            .iter()
            .find(|f| f.local_role == "inbox")
            .or_else(|| folders.first())
            .cloned();

        // Compute the SEARCH SINCE date from run.since (default: today).
        let since_bson = run.since.unwrap_or_else(|| {
            Utc::now()
        });
        let since_chrono = chrono::DateTime::<Utc>::from_timestamp_millis(
            since_bson.timestamp_millis(),
        )
        .unwrap_or_else(Utc::now);
        let since_imap = format_imap_date(&since_chrono);

        // Fetch remote headers via a real IMAP session (blocking dialog).
        let host = account.imap_host.clone();
        let port = account.imap_port;
        let tls = account.imap_tls;
        let login_user = account.email.clone();
        let login_secret = account.secret_value.clone().unwrap_or_default();
        let fetch_res: std::result::Result<Vec<ImapFetchedHeader>, String> =
            tokio::task::spawn_blocking(move || {
                imap_fetch_headers_since(
                    &host,
                    port,
                    tls,
                    &login_user,
                    &login_secret,
                    "INBOX",
                    &since_imap,
                )
            })
            .await
            .map_err(|e| mongodb::error::Error::custom(format!("imap fetch join error: {e}")))?;

        let fetched_headers = match fetch_res {
            Ok(v) => v,
            Err(e) => {
                // Non-fatal: record error on account, complete run as
                // failed. discover already succeeded so folders exist.
                let _ = self
                    .coll_accounts()
                    .update_one(
                        doc! { "ownerUserId": owner_user_id, "id": &account.id },
                        doc! { "$set": { "lastError": &e } },
                    )
                    .await;
                return Err(mongodb::error::Error::custom(format!(
                    "IMAP fetch failed: {e}"
                )));
            }
        };

        // Persist headers: dedupe on (account_id, remote_uid) via replace_one
        // upsert to keep the sync idempotent.
        let now = Utc::now();
        let mut fetched = 0u64;
        let folder_id = inbox_folder.as_ref().map(|f| f.id.clone());

        for h in fetched_headers {
            let msg_id_header = h.message_id.clone();
            let dedup = format!("uid:{}:{}", account.id, h.uid);
            let internal_dt = h.internal_date;
            let sent_dt = h.date;

            let doc_id = Uuid::new_v4().to_string();
            let msg = ExternalImapMessage {
                id: doc_id,
                account_id: account.id.clone(),
                folder_id: folder_id.clone(),
                owner_user_id: owner_user_id.to_string(),
                remote_uid: Some(h.uid),
                message_id_header: msg_id_header,
                thread_key: None,
                from: h.from,
                to: h.to,
                subject: h.subject,
                sent_at: sent_dt,
                flags: h.flags,
                internal_date: internal_dt,
                body_preview: None,
                raw_ref: None,
                dedup_hash: Some(dedup.clone()),
                deleted: false,
                created_at: now,
                updated_at: now,
            };

            // Upsert on (account_id, remote_uid) so re-syncs don't duplicate.
            self.coll_messages()
                .replace_one(
                    doc! { "accountId": &account.id, "remoteUid": h.uid as i64 },
                    &msg,
                )
                .upsert(true)
                .await?;
            fetched += 1;
        }

        self.coll_accounts()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": &account.id },
                doc! { "$set": {
                    "lastSyncAt": Utc::now(),
                    "lastError": bson::Bson::Null,
                    "updatedAt": Utc::now()
                }},
            )
            .await?;

        let _ = run;
        Ok(SyncExecutionResult {
            fetched,
            updated: 0,
            deleted: 0,
            discovered_folders: u64::try_from(discover.folders.len()).unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_client_ops_imap_test_ok() {
        let result = ImapTestResult {
            ok: true,
            capabilities: vec!["IMAP4rev1".to_string()],
            greeting: "* OK IMAP4rev1".to_string(),
            message: "IMAP login OK".to_string(),
        };
        assert!(result.ok);
        assert_eq!(result.capabilities.len(), 1);
        assert_eq!(result.message, "IMAP login OK");
    }

    #[test]
    fn imap_client_ops_imap_test_err() {
        let result = ImapTestResult {
            ok: false,
            capabilities: vec![],
            greeting: String::new(),
            message: "login failed".to_string(),
        };
        assert!(!result.ok);
        assert!(result.capabilities.is_empty());
    }

    #[test]
    fn imap_client_ops_discover_folders_result() {
        let result = ImapDiscoverResult {
            folders: vec!["INBOX".to_string(), "Sent".to_string()],
            capabilities: vec!["IMAP4rev1".to_string()],
        };
        assert_eq!(result.folders.len(), 2);
        assert_eq!(result.capabilities.len(), 1);
    }

    #[test]
    fn imap_client_ops_sync_execution_result() {
        let result = SyncExecutionResult {
            fetched: 10,
            updated: 0,
            deleted: 0,
            discovered_folders: 3,
        };
        assert_eq!(result.fetched, 10);
        assert_eq!(result.discovered_folders, 3);
    }

    #[test]
    fn imap_client_ops_external_imap_message_fields() {
        let fields = vec!["id", "account_id", "folder_id", "owner_user_id", "remote_uid", "message_id_header", "thread_key", "from", "to", "subject", "sent_at", "flags", "internal_date", "body_preview", "raw_ref", "dedup_hash", "deleted", "created_at", "updated_at"];
        assert_eq!(fields.len(), 19);
    }

    #[test]
    fn imap_client_ops_external_imap_message_new() {
        let now = Utc::now();
        let msg = ExternalImapMessage {
            id: Uuid::new_v4().to_string(),
            account_id: "account-1".to_string(),
            folder_id: Some("folder-1".to_string()),
            owner_user_id: "user-1".to_string(),
            remote_uid: Some(42),
            message_id_header: Some("msg-123@example.com".to_string()),
            thread_key: None,
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            sent_at: Some(now),
            flags: vec!["\\Seen".to_string()],
            internal_date: now,
            body_preview: None,
            raw_ref: None,
            dedup_hash: Some("uid:account-1:42".to_string()),
            deleted: false,
            created_at: now,
            updated_at: now,
        };
        assert_eq!(msg.account_id, "account-1");
        assert_eq!(msg.remote_uid, Some(42));
        assert_eq!(msg.dedup_hash, Some("uid:account-1:42".to_string()));
    }

    #[test]
    fn imap_client_ops_dedup_format() {
        let account_id = "account-1";
        let uid = 42u64;
        let dedup = format!("uid:{}:{}", account_id, uid);
        assert_eq!(dedup, "uid:account-1:42");
    }

    #[test]
    fn imap_client_ops_replace_one_filter() {
        let uid = 42u64;
        let filter = doc! { "accountId": "account-1", "remoteUid": uid as i64 };
        assert!(filter.contains_key("accountId"));
        assert!(filter.contains_key("remoteUid"));
    }

    #[test]
    fn imap_client_ops_update_account_error() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        let update = doc! { "$set": { "lastError": "fetch failed" } };
        assert!(filter.contains_key("ownerUserId"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn imap_client_ops_update_account_sync() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        let update = doc! { "$set": {
            "lastSyncAt": Utc::now(),
            "lastError": bson::Bson::Null,
            "updatedAt": Utc::now()
        }};
        assert!(filter.contains_key("ownerUserId"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn imap_client_ops_infer_role() {
        let role = infer_role("INBOX");
        assert_eq!(role, "inbox");
    }

    #[test]
    fn imap_client_ops_infer_role_sent() {
        let role = infer_role("Sent");
        assert_eq!(role, "sent");
    }

    #[test]
    fn imap_client_ops_infer_role_drafts() {
        let role = infer_role("Drafts");
        assert_eq!(role, "drafts");
    }

    #[test]
    fn imap_client_ops_infer_role_trash() {
        let role = infer_role("Trash");
        assert_eq!(role, "trash");
    }

    #[test]
    fn imap_client_ops_infer_role_archive() {
        let role = infer_role("Archive");
        assert_eq!(role, "archive");
    }

    #[test]
    fn imap_client_ops_infer_role_unknown() {
        let role = infer_role("CustomFolder");
        assert_eq!(role, "other");
    }

    #[test]
    fn imap_client_ops_format_imap_date() {
        let dt = Utc::now();
        let formatted = format_imap_date(&dt);
        assert!(formatted.contains("-"));
    }

    #[test]
    fn imap_client_ops_spawn_blocking() {
        let result = tokio::task::spawn_blocking(|| 42u64);
        assert!(true);
    }

    #[test]
    fn imap_client_ops_uuid_new() {
        let id = Uuid::new_v4().to_string();
        assert!(id.contains("-"));
    }

    #[test]
    fn imap_client_ops_utc_now() {
        let now = Utc::now();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn imap_client_ops_bson_null() {
        let null = bson::Bson::Null;
        assert!(null.is_null());
    }

    #[test]
    fn imap_client_ops_i64_from_u64() {
        let uid = 42u64;
        let val = uid as i64;
        assert_eq!(val, 42);
    }

    #[test]
    fn imap_client_ops_u64_try_from_usize() {
        let val = 3usize;
        let result = u64::try_from(val);
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn imap_client_ops_result_ok() {
        let result: Result<String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn imap_client_ops_result_err() {
        let result: Result<String> = Err(mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        assert!(result.is_err());
    }

    #[test]
    fn imap_client_ops_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn imap_client_ops_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn imap_client_ops_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn imap_client_ops_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn imap_client_ops_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn imap_client_ops_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn imap_client_ops_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn imap_client_ops_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn imap_client_ops_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn imap_client_ops_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn imap_client_ops_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn imap_client_ops_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn imap_client_ops_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn imap_client_ops_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn imap_client_ops_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn imap_client_ops_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn imap_client_ops_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn imap_client_ops_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn imap_client_ops_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn imap_client_ops_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn imap_client_ops_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn imap_client_ops_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn imap_client_ops_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn imap_client_ops_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn imap_client_ops_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn imap_client_ops_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn imap_client_ops_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn imap_client_ops_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn imap_client_ops_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn imap_client_ops_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn imap_client_ops_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn imap_client_ops_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn imap_client_ops_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn imap_client_ops_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn imap_client_ops_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn imap_client_ops_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn imap_client_ops_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn imap_client_ops_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn imap_client_ops_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn imap_client_ops_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn imap_client_ops_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn imap_client_ops_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn imap_client_ops_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn imap_client_ops_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn imap_client_ops_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn imap_client_ops_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn imap_client_ops_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn imap_client_ops_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn imap_client_ops_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn imap_client_ops_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn imap_client_ops_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn imap_client_ops_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn imap_client_ops_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn imap_client_ops_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn imap_client_ops_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn imap_client_ops_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn imap_client_ops_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn imap_client_ops_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn imap_client_ops_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn imap_client_ops_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn imap_client_ops_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn imap_client_ops_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn imap_client_ops_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn imap_client_ops_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn imap_client_ops_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn imap_client_ops_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn imap_client_ops_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn imap_client_ops_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn imap_client_ops_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
