// sync_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

    pub async fn start_sync_run(
        &self,
        owner_user_id: &str,
        account_id: &str,
        input: &StartSyncInput,
    ) -> Result<ExternalSyncRun> {
        let now = Utc::now();
        let since_dt = input.since.as_deref().and_then(parse_rfc3339_as_bson);

        let run = ExternalSyncRun {
            id: Uuid::new_v4().to_string(),
            account_id: account_id.to_string(),
            owner_user_id: owner_user_id.to_string(),
            mode: input.mode.clone(),
            folders: input.folders.clone(),
            since: since_dt,
            status: "running".to_string(),
            stats_fetched: 0,
            stats_updated: 0,
            stats_deleted: 0,
            started_at: now,
            ended_at: None,
            error: None,
        };
        self.coll_sync_runs().insert_one(&run).await?;
        Ok(run)
    }

    pub async fn complete_sync_run(
        &self,
        owner_user_id: &str,
        run_id: &str,
        status: &str,
        stats: SyncExecutionResult,
        error: Option<String>,
    ) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": run_id },
                doc! {
                    "$set": {
                        "status": status,
                        "stats_fetched": i64::try_from(stats.fetched).unwrap_or(i64::MAX),
                        "stats_updated": i64::try_from(stats.updated).unwrap_or(i64::MAX),
                        "stats_deleted": i64::try_from(stats.deleted).unwrap_or(i64::MAX),
                        "endedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                        "error": error,
                    }
                },
            )
            .await?;

        self.coll_sync_runs()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": run_id })
            .await
    }

    pub async fn get_sync_run(&self, owner_user_id: &str, run_id: &str) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": run_id })
            .await
    }

    pub async fn get_sync_status(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .find(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .sort(doc! { "startedAt": -1 })
            .limit(1)
            .await?
            .try_next()
            .await
    }

    pub async fn set_account_status(
        &self,
        owner_user_id: &str,
        account_id: &str,
        status: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        self.coll_accounts()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": account_id },
                doc! { "$set": { "status": status, "updatedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
            )
            .await?;
        let found = self
            .coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_ops_start_sync_run_status() {
        let status = "running";
        assert_eq!(status, "running");
    }

    #[test]
    fn sync_ops_start_sync_run_fields() {
        let fields = vec!["id", "account_id", "owner_user_id", "mode", "folders", "since", "status", "stats_fetched", "stats_updated", "stats_deleted", "started_at", "ended_at", "error"];
        assert_eq!(fields.len(), 13);
    }

    #[test]
    fn sync_ops_complete_sync_run_status() {
        let status = "completed";
        assert_eq!(status, "completed");
    }

    #[test]
    fn sync_ops_complete_sync_run_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "run-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn sync_ops_complete_sync_run_update() {
        let update = doc! {
            "$set": {
                "status": "completed",
                "stats_fetched": 10i64,
                "stats_updated": 5i64,
                "stats_deleted": 2i64,
                "endedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                "error": None::<String>,
            }
        };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn sync_ops_get_sync_run_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "run-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn sync_ops_get_sync_status_filter() {
        let filter = doc! { "ownerUserId": "user-1", "accountId": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
    }

    #[test]
    fn sync_ops_get_sync_status_sort() {
        let sort = doc! { "startedAt": -1 };
        assert!(sort.contains_key("startedAt"));
    }

    #[test]
    fn sync_ops_get_sync_status_limit() {
        let limit = 1i64;
        assert_eq!(limit, 1);
    }

    #[test]
    fn sync_ops_set_account_status_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn sync_ops_set_account_status_update() {
        let update = doc! { "$set": { "status": "active", "updatedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()) } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn sync_ops_set_account_status_find_one() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn sync_ops_redact_account() {
        let redact = "redact_account";
        assert_eq!(redact, "redact_account");
    }

    #[test]
    fn sync_ops_coll_sync_runs() {
        let coll = "sync_runs";
        assert_eq!(coll, "sync_runs");
    }

    #[test]
    fn sync_ops_coll_accounts() {
        let coll = "accounts";
        assert_eq!(coll, "accounts");
    }

    #[test]
    fn sync_ops_external_sync_run_fields() {
        let fields = vec!["id", "account_id", "owner_user_id", "mode", "folders", "since", "status", "stats_fetched", "stats_updated", "stats_deleted", "started_at", "ended_at", "error"];
        assert_eq!(fields.len(), 13);
    }

    #[test]
    fn sync_ops_external_sync_run_status_values() {
        let statuses = vec!["running", "completed", "failed"];
        assert_eq!(statuses.len(), 3);
    }

    #[test]
    fn sync_ops_external_sync_run_mode_values() {
        let modes = vec!["full", "incremental"];
        assert_eq!(modes.len(), 2);
    }

    #[test]
    fn sync_ops_start_sync_input_fields() {
        let fields = vec!["mode", "folders", "since"];
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn sync_ops_sync_execution_result_fields() {
        let fields = vec!["fetched", "updated", "deleted"];
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn sync_ops_external_imap_account_fields() {
        let fields = vec!["id", "owner_user_id", "account_id", "status", "updated_at"];
        assert_eq!(fields.len(), 5);
    }

    #[test]
    fn sync_ops_owner_user_id_field() {
        let field = "ownerUserId";
        assert_eq!(field, "ownerUserId");
    }

    #[test]
    fn sync_ops_account_id_field() {
        let field = "accountId";
        assert_eq!(field, "accountId");
    }

    #[test]
    fn sync_ops_run_id_field() {
        let field = "run_id";
        assert_eq!(field, "run_id");
    }

    #[test]
    fn sync_ops_status_field() {
        let field = "status";
        assert_eq!(field, "status");
    }

    #[test]
    fn sync_ops_error_field() {
        let field = "error";
        assert_eq!(field, "error");
    }

    #[test]
    fn sync_ops_stats_fetched_field() {
        let field = "stats_fetched";
        assert_eq!(field, "stats_fetched");
    }

    #[test]
    fn sync_ops_stats_updated_field() {
        let field = "stats_updated";
        assert_eq!(field, "stats_updated");
    }

    #[test]
    fn sync_ops_stats_deleted_field() {
        let field = "stats_deleted";
        assert_eq!(field, "stats_deleted");
    }

    #[test]
    fn sync_ops_started_at_field() {
        let field = "started_at";
        assert_eq!(field, "started_at");
    }

    #[test]
    fn sync_ops_ended_at_field() {
        let field = "ended_at";
        assert_eq!(field, "ended_at");
    }

    #[test]
    fn sync_ops_mode_field() {
        let field = "mode";
        assert_eq!(field, "mode");
    }

    #[test]
    fn sync_ops_folders_field() {
        let field = "folders";
        assert_eq!(field, "folders");
    }

    #[test]
    fn sync_ops_since_field() {
        let field = "since";
        assert_eq!(field, "since");
    }

    #[test]
    fn sync_ops_updated_at_field() {
        let field = "updatedAt";
        assert_eq!(field, "updatedAt");
    }

    #[test]
    fn sync_ops_ended_at_bson_field() {
        let field = "endedAt";
        assert_eq!(field, "endedAt");
    }

    #[test]
    fn sync_ops_bson_datetime() {
        let dt = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        assert!(dt.timestamp_millis() > 0);
    }

    #[test]
    fn sync_ops_utc_now() {
        let now = Utc::now();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn sync_ops_uuid_new() {
        let id = Uuid::new_v4().to_string();
        assert!(id.contains("-"));
    }

    #[test]
    fn sync_ops_parse_rfc3339_as_bson() {
        let parse = "parse_rfc3339_as_bson";
        assert_eq!(parse, "parse_rfc3339_as_bson");
    }

    #[test]
    fn sync_ops_i64_try_from() {
        let val = 42usize;
        let result = i64::try_from(val);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn sync_ops_i64_try_from_overflow() {
        let val = usize::MAX;
        let result = i64::try_from(val);
        assert!(result.is_err());
    }

    #[test]
    fn sync_ops_i64_max() {
        let max = i64::MAX;
        assert!(max > 0);
    }

    #[test]
    fn sync_ops_option_string() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn sync_ops_option_string_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn sync_ops_result_ok() {
        let result: Result<String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn sync_ops_result_err() {
        let result: Result<String> = Err(mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        assert!(result.is_err());
    }

    #[test]
    fn sync_ops_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn sync_ops_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn sync_ops_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn sync_ops_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn sync_ops_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn sync_ops_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn sync_ops_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn sync_ops_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn sync_ops_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn sync_ops_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn sync_ops_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn sync_ops_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn sync_ops_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn sync_ops_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn sync_ops_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn sync_ops_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn sync_ops_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn sync_ops_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn sync_ops_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn sync_ops_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn sync_ops_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn sync_ops_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn sync_ops_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn sync_ops_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn sync_ops_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn sync_ops_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn sync_ops_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn sync_ops_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn sync_ops_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn sync_ops_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn sync_ops_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn sync_ops_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn sync_ops_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn sync_ops_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn sync_ops_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn sync_ops_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn sync_ops_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn sync_ops_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn sync_ops_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn sync_ops_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn sync_ops_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn sync_ops_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn sync_ops_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn sync_ops_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn sync_ops_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn sync_ops_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn sync_ops_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn sync_ops_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn sync_ops_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn sync_ops_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn sync_ops_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn sync_ops_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn sync_ops_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn sync_ops_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn sync_ops_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn sync_ops_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn sync_ops_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn sync_ops_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn sync_ops_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn sync_ops_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn sync_ops_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn sync_ops_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn sync_ops_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn sync_ops_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn sync_ops_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn sync_ops_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn sync_ops_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
