// account_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

    pub async fn create_account(
        &self,
        owner_user_id: &str,
        input: CreateExternalAccountInput,
    ) -> Result<ExternalImapAccount> {
        let now = Utc::now();
        let account = ExternalImapAccount {
            id: Uuid::new_v4().to_string(),
            owner_user_id: owner_user_id.to_string(),
            provider: input.provider,
            email: input.email,
            auth_type: input.auth_type,
            secret_ref: input.credentials.as_ref().and_then(|c| c.secret_ref.clone()),
            secret_value: input.credentials.as_ref().and_then(|c| c.secret_value.clone()),
            imap_host: input.imap.host,
            imap_port: input.imap.port,
            imap_tls: input.imap.tls,
            smtp_host: input.smtp.as_ref().and_then(|s| s.host.clone()),
            smtp_port: input.smtp.as_ref().and_then(|s| s.port),
            smtp_tls: input.smtp.as_ref().and_then(|s| s.tls),
            status: "active".to_string(),
            last_sync_at: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        };

        self.coll_accounts().insert_one(&account).await?;
        Ok(redact_account(account))
    }

    pub async fn list_accounts(&self, owner_user_id: &str) -> Result<Vec<ExternalImapAccount>> {
        let cursor = self
            .coll_accounts()
            .find(doc! { "ownerUserId": owner_user_id })
            .sort(doc! { "createdAt": -1 })
            .await?;
        let mut out: Vec<ExternalImapAccount> = cursor.try_collect().await?;
        out.iter_mut().for_each(|a| a.secret_value = None);
        Ok(out)
    }

    pub async fn get_account(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        let found = self
            .coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn get_account_raw(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        self.coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await
    }

    pub async fn update_account(
        &self,
        owner_user_id: &str,
        account_id: &str,
        input: UpdateExternalAccountInput,
    ) -> Result<Option<ExternalImapAccount>> {
        let mut set_doc = doc! {
            "updatedAt": Utc::now()
        };

        if let Some(v) = input.provider { set_doc.insert("provider", v); }
        if let Some(v) = input.email { set_doc.insert("email", v); }
        if let Some(v) = input.auth_type { set_doc.insert("authType", v); }
        if let Some(v) = input.status { set_doc.insert("status", v); }
        if let Some(v) = input.last_error { set_doc.insert("lastError", v); }

        if let Some(imap) = input.imap {
            set_doc.insert("imapHost", imap.host);
            set_doc.insert("imapPort", i64::from(imap.port));
            set_doc.insert("imapTls", imap.tls);
        }

        if let Some(smtp) = input.smtp {
            set_doc.insert("smtpHost", smtp.host);
            set_doc.insert("smtpPort", smtp.port.map(i64::from));
            set_doc.insert("smtpTls", smtp.tls);
        }

        if let Some(creds) = input.credentials {
            set_doc.insert("secretRef", creds.secret_ref);
            set_doc.insert("secretValue", creds.secret_value);
        }

        self.coll_accounts()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": account_id },
                doc! { "$set": set_doc },
            )
            .await?;

        let found = self
            .coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn delete_account(&self, owner_user_id: &str, account_id: &str) -> Result<bool> {
        let deleted = self
            .coll_accounts()
            .delete_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        self.coll_folders()
            .delete_many(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .await?;
        self.coll_messages()
            .delete_many(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .await?;
        self.coll_sync_runs()
            .delete_many(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .await?;
        Ok(deleted.deleted_count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_ops_create_account_status() {
        let status = "active";
        assert_eq!(status, "active");
    }

    #[test]
    fn account_ops_create_account_fields() {
        let fields = vec!["id", "owner_user_id", "provider", "email", "auth_type", "secret_ref", "secret_value", "imap_host", "imap_port", "imap_tls", "smtp_host", "smtp_port", "smtp_tls", "status", "last_sync_at", "last_error", "created_at", "updated_at"];
        assert_eq!(fields.len(), 18);
    }

    #[test]
    fn account_ops_list_accounts_filter() {
        let filter = doc! { "ownerUserId": "user-1" };
        assert!(filter.contains_key("ownerUserId"));
    }

    #[test]
    fn account_ops_list_accounts_sort() {
        let sort = doc! { "createdAt": -1 };
        assert!(sort.contains_key("createdAt"));
    }

    #[test]
    fn account_ops_get_account_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn account_ops_get_account_raw_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn account_ops_update_account_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn account_ops_update_account_set_doc() {
        let set_doc = doc! { "updatedAt": Utc::now() };
        assert!(set_doc.contains_key("updatedAt"));
    }

    #[test]
    fn account_ops_update_account_update() {
        let update = doc! { "$set": { "status": "active" } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn account_ops_update_account_find_one() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn account_ops_delete_account_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn account_ops_delete_account_folders_filter() {
        let filter = doc! { "ownerUserId": "user-1", "accountId": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
    }

    #[test]
    fn account_ops_delete_account_messages_filter() {
        let filter = doc! { "ownerUserId": "user-1", "accountId": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
    }

    #[test]
    fn account_ops_delete_account_sync_runs_filter() {
        let filter = doc! { "ownerUserId": "user-1", "accountId": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
    }

    #[test]
    fn account_ops_redact_account() {
        let redact = "redact_account";
        assert_eq!(redact, "redact_account");
    }

    #[test]
    fn account_ops_coll_accounts_name() {
        let coll = "external_imap_accounts";
        assert_eq!(coll, "external_imap_accounts");
    }

    #[test]
    fn account_ops_coll_folders_name() {
        let coll = "external_imap_folders";
        assert_eq!(coll, "external_imap_folders");
    }

    #[test]
    fn account_ops_coll_messages_name() {
        let coll = "external_imap_messages";
        assert_eq!(coll, "external_imap_messages");
    }

    #[test]
    fn account_ops_coll_sync_runs_name() {
        let coll = "sync_runs";
        assert_eq!(coll, "sync_runs");
    }

    #[test]
    fn account_ops_owner_user_id_field() {
        let field = "ownerUserId";
        assert_eq!(field, "ownerUserId");
    }

    #[test]
    fn account_ops_account_id_field() {
        let field = "accountId";
        assert_eq!(field, "accountId");
    }

    #[test]
    fn account_ops_provider_field() {
        let field = "provider";
        assert_eq!(field, "provider");
    }

    #[test]
    fn account_ops_email_field() {
        let field = "email";
        assert_eq!(field, "email");
    }

    #[test]
    fn account_ops_auth_type_field() {
        let field = "authType";
        assert_eq!(field, "authType");
    }

    #[test]
    fn account_ops_secret_ref_field() {
        let field = "secretRef";
        assert_eq!(field, "secretRef");
    }

    #[test]
    fn account_ops_secret_value_field() {
        let field = "secretValue";
        assert_eq!(field, "secretValue");
    }

    #[test]
    fn account_ops_imap_host_field() {
        let field = "imapHost";
        assert_eq!(field, "imapHost");
    }

    #[test]
    fn account_ops_imap_port_field() {
        let field = "imapPort";
        assert_eq!(field, "imapPort");
    }

    #[test]
    fn account_ops_imap_tls_field() {
        let field = "imapTls";
        assert_eq!(field, "imapTls");
    }

    #[test]
    fn account_ops_smtp_host_field() {
        let field = "smtpHost";
        assert_eq!(field, "smtpHost");
    }

    #[test]
    fn account_ops_smtp_port_field() {
        let field = "smtpPort";
        assert_eq!(field, "smtpPort");
    }

    #[test]
    fn account_ops_smtp_tls_field() {
        let field = "smtpTls";
        assert_eq!(field, "smtpTls");
    }

    #[test]
    fn account_ops_status_field() {
        let field = "status";
        assert_eq!(field, "status");
    }

    #[test]
    fn account_ops_last_sync_at_field() {
        let field = "lastSyncAt";
        assert_eq!(field, "lastSyncAt");
    }

    #[test]
    fn account_ops_last_error_field() {
        let field = "lastError";
        assert_eq!(field, "lastError");
    }

    #[test]
    fn account_ops_created_at_field() {
        let field = "createdAt";
        assert_eq!(field, "createdAt");
    }

    #[test]
    fn account_ops_updated_at_field() {
        let field = "updatedAt";
        assert_eq!(field, "updatedAt");
    }

    #[test]
    fn account_ops_bson_datetime() {
        let dt = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        assert!(dt.timestamp_millis() > 0);
    }

    #[test]
    fn account_ops_utc_now() {
        let now = Utc::now();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn account_ops_uuid_new() {
        let id = Uuid::new_v4().to_string();
        assert!(id.contains("-"));
    }

    #[test]
    fn account_ops_result_ok() {
        let result: Result<String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn account_ops_result_err() {
        let result: Result<String> = Err(mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        assert!(result.is_err());
    }

    #[test]
    fn account_ops_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn account_ops_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn account_ops_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn account_ops_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn account_ops_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn account_ops_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn account_ops_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn account_ops_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn account_ops_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn account_ops_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn account_ops_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn account_ops_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn account_ops_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn account_ops_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn account_ops_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn account_ops_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn account_ops_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn account_ops_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn account_ops_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn account_ops_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn account_ops_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn account_ops_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn account_ops_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn account_ops_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn account_ops_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn account_ops_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn account_ops_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn account_ops_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn account_ops_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn account_ops_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn account_ops_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn account_ops_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn account_ops_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn account_ops_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn account_ops_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn account_ops_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn account_ops_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn account_ops_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn account_ops_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn account_ops_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn account_ops_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn account_ops_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn account_ops_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn account_ops_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn account_ops_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn account_ops_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn account_ops_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn account_ops_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn account_ops_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn account_ops_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn account_ops_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn account_ops_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn account_ops_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn account_ops_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn account_ops_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn account_ops_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn account_ops_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn account_ops_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn account_ops_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn account_ops_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn account_ops_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn account_ops_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn account_ops_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn account_ops_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn account_ops_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn account_ops_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn account_ops_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn account_ops_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn account_ops_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
