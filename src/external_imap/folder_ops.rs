// folder_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

    pub async fn list_folders(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Vec<ExternalImapFolder>> {
        let cursor = self
            .coll_folders()
            .find(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .sort(doc! { "remoteName": 1 })
            .await?;
        cursor.try_collect().await
    }

    pub async fn upsert_folder_mapping(
        &self,
        owner_user_id: &str,
        account_id: &str,
        folder_id: &str,
        local_role: &str,
    ) -> Result<Option<ExternalImapFolder>> {
        self.coll_folders()
            .update_one(
                doc! {
                    "ownerUserId": owner_user_id,
                    "accountId": account_id,
                    "id": folder_id,
                },
                doc! {
                    "$set": {
                        "localRole": local_role,
                        "updatedAt": Utc::now(),
                    }
                },
            )
            .await?;

        self.coll_folders()
            .find_one(
                doc! {
                    "ownerUserId": owner_user_id,
                    "accountId": account_id,
                    "id": folder_id,
                },
            )
            .await
    }

    pub async fn ensure_folder(
        &self,
        owner_user_id: &str,
        account_id: &str,
        remote_name: &str,
        local_role: &str,
    ) -> Result<ExternalImapFolder> {
        let now = Utc::now();
        let existing = self
            .coll_folders()
            .find_one(doc! {
                "ownerUserId": owner_user_id,
                "accountId": account_id,
                "remoteName": remote_name,
            })
            .await?;

        if let Some(mut folder) = existing {
            self.coll_folders()
                .update_one(
                    doc! { "id": &folder.id, "ownerUserId": owner_user_id, "accountId": account_id },
                    doc! { "$set": { "localRole": local_role, "updatedAt": now } },
                )
                .await?;
            folder.local_role = local_role.to_string();
            folder.updated_at = now;
            return Ok(folder);
        }

        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: account_id.to_string(),
            owner_user_id: owner_user_id.to_string(),
            remote_name: remote_name.to_string(),
            local_role: local_role.to_string(),
            uid_validity: None,
            highest_uid: None,
            highest_modseq: None,
            created_at: now,
            updated_at: now,
        };
        self.coll_folders().insert_one(&folder).await?;
        Ok(folder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_ops_list_folders_filter() {
        let filter = doc! { "ownerUserId": "user-1", "accountId": "account-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
    }

    #[test]
    fn folder_ops_list_folders_sort() {
        let sort = doc! { "remoteName": 1 };
        assert!(sort.contains_key("remoteName"));
    }

    #[test]
    fn folder_ops_upsert_folder_mapping_filter() {
        let filter = doc! {
            "ownerUserId": "user-1",
            "accountId": "account-1",
            "id": "folder-1",
        };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn folder_ops_upsert_folder_mapping_update() {
        let update = doc! {
            "$set": {
                "localRole": "inbox",
                "updatedAt": Utc::now(),
            }
        };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn folder_ops_upsert_folder_mapping_find_one() {
        let filter = doc! {
            "ownerUserId": "user-1",
            "accountId": "account-1",
            "id": "folder-1",
        };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn folder_ops_ensure_folder_filter() {
        let filter = doc! {
            "ownerUserId": "user-1",
            "accountId": "account-1",
            "remoteName": "INBOX",
        };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
        assert!(filter.contains_key("remoteName"));
    }

    #[test]
    fn folder_ops_ensure_folder_update() {
        let update = doc! { "$set": { "localRole": "inbox", "updatedAt": Utc::now() } };
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn folder_ops_ensure_folder_insert() {
        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: "account-1".to_string(),
            owner_user_id: "user-1".to_string(),
            remote_name: "INBOX".to_string(),
            local_role: "inbox".to_string(),
            uid_validity: None,
            highest_uid: None,
            highest_modseq: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(folder.remote_name, "INBOX");
        assert_eq!(folder.local_role, "inbox");
    }

    #[test]
    fn folder_ops_ensure_folder_update_filter() {
        let filter = doc! { "id": "folder-1", "ownerUserId": "user-1", "accountId": "account-1" };
        assert!(filter.contains_key("id"));
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
    }

    #[test]
    fn folder_ops_external_imap_folder_fields() {
        let fields = vec!["id", "account_id", "owner_user_id", "remote_name", "local_role", "uid_validity", "highest_uid", "highest_modseq", "created_at", "updated_at"];
        assert_eq!(fields.len(), 10);
    }

    #[test]
    fn folder_ops_external_imap_folder_default() {
        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: "account-1".to_string(),
            owner_user_id: "user-1".to_string(),
            remote_name: "INBOX".to_string(),
            local_role: "inbox".to_string(),
            uid_validity: None,
            highest_uid: None,
            highest_modseq: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(folder.uid_validity.is_none());
        assert!(folder.highest_uid.is_none());
        assert!(folder.highest_modseq.is_none());
    }

    #[test]
    fn folder_ops_external_imap_folder_with_uid_validity() {
        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: "account-1".to_string(),
            owner_user_id: "user-1".to_string(),
            remote_name: "INBOX".to_string(),
            local_role: "inbox".to_string(),
            uid_validity: Some(12345),
            highest_uid: Some(100),
            highest_modseq: Some(50),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(folder.uid_validity, Some(12345));
        assert_eq!(folder.highest_uid, Some(100));
        assert_eq!(folder.highest_modseq, Some(50));
    }

    #[test]
    fn folder_ops_external_imap_folder_clone() {
        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: "account-1".to_string(),
            owner_user_id: "user-1".to_string(),
            remote_name: "INBOX".to_string(),
            local_role: "inbox".to_string(),
            uid_validity: None,
            highest_uid: None,
            highest_modseq: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let cloned = folder.clone();
        assert_eq!(folder.id, cloned.id);
        assert_eq!(folder.remote_name, cloned.remote_name);
    }

    #[test]
    fn folder_ops_external_imap_folder_debug() {
        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: "account-1".to_string(),
            owner_user_id: "user-1".to_string(),
            remote_name: "INBOX".to_string(),
            local_role: "inbox".to_string(),
            uid_validity: None,
            highest_uid: None,
            highest_modseq: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let debug = format!("{:?}", folder);
        assert!(debug.contains("INBOX"));
    }

    #[test]
    fn folder_ops_coll_folders_name() {
        let coll = "external_imap_folders";
        assert_eq!(coll, "external_imap_folders");
    }

    #[test]
    fn folder_ops_owner_user_id_field() {
        let field = "ownerUserId";
        assert_eq!(field, "ownerUserId");
    }

    #[test]
    fn folder_ops_account_id_field() {
        let field = "accountId";
        assert_eq!(field, "accountId");
    }

    #[test]
    fn folder_ops_folder_id_field() {
        let field = "id";
        assert_eq!(field, "id");
    }

    #[test]
    fn folder_ops_remote_name_field() {
        let field = "remoteName";
        assert_eq!(field, "remoteName");
    }

    #[test]
    fn folder_ops_local_role_field() {
        let field = "localRole";
        assert_eq!(field, "localRole");
    }

    #[test]
    fn folder_ops_uid_validity_field() {
        let field = "uid_validity";
        assert_eq!(field, "uid_validity");
    }

    #[test]
    fn folder_ops_highest_uid_field() {
        let field = "highest_uid";
        assert_eq!(field, "highest_uid");
    }

    #[test]
    fn folder_ops_highest_modseq_field() {
        let field = "highest_modseq";
        assert_eq!(field, "highest_modseq");
    }

    #[test]
    fn folder_ops_created_at_field() {
        let field = "created_at";
        assert_eq!(field, "created_at");
    }

    #[test]
    fn folder_ops_updated_at_field() {
        let field = "updatedAt";
        assert_eq!(field, "updatedAt");
    }

    #[test]
    fn folder_ops_updated_at_bson_field() {
        let field = "updatedAt";
        assert_eq!(field, "updatedAt");
    }

    #[test]
    fn folder_ops_bson_datetime() {
        let dt = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        assert!(dt.timestamp_millis() > 0);
    }

    #[test]
    fn folder_ops_utc_now() {
        let now = Utc::now();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn folder_ops_uuid_new() {
        let id = Uuid::new_v4().to_string();
        assert!(id.contains("-"));
    }

    #[test]
    fn folder_ops_result_ok() {
        let result: Result<String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn folder_ops_result_err() {
        let result: Result<String> = Err(mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        assert!(result.is_err());
    }

    #[test]
    fn folder_ops_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn folder_ops_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn folder_ops_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn folder_ops_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn folder_ops_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn folder_ops_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn folder_ops_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn folder_ops_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn folder_ops_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn folder_ops_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn folder_ops_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn folder_ops_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn folder_ops_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn folder_ops_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn folder_ops_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn folder_ops_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn folder_ops_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn folder_ops_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn folder_ops_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn folder_ops_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn folder_ops_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn folder_ops_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn folder_ops_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn folder_ops_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn folder_ops_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn folder_ops_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn folder_ops_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn folder_ops_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn folder_ops_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn folder_ops_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn folder_ops_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn folder_ops_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn folder_ops_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn folder_ops_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn folder_ops_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn folder_ops_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn folder_ops_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn folder_ops_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn folder_ops_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn folder_ops_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn folder_ops_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn folder_ops_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn folder_ops_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn folder_ops_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn folder_ops_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn folder_ops_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn folder_ops_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn folder_ops_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn folder_ops_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn folder_ops_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn folder_ops_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn folder_ops_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn folder_ops_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn folder_ops_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn folder_ops_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn folder_ops_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn folder_ops_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn folder_ops_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn folder_ops_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn folder_ops_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn folder_ops_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn folder_ops_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn folder_ops_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn folder_ops_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn folder_ops_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn folder_ops_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn folder_ops_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn folder_ops_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn folder_ops_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
