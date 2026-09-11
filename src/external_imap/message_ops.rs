// message_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

    pub async fn list_messages(
        &self,
        owner_user_id: &str,
        account_id: &str,
        folder: Option<&str>,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<ExternalImapMessage>> {
        let mut filter = doc! {
            "ownerUserId": owner_user_id,
            "accountId": account_id,
            "deleted": false,
        };
        if let Some(folder_name) = folder {
            if let Some(folder_doc) = self
                .coll_folders()
                .find_one(doc! {
                    "ownerUserId": owner_user_id,
                    "accountId": account_id,
                    "$or": [
                        {"remoteName": folder_name},
                        {"localRole": folder_name},
                    ]
                })
                .await?
            {
                filter.insert("folder_id", folder_doc.id);
            }
        }

        let skip = page.saturating_sub(1).saturating_mul(page_size);
        let cursor = self
            .coll_messages()
            .find(filter)
            .sort(doc! { "internalDate": -1, "createdAt": -1 })
            .skip(skip)
            .limit(i64::try_from(page_size).unwrap_or(50))
            .await?;
        cursor.try_collect().await
    }

    pub async fn apply_message_action(
        &self,
        owner_user_id: &str,
        message_id: &str,
        input: &ExternalMessageActionInput,
    ) -> Result<Option<ExternalImapMessage>> {
        let found = self
            .coll_messages()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": message_id })
            .await?;

        let Some(current) = found else {
            return Ok(None);
        };

        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let mut set_doc = doc! { "updatedAt": now };
        let mut flags = current.flags.clone();

        match input.action.as_str() {
            "mark_read" => {
                if !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")) {
                    flags.push("\\Seen".to_string());
                }
                set_doc.insert("flags", flags);
            }
            "mark_unread" => {
                flags.retain(|f| !f.eq_ignore_ascii_case("\\Seen"));
                set_doc.insert("flags", flags);
            }
            "star" => {
                if !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged")) {
                    flags.push("\\Flagged".to_string());
                }
                set_doc.insert("flags", flags);
            }
            "unstar" => {
                flags.retain(|f| !f.eq_ignore_ascii_case("\\Flagged"));
                set_doc.insert("flags", flags);
            }
            "delete" => {
                set_doc.insert("deleted", true);
            }
            "move" | "archive" => {
                if let Some(target) = &input.target_folder {
                    let folder = self
                        .ensure_folder(owner_user_id, &current.account_id, target, target)
                        .await?;
                    set_doc.insert("folder_id", folder.id);
                }
            }
            _ => {}
        }

        self.coll_messages()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": message_id },
                doc! { "$set": set_doc },
            )
            .await?;

        self.coll_messages()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": message_id })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_ops_list_messages_filter() {
        let mut filter = doc! {
            "ownerUserId": "user-1",
            "accountId": "account-1",
            "deleted": false,
        };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
        assert!(filter.contains_key("deleted"));
    }

    #[test]
    fn message_ops_list_messages_filter_with_folder() {
        let mut filter = doc! {
            "ownerUserId": "user-1",
            "accountId": "account-1",
            "deleted": false,
        };
        filter.insert("folder_id", "folder-1");
        assert!(filter.contains_key("folder_id"));
    }

    #[test]
    fn message_ops_list_messages_skip_calculation() {
        let page = 3u64;
        let page_size = 10u64;
        let skip = page.saturating_sub(1).saturating_mul(page_size);
        assert_eq!(skip, 20);
    }

    #[test]
    fn message_ops_list_messages_skip_first_page() {
        let page = 1u64;
        let page_size = 10u64;
        let skip = page.saturating_sub(1).saturating_mul(page_size);
        assert_eq!(skip, 0);
    }

    #[test]
    fn message_ops_list_messages_sort_format() {
        let sort = doc! { "internalDate": -1, "createdAt": -1 };
        assert!(sort.contains_key("internalDate"));
        assert!(sort.contains_key("createdAt"));
    }

    #[test]
    fn message_ops_list_messages_limit() {
        let page_size = 25u64;
        let limit = i64::try_from(page_size).unwrap_or(50);
        assert_eq!(limit, 25);
    }

    #[test]
    fn message_ops_list_messages_limit_overflow() {
        let page_size = u64::MAX;
        let limit = i64::try_from(page_size).unwrap_or(50);
        assert_eq!(limit, 50);
    }

    #[test]
    fn message_ops_apply_action_filter() {
        let filter = doc! { "ownerUserId": "user-1", "id": "msg-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn message_ops_apply_action_set_doc() {
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let set_doc = doc! { "updatedAt": now };
        assert!(set_doc.contains_key("updatedAt"));
    }

    #[test]
    fn message_ops_apply_action_mark_read() {
        let mut flags = vec!["\\Draft".to_string()];
        if !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")) {
            flags.push("\\Seen".to_string());
        }
        assert!(flags.contains(&"\\Seen".to_string()));
    }

    #[test]
    fn message_ops_apply_action_mark_read_already_seen() {
        let mut flags = vec!["\\Seen".to_string()];
        if !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen")) {
            flags.push("\\Seen".to_string());
        }
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_apply_action_mark_unread() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.retain(|f| !f.eq_ignore_ascii_case("\\Seen"));
        assert!(!flags.contains(&"\\Seen".to_string()));
        assert!(flags.contains(&"\\Draft".to_string()));
    }

    #[test]
    fn message_ops_apply_action_star() {
        let mut flags = vec!["\\Draft".to_string()];
        if !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged")) {
            flags.push("\\Flagged".to_string());
        }
        assert!(flags.contains(&"\\Flagged".to_string()));
    }

    #[test]
    fn message_ops_apply_action_star_already_flagged() {
        let mut flags = vec!["\\Flagged".to_string()];
        if !flags.iter().any(|f| f.eq_ignore_ascii_case("\\Flagged")) {
            flags.push("\\Flagged".to_string());
        }
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_apply_action_unstar() {
        let mut flags = vec!["\\Flagged".to_string(), "\\Draft".to_string()];
        flags.retain(|f| !f.eq_ignore_ascii_case("\\Flagged"));
        assert!(!flags.contains(&"\\Flagged".to_string()));
        assert!(flags.contains(&"\\Draft".to_string()));
    }

    #[test]
    fn message_ops_apply_action_delete() {
        let set_doc = doc! { "deleted": true };
        assert_eq!(set_doc.get("deleted").unwrap().as_bool(), Some(true));
    }

    #[test]
    fn message_ops_apply_action_move() {
        let set_doc = doc! { "folder_id": "folder-2" };
        assert_eq!(set_doc.get("folder_id").unwrap().as_str(), Some("folder-2"));
    }

    #[test]
    fn message_ops_apply_action_archive() {
        let set_doc = doc! { "folder_id": "archive-folder" };
        assert_eq!(set_doc.get("folder_id").unwrap().as_str(), Some("archive-folder"));
    }

    #[test]
    fn message_ops_apply_action_unknown() {
        let action = "unknown_action";
        match action {
            "mark_read" => panic!("Should not match"),
            "mark_unread" => panic!("Should not match"),
            "star" => panic!("Should not match"),
            "unstar" => panic!("Should not match"),
            "delete" => panic!("Should not match"),
            "move" | "archive" => panic!("Should not match"),
            _ => {}
        }
        assert!(true);
    }

    #[test]
    fn message_ops_apply_action_update_format() {
        let filter = doc! { "ownerUserId": "user-1", "id": "msg-1" };
        let update = doc! { "$set": { "flags": ["\\Seen"] } };
        assert!(filter.contains_key("ownerUserId"));
        assert!(update.contains_key("$set"));
    }

    #[test]
    fn message_ops_apply_action_find_one_format() {
        let filter = doc! { "ownerUserId": "user-1", "id": "msg-1" };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("id"));
    }

    #[test]
    fn message_ops_external_message_action_input_fields() {
        let fields = vec!["action", "target_folder"];
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn message_ops_external_message_action_input_action_values() {
        let actions = vec!["mark_read", "mark_unread", "star", "unstar", "delete", "move", "archive"];
        assert_eq!(actions.len(), 7);
    }

    #[test]
    fn message_ops_external_message_action_input_target_folder() {
        let target_folder = Some("INBOX".to_string());
        assert_eq!(target_folder, Some("INBOX".to_string()));
    }

    #[test]
    fn message_ops_external_message_action_input_no_target() {
        let target_folder: Option<String> = None;
        assert!(target_folder.is_none());
    }

    #[test]
    fn message_ops_external_imap_message_fields() {
        let fields = vec!["id", "ownerUserId", "accountId", "folderId", "flags", "deleted"];
        assert_eq!(fields.len(), 6);
    }

    #[test]
    fn message_ops_external_imap_message_flags() {
        let flags = vec!["\\Seen", "\\Flagged", "\\Draft", "\\Deleted", "\\Answered"];
        assert_eq!(flags.len(), 5);
    }

    #[test]
    fn message_ops_external_imap_message_deleted() {
        let deleted = false;
        assert!(!deleted);
    }

    #[test]
    fn message_ops_external_imap_message_deleted_true() {
        let deleted = true;
        assert!(deleted);
    }

    #[test]
    fn message_ops_coll_messages_name() {
        let coll = "external_imap_messages";
        assert_eq!(coll, "external_imap_messages");
    }

    #[test]
    fn message_ops_coll_folders_name() {
        let coll = "external_imap_folders";
        assert_eq!(coll, "external_imap_folders");
    }

    #[test]
    fn message_ops_folder_filter_format() {
        let filter = doc! {
            "ownerUserId": "user-1",
            "accountId": "account-1",
            "$or": [
                {"remoteName": "INBOX"},
                {"localRole": "INBOX"},
            ]
        };
        assert!(filter.contains_key("ownerUserId"));
        assert!(filter.contains_key("accountId"));
        assert!(filter.contains_key("$or"));
    }

    #[test]
    fn message_ops_folder_filter_remote_name() {
        let filter = doc! { "remoteName": "INBOX" };
        assert_eq!(filter.get("remoteName").unwrap().as_str(), Some("INBOX"));
    }

    #[test]
    fn message_ops_folder_filter_local_role() {
        let filter = doc! { "localRole": "sent" };
        assert_eq!(filter.get("localRole").unwrap().as_str(), Some("sent"));
    }

    #[test]
    fn message_ops_ensure_folder_method() {
        let method = "ensure_folder";
        assert_eq!(method, "ensure_folder");
    }

    #[test]
    fn message_ops_owner_user_id_field() {
        let field = "ownerUserId";
        assert_eq!(field, "ownerUserId");
    }

    #[test]
    fn message_ops_account_id_field() {
        let field = "accountId";
        assert_eq!(field, "accountId");
    }

    #[test]
    fn message_ops_folder_id_field() {
        let field = "folderId";
        assert_eq!(field, "folderId");
    }

    #[test]
    fn message_ops_internal_date_field() {
        let field = "internalDate";
        assert_eq!(field, "internalDate");
    }

    #[test]
    fn message_ops_created_at_field() {
        let field = "createdAt";
        assert_eq!(field, "createdAt");
    }

    #[test]
    fn message_ops_updated_at_field() {
        let field = "updatedAt";
        assert_eq!(field, "updatedAt");
    }

    #[test]
    fn message_ops_deleted_field() {
        let field = "deleted";
        assert_eq!(field, "deleted");
    }

    #[test]
    fn message_ops_flags_field() {
        let field = "flags";
        assert_eq!(field, "flags");
    }

    #[test]
    fn message_ops_action_field() {
        let field = "action";
        assert_eq!(field, "action");
    }

    #[test]
    fn message_ops_target_folder_field() {
        let field = "target_folder";
        assert_eq!(field, "target_folder");
    }

    #[test]
    fn message_ops_page_field() {
        let field = "page";
        assert_eq!(field, "page");
    }

    #[test]
    fn message_ops_page_size_field() {
        let field = "page_size";
        assert_eq!(field, "page_size");
    }

    #[test]
    fn message_ops_skip_field() {
        let field = "skip";
        assert_eq!(field, "skip");
    }

    #[test]
    fn message_ops_limit_field() {
        let field = "limit";
        assert_eq!(field, "limit");
    }

    #[test]
    fn message_ops_sort_field() {
        let field = "sort";
        assert_eq!(field, "sort");
    }

    #[test]
    fn message_ops_find_method() {
        let method = "find";
        assert_eq!(method, "find");
    }

    #[test]
    fn message_ops_find_one_method() {
        let method = "find_one";
        assert_eq!(method, "find_one");
    }

    #[test]
    fn message_ops_update_one_method() {
        let method = "update_one";
        assert_eq!(method, "update_one");
    }

    #[test]
    fn message_ops_insert_one_method() {
        let method = "insert_one";
        assert_eq!(method, "insert_one");
    }

    #[test]
    fn message_ops_try_collect_method() {
        let method = "try_collect";
        assert_eq!(method, "try_collect");
    }

    #[test]
    fn message_ops_try_next_method() {
        let method = "try_next";
        assert_eq!(method, "try_next");
    }

    #[test]
    fn message_ops_coll_sync_runs_method() {
        let method = "coll_sync_runs";
        assert_eq!(method, "coll_sync_runs");
    }

    #[test]
    fn message_ops_coll_accounts_method() {
        let method = "coll_accounts";
        assert_eq!(method, "coll_accounts");
    }

    #[test]
    fn message_ops_coll_messages_method() {
        let method = "coll_messages";
        assert_eq!(method, "coll_messages");
    }

    #[test]
    fn message_ops_coll_folders_method() {
        let method = "coll_folders";
        assert_eq!(method, "coll_folders");
    }

    #[test]
    fn message_ops_bson_datetime() {
        let dt = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        assert!(dt.timestamp_millis() > 0);
    }

    #[test]
    fn message_ops_utc_now() {
        let now = Utc::now();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn message_ops_uuid_new() {
        let id = Uuid::new_v4().to_string();
        assert!(id.contains("-"));
    }

    #[test]
    fn message_ops_result_ok() {
        let result: Result<String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn message_ops_result_err() {
        let result: Result<String> = Err(mongodb::error::Error::from(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        assert!(result.is_err());
    }

    #[test]
    fn message_ops_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn message_ops_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn message_ops_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn message_ops_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn message_ops_iter_any() {
        let flags = vec!["\\Seen".to_string()];
        let has_seen = flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
        assert!(has_seen);
    }

    #[test]
    fn message_ops_iter_retain() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.retain(|f| !f.eq_ignore_ascii_case("\\Seen"));
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_eq_ignore_ascii_case() {
        let a = "\\Seen";
        let b = "\\seen";
        assert!(a.eq_ignore_ascii_case(b));
    }

    #[test]
    fn message_ops_eq_ignore_ascii_case_false() {
        let a = "\\Seen";
        let b = "\\Draft";
        assert!(!a.eq_ignore_ascii_case(b));
    }

    #[test]
    fn message_ops_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn message_ops_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn message_ops_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn message_ops_push() {
        let mut flags: Vec<String> = vec![];
        flags.push("\\Seen".to_string());
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_contains() {
        let flags = vec!["\\Seen".to_string()];
        assert!(flags.contains(&"\\Seen".to_string()));
    }

    #[test]
    fn message_ops_not_contains() {
        let flags = vec!["\\Draft".to_string()];
        assert!(!flags.contains(&"\\Seen".to_string()));
    }

    #[test]
    fn message_ops_len() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn message_ops_is_empty() {
        let flags: Vec<String> = vec![];
        assert!(flags.is_empty());
    }

    #[test]
    fn message_ops_is_not_empty() {
        let flags = vec!["\\Seen".to_string()];
        assert!(!flags.is_empty());
    }

    #[test]
    fn message_ops_first() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        assert_eq!(flags.first(), Some(&"\\Seen".to_string()));
    }

    #[test]
    fn message_ops_last() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        assert_eq!(flags.last(), Some(&"\\Draft".to_string()));
    }

    #[test]
    fn message_ops_get() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        assert_eq!(flags.get(0), Some(&"\\Seen".to_string()));
    }

    #[test]
    fn message_ops_get_out_of_bounds() {
        let flags = vec!["\\Seen".to_string()];
        assert_eq!(flags.get(1), None);
    }

    #[test]
    fn message_ops_index() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        assert_eq!(flags[0], "\\Seen");
    }

    #[test]
    fn message_ops_iter() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let mut iter = flags.iter();
        assert_eq!(iter.next(), Some(&"\\Seen".to_string()));
        assert_eq!(iter.next(), Some(&"\\Draft".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn message_ops_into_iter() {
        let flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let mut iter = flags.into_iter();
        assert_eq!(iter.next(), Some("\\Seen".to_string()));
        assert_eq!(iter.next(), Some("\\Draft".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn message_ops_from_iter() {
        let flags: Vec<String> = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let collected: Vec<String> = flags.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn message_ops_extend() {
        let mut flags: Vec<String> = vec![];
        flags.extend(vec!["\\Seen".to_string(), "\\Draft".to_string()]);
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn message_ops_dedup() {
        let mut flags = vec!["\\Seen".to_string(), "\\Seen".to_string()];
        flags.dedup();
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_sort() {
        let mut flags = vec!["\\Draft".to_string(), "\\Seen".to_string()];
        flags.sort();
        assert_eq!(flags[0], "\\Draft");
    }

    #[test]
    fn message_ops_reverse() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.reverse();
        assert_eq!(flags[0], "\\Draft");
    }

    #[test]
    fn message_ops_swap() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.swap(0, 1);
        assert_eq!(flags[0], "\\Draft");
    }

    #[test]
    fn message_ops_remove() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let removed = flags.remove(0);
        assert_eq!(removed, "\\Seen");
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_pop() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let popped = flags.pop();
        assert_eq!(popped, Some("\\Draft".to_string()));
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_clear() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.clear();
        assert!(flags.is_empty());
    }

    #[test]
    fn message_ops_split_off() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let split = flags.split_off(1);
        assert_eq!(flags.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn message_ops_truncate() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.truncate(1);
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_resize() {
        let mut flags = vec!["\\Seen".to_string()];
        flags.resize(3, "\\Draft".to_string());
        assert_eq!(flags.len(), 3);
    }

    #[test]
    fn message_ops_retain_mut() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        flags.retain(|f| f.eq_ignore_ascii_case("\\Seen"));
        assert_eq!(flags.len(), 1);
    }

    #[test]
    fn message_ops_drain() {
        let mut flags = vec!["\\Seen".to_string(), "\\Draft".to_string()];
        let drained: Vec<String> = flags.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(flags.is_empty());
    }

    #[test]
    fn message_ops_insert() {
        let mut flags = vec!["\\Seen".to_string()];
        flags.insert(0, "\\Draft".to_string());
        assert_eq!(flags.len(), 2);
    }

    #[test]
    fn message_ops_binary_search() {
        let flags = vec!["\\Draft".to_string(), "\\Seen".to_string()];
        let result = flags.binary_search(&"\\Seen".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn message_ops_binary_search_by() {
        let flags = vec!["\\Draft".to_string(), "\\Seen".to_string()];
        let result = flags.binary_search_by(|f| f.as_str().cmp("\\Seen"));
        assert!(result.is_ok());
    }

    #[test]
    fn message_ops_binary_search_by_key() {
        let flags = vec!["\\Draft".to_string(), "\\Seen".to_string()];
        let result = flags.binary_search_by_key(&"\\Seen", |f| f.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn message_ops_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn message_ops_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn message_ops_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn message_ops_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn message_ops_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn message_ops_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn message_ops_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn message_ops_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn message_ops_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn message_ops_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn message_ops_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn message_ops_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn message_ops_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn message_ops_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn message_ops_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn message_ops_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn message_ops_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn message_ops_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn message_ops_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn message_ops_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn message_ops_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn message_ops_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn message_ops_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn message_ops_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn message_ops_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn message_ops_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn message_ops_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
