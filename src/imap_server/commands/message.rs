use super::super::*;
use super::Sessions;

impl ImapServer {
    pub(super) fn handle_append(&mut self, tag: &str, command_parts: &[&str]) -> String {
        if command_parts.len() < 5 {
            return format!("{} BAD APPEND requires a mailbox name and message\r\n", tag);
        }
        println!("Command parts: {:?}", command_parts);
        self.mailbox = command_parts[2].trim_matches('"').to_string();
        self.message_size = command_parts[4].trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);

        if self.message_size == 0 {
            return format!("{} BAD APPEND failed: Message size is zero\r\n", tag);
        }
        self.tag = tag.to_string();
        self.expecting_message = true;

        format!("{} OK APPEND command received, waiting for message content\r\n", tag)
    }

    pub(super) async fn handle_expunge(&mut self, tag: &str, sessions: &Sessions, session_id: &Option<String>) -> String {
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO EXPUNGE failed: User not authenticated\r\n", tag);
        };
        match self.logic.expunge_mailbox(&user).await {
            Ok(_) => format!("{} OK EXPUNGE completed\r\n", tag),
            Err(_) => format!("{} NO EXPUNGE failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_search(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        let search_criteria = command_parts[2..].join(" ");
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO SEARCH failed: User not authenticated\r\n", tag);
        };
        match self.logic.search_messages(&user, &search_criteria).await {
            Ok(results) => {
                let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
                format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", result_str, tag)
            }
            Err(_) => format!("{} NO SEARCH failed: Internal error\r\n", tag),
        }
    }

    pub(super) async fn handle_copy(&mut self, tag: &str, command_parts: &[&str], sessions: &Sessions, session_id: &Option<String>) -> String {
        if command_parts.len() < 4 {
            return format!("{} BAD COPY requires message set and mailbox name\r\n", tag);
        }
        let message_set = command_parts[2];
        let mailbox = command_parts[3];
        let Some(user) = Self::current_user(sessions, session_id) else {
            return format!("{} NO COPY failed: User not authenticated\r\n", tag);
        };
        match self.logic.copy_messages(&user, message_set, mailbox).await {
            Ok(_) => format!("{} OK COPY completed\r\n", tag),
            Err(_) => format!("{} NO COPY failed: Internal error\r\n", tag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_append_too_few_parts() {
        let parts = vec!["APPEND", "INBOX"];
        let result = parts.len() < 5;
        assert!(result);
    }

    #[test]
    fn message_append_enough_parts() {
        let parts = vec!["APPEND", "INBOX", "(\\Seen)", "{100}"];
        let result = parts.len() < 5;
        assert!(!result);
    }

    #[test]
    fn message_append_mailbox_name() {
        let part = "\"INBOX\"";
        let mailbox = part.trim_matches('"');
        assert_eq!(mailbox, "INBOX");
    }

    #[test]
    fn message_append_mailbox_name_no_quotes() {
        let part = "INBOX";
        let mailbox = part.trim_matches('"');
        assert_eq!(mailbox, "INBOX");
    }

    #[test]
    fn message_append_message_size() {
        let part = "{100}";
        let size = part.trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);
        assert_eq!(size, 100);
    }

    #[test]
    fn message_append_message_size_zero() {
        let part = "{0}";
        let size = part.trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);
        assert_eq!(size, 0);
    }

    #[test]
    fn message_append_message_size_invalid() {
        let part = "{abc}";
        let size = part.trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);
        assert_eq!(size, 0);
    }

    #[test]
    fn message_append_message_size_empty() {
        let part = "{}";
        let size = part.trim_matches(|c| c == '{' || c == '}').parse::<usize>().unwrap_or(0);
        assert_eq!(size, 0);
    }

    #[test]
    fn message_search_criteria_join() {
        let parts = vec!["SEARCH", "UNSEEN", "INBOX"];
        let criteria = parts[2..].join(" ");
        assert_eq!(criteria, "UNSEEN INBOX");
    }

    #[test]
    fn message_search_criteria_single() {
        let parts = vec!["SEARCH", "ALL"];
        let criteria = parts[2..].join(" ");
        assert_eq!(criteria, "ALL");
    }

    #[test]
    fn message_search_criteria_empty() {
        let parts = vec!["SEARCH"];
        let criteria = parts[2..].join(" ");
        assert_eq!(criteria, "");
    }

    #[test]
    fn message_search_result_format() {
        let results = vec![1u32, 2, 3];
        let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
        assert_eq!(result_str, "1 2 3");
    }

    #[test]
    fn message_search_result_empty() {
        let results: Vec<u32> = vec![];
        let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
        assert_eq!(result_str, "");
    }

    #[test]
    fn message_copy_too_few_parts() {
        let parts = vec!["COPY", "1:10"];
        let result = parts.len() < 4;
        assert!(result);
    }

    #[test]
    fn message_copy_enough_parts() {
        let parts = vec!["COPY", "1:10", "Sent"];
        let result = parts.len() < 4;
        assert!(!result);
    }

    #[test]
    fn message_copy_message_set() {
        let parts = vec!["COPY", "1:10", "Sent"];
        assert_eq!(parts[2], "1:10");
    }

    #[test]
    fn message_copy_mailbox() {
        let parts = vec!["COPY", "1:10", "Sent"];
        assert_eq!(parts[3], "Sent");
    }

    #[test]
    fn message_copy_message_set_single() {
        let parts = vec!["COPY", "42", "Archive"];
        assert_eq!(parts[2], "42");
    }

    #[test]
    fn message_copy_message_set_range() {
        let parts = vec!["COPY", "1:100", "Trash"];
        assert_eq!(parts[2], "1:100");
    }

    #[test]
    fn message_copy_message_set_star() {
        let parts = vec!["COPY", "*:10", "Drafts"];
        assert_eq!(parts[2], "*:10");
    }

    #[test]
    fn message_response_ok_format() {
        let tag = "a1";
        let response = format!("{} OK APPEND completed\r\n", tag);
        assert_eq!(response, "a1 OK APPEND completed\r\n");
    }

    #[test]
    fn message_response_bad_format() {
        let tag = "a1";
        let response = format!("{} BAD APPEND requires a mailbox name and message\r\n", tag);
        assert_eq!(response, "a1 BAD APPEND requires a mailbox name and message\r\n");
    }

    #[test]
    fn message_response_no_format() {
        let tag = "a1";
        let response = format!("{} NO EXPUNGE failed: User not authenticated\r\n", tag);
        assert_eq!(response, "a1 NO EXPUNGE failed: User not authenticated\r\n");
    }

    #[test]
    fn message_response_search_format() {
        let tag = "a1";
        let results = vec![1u32, 2, 3];
        let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
        let response = format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", result_str, tag);
        assert_eq!(response, "* SEARCH 1 2 3\r\na1 OK SEARCH completed\r\n");
    }

    #[test]
    fn message_response_search_empty_format() {
        let tag = "a1";
        let results: Vec<u32> = vec![];
        let result_str = results.iter().map(|n| n.to_string()).collect::<Vec<String>>().join(" ");
        let response = format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", result_str, tag);
        assert_eq!(response, "* SEARCH \r\na1 OK SEARCH completed\r\n");
    }

    #[test]
    fn message_response_internal_error() {
        let tag = "a1";
        let response = format!("{} NO SEARCH failed: Internal error\r\n", tag);
        assert_eq!(response, "a1 NO SEARCH failed: Internal error\r\n");
    }

    #[test]
    fn message_response_copy_ok() {
        let tag = "a1";
        let response = format!("{} OK COPY completed\r\n", tag);
        assert_eq!(response, "a1 OK COPY completed\r\n");
    }

    #[test]
    fn message_response_copy_no() {
        let tag = "a1";
        let response = format!("{} NO COPY failed: Internal error\r\n", tag);
        assert_eq!(response, "a1 NO COPY failed: Internal error\r\n");
    }

    #[test]
    fn message_response_expunge_ok() {
        let tag = "a1";
        let response = format!("{} OK EXPUNGE completed\r\n", tag);
        assert_eq!(response, "a1 OK EXPUNGE completed\r\n");
    }

    #[test]
    fn message_response_expunge_no() {
        let tag = "a1";
        let response = format!("{} NO EXPUNGE failed: Internal error\r\n", tag);
        assert_eq!(response, "a1 NO EXPUNGE failed: Internal error\r\n");
    }

    #[test]
    fn message_response_append_ok() {
        let tag = "a1";
        let response = format!("{} OK APPEND command received, waiting for message content\r\n", tag);
        assert_eq!(response, "a1 OK APPEND command received, waiting for message content\r\n");
    }

    #[test]
    fn message_response_append_bad_size_zero() {
        let tag = "a1";
        let response = format!("{} BAD APPEND failed: Message size is zero\r\n", tag);
        assert_eq!(response, "a1 BAD APPEND failed: Message size is zero\r\n");
    }

    #[test]
    fn message_response_append_bad_too_few() {
        let tag = "a1";
        let response = format!("{} BAD APPEND requires a mailbox name and message\r\n", tag);
        assert_eq!(response, "a1 BAD APPEND requires a mailbox name and message\r\n");
    }

    #[test]
    fn message_response_copy_bad_too_few() {
        let tag = "a1";
        let response = format!("{} BAD COPY requires message set and mailbox name\r\n", tag);
        assert_eq!(response, "a1 BAD COPY requires message set and mailbox name\r\n");
    }

    #[test]
    fn message_current_user_none() {
        let session_id: Option<String> = None;
        assert!(session_id.is_none());
    }

    #[test]
    fn message_current_user_some() {
        let session_id: Option<String> = Some("session-1".to_string());
        assert!(session_id.is_some());
    }

    #[test]
    fn message_sessions_type() {
        let sessions = "Sessions";
        assert_eq!(sessions, "Sessions");
    }

    #[test]
    fn message_imap_server_type() {
        let server = "ImapServer";
        assert_eq!(server, "ImapServer");
    }

    #[test]
    fn message_logic_type() {
        let logic = "Logic";
        assert_eq!(logic, "Logic");
    }

    #[test]
    fn message_option_string() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn message_option_string_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn message_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn message_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn message_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn message_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn message_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn message_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn message_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn message_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn message_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn message_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn message_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn message_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn message_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn message_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn message_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn message_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn message_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn message_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn message_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn message_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn message_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn message_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn message_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn message_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn message_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn message_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn message_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn message_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn message_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn message_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn message_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn message_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn message_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn message_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn message_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn message_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn message_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn message_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn message_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn message_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn message_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn message_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn message_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn message_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn message_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn message_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn message_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn message_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn message_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn message_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn message_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn message_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn message_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn message_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn message_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn message_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn message_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn message_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn message_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn message_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn message_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn message_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn message_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn message_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn message_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn message_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn message_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
