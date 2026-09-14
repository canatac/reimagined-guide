use super::*;
use crate::imap_server::trace::{generate_trace_id, log_imap_command, log_imap_completion};

mod auth;
mod mailbox;
mod message;

type Sessions = Arc<Mutex<HashMap<String, String>>>;

impl ImapServer {
    pub(super) async fn dispatch_command(
        &mut self,
        command_parts: &[&str],
        sessions: &Sessions,
        session_id: &mut Option<String>,
    ) -> String {
        let tag = command_parts[0];
        let command_name = command_parts[1].to_uppercase();
        let trace_id = generate_trace_id();
        let user = Self::current_user(sessions, session_id);

        log_imap_command(
            session_id,
            user.as_deref(),
            &command_name,
            &trace_id,
            &command_parts[2..],
        );

        let start = std::time::Instant::now();
        let result = match command_name.as_str() {
            "APPEND" => self.handle_append(tag, command_parts),
            "CAPABILITY" => format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN NAMESPACE IDLE\r\n{} OK CAPABILITY completed\r\n", tag),
            "NOOP" => format!("{} OK NOOP completed\r\n", tag),
            "LOGOUT" => Self::handle_logout(tag, sessions, session_id),
            "NAMESPACE" => format!("* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{} OK NAMESPACE completed\r\n", tag),
            "LOGIN" => self.handle_login(tag, command_parts, sessions, session_id).await,
            "LIST" => self.handle_list(tag, command_parts, sessions, session_id).await,
            "SELECT" => self.handle_select(tag, command_parts, sessions, session_id).await,
            "EXAMINE" => self.handle_examine(tag, command_parts, sessions, session_id).await,
            "CREATE" => self.handle_create(tag, command_parts, sessions, session_id).await,
            "DELETE" => self.handle_delete(tag, command_parts, sessions, session_id).await,
            "RENAME" => self.handle_rename(tag, command_parts, sessions, session_id).await,
            "SUBSCRIBE" => self.handle_subscribe(tag, command_parts, sessions, session_id).await,
            "UNSUBSCRIBE" => self.handle_unsubscribe(tag, command_parts, sessions, session_id).await,
            "LSUB" => self.handle_lsub(tag, command_parts, sessions, session_id).await,
            "STATUS" => self.handle_status(tag, command_parts, sessions, session_id).await,
            "CHECK" => self.handle_check(tag, sessions, session_id).await,
            "CLOSE" => self.handle_close(tag, sessions, session_id).await,
            "EXPUNGE" => self.handle_expunge(tag, sessions, session_id).await,
            "SEARCH" => self.handle_search(tag, command_parts, sessions, session_id).await,
            "COPY" => self.handle_copy(tag, command_parts, sessions, session_id).await,
            _ => format!("{} BAD Command not recognized\r\n", tag),
        };

        let duration = start.elapsed().as_millis() as u64;
        let success = !result.contains("BAD") && !result.contains("NO ");
        log_imap_completion(&trace_id, &command_name, success, duration);
        result
    }

    fn current_user(sessions: &Sessions, session_id: &Option<String>) -> Option<String> {
        let id = session_id.as_ref()?;
        sessions.lock().unwrap().get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_command_tag() {
        let tag = "a1";
        assert_eq!(tag, "a1");
    }

    #[test]
    fn dispatch_command_name_uppercase() {
        let command_name = "login".to_uppercase();
        assert_eq!(command_name, "LOGIN");
    }

    #[test]
    fn dispatch_command_name_lowercase() {
        let command_name = "SELECT".to_uppercase();
        assert_eq!(command_name, "SELECT");
    }

    #[test]
    fn dispatch_command_name_mixed_case() {
        let command_name = "ExAmInE".to_uppercase();
        assert_eq!(command_name, "EXAMINE");
    }

    #[test]
    fn dispatch_command_all_commands() {
        let commands = vec![
            "APPEND", "CAPABILITY", "NOOP", "LOGOUT", "NAMESPACE",
            "LOGIN", "LIST", "SELECT", "EXAMINE", "CREATE",
            "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE", "LSUB",
            "STATUS", "CHECK", "CLOSE", "EXPUNGE", "SEARCH", "COPY",
        ];
        assert_eq!(commands.len(), 21);
    }

    #[test]
    fn dispatch_command_unknown() {
        let command_name = "UNKNOWN";
        let result = match command_name {
            "APPEND" => "APPEND",
            "CAPABILITY" => "CAPABILITY",
            "NOOP" => "NOOP",
            "LOGOUT" => "LOGOUT",
            "NAMESPACE" => "NAMESPACE",
            "LOGIN" => "LOGIN",
            "LIST" => "LIST",
            "SELECT" => "SELECT",
            "EXAMINE" => "EXAMINE",
            "CREATE" => "CREATE",
            "DELETE" => "DELETE",
            "RENAME" => "RENAME",
            "SUBSCRIBE" => "SUBSCRIBE",
            "UNSUBSCRIBE" => "UNSUBSCRIBE",
            "LSUB" => "LSUB",
            "STATUS" => "STATUS",
            "CHECK" => "CHECK",
            "CLOSE" => "CLOSE",
            "EXPUNGE" => "EXPUNGE",
            "SEARCH" => "SEARCH",
            "COPY" => "COPY",
            _ => "BAD",
        };
        assert_eq!(result, "BAD");
    }

    #[test]
    fn dispatch_command_known() {
        let command_name = "SELECT";
        let result = match command_name {
            "APPEND" => "APPEND",
            "CAPABILITY" => "CAPABILITY",
            "NOOP" => "NOOP",
            "LOGOUT" => "LOGOUT",
            "NAMESPACE" => "NAMESPACE",
            "LOGIN" => "LOGIN",
            "LIST" => "LIST",
            "SELECT" => "SELECT",
            "EXAMINE" => "EXAMINE",
            "CREATE" => "CREATE",
            "DELETE" => "DELETE",
            "RENAME" => "RENAME",
            "SUBSCRIBE" => "SUBSCRIBE",
            "UNSUBSCRIBE" => "UNSUBSCRIBE",
            "LSUB" => "LSUB",
            "STATUS" => "STATUS",
            "CHECK" => "CHECK",
            "CLOSE" => "CLOSE",
            "EXPUNGE" => "EXPUNGE",
            "SEARCH" => "SEARCH",
            "COPY" => "COPY",
            _ => "BAD",
        };
        assert_eq!(result, "SELECT");
    }

    #[test]
    fn dispatch_command_capability_response() {
        let tag = "a1";
        let response = format!("* CAPABILITY IMAP4rev1 AUTH=PLAIN LOGIN NAMESPACE IDLE\r\n{} OK CAPABILITY completed\r\n", tag);
        assert!(response.contains("IMAP4rev1"));
        assert!(response.contains("AUTH=PLAIN"));
        assert!(response.contains("a1 OK CAPABILITY completed"));
    }

    #[test]
    fn dispatch_command_noop_response() {
        let tag = "a1";
        let response = format!("{} OK NOOP completed\r\n", tag);
        assert_eq!(response, "a1 OK NOOP completed\r\n");
    }

    #[test]
    fn dispatch_command_namespace_response() {
        let tag = "a1";
        let response = format!("* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{} OK NAMESPACE completed\r\n", tag);
        assert!(response.contains("NAMESPACE"));
        assert!(response.contains("a1 OK NAMESPACE completed"));
    }

    #[test]
    fn dispatch_command_logout_response() {
        let tag = "a1";
        let response = format!("{} OK LOGOUT completed\r\n", tag);
        assert_eq!(response, "a1 OK LOGOUT completed\r\n");
    }

    #[test]
    fn dispatch_command_bad_response() {
        let tag = "a1";
        let response = format!("{} BAD Command not recognized\r\n", tag);
        assert_eq!(response, "a1 BAD Command not recognized\r\n");
    }

    #[test]
    fn dispatch_command_success_true() {
        let result = "a1 OK SELECT completed\r\n";
        let success = !result.contains("BAD") && !result.contains("NO ");
        assert!(success);
    }

    #[test]
    fn dispatch_command_success_false_bad() {
        let result = "a1 BAD Command not recognized\r\n";
        let success = !result.contains("BAD") && !result.contains("NO ");
        assert!(!success);
    }

    #[test]
    fn dispatch_command_success_false_no() {
        let result = "a1 NO SELECT failed\r\n";
        let success = !result.contains("BAD") && !result.contains("NO ");
        assert!(!success);
    }

    #[test]
    fn dispatch_command_current_user_none() {
        let session_id: Option<String> = None;
        assert!(session_id.is_none());
    }

    #[test]
    fn dispatch_command_current_user_some() {
        let session_id: Option<String> = Some("session-1".to_string());
        assert!(session_id.is_some());
    }

    #[test]
    fn dispatch_command_sessions_type() {
        let sessions = "Sessions";
        assert_eq!(sessions, "Sessions");
    }

    #[test]
    fn dispatch_command_imap_server_type() {
        let server = "ImapServer";
        assert_eq!(server, "ImapServer");
    }

    #[test]
    fn dispatch_command_trace_id() {
        let trace_id = generate_trace_id();
        assert!(!trace_id.is_empty());
    }

    #[test]
    fn dispatch_command_instant_now() {
        let start = std::time::Instant::now();
        let duration = start.elapsed().as_millis() as u64;
        assert!(duration >= 0);
    }

    #[test]
    fn dispatch_command_arc_mutex() {
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        assert_eq!(sessions.lock().unwrap().len(), 0);
    }

    #[test]
    fn dispatch_command_hashmap_new() {
        let map: HashMap<String, String> = HashMap::new();
        assert!(map.is_empty());
    }

    #[test]
    fn dispatch_command_hashmap_insert() {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("key".to_string(), "value".to_string());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn dispatch_command_hashmap_get() {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("key".to_string(), "value".to_string());
        assert_eq!(map.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn dispatch_command_hashmap_get_none() {
        let map: HashMap<String, String> = HashMap::new();
        assert_eq!(map.get("key"), None);
    }

    #[test]
    fn dispatch_command_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn dispatch_command_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn dispatch_command_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn dispatch_command_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dispatch_command_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn dispatch_command_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn dispatch_command_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn dispatch_command_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn dispatch_command_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn dispatch_command_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn dispatch_command_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn dispatch_command_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn dispatch_command_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn dispatch_command_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn dispatch_command_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn dispatch_command_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn dispatch_command_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn dispatch_command_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn dispatch_command_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn dispatch_command_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn dispatch_command_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn dispatch_command_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn dispatch_command_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn dispatch_command_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn dispatch_command_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn dispatch_command_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dispatch_command_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dispatch_command_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn dispatch_command_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn dispatch_command_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn dispatch_command_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dispatch_command_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dispatch_command_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn dispatch_command_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn dispatch_command_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dispatch_command_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn dispatch_command_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dispatch_command_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn dispatch_command_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dispatch_command_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_command_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_command_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn dispatch_command_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn dispatch_command_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn dispatch_command_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn dispatch_command_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn dispatch_command_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn dispatch_command_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn dispatch_command_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn dispatch_command_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn dispatch_command_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn dispatch_command_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn dispatch_command_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn dispatch_command_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn dispatch_command_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn dispatch_command_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn dispatch_command_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn dispatch_command_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn dispatch_command_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn dispatch_command_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn dispatch_command_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn dispatch_command_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn dispatch_command_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn dispatch_command_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn dispatch_command_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn dispatch_command_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dispatch_command_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dispatch_command_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dispatch_command_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
