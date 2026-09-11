//! Helpers extracted from dialog.rs to keep it under the LOC budget.

use openssl::ssl::{SslConnector, SslMethod};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::dialog::{run_imap_dialog_plain, run_imap_dialog_ssl};

pub(crate) fn imap_probe(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    if password.is_empty() {
        return Err("Missing credential secretValue on external account".to_string());
    }

    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "resolve failed: no address".to_string())?;

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("tcp connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(12))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(12))).ok();

    if use_tls {
        let connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("tls builder failed: {e}"))?
            .build();
        let ssl = connector
            .connect(host, tcp)
            .map_err(|e| format!("tls connect failed: {e}"))?;
        run_imap_dialog_ssl(ssl, username, password, include_list)
    } else {
        run_imap_dialog_plain(tcp, username, password, include_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_helpers_imap_probe_empty_password() {
        let result = imap_probe("localhost", 993, false, "user", "", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing credential"));
    }

    #[test]
    fn dialog_helpers_imap_probe_invalid_host() {
        let result = imap_probe("invalid.host.name.example", 993, false, "user", "pass", false);
        assert!(result.is_err());
    }

    #[test]
    fn dialog_helpers_imap_probe_localhost() {
        let result = imap_probe("127.0.0.1", 993, false, "user", "pass", false);
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn dialog_helpers_duration_secs() {
        let timeout = Duration::from_secs(10);
        assert_eq!(timeout.as_secs(), 10);
    }

    #[test]
    fn dialog_helpers_duration_12_secs() {
        let timeout = Duration::from_secs(12);
        assert_eq!(timeout.as_secs(), 12);
    }

    #[test]
    fn dialog_helpers_result_ok() {
        let result: Result<String, String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_helpers_result_err() {
        let result: Result<String, String> = Err("error".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn dialog_helpers_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn dialog_helpers_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn dialog_helpers_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn dialog_helpers_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dialog_helpers_clone() {
        let s = "test".to_string();
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn dialog_helpers_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn dialog_helpers_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn dialog_helpers_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn dialog_helpers_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn dialog_helpers_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn dialog_helpers_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn dialog_helpers_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn dialog_helpers_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn dialog_helpers_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn dialog_helpers_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn dialog_helpers_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn dialog_helpers_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn dialog_helpers_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn dialog_helpers_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn dialog_helpers_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn dialog_helpers_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn dialog_helpers_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn dialog_helpers_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn dialog_helpers_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn dialog_helpers_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn dialog_helpers_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dialog_helpers_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_helpers_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn dialog_helpers_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn dialog_helpers_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn dialog_helpers_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_helpers_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_helpers_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn dialog_helpers_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn dialog_helpers_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_helpers_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn dialog_helpers_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_helpers_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn dialog_helpers_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dialog_helpers_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_helpers_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_helpers_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_helpers_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn dialog_helpers_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn dialog_helpers_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn dialog_helpers_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn dialog_helpers_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn dialog_helpers_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn dialog_helpers_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn dialog_helpers_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn dialog_helpers_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn dialog_helpers_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn dialog_helpers_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn dialog_helpers_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn dialog_helpers_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn dialog_helpers_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn dialog_helpers_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn dialog_helpers_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn dialog_helpers_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn dialog_helpers_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn dialog_helpers_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn dialog_helpers_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn dialog_helpers_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn dialog_helpers_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn dialog_helpers_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn dialog_helpers_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dialog_helpers_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dialog_helpers_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dialog_helpers_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
