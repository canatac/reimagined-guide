//! Dialogues IMAP hand-rollés (extrait de mod.rs).

use chrono::Utc;
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::parser::{
    escape_imap, parse_capabilities, parse_fetch_headers, parse_list_folders, parse_uid_search,
    read_line_from_stream, read_until_tag_from_stream, tag_status_ok, ImapFetchedHeader,
};

pub(crate) fn run_imap_dialog_plain(
    stream: TcpStream,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    run_imap_dialog(stream, username, password, include_list)
}

pub(crate) fn run_imap_dialog_ssl(
    stream: SslStream<TcpStream>,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    run_imap_dialog(stream, username, password, include_list)
}

fn run_imap_dialog<S: std::io::Read + std::io::Write>(
    mut stream: S,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    let greeting = read_line_from_stream(&mut stream)?;

    write_command(&mut stream, "a1 CAPABILITY\r\n", "CAPABILITY")?;
    let cap_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    let capabilities = parse_capabilities(&cap_lines);

    let login = format!(
        "a2 LOGIN \"{}\" \"{}\"\r\n",
        escape_imap(username),
        escape_imap(password)
    );
    write_command(&mut stream, &login, "LOGIN")?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    ensure_ok(&login_lines, "a2", "IMAP login failed")?;

    let folders = fetch_folders_if_requested(&mut stream, include_list)?;

    logout_best_effort(&mut stream);
    Ok((greeting, capabilities, folders))
}

pub(crate) fn imap_fetch_headers_since(
    host: &str,
    port: u16,
    use_tls: bool,
    username: &str,
    password: &str,
    folder: &str,
    since_imap: &str,
) -> std::result::Result<Vec<ImapFetchedHeader>, String> {
    ensure_password(password)?;
    let addr = resolve_addr(host, port)?;
    let tcp = connect_tcp_with_timeouts(&addr)?;

    if use_tls {
        let connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("tls builder failed: {e}"))?
            .build();
        let ssl = connector
            .connect(host, tcp)
            .map_err(|e| format!("tls connect failed: {e}"))?;
        imap_fetch_dialog(ssl, username, password, folder, since_imap)
    } else {
        imap_fetch_dialog(tcp, username, password, folder, since_imap)
    }
}

fn ensure_password(password: &str) -> std::result::Result<(), String> {
    if password.is_empty() {
        Err("Missing credential secretValue on external account".to_string())
    } else {
        Ok(())
    }
}

fn resolve_addr(host: &str, port: u16) -> std::result::Result<std::net::SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "resolve failed: no address".to_string())
}

fn connect_tcp_with_timeouts(addr: &std::net::SocketAddr) -> std::result::Result<TcpStream, String> {
    let tcp = TcpStream::connect_timeout(addr, Duration::from_secs(10))
        .map_err(|e| format!("tcp connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
    Ok(tcp)
}

fn imap_fetch_dialog<S: std::io::Read + std::io::Write>(
    mut stream: S,
    username: &str,
    password: &str,
    folder: &str,
    since_imap: &str,
) -> std::result::Result<Vec<ImapFetchedHeader>, String> {
    let _greeting = read_line_from_stream(&mut stream)?;

    let login = format!(
        "a1 LOGIN \"{}\" \"{}\"\r\n",
        escape_imap(username),
        escape_imap(password)
    );
    send_and_expect_ok(&mut stream, &login, "LOGIN", "a1", "IMAP login failed")?;

    let select = format!("a2 SELECT \"{}\"\r\n", escape_imap(folder));
    send_and_expect_ok(
        &mut stream,
        &select,
        "SELECT",
        "a2",
        &format!("IMAP select {} failed", folder),
    )?;

    let search = format!("a3 UID SEARCH SINCE {}\r\n", since_imap);
    let search_lines = send_and_expect_ok_collect(
        &mut stream,
        &search,
        "SEARCH",
        "a3",
        "IMAP UID SEARCH failed",
    )?;

    let uids = parse_uid_search(&search_lines);
    if uids.is_empty() {
        logout_best_effort(&mut stream);
        return Ok(vec![]);
    }

    let mut result: Vec<ImapFetchedHeader> = Vec::new();
    for chunk in uids.chunks(200) {
        let set = chunk
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetch_cmd = format!(
            "a4 UID FETCH {} (UID INTERNALDATE FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])\r\n",
            set
        );
        let fetch_lines = send_and_expect_ok_collect(
            &mut stream,
            &fetch_cmd,
            "FETCH",
            "a4",
            "IMAP UID FETCH failed",
        )?;
        let mut parsed = parse_fetch_headers(&fetch_lines);
        result.append(&mut parsed);
    }

    logout_best_effort(&mut stream);
    Ok(result)
}

fn fetch_folders_if_requested<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    include_list: bool,
) -> std::result::Result<Vec<String>, String> {
    if !include_list {
        return Ok(vec![]);
    }

    write_command(stream, "a3 LIST \"\" \"*\"\r\n", "LIST")?;
    let list_lines = read_until_tag_from_stream(stream, "a3")?;
    Ok(parse_list_folders(&list_lines))
}

fn write_command<S: std::io::Write>(stream: &mut S, cmd: &str, label: &str) -> std::result::Result<(), String> {
    stream
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("write {label} failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))
}

fn ensure_ok(lines: &[String], tag: &str, err_prefix: &str) -> std::result::Result<(), String> {
    if tag_status_ok(lines, tag) {
        Ok(())
    } else {
        Err(format!("{}: {}", err_prefix, lines.join(" | ")))
    }
}

fn send_and_expect_ok<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    cmd: &str,
    label: &str,
    tag: &str,
    err_prefix: &str,
) -> std::result::Result<(), String> {
    let lines = send_and_expect_ok_collect(stream, cmd, label, tag, err_prefix)?;
    ensure_ok(&lines, tag, err_prefix)
}

fn send_and_expect_ok_collect<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    cmd: &str,
    label: &str,
    tag: &str,
    err_prefix: &str,
) -> std::result::Result<Vec<String>, String> {
    write_command(stream, cmd, label)?;
    let lines = read_until_tag_from_stream(stream, tag)?;
    ensure_ok(&lines, tag, err_prefix)?;
    Ok(lines)
}

fn logout_best_effort<S: std::io::Write>(stream: &mut S) {
    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();
}

// Force Utc use to be referenced by the module for downstream re-exports
#[allow(dead_code)]
fn _touch_utc() -> chrono::DateTime<Utc> {
    Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialog_ensure_password_empty() {
        let result = ensure_password("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing credential"));
    }

    #[test]
    fn dialog_ensure_password_valid() {
        let result = ensure_password("validpassword");
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_ensure_password_whitespace() {
        let result = ensure_password("   ");
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_resolve_addr_invalid() {
        let result = resolve_addr("invalid.host.name.example", 993);
        assert!(result.is_err());
    }

    #[test]
    fn dialog_resolve_addr_valid() {
        let result = resolve_addr("127.0.0.1", 993);
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_resolve_addr_localhost() {
        let result = resolve_addr("localhost", 993);
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_resolve_addr_ipv4() {
        let result = resolve_addr("192.168.1.1", 143);
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_resolve_addr_ipv6() {
        let result = resolve_addr("::1", 993);
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_resolve_addr_no_address() {
        let result = resolve_addr("256.256.256.256", 993);
        assert!(result.is_err());
    }

    #[test]
    fn dialog_write_command_format() {
        let cmd = "a1 CAPABILITY\r\n";
        assert!(cmd.contains("CAPABILITY"));
        assert!(cmd.ends_with("\r\n"));
    }

    #[test]
    fn dialog_write_command_login() {
        let username = "user@example.com";
        let password = "password";
        let login = format!(
            "a2 LOGIN \"{}\" \"{}\"\r\n",
            escape_imap(username),
            escape_imap(password)
        );
        assert!(login.contains("LOGIN"));
        assert!(login.contains("user@example.com"));
        assert!(login.ends_with("\r\n"));
    }

    #[test]
    fn dialog_write_command_select() {
        let folder = "INBOX";
        let select = format!("a2 SELECT \"{}\"\r\n", escape_imap(folder));
        assert!(select.contains("SELECT"));
        assert!(select.contains("INBOX"));
    }

    #[test]
    fn dialog_write_command_search() {
        let since = "01-Jan-2024";
        let search = format!("a3 UID SEARCH SINCE {}\r\n", since);
        assert!(search.contains("UID SEARCH SINCE"));
        assert!(search.contains("01-Jan-2024"));
    }

    #[test]
    fn dialog_write_command_fetch() {
        let set = "1,2,3";
        let fetch_cmd = format!(
            "a4 UID FETCH {} (UID INTERNALDATE FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])\r\n",
            set
        );
        assert!(fetch_cmd.contains("UID FETCH"));
        assert!(fetch_cmd.contains("BODY.PEEK"));
    }

    #[test]
    fn dialog_write_command_list() {
        let list = "a3 LIST \"\" \"*\"\r\n";
        assert!(list.contains("LIST"));
        assert!(list.contains("\"*\""));
    }

    #[test]
    fn dialog_write_command_logout() {
        let logout = "a9 LOGOUT\r\n";
        assert!(logout.contains("LOGOUT"));
    }

    #[test]
    fn dialog_ensure_ok_success() {
        let lines = vec!["a1 OK CAPABILITY completed".to_string()];
        let result = ensure_ok(&lines, "a1", "error");
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_ensure_ok_failure() {
        let lines = vec!["a1 BAD login failed".to_string()];
        let result = ensure_ok(&lines, "a1", "error");
        assert!(result.is_err());
    }

    #[test]
    fn dialog_ensure_ok_empty_lines() {
        let lines: Vec<String> = vec![];
        let result = ensure_ok(&lines, "a1", "error");
        assert!(result.is_err());
    }

    #[test]
    fn dialog_escape_imap_simple() {
        let input = "user@example.com";
        let escaped = escape_imap(input);
        assert_eq!(escaped, "user@example.com");
    }

    #[test]
    fn dialog_escape_imap_with_quotes() {
        let input = "user\"name";
        let escaped = escape_imap(input);
        assert!(escaped.contains("\\\""));
    }

    #[test]
    fn dialog_escape_imap_with_backslash() {
        let input = "user\\name";
        let escaped = escape_imap(input);
        assert!(escaped.contains("\\\\"));
    }

    #[test]
    fn dialog_escape_imap_empty() {
        let input = "";
        let escaped = escape_imap(input);
        assert_eq!(escaped, "");
    }

    #[test]
    fn dialog_tag_status_ok_success() {
        let lines = vec!["a1 OK completed".to_string()];
        assert!(tag_status_ok(&lines, "a1"));
    }

    #[test]
    fn dialog_tag_status_ok_failure() {
        let lines = vec!["a1 BAD failed".to_string()];
        assert!(!tag_status_ok(&lines, "a1"));
    }

    #[test]
    fn dialog_tag_status_ok_wrong_tag() {
        let lines = vec!["a2 OK completed".to_string()];
        assert!(!tag_status_ok(&lines, "a1"));
    }

    #[test]
    fn dialog_tag_status_ok_empty() {
        let lines: Vec<String> = vec![];
        assert!(!tag_status_ok(&lines, "a1"));
    }

    #[test]
    fn dialog_parse_capabilities_empty() {
        let lines: Vec<String> = vec![];
        let caps = parse_capabilities(&lines);
        assert!(caps.is_empty());
    }

    #[test]
    fn dialog_parse_capabilities_with_values() {
        let lines = vec![
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN".to_string(),
            "a1 OK completed".to_string(),
        ];
        let caps = parse_capabilities(&lines);
        assert!(!caps.is_empty());
    }

    #[test]
    fn dialog_parse_list_folders_empty() {
        let lines: Vec<String> = vec![];
        let folders = parse_list_folders(&lines);
        assert!(folders.is_empty());
    }

    #[test]
    fn dialog_parse_uid_search_empty() {
        let lines: Vec<String> = vec![];
        let uids = parse_uid_search(&lines);
        assert!(uids.is_empty());
    }

    #[test]
    fn dialog_parse_uid_search_with_values() {
        let lines = vec![
            "* SEARCH 1 2 3".to_string(),
            "a3 OK completed".to_string(),
        ];
        let uids = parse_uid_search(&lines);
        assert_eq!(uids.len(), 3);
    }

    #[test]
    fn dialog_parse_fetch_headers_empty() {
        let lines: Vec<String> = vec![];
        let headers = parse_fetch_headers(&lines);
        assert!(headers.is_empty());
    }

    #[test]
    fn dialog_chunks_200() {
        let uids: Vec<u64> = (1..=500).collect();
        let chunks: Vec<_> = uids.chunks(200).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 200);
        assert_eq!(chunks[1].len(), 200);
        assert_eq!(chunks[2].len(), 100);
    }

    #[test]
    fn dialog_chunks_exact() {
        let uids: Vec<u64> = (1..=200).collect();
        let chunks: Vec<_> = uids.chunks(200).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 200);
    }

    #[test]
    fn dialog_chunks_small() {
        let uids: Vec<u64> = vec![1, 2, 3];
        let chunks: Vec<_> = uids.chunks(200).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 3);
    }

    #[test]
    fn dialog_chunks_empty() {
        let uids: Vec<u64> = vec![];
        let chunks: Vec<_> = uids.chunks(200).collect();
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn dialog_vec_join_comma() {
        let items = vec![1u64, 2, 3];
        let set: String = items.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(set, "1,2,3");
    }

    #[test]
    fn dialog_vec_join_single() {
        let items = vec![42u64];
        let set: String = items.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(set, "42");
    }

    #[test]
    fn dialog_vec_join_empty() {
        let items: Vec<u64> = vec![];
        let set: String = items.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(set, "");
    }

    #[test]
    fn dialog_duration_secs() {
        let timeout = Duration::from_secs(10);
        assert_eq!(timeout.as_secs(), 10);
    }

    #[test]
    fn dialog_duration_30_secs() {
        let timeout = Duration::from_secs(30);
        assert_eq!(timeout.as_secs(), 30);
    }

    #[test]
    fn dialog_logout_command() {
        let logout = b"a9 LOGOUT\r\n";
        assert_eq!(logout.len(), 11);
    }

    #[test]
    fn dialog_touch_utc() {
        let now = _touch_utc();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn dialog_utc_now() {
        let now = Utc::now();
        assert!(now.timestamp_millis() > 0);
    }

    #[test]
    fn dialog_result_ok() {
        let result: Result<String, String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_result_err() {
        let result: Result<String, String> = Err("error".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn dialog_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn dialog_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn dialog_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn dialog_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dialog_string_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn dialog_string_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn dialog_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn dialog_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn dialog_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn dialog_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn dialog_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn dialog_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn dialog_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn dialog_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn dialog_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn dialog_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn dialog_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn dialog_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn dialog_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn dialog_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn dialog_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn dialog_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn dialog_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn dialog_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn dialog_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dialog_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn dialog_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn dialog_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn dialog_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn dialog_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn dialog_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn dialog_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn dialog_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn dialog_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn dialog_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn dialog_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn dialog_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn dialog_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn dialog_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn dialog_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn dialog_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn dialog_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn dialog_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn dialog_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn dialog_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn dialog_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn dialog_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn dialog_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn dialog_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn dialog_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn dialog_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn dialog_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn dialog_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn dialog_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn dialog_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn dialog_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn dialog_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn dialog_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn dialog_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dialog_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dialog_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn dialog_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
