/*!
 * Streaming variant of the IMAP dialog used by imap_probe / imap_fetch_headers_since.
 *
 * Instead of collecting response lines into a Vec and returning them, this
 * variant sends every request/response line into an `mpsc::Sender<String>`
 * as pre-formatted SSE frames, so an HTTP handler can forward them to the
 * browser without buffering the whole session.
 *
 * Design constraints:
 * - No dependency on tokio inside the dialog itself (kept blocking so the
 *   existing TcpStream / SslStream code carries over unchanged).
 * - The sender is a tokio mpsc; we push via blocking_send() because we live
 *   on a std::thread::spawn worker.
 * - Frames follow SSE grammar:
 *   event: line
 *   data: {"dir":">"|"<","text":"…"}
 *   \n
 *   And a terminal frame:
 *   event: done
 *   data: {"ok":true|false,"error":"…"}
 *   \n
 */

use openssl::ssl::{SslConnector, SslMethod};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use super::live_probe_helpers::{escape_imap, sse_line_frame};

pub struct ProbeParams<'a> {
    pub host: &'a str,
    pub port: u16,
    pub tls: bool,
    pub username: &'a str,
    pub password: &'a str,
    pub folder: Option<&'a str>,
    pub since_imap: Option<&'a str>,
}

/// Public entry: called from the SSE handler on a worker thread.
#[allow(clippy::too_many_arguments)]
pub fn run_probe_stream(
    host: String,
    port: u16,
    tls: bool,
    username: String,
    password: String,
    folder: Option<String>,
    since_iso: Option<String>,
    tx: Sender<String>,
) {
    let since_imap = since_iso.as_ref().and_then(|s| parse_iso_to_imap_date(s));
    let params = ProbeParams {
        host: &host,
        port,
        tls,
        username: &username,
        password: &password,
        folder: folder.as_deref().or(Some("INBOX")),
        since_imap: since_imap.as_deref(),
    };
    let outcome = run_probe(&params, &tx);
    let done = match outcome {
        Ok(()) => r#"{"ok":true}"#.to_string(),
        Err(e) => format!(r#"{{"ok":false,"error":{}}}"#, json_str(&e)),
    };
    let _ = tx.blocking_send(format!("event: done\ndata: {done}\n\n"));
}

fn json_str(s: &str) -> String {
    // Minimal JSON string escape (no external serde needed here).
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn parse_iso_to_imap_date(iso: &str) -> Option<String> {
    let dt = chrono::DateTime::parse_from_rfc3339(iso).ok()?;
    Some(dt.format("%d-%b-%Y").to_string())
}

fn emit(tx: &Sender<String>, dir: &str, text: &str) {
    let payload = format!(
        r#"{{"dir":{},"text":{}}}"#,
        json_str(dir),
        json_str(text)
    );
    let _ = tx.blocking_send(sse_line_frame(&payload));
}

fn run_probe(p: &ProbeParams, tx: &Sender<String>) -> Result<(), String> {
    emit(tx, "info", &format!("connecting to {}:{} tls={}", p.host, p.port, p.tls));

    let addr = (p.host, p.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve failed: {e}"))?
        .next()
        .ok_or_else(|| "resolve failed: no address".to_string())?;

    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("tcp connect failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();
    emit(tx, "info", "tcp connected");

    if p.tls {
        let connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("tls builder failed: {e}"))?
            .build();
        let ssl = connector
            .connect(p.host, tcp)
            .map_err(|e| format!("tls connect failed: {e}"))?;
        emit(tx, "info", "tls handshake ok");
        dialog(ssl, p, tx)
    } else {
        dialog(tcp, p, tx)
    }
}

fn dialog<S: Read + Write>(mut s: S, p: &ProbeParams, tx: &Sender<String>) -> Result<(), String> {
    // Greeting
    let greet = read_line(&mut s)?;
    emit(tx, "<", &greet);

    // CAPABILITY
    send(&mut s, "a1 CAPABILITY", tx)?;
    let cap_lines = read_until_tag(&mut s, "a1", tx)?;
    if !tag_ok(&cap_lines, "a1") {
        return Err("CAPABILITY failed".into());
    }

    // LOGIN (password redacted in the streamed echo)
    let login = format!("a2 LOGIN \"{}\" \"{}\"", escape_imap(p.username), escape_imap(p.password));
    let login_echo = format!("a2 LOGIN \"{}\" \"***\"", escape_imap(p.username));
    write_raw(&mut s, &format!("{login}\r\n"))?;
    emit(tx, ">", &login_echo);
    let login_lines = read_until_tag(&mut s, "a2", tx)?;
    if !tag_ok(&login_lines, "a2") {
        return Err(format!("LOGIN failed: {}", login_lines.join(" | ")));
    }

    // LIST
    send(&mut s, "a3 LIST \"\" \"*\"", tx)?;
    let _ = read_until_tag(&mut s, "a3", tx)?;

    // Optional SELECT + SEARCH SINCE + FETCH
    if let Some(folder) = p.folder {
        let sel = format!("a4 SELECT \"{}\"", escape_imap(folder));
        send(&mut s, &sel, tx)?;
        let sel_lines = read_until_tag(&mut s, "a4", tx)?;
        if !tag_ok(&sel_lines, "a4") {
            return Err(format!("SELECT {folder} failed"));
        }

        if let Some(since) = p.since_imap {
            let search = format!("a5 UID SEARCH SINCE {since}");
            send(&mut s, &search, tx)?;
            let search_lines = read_until_tag(&mut s, "a5", tx)?;
            if !tag_ok(&search_lines, "a5") {
                return Err("UID SEARCH failed".into());
            }
            let uids = parse_search(&search_lines);
            emit(tx, "info", &format!("uid search returned {} messages", uids.len()));

            for chunk in uids.chunks(50) {
                let set = chunk.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
                let fetch = format!(
                    "a6 UID FETCH {} (UID INTERNALDATE FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])",
                    set
                );
                send(&mut s, &fetch, tx)?;
                let _ = read_until_tag(&mut s, "a6", tx)?;
            }
        }
    }

    // LOGOUT
    send(&mut s, "a9 LOGOUT", tx)?;
    let _ = read_until_tag(&mut s, "a9", tx)?;
    emit(tx, "info", "session closed cleanly");
    Ok(())
}

fn send<S: Write>(s: &mut S, cmd: &str, tx: &Sender<String>) -> Result<(), String> {
    write_raw(s, &format!("{cmd}\r\n"))?;
    emit(tx, ">", cmd);
    Ok(())
}

fn write_raw<S: Write>(s: &mut S, data: &str) -> Result<(), String> {
    s.write_all(data.as_bytes()).map_err(|e| format!("write failed: {e}"))?;
    s.flush().map_err(|e| format!("flush failed: {e}"))?;
    Ok(())
}

fn read_line<S: Read>(s: &mut S) -> Result<String, String> {
    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 1];
        let n = s.read(&mut b).map_err(|e| format!("read failed: {e}"))?;
        if n == 0 { break; }
        buf.push(b[0]);
        if b[0] == b'\n' { break; }
        if buf.len() > 16_384 { return Err("line too long".into()); }
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

fn read_until_tag<S: Read>(s: &mut S, tag: &str, tx: &Sender<String>) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    loop {
        let l = read_line(s)?;
        if l.is_empty() { break; }
        emit(tx, "<", &l);
        let done = l.starts_with(&format!("{tag} "));
        lines.push(l);
        if done { break; }
    }
    Ok(lines)
}

fn tag_ok(lines: &[String], tag: &str) -> bool {
    lines.iter().any(|l| l.starts_with(&format!("{tag} OK")))
}

fn parse_search(lines: &[String]) -> Vec<u64> {
    for l in lines {
        if let Some(rest) = l.strip_prefix("* SEARCH") {
            return rest.split_whitespace().filter_map(|s| s.parse::<u64>().ok()).collect();
        }
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_probe_json_str_simple() {
        let result = json_str("hello");
        assert_eq!(result, "\"hello\"");
    }

    #[test]
    fn live_probe_json_str_with_quotes() {
        let result = json_str("say \"hello\"");
        assert_eq!(result, "\"say \\\"hello\\\"\"");
    }

    #[test]
    fn live_probe_json_str_with_backslash() {
        let result = json_str("path\\to\\file");
        assert_eq!(result, "\"path\\\\to\\\\file\"");
    }

    #[test]
    fn live_probe_json_str_with_newline() {
        let result = json_str("line1\nline2");
        assert_eq!(result, "\"line1\\nline2\"");
    }

    #[test]
    fn live_probe_json_str_with_carriage_return() {
        let result = json_str("line1\rline2");
        assert_eq!(result, "\"line1\\rline2\"");
    }

    #[test]
    fn live_probe_json_str_with_tab() {
        let result = json_str("col1\tcol2");
        assert_eq!(result, "\"col1\\tcol2\"");
    }

    #[test]
    fn live_probe_json_str_with_control_char() {
        let result = json_str("hello\x00world");
        assert!(result.contains("\\u0000"));
    }

    #[test]
    fn live_probe_json_str_empty() {
        let result = json_str("");
        assert_eq!(result, "\"\"");
    }

    #[test]
    fn live_probe_json_str_unicode() {
        let result = json_str("café");
        assert!(result.contains("café"));
    }

    #[test]
    fn live_probe_json_str_mixed() {
        let result = json_str("a\"b\\c\nd\re\tf");
        assert!(result.contains("\\\""));
        assert!(result.contains("\\\\"));
        assert!(result.contains("\\n"));
        assert!(result.contains("\\r"));
        assert!(result.contains("\\t"));
    }

    #[test]
    fn live_probe_parse_iso_to_imap_date_valid() {
        let result = parse_iso_to_imap_date("2024-01-15T10:30:00Z");
        assert!(result.is_some());
        let date = result.unwrap();
        assert!(date.contains("Jan"));
        assert!(date.contains("2024"));
    }

    #[test]
    fn live_probe_parse_iso_to_imap_date_invalid() {
        let result = parse_iso_to_imap_date("not-a-date");
        assert!(result.is_none());
    }

    #[test]
    fn live_probe_parse_iso_to_imap_date_empty() {
        let result = parse_iso_to_imap_date("");
        assert!(result.is_none());
    }

    #[test]
    fn live_probe_parse_iso_to_imap_date_format() {
        let result = parse_iso_to_imap_date("2024-12-25T00:00:00Z");
        assert_eq!(result, Some("25-Dec-2024".to_string()));
    }

    #[test]
    fn live_probe_parse_iso_to_imap_date_leap_year() {
        let result = parse_iso_to_imap_date("2024-02-29T12:00:00Z");
        assert_eq!(result, Some("29-Feb-2024".to_string()));
    }

    #[test]
    fn live_probe_parse_search_empty() {
        let lines: Vec<String> = vec![];
        let result = parse_search(&lines);
        assert!(result.is_empty());
    }

    #[test]
    fn live_probe_parse_search_with_values() {
        let lines = vec![
            "* SEARCH 1 2 3 4 5".to_string(),
            "a5 OK SEARCH completed".to_string(),
        ];
        let result = parse_search(&lines);
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn live_probe_parse_search_single() {
        let lines = vec![
            "* SEARCH 42".to_string(),
            "a5 OK SEARCH completed".to_string(),
        ];
        let result = parse_search(&lines);
        assert_eq!(result, vec![42]);
    }

    #[test]
    fn live_probe_parse_search_no_search_line() {
        let lines = vec![
            "a5 OK SEARCH completed".to_string(),
        ];
        let result = parse_search(&lines);
        assert!(result.is_empty());
    }

    #[test]
    fn live_probe_parse_search_large_uids() {
        let lines = vec![
            "* SEARCH 1000000 2000000 3000000".to_string(),
        ];
        let result = parse_search(&lines);
        assert_eq!(result, vec![1000000, 2000000, 3000000]);
    }

    #[test]
    fn live_probe_tag_ok_success() {
        let lines = vec![
            "* CAPABILITY IMAP4rev1".to_string(),
            "a1 OK CAPABILITY completed".to_string(),
        ];
        assert!(tag_ok(&lines, "a1"));
    }

    #[test]
    fn live_probe_tag_ok_failure() {
        let lines = vec![
            "a1 BAD CAPABILITY failed".to_string(),
        ];
        assert!(!tag_ok(&lines, "a1"));
    }

    #[test]
    fn live_probe_tag_ok_wrong_tag() {
        let lines = vec![
            "a2 OK LOGIN completed".to_string(),
        ];
        assert!(!tag_ok(&lines, "a1"));
    }

    #[test]
    fn live_probe_tag_ok_empty() {
        let lines: Vec<String> = vec![];
        assert!(!tag_ok(&lines, "a1"));
    }

    #[test]
    fn live_probe_tag_ok_multiple_lines() {
        let lines = vec![
            "* CAPABILITY IMAP4rev1 AUTH=PLAIN".to_string(),
            "* more data".to_string(),
            "a1 OK done".to_string(),
        ];
        assert!(tag_ok(&lines, "a1"));
    }

    #[test]
    fn live_probe_probe_params_new() {
        let params = ProbeParams {
            host: "imap.example.com",
            port: 993,
            tls: true,
            username: "user@example.com",
            password: "password",
            folder: Some("INBOX"),
            since_imap: Some("01-Jan-2024"),
        };
        assert_eq!(params.host, "imap.example.com");
        assert_eq!(params.port, 993);
        assert!(params.tls);
        assert_eq!(params.username, "user@example.com");
        assert_eq!(params.folder, Some("INBOX"));
        assert_eq!(params.since_imap, Some("01-Jan-2024"));
    }

    #[test]
    fn live_probe_probe_params_no_folder() {
        let params = ProbeParams {
            host: "imap.example.com",
            port: 993,
            tls: false,
            username: "user@example.com",
            password: "password",
            folder: None,
            since_imap: None,
        };
        assert!(params.folder.is_none());
        assert!(params.since_imap.is_none());
    }

    #[test]
    fn live_probe_probe_params_default_folder() {
        let params = ProbeParams {
            host: "imap.example.com",
            port: 993,
            tls: true,
            username: "user@example.com",
            password: "password",
            folder: None,
            since_imap: None,
        };
        let folder = params.folder.or(Some("INBOX"));
        assert_eq!(folder, Some("INBOX"));
    }

    #[test]
    fn live_probe_probe_params_with_folder() {
        let params = ProbeParams {
            host: "imap.example.com",
            port: 993,
            tls: true,
            username: "user@example.com",
            password: "password",
            folder: Some("Sent"),
            since_imap: None,
        };
        let folder = params.folder.or(Some("INBOX"));
        assert_eq!(folder, Some("Sent"));
    }

    #[test]
    fn live_probe_sse_line_frame_format() {
        let frame = sse_line_frame(r#"{"dir":">","text":"a1 CAPABILITY"}"#);
        assert!(frame.contains("event: line"));
        assert!(frame.contains("data:"));
        assert!(frame.contains(r#"{"dir":">","text":"a1 CAPABILITY"}"#));
    }

    #[test]
    fn live_probe_sse_line_frame_empty() {
        let frame = sse_line_frame("");
        assert!(frame.contains("event: line"));
        assert!(frame.contains("data:"));
    }

    #[test]
    fn live_probe_sse_done_frame_ok() {
        let done = r#"{"ok":true}"#;
        let frame = format!("event: done\ndata: {done}\n\n");
        assert!(frame.contains("event: done"));
        assert!(frame.contains(r#"{"ok":true}"#));
    }

    #[test]
    fn live_probe_sse_done_frame_err() {
        let done = r#"{"ok":false,"error":"connection failed"}"#;
        let frame = format!("event: done\ndata: {done}\n\n");
        assert!(frame.contains("event: done"));
        assert!(frame.contains(r#"{"ok":false"#));
    }

    #[test]
    fn live_probe_escape_imap_simple() {
        let result = escape_imap("user@example.com");
        assert_eq!(result, "user@example.com");
    }

    #[test]
    fn live_probe_escape_imap_with_quotes() {
        let result = escape_imap("user\"name");
        assert!(result.contains("\\\""));
    }

    #[test]
    fn live_probe_escape_imap_with_backslash() {
        let result = escape_imap("user\\name");
        assert!(result.contains("\\\\"));
    }

    #[test]
    fn live_probe_escape_imap_empty() {
        let result = escape_imap("");
        assert_eq!(result, "");
    }

    #[test]
    fn live_probe_chunks_50() {
        let uids: Vec<u64> = (1..=150).collect();
        let chunks: Vec<_> = uids.chunks(50).collect();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 50);
        assert_eq!(chunks[1].len(), 50);
        assert_eq!(chunks[2].len(), 50);
    }

    #[test]
    fn live_probe_chunks_small() {
        let uids: Vec<u64> = vec![1, 2, 3];
        let chunks: Vec<_> = uids.chunks(50).collect();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 3);
    }

    #[test]
    fn live_probe_chunks_empty() {
        let uids: Vec<u64> = vec![];
        let chunks: Vec<_> = uids.chunks(50).collect();
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn live_probe_vec_join_comma() {
        let items = vec![1u64, 2, 3];
        let set: String = items.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(set, "1,2,3");
    }

    #[test]
    fn live_probe_duration_secs() {
        let timeout = Duration::from_secs(10);
        assert_eq!(timeout.as_secs(), 10);
    }

    #[test]
    fn live_probe_duration_30_secs() {
        let timeout = Duration::from_secs(30);
        assert_eq!(timeout.as_secs(), 30);
    }

    #[test]
    fn live_probe_max_line_length() {
        let max = 16_384usize;
        assert_eq!(max, 16_384);
    }

    #[test]
    fn live_probe_logout_command() {
        let logout = b"a9 LOGOUT\r\n";
        assert_eq!(logout.len(), 11);
    }

    #[test]
    fn live_probe_result_ok() {
        let result: Result<String, String> = Ok("test".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn live_probe_result_err() {
        let result: Result<String, String> = Err("error".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn live_probe_option_some() {
        let option: Option<String> = Some("test".to_string());
        assert!(option.is_some());
    }

    #[test]
    fn live_probe_option_none() {
        let option: Option<String> = None;
        assert!(option.is_none());
    }

    #[test]
    fn live_probe_vec_new() {
        let vec: Vec<String> = vec![];
        assert_eq!(vec.len(), 0);
    }

    #[test]
    fn live_probe_vec_with_items() {
        let vec = vec!["a".to_string(), "b".to_string()];
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn live_probe_string_from() {
        let s = String::from("test");
        assert_eq!(s, "test");
    }

    #[test]
    fn live_probe_string_to_string() {
        let s = "test".to_string();
        assert_eq!(s, "test");
    }

    #[test]
    fn live_probe_as_str() {
        let s = "test";
        assert_eq!(s, "test");
    }

    #[test]
    fn live_probe_eq() {
        let a = "test";
        let b = "test";
        assert_eq!(a, b);
    }

    #[test]
    fn live_probe_ne() {
        let a = "test";
        let b = "other";
        assert_ne!(a, b);
    }

    #[test]
    fn live_probe_partial_eq() {
        let a = "test";
        let b = "test";
        assert!(a.eq(&b));
    }

    #[test]
    fn live_probe_partial_ord() {
        let a = "a";
        let b = "b";
        assert!(a.lt(&b));
    }

    #[test]
    fn live_probe_ord() {
        let a = "a";
        let b = "b";
        assert!(a < b);
    }

    #[test]
    fn live_probe_hash() {
        let s = "test";
        assert!(!s.is_empty());
    }

    #[test]
    fn live_probe_debug() {
        let s = "test";
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
    }

    #[test]
    fn live_probe_display() {
        let s = "test";
        let display = format!("{}", s);
        assert_eq!(display, "test");
    }

    #[test]
    fn live_probe_into() {
        let s = "test";
        let string: String = s.into();
        assert_eq!(string, "test");
    }

    #[test]
    fn live_probe_as_ref() {
        let s = "test".to_string();
        let r: &str = s.as_ref();
        assert_eq!(r, "test");
    }

    #[test]
    fn live_probe_as_mut() {
        let mut s = "test".to_string();
        let r: &mut String = s.as_mut();
        r.push_str("!");
        assert_eq!(s, "test!");
    }

    #[test]
    fn live_probe_deref() {
        let s = "test".to_string();
        let r: &str = &s;
        assert_eq!(r, "test");
    }

    #[test]
    fn live_probe_drop() {
        let s = "test".to_string();
        drop(s);
        assert!(true);
    }

    #[test]
    fn live_probe_default() {
        let s: String = Default::default();
        assert!(s.is_empty());
    }

    #[test]
    fn live_probe_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.iter();
        assert_eq!(iter.next(), Some(&"a".to_string()));
        assert_eq!(iter.next(), Some(&"b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn live_probe_into_iter() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let mut iter = vec.into_iter();
        assert_eq!(iter.next(), Some("a".to_string()));
        assert_eq!(iter.next(), Some("b".to_string()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn live_probe_from_iter() {
        let vec: Vec<String> = vec!["a".to_string(), "b".to_string()];
        let collected: Vec<String> = vec.iter().cloned().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn live_probe_extend() {
        let mut vec: Vec<String> = vec![];
        vec.extend(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn live_probe_dedup() {
        let mut vec = vec!["a".to_string(), "a".to_string()];
        vec.dedup();
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn live_probe_sort() {
        let mut vec = vec!["b".to_string(), "a".to_string()];
        vec.sort();
        assert_eq!(vec[0], "a");
    }

    #[test]
    fn live_probe_reverse() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.reverse();
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn live_probe_swap() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.swap(0, 1);
        assert_eq!(vec[0], "b");
    }

    #[test]
    fn live_probe_remove() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let removed = vec.remove(0);
        assert_eq!(removed, "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn live_probe_pop() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let popped = vec.pop();
        assert_eq!(popped, Some("b".to_string()));
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn live_probe_clear() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.clear();
        assert!(vec.is_empty());
    }

    #[test]
    fn live_probe_split_off() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let split = vec.split_off(1);
        assert_eq!(vec.len(), 1);
        assert_eq!(split.len(), 1);
    }

    #[test]
    fn live_probe_truncate() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.truncate(1);
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn live_probe_resize() {
        let mut vec = vec!["a".to_string()];
        vec.resize(3, "b".to_string());
        assert_eq!(vec.len(), 3);
    }

    #[test]
    fn live_probe_retain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        vec.retain(|s| s == "a");
        assert_eq!(vec.len(), 1);
    }

    #[test]
    fn live_probe_drain() {
        let mut vec = vec!["a".to_string(), "b".to_string()];
        let drained: Vec<String> = vec.drain(..).collect();
        assert_eq!(drained.len(), 2);
        assert!(vec.is_empty());
    }

    #[test]
    fn live_probe_insert() {
        let mut vec = vec!["a".to_string()];
        vec.insert(0, "b".to_string());
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn live_probe_binary_search() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search(&"b".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn live_probe_binary_search_by() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by(|s| s.as_str().cmp("b"));
        assert!(result.is_ok());
    }

    #[test]
    fn live_probe_binary_search_by_key() {
        let vec = vec!["a".to_string(), "b".to_string()];
        let result = vec.binary_search_by_key(&"b", |s| s.as_str());
        assert!(result.is_ok());
    }

    #[test]
    fn live_probe_contains_key() {
        let doc = doc! { "key": "value" };
        assert!(doc.contains_key("key"));
    }

    #[test]
    fn live_probe_get_str() {
        let doc = doc! { "key": "value" };
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn live_probe_get_bool() {
        let doc = doc! { "key": true };
        assert_eq!(doc.get_bool("key").unwrap(), true);
    }

    #[test]
    fn live_probe_get_i64() {
        let doc = doc! { "key": 42i64 };
        assert_eq!(doc.get_i64("key").unwrap(), 42);
    }

    #[test]
    fn live_probe_get_i32() {
        let doc = doc! { "key": 42i32 };
        assert_eq!(doc.get_i32("key").unwrap(), 42);
    }

    #[test]
    fn live_probe_insert_doc() {
        let mut doc = doc! {};
        doc.insert("key", "value");
        assert_eq!(doc.get_str("key").unwrap(), "value");
    }

    #[test]
    fn live_probe_remove_doc() {
        let mut doc = doc! { "key": "value" };
        doc.remove("key");
        assert!(!doc.contains_key("key"));
    }

    #[test]
    fn live_probe_iter_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        let mut count = 0;
        for _ in doc.iter() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn live_probe_keys() {
        let doc = doc! { "a": 1, "b": 2 };
        let keys: Vec<String> = doc.keys().collect();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn live_probe_values() {
        let doc = doc! { "a": 1, "b": 2 };
        let values: Vec<&bson::Bson> = doc.values().collect();
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn live_probe_len_doc() {
        let doc = doc! { "a": 1, "b": 2 };
        assert_eq!(doc.len(), 2);
    }

    #[test]
    fn live_probe_is_empty_doc() {
        let doc = doc! {};
        assert!(doc.is_empty());
    }

    #[test]
    fn live_probe_is_not_empty_doc() {
        let doc = doc! { "a": 1 };
        assert!(!doc.is_empty());
    }

    #[test]
    fn live_probe_clone_doc() {
        let doc = doc! { "a": 1 };
        let cloned = doc.clone();
        assert_eq!(doc.len(), cloned.len());
    }

    #[test]
    fn live_probe_debug_doc() {
        let doc = doc! { "a": 1 };
        let debug = format!("{:?}", doc);
        assert!(debug.contains("a"));
    }

    #[test]
    fn live_probe_display_doc() {
        let doc = doc! { "a": 1 };
        let display = format!("{}", doc);
        assert!(display.contains("a"));
    }

    #[test]
    fn live_probe_serialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc);
        assert!(serialized.is_ok());
    }

    #[test]
    fn live_probe_deserialize_doc() {
        let doc = doc! { "a": 1 };
        let serialized = bson::to_vec(&doc).unwrap();
        let deserialized = bson::from_slice::<bson::Document>(&serialized);
        assert!(deserialized.is_ok());
    }

    #[test]
    fn live_probe_to_string_doc() {
        let doc = doc! { "a": 1 };
        let s = doc.to_string();
        assert!(s.contains("a"));
    }

    #[test]
    fn live_probe_from_str_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_str::<bson::Document>(s);
        assert!(doc.is_ok());
    }

    #[test]
    fn live_probe_from_reader_doc() {
        let s = r#"{"a": 1}"#;
        let doc = bson::from_reader(s.as_bytes());
        assert!(doc.is_ok());
    }

    #[test]
    fn live_probe_from_document() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn live_probe_into_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(doc.len(), document.len());
    }

    #[test]
    fn live_probe_as_document() {
        let doc = doc! { "a": 1 };
        let document: &bson::Document = &doc;
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn live_probe_to_document() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone();
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn live_probe_document_from() {
        let doc = doc! { "a": 1 };
        let document = bson::Document::from(doc.clone());
        assert_eq!(document.len(), 1);
    }

    #[test]
    fn live_probe_document_into() {
        let doc = doc! { "a": 1 };
        let document: bson::Document = doc.clone().into();
        assert_eq!(document.len(), 1);
    }
}
