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
 *       event: line
 *       data: {"dir":">"|"<","text":"…"}
 *       \n
 *   And a terminal frame:
 *       event: done
 *       data: {"ok":true|false,"error":"…"}
 *       \n
 */

use openssl::ssl::{SslConnector, SslMethod};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use tokio::sync::mpsc::Sender;

fn escape_imap(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sse_line_frame(payload: &str) -> String {
    format!("event: line\ndata: {payload}\n\n")
}

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
