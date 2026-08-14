use crate::entities::{
    ExternalImapAccount, ExternalImapFolder, ExternalImapMessage, ExternalSyncRun,
};

pub mod live_probe;

use chrono::Utc;
use futures_util::TryStreamExt;
use mongodb::bson;
use mongodb::bson::doc;
use mongodb::error::Result;
use mongodb::{Client, Collection};
use openssl::ssl::{SslConnector, SslMethod, SslStream};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalAccountCredentials {
    pub secret_value: Option<String>,
    pub secret_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalImapServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalSmtpServerConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub tls: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateExternalAccountInput {
    pub provider: String,
    pub email: String,
    pub auth_type: String,
    pub imap: ExternalImapServerConfig,
    pub smtp: Option<ExternalSmtpServerConfig>,
    pub credentials: Option<ExternalAccountCredentials>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateExternalAccountInput {
    pub provider: Option<String>,
    pub email: Option<String>,
    pub auth_type: Option<String>,
    pub status: Option<String>,
    pub imap: Option<ExternalImapServerConfig>,
    pub smtp: Option<ExternalSmtpServerConfig>,
    pub credentials: Option<ExternalAccountCredentials>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalFolderMappingInput {
    pub local_role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartSyncInput {
    pub mode: String,
    #[serde(default)]
    pub folders: Vec<String>,
    pub since: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalMessageActionInput {
    pub action: String,
    pub target_folder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImapTestResult {
    pub ok: bool,
    pub capabilities: Vec<String>,
    pub greeting: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImapDiscoverResult {
    pub folders: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncExecutionResult {
    pub fetched: u64,
    pub updated: u64,
    pub deleted: u64,
    pub discovered_folders: u64,
}

pub struct ExternalImapService {
    client: Arc<Client>,
}

fn default_true() -> bool {
    true
}

impl ExternalImapService {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    fn db_name() -> String {
        std::env::var("MONGODB_DATABASE").unwrap_or_else(|_| "mailserver".to_string())
    }

    fn coll_accounts(&self) -> Collection<ExternalImapAccount> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalImapAccount>("external_imap_accounts")
    }

    fn coll_folders(&self) -> Collection<ExternalImapFolder> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalImapFolder>("external_imap_folders")
    }

    fn coll_messages(&self) -> Collection<ExternalImapMessage> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalImapMessage>("external_imap_messages")
    }

    fn coll_sync_runs(&self) -> Collection<ExternalSyncRun> {
        self.client
            .database(&Self::db_name())
            .collection::<ExternalSyncRun>("external_imap_sync_runs")
    }
}


// Helpers Sprint 14 (déplacés depuis imap_client_ops)

pub(crate) fn redact_account(mut a: ExternalImapAccount) -> ExternalImapAccount {
    a.secret_value = None;
    a
}

pub(crate) fn parse_rfc3339_as_bson(s: &String) -> Option<bson::DateTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()))
}

pub(crate) fn infer_role(remote_name: &str) -> String {
    let lower = remote_name.to_ascii_lowercase();
    if lower == "inbox" {
        "inbox".to_string()
    } else if lower.contains("sent") {
        "sent".to_string()
    } else if lower.contains("draft") {
        "drafts".to_string()
    } else if lower.contains("trash") || lower.contains("bin") {
        "trash".to_string()
    } else if lower.contains("spam") || lower.contains("junk") {
        "spam".to_string()
    } else if lower.contains("archive") {
        "archive".to_string()
    } else {
        "custom".to_string()
    }
}

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

pub(crate) fn run_imap_dialog_plain(
    mut stream: TcpStream,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    let greeting = read_line_from_stream(&mut stream)?;

    stream
        .write_all(b"a1 CAPABILITY\r\n")
        .map_err(|e| format!("write CAPABILITY failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let cap_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    let capabilities = parse_capabilities(&cap_lines);

    let login = format!("a2 LOGIN \"{}\" \"{}\"\r\n", escape_imap(username), escape_imap(password));
    stream
        .write_all(login.as_bytes())
        .map_err(|e| format!("write LOGIN failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    if !tag_status_ok(&login_lines, "a2") {
        return Err(format!("IMAP login failed: {}", login_lines.join(" | ")));
    }

    let mut folders = vec![];
    if include_list {
        stream
            .write_all(b"a3 LIST \"\" \"*\"\r\n")
            .map_err(|e| format!("write LIST failed: {e}"))?;
        stream.flush().map_err(|e| format!("flush failed: {e}"))?;
        let list_lines = read_until_tag_from_stream(&mut stream, "a3")?;
        folders = parse_list_folders(&list_lines);
    }

    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();

    Ok((greeting, capabilities, folders))
}

pub(crate) fn run_imap_dialog_ssl(
    mut stream: SslStream<TcpStream>,
    username: &str,
    password: &str,
    include_list: bool,
) -> std::result::Result<(String, Vec<String>, Vec<String>), String> {
    let greeting = read_line_from_stream(&mut stream)?;

    stream
        .write_all(b"a1 CAPABILITY\r\n")
        .map_err(|e| format!("write CAPABILITY failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let cap_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    let capabilities = parse_capabilities(&cap_lines);

    let login = format!("a2 LOGIN \"{}\" \"{}\"\r\n", escape_imap(username), escape_imap(password));
    stream
        .write_all(login.as_bytes())
        .map_err(|e| format!("write LOGIN failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    if !tag_status_ok(&login_lines, "a2") {
        return Err(format!("IMAP login failed: {}", login_lines.join(" | ")));
    }

    let mut folders = vec![];
    if include_list {
        stream
            .write_all(b"a3 LIST \"\" \"*\"\r\n")
            .map_err(|e| format!("write LIST failed: {e}"))?;
        stream.flush().map_err(|e| format!("flush failed: {e}"))?;
        let list_lines = read_until_tag_from_stream(&mut stream, "a3")?;
        folders = parse_list_folders(&list_lines);
    }

    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();

    Ok((greeting, capabilities, folders))
}

pub(crate) fn read_line_from_stream<S: std::io::Read>(stream: &mut S) -> std::result::Result<String, String> {
    let mut buf = Vec::new();
    loop {
        let mut one = [0u8; 1];
        let n = stream
            .read(&mut one)
            .map_err(|e| format!("imap read line failed: {e}"))?;
        if n == 0 {
            break;
        }
        buf.push(one[0]);
        if one[0] == b'\n' {
            break;
        }
        if buf.len() > 16_384 {
            return Err("imap line too long".to_string());
        }
    }
    let line = String::from_utf8_lossy(&buf).trim().to_string();
    Ok(line)
}

pub(crate) fn read_until_tag_from_stream<S: std::io::Read>(
    stream: &mut S,
    tag: &str,
) -> std::result::Result<Vec<String>, String> {
    let mut lines = vec![];
    loop {
        let l = read_line_from_stream(stream)?;
        if l.is_empty() {
            break;
        }
        let done = l.starts_with(&format!("{} ", tag));
        lines.push(l);
        if done {
            break;
        }
    }
    Ok(lines)
}

pub(crate) fn parse_capabilities(lines: &[String]) -> Vec<String> {
    for l in lines {
        if let Some(rest) = l.strip_prefix("* CAPABILITY ") {
            return rest.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    vec![]
}

pub(crate) fn tag_status_ok(lines: &[String], tag: &str) -> bool {
    lines
        .iter()
        .any(|l| l.starts_with(&format!("{} OK", tag)))
}

pub(crate) fn parse_list_folders(lines: &[String]) -> Vec<String> {
    let mut out = vec![];
    for l in lines {
        if l.starts_with("* LIST") {
            let parts: Vec<&str> = l.split('"').collect();
            if let Some(name) = parts.last() {
                let candidate = name.trim();
                if !candidate.is_empty() {
                    out.push(candidate.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub(crate) fn escape_imap(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/* ---------------------------------------------------------------- *
 * Real IMAP header FETCH (introduced for the external-account sync)
 *
 * Reuses the same hand-rolled CAPABILITY/LOGIN/LIST dialog and adds:
 *   a4 SELECT <folder>
 *   a5 UID SEARCH SINCE <dd-Mmm-yyyy>
 *   a6 UID FETCH <uids> (UID INTERNALDATE FLAGS
 *                        BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)])
 * Returns a Vec<ImapFetchedHeader> the sync layer persists via replace_one.
 * ---------------------------------------------------------------- */

#[derive(Debug, Clone)]
pub(crate) struct ImapFetchedHeader {
    pub uid: u64,
    pub flags: Vec<String>,
    pub internal_date: Option<chrono::DateTime<Utc>>,
    pub date: Option<chrono::DateTime<Utc>>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
}

/// Format a chrono UTC date as RFC 3501 SEARCH date: "01-Jan-2026".
pub(crate) fn format_imap_date(dt: &chrono::DateTime<Utc>) -> String {
    dt.format("%d-%b-%Y").to_string()
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
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();

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

mod account_ops;
mod folder_ops;
mod sync_ops;
mod message_ops;
mod imap_client_ops;


fn imap_fetch_dialog<S: std::io::Read + std::io::Write>(
    mut stream: S,
    username: &str,
    password: &str,
    folder: &str,
    since_imap: &str,
) -> std::result::Result<Vec<ImapFetchedHeader>, String> {
    // Greeting
    let _greeting = read_line_from_stream(&mut stream)?;

    // LOGIN
    let login = format!(
        "a1 LOGIN \"{}\" \"{}\"\r\n",
        escape_imap(username),
        escape_imap(password)
    );
    stream
        .write_all(login.as_bytes())
        .map_err(|e| format!("write LOGIN failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let login_lines = read_until_tag_from_stream(&mut stream, "a1")?;
    if !tag_status_ok(&login_lines, "a1") {
        return Err(format!("IMAP login failed: {}", login_lines.join(" | ")));
    }

    // SELECT
    let sel = format!("a2 SELECT \"{}\"\r\n", escape_imap(folder));
    stream
        .write_all(sel.as_bytes())
        .map_err(|e| format!("write SELECT failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let sel_lines = read_until_tag_from_stream(&mut stream, "a2")?;
    if !tag_status_ok(&sel_lines, "a2") {
        return Err(format!(
            "IMAP select {} failed: {}",
            folder,
            sel_lines.join(" | ")
        ));
    }

    // UID SEARCH SINCE
    let search = format!("a3 UID SEARCH SINCE {}\r\n", since_imap);
    stream
        .write_all(search.as_bytes())
        .map_err(|e| format!("write SEARCH failed: {e}"))?;
    stream.flush().map_err(|e| format!("flush failed: {e}"))?;
    let search_lines = read_until_tag_from_stream(&mut stream, "a3")?;
    if !tag_status_ok(&search_lines, "a3") {
        return Err(format!(
            "IMAP UID SEARCH failed: {}",
            search_lines.join(" | ")
        ));
    }
    let uids = parse_uid_search(&search_lines);
    if uids.is_empty() {
        // Nothing to fetch — logout cleanly, return empty.
        let _ = stream.write_all(b"a9 LOGOUT\r\n");
        let _ = stream.flush();
        return Ok(vec![]);
    }

    // UID FETCH <uid-set> (…)
    // We chunk to avoid oversized single command lines on large mailboxes.
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
        stream
            .write_all(fetch_cmd.as_bytes())
            .map_err(|e| format!("write FETCH failed: {e}"))?;
        stream.flush().map_err(|e| format!("flush failed: {e}"))?;
        let fetch_lines = read_until_tag_from_stream(&mut stream, "a4")?;
        if !tag_status_ok(&fetch_lines, "a4") {
            return Err(format!(
                "IMAP UID FETCH failed: {}",
                fetch_lines.join(" | ")
            ));
        }
        let mut parsed = parse_fetch_headers(&fetch_lines);
        result.append(&mut parsed);
    }

    let _ = stream.write_all(b"a9 LOGOUT\r\n");
    let _ = stream.flush();
    Ok(result)
}

fn parse_uid_search(lines: &[String]) -> Vec<u64> {
    for l in lines {
        if let Some(rest) = l.strip_prefix("* SEARCH") {
            return rest
                .split_whitespace()
                .filter_map(|s| s.parse::<u64>().ok())
                .collect();
        }
    }
    vec![]
}

/// Best-effort parse of `* N FETCH (…)` blocks over a flat line stream.
///
/// The RFC 3501 grammar allows literals ({N}\r\n<N bytes>) and multi-line
/// responses. Our reader tokenizes by CRLF, so an untagged FETCH response
/// spans several entries in `lines`. We concatenate anything between two
/// "* N FETCH" lines (or up to the tagged completion) into a single blob
/// and pick out UID / INTERNALDATE / FLAGS / body headers with regex-free
/// substring scanning.
fn parse_fetch_headers(lines: &[String]) -> Vec<ImapFetchedHeader> {
    let mut out = Vec::new();

    // Group lines into per-message blocks.
    let mut blocks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for l in lines {
        if l.starts_with("* ") && l.contains(" FETCH ") {
            if !cur.is_empty() {
                blocks.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(l);
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }

    for b in blocks {
        if !b.contains(" FETCH ") {
            continue;
        }
        let uid = extract_uid(&b).unwrap_or(0);
        if uid == 0 {
            continue;
        }
        let internal_date = extract_internaldate(&b);
        let flags = extract_flags(&b);
        let (from, to, subject, date_hdr, message_id) = extract_header_fields(&b);
        out.push(ImapFetchedHeader {
            uid,
            flags,
            internal_date,
            date: date_hdr,
            from,
            to,
            subject,
            message_id,
        });
    }
    out
}

fn extract_uid(blob: &str) -> Option<u64> {
    // Look for "UID <digits>" inside the parenthesized response.
    let idx = blob.find("UID ")?;
    let rest = &blob[idx + 4..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse::<u64>().ok()
}

fn extract_internaldate(blob: &str) -> Option<chrono::DateTime<Utc>> {
    // INTERNALDATE "01-Jan-2026 12:34:56 +0000"
    let idx = blob.find("INTERNALDATE ")?;
    let rest = &blob[idx + "INTERNALDATE ".len()..];
    let start = rest.find('"')? + 1;
    let end = start + rest[start..].find('"')?;
    let raw = &rest[start..end];
    // Format: "%d-%b-%Y %H:%M:%S %z"
    chrono::DateTime::parse_from_str(raw, "%d-%b-%Y %H:%M:%S %z")
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn extract_flags(blob: &str) -> Vec<String> {
    let idx = match blob.find("FLAGS (") {
        Some(i) => i,
        None => return vec![],
    };
    let rest = &blob[idx + "FLAGS (".len()..];
    let end = match rest.find(')') {
        Some(i) => i,
        None => return vec![],
    };
    rest[..end]
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

fn extract_header_fields(
    blob: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<chrono::DateTime<Utc>>,
    Option<String>,
) {
    // Body of BODY[HEADER.FIELDS (...)] is a raw header block. We look for
    // the literal marker `{N}` followed by \n and then read the header lines.
    let mut from = None;
    let mut to = None;
    let mut subject = None;
    let mut date = None;
    let mut message_id = None;

    // The header block lives between the last "{N}" marker and the closing
    // ")" of the FETCH response. Cheap heuristic: scan every line for the
    // "Header: value" pattern.
    for raw_line in blob.lines() {
        let line = raw_line.trim_start();
        if let Some(v) = line.strip_prefix("From: ") {
            from = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("To: ") {
            to = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Subject: ") {
            subject = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Message-ID: ") {
            message_id = Some(v.trim().trim_matches(|c| c == '<' || c == '>').to_string());
        } else if let Some(v) = line.strip_prefix("Date: ") {
            date = chrono::DateTime::parse_from_rfc2822(v.trim())
                .ok()
                .map(|dt| dt.with_timezone(&Utc));
        }
    }

    (from, to, subject, date, message_id)
}
