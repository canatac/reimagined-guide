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
