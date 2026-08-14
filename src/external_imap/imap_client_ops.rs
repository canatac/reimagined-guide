// imap_client_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;

impl ExternalImapService {

    pub async fn imap_test(&self, account: &ExternalImapAccount) -> Result<ImapTestResult> {
        let host = account.imap_host.clone();
        let port = account.imap_port;
        let tls = account.imap_tls;
        let login_user = account.email.clone();
        let login_secret = account.secret_value.clone().unwrap_or_default();
        let res = tokio::task::spawn_blocking(move || {
            imap_probe(&host, port, tls, &login_user, &login_secret, false)
        })
        .await
        .map_err(|e| mongodb::error::Error::custom(format!("imap test join error: {e}")))?;

        match res {
            Ok((greeting, caps, _folders)) => Ok(ImapTestResult {
                ok: true,
                capabilities: caps,
                greeting,
                message: "IMAP login OK".to_string(),
            }),
            Err(e) => Ok(ImapTestResult {
                ok: false,
                capabilities: vec![],
                greeting: String::new(),
                message: e,
            }),
        }
    }

    pub async fn discover_folders(
        &self,
        owner_user_id: &str,
        account: &ExternalImapAccount,
    ) -> Result<ImapDiscoverResult> {
        let host = account.imap_host.clone();
        let port = account.imap_port;
        let tls = account.imap_tls;
        let login_user = account.email.clone();
        let login_secret = account.secret_value.clone().unwrap_or_default();
        let account_id = account.id.clone();

        let res = tokio::task::spawn_blocking(move || {
            imap_probe(&host, port, tls, &login_user, &login_secret, true)
        })
        .await
        .map_err(|e| mongodb::error::Error::custom(format!("imap discover join error: {e}")))?;

        let (_greeting, caps, folders) = res.map_err(mongodb::error::Error::custom)?;

        for f in &folders {
            let role = infer_role(f);
            let _ = self.ensure_folder(owner_user_id, &account_id, f, &role).await?;
        }

        Ok(ImapDiscoverResult {
            folders,
            capabilities: caps,
        })
    }

    pub async fn run_sync_now(
        &self,
        owner_user_id: &str,
        account: &ExternalImapAccount,
        run: &ExternalSyncRun,
    ) -> Result<SyncExecutionResult> {
        let discover = self.discover_folders(owner_user_id, account).await?;

        // Resolve the target inbox folder (create-if-missing is handled by
        // discover_folders → ensure_folder). We fetch into whichever local
        // folder has role="inbox"; if none, fall back to the first folder.
        let folders = self.list_folders(owner_user_id, &account.id).await?;
        let inbox_folder = folders
            .iter()
            .find(|f| f.local_role == "inbox")
            .or_else(|| folders.first())
            .cloned();

        // Compute the SEARCH SINCE date from run.since (default: today).
        let since_bson = run.since.unwrap_or_else(|| {
            bson::DateTime::from_millis(Utc::now().timestamp_millis())
        });
        let since_chrono = chrono::DateTime::<Utc>::from_timestamp_millis(
            since_bson.timestamp_millis(),
        )
        .unwrap_or_else(Utc::now);
        let since_imap = format_imap_date(&since_chrono);

        // Fetch remote headers via a real IMAP session (blocking dialog).
        let host = account.imap_host.clone();
        let port = account.imap_port;
        let tls = account.imap_tls;
        let login_user = account.email.clone();
        let login_secret = account.secret_value.clone().unwrap_or_default();
        let fetch_res: std::result::Result<Vec<ImapFetchedHeader>, String> =
            tokio::task::spawn_blocking(move || {
                imap_fetch_headers_since(
                    &host,
                    port,
                    tls,
                    &login_user,
                    &login_secret,
                    "INBOX",
                    &since_imap,
                )
            })
            .await
            .map_err(|e| mongodb::error::Error::custom(format!("imap fetch join error: {e}")))?;

        let fetched_headers = match fetch_res {
            Ok(v) => v,
            Err(e) => {
                // Non-fatal: record error on account, complete run as
                // failed. discover already succeeded so folders exist.
                let _ = self
                    .coll_accounts()
                    .update_one(
                        doc! { "ownerUserId": owner_user_id, "id": &account.id },
                        doc! { "$set": { "lastError": &e } },
                    )
                    .await;
                return Err(mongodb::error::Error::custom(format!(
                    "IMAP fetch failed: {e}"
                )));
            }
        };

        // Persist headers: dedupe on (account_id, remote_uid) via replace_one
        // upsert to keep the sync idempotent.
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let mut fetched = 0u64;
        let folder_id = inbox_folder.as_ref().map(|f| f.id.clone());

        for h in fetched_headers {
            let msg_id_header = h.message_id.clone();
            let dedup = format!("uid:{}:{}", account.id, h.uid);
            let internal_dt = h
                .internal_date
                .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()));
            let sent_dt = h
                .date
                .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()));

            let doc_id = Uuid::new_v4().to_string();
            let msg = ExternalImapMessage {
                id: doc_id,
                account_id: account.id.clone(),
                folder_id: folder_id.clone(),
                owner_user_id: owner_user_id.to_string(),
                remote_uid: Some(h.uid),
                message_id_header: msg_id_header,
                thread_key: None,
                from: h.from,
                to: h.to,
                subject: h.subject,
                sent_at: sent_dt,
                flags: h.flags,
                internal_date: internal_dt,
                body_preview: None,
                raw_ref: None,
                dedup_hash: Some(dedup.clone()),
                deleted: false,
                created_at: now,
                updated_at: now,
            };

            // Upsert on (account_id, remote_uid) so re-syncs don't duplicate.
            self.coll_messages()
                .replace_one(
                    doc! { "accountId": &account.id, "remoteUid": h.uid as i64 },
                    &msg,
                )
                .upsert(true)
                .await?;
            fetched += 1;
        }

        self.coll_accounts()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": &account.id },
                doc! { "$set": {
                    "lastSyncAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                    "lastError": bson::Bson::Null,
                    "updatedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis())
                }},
            )
            .await?;

        let _ = run;
        Ok(SyncExecutionResult {
            fetched,
            updated: 0,
            deleted: 0,
            discovered_folders: u64::try_from(discover.folders.len()).unwrap_or(0),
        })
    }
}

fn redact_account(mut a: ExternalImapAccount) -> ExternalImapAccount {
    a.secret_value = None;
    a
}

fn parse_rfc3339_as_bson(s: &String) -> Option<bson::DateTime> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| bson::DateTime::from_millis(dt.timestamp_millis()))
}

fn infer_role(remote_name: &str) -> String {
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

fn imap_probe(
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

fn run_imap_dialog_plain(
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

fn run_imap_dialog_ssl(
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

fn read_line_from_stream<S: std::io::Read>(stream: &mut S) -> std::result::Result<String, String> {
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

fn read_until_tag_from_stream<S: std::io::Read>(
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

fn parse_capabilities(lines: &[String]) -> Vec<String> {
    for l in lines {
        if let Some(rest) = l.strip_prefix("* CAPABILITY ") {
            return rest.split_whitespace().map(|s| s.to_string()).collect();
        }
    }
    vec![]
}

fn tag_status_ok(lines: &[String], tag: &str) -> bool {
    lines
        .iter()
        .any(|l| l.starts_with(&format!("{} OK", tag)))
}

fn parse_list_folders(lines: &[String]) -> Vec<String> {
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

fn escape_imap(s: &str) -> String {
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
fn format_imap_date(dt: &chrono::DateTime<Utc>) -> String {
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
