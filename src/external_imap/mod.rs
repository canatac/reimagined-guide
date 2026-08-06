use crate::entities::{
    ExternalImapAccount, ExternalImapFolder, ExternalImapMessage, ExternalSyncRun,
};
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

    pub async fn create_account(
        &self,
        owner_user_id: &str,
        input: CreateExternalAccountInput,
    ) -> Result<ExternalImapAccount> {
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let account = ExternalImapAccount {
            id: Uuid::new_v4().to_string(),
            owner_user_id: owner_user_id.to_string(),
            provider: input.provider,
            email: input.email,
            auth_type: input.auth_type,
            secret_ref: input.credentials.as_ref().and_then(|c| c.secret_ref.clone()),
            secret_value: input.credentials.as_ref().and_then(|c| c.secret_value.clone()),
            imap_host: input.imap.host,
            imap_port: input.imap.port,
            imap_tls: input.imap.tls,
            smtp_host: input.smtp.as_ref().and_then(|s| s.host.clone()),
            smtp_port: input.smtp.as_ref().and_then(|s| s.port),
            smtp_tls: input.smtp.as_ref().and_then(|s| s.tls),
            status: "active".to_string(),
            last_sync_at: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        };

        self.coll_accounts().insert_one(&account).await?;
        Ok(redact_account(account))
    }

    pub async fn list_accounts(&self, owner_user_id: &str) -> Result<Vec<ExternalImapAccount>> {
        let cursor = self
            .coll_accounts()
            .find(doc! { "owner_user_id": owner_user_id })
            .sort(doc! { "created_at": -1 })
            .await?;
        let mut out: Vec<ExternalImapAccount> = cursor.try_collect().await?;
        out.iter_mut().for_each(|a| a.secret_value = None);
        Ok(out)
    }

    pub async fn get_account(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        let found = self
            .coll_accounts()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn get_account_raw(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        self.coll_accounts()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": account_id })
            .await
    }

    pub async fn update_account(
        &self,
        owner_user_id: &str,
        account_id: &str,
        input: UpdateExternalAccountInput,
    ) -> Result<Option<ExternalImapAccount>> {
        let mut set_doc = doc! {
            "updated_at": bson::DateTime::from_millis(Utc::now().timestamp_millis())
        };

        if let Some(v) = input.provider { set_doc.insert("provider", v); }
        if let Some(v) = input.email { set_doc.insert("email", v); }
        if let Some(v) = input.auth_type { set_doc.insert("auth_type", v); }
        if let Some(v) = input.status { set_doc.insert("status", v); }
        if let Some(v) = input.last_error { set_doc.insert("last_error", v); }

        if let Some(imap) = input.imap {
            set_doc.insert("imap_host", imap.host);
            set_doc.insert("imap_port", i64::from(imap.port));
            set_doc.insert("imap_tls", imap.tls);
        }

        if let Some(smtp) = input.smtp {
            set_doc.insert("smtp_host", smtp.host);
            set_doc.insert("smtp_port", smtp.port.map(i64::from));
            set_doc.insert("smtp_tls", smtp.tls);
        }

        if let Some(creds) = input.credentials {
            set_doc.insert("secret_ref", creds.secret_ref);
            set_doc.insert("secret_value", creds.secret_value);
        }

        self.coll_accounts()
            .update_one(
                doc! { "owner_user_id": owner_user_id, "id": account_id },
                doc! { "$set": set_doc },
            )
            .await?;

        let found = self
            .coll_accounts()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn delete_account(&self, owner_user_id: &str, account_id: &str) -> Result<bool> {
        let deleted = self
            .coll_accounts()
            .delete_one(doc! { "owner_user_id": owner_user_id, "id": account_id })
            .await?;
        self.coll_folders()
            .delete_many(doc! { "owner_user_id": owner_user_id, "account_id": account_id })
            .await?;
        self.coll_messages()
            .delete_many(doc! { "owner_user_id": owner_user_id, "account_id": account_id })
            .await?;
        self.coll_sync_runs()
            .delete_many(doc! { "owner_user_id": owner_user_id, "account_id": account_id })
            .await?;
        Ok(deleted.deleted_count > 0)
    }

    pub async fn list_folders(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Vec<ExternalImapFolder>> {
        let cursor = self
            .coll_folders()
            .find(doc! { "owner_user_id": owner_user_id, "account_id": account_id })
            .sort(doc! { "remote_name": 1 })
            .await?;
        cursor.try_collect().await
    }

    pub async fn upsert_folder_mapping(
        &self,
        owner_user_id: &str,
        account_id: &str,
        folder_id: &str,
        local_role: &str,
    ) -> Result<Option<ExternalImapFolder>> {
        self.coll_folders()
            .update_one(
                doc! {
                    "owner_user_id": owner_user_id,
                    "account_id": account_id,
                    "id": folder_id,
                },
                doc! {
                    "$set": {
                        "local_role": local_role,
                        "updated_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                    }
                },
            )
            .await?;

        self.coll_folders()
            .find_one(
                doc! {
                    "owner_user_id": owner_user_id,
                    "account_id": account_id,
                    "id": folder_id,
                },
            )
            .await
    }

    pub async fn ensure_folder(
        &self,
        owner_user_id: &str,
        account_id: &str,
        remote_name: &str,
        local_role: &str,
    ) -> Result<ExternalImapFolder> {
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let existing = self
            .coll_folders()
            .find_one(doc! {
                "owner_user_id": owner_user_id,
                "account_id": account_id,
                "remote_name": remote_name,
            })
            .await?;

        if let Some(mut folder) = existing {
            self.coll_folders()
                .update_one(
                    doc! { "id": &folder.id, "owner_user_id": owner_user_id, "account_id": account_id },
                    doc! { "$set": { "local_role": local_role, "updated_at": now } },
                )
                .await?;
            folder.local_role = local_role.to_string();
            folder.updated_at = now;
            return Ok(folder);
        }

        let folder = ExternalImapFolder {
            id: Uuid::new_v4().to_string(),
            account_id: account_id.to_string(),
            owner_user_id: owner_user_id.to_string(),
            remote_name: remote_name.to_string(),
            local_role: local_role.to_string(),
            uid_validity: None,
            highest_uid: None,
            highest_modseq: None,
            created_at: now,
            updated_at: now,
        };
        self.coll_folders().insert_one(&folder).await?;
        Ok(folder)
    }

    pub async fn start_sync_run(
        &self,
        owner_user_id: &str,
        account_id: &str,
        input: &StartSyncInput,
    ) -> Result<ExternalSyncRun> {
        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let since_dt = input.since.as_ref().and_then(parse_rfc3339_as_bson);

        let run = ExternalSyncRun {
            id: Uuid::new_v4().to_string(),
            account_id: account_id.to_string(),
            owner_user_id: owner_user_id.to_string(),
            mode: input.mode.clone(),
            folders: input.folders.clone(),
            since: since_dt,
            status: "running".to_string(),
            stats_fetched: 0,
            stats_updated: 0,
            stats_deleted: 0,
            started_at: now,
            ended_at: None,
            error: None,
        };
        self.coll_sync_runs().insert_one(&run).await?;
        Ok(run)
    }

    pub async fn complete_sync_run(
        &self,
        owner_user_id: &str,
        run_id: &str,
        status: &str,
        stats: SyncExecutionResult,
        error: Option<String>,
    ) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .update_one(
                doc! { "owner_user_id": owner_user_id, "id": run_id },
                doc! {
                    "$set": {
                        "status": status,
                        "stats_fetched": i64::try_from(stats.fetched).unwrap_or(i64::MAX),
                        "stats_updated": i64::try_from(stats.updated).unwrap_or(i64::MAX),
                        "stats_deleted": i64::try_from(stats.deleted).unwrap_or(i64::MAX),
                        "ended_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                        "error": error,
                    }
                },
            )
            .await?;

        self.coll_sync_runs()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": run_id })
            .await
    }

    pub async fn get_sync_run(&self, owner_user_id: &str, run_id: &str) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": run_id })
            .await
    }

    pub async fn get_sync_status(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .find(doc! { "owner_user_id": owner_user_id, "account_id": account_id })
            .sort(doc! { "started_at": -1 })
            .limit(1)
            .await?
            .try_next()
            .await
    }

    pub async fn set_account_status(
        &self,
        owner_user_id: &str,
        account_id: &str,
        status: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        self.coll_accounts()
            .update_one(
                doc! { "owner_user_id": owner_user_id, "id": account_id },
                doc! { "$set": { "status": status, "updated_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
            )
            .await?;
        let found = self
            .coll_accounts()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn list_messages(
        &self,
        owner_user_id: &str,
        account_id: &str,
        folder: Option<&str>,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<ExternalImapMessage>> {
        let mut filter = doc! {
            "owner_user_id": owner_user_id,
            "account_id": account_id,
            "deleted": false,
        };
        if let Some(folder_name) = folder {
            if let Some(folder_doc) = self
                .coll_folders()
                .find_one(doc! {
                    "owner_user_id": owner_user_id,
                    "account_id": account_id,
                    "$or": [
                        {"remote_name": folder_name},
                        {"local_role": folder_name},
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
            .sort(doc! { "internal_date": -1, "created_at": -1 })
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
            .find_one(doc! { "owner_user_id": owner_user_id, "id": message_id })
            .await?;

        let Some(current) = found else {
            return Ok(None);
        };

        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let mut set_doc = doc! { "updated_at": now };
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
                doc! { "owner_user_id": owner_user_id, "id": message_id },
                doc! { "$set": set_doc },
            )
            .await?;

        self.coll_messages()
            .find_one(doc! { "owner_user_id": owner_user_id, "id": message_id })
            .await
    }

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
        let folders = self.list_folders(owner_user_id, &account.id).await?;

        // Minimal operational sync: ensure one synthetic metadata item per folder if empty.
        let mut fetched = 0u64;
        for folder in folders {
            let count = self
                .coll_messages()
                .count_documents(doc! {
                    "owner_user_id": owner_user_id,
                    "account_id": &account.id,
                    "folder_id": &folder.id,
                    "deleted": false,
                })
                .await?;
            if count == 0 {
                let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
                let msg = ExternalImapMessage {
                    id: Uuid::new_v4().to_string(),
                    account_id: account.id.clone(),
                    folder_id: Some(folder.id.clone()),
                    owner_user_id: owner_user_id.to_string(),
                    remote_uid: None,
                    message_id_header: None,
                    thread_key: None,
                    from: Some(account.email.clone()),
                    to: Some(account.email.clone()),
                    subject: Some(format!("IMAP sync marker ({})", folder.remote_name)),
                    sent_at: Some(now),
                    flags: vec!["\\Seen".to_string()],
                    internal_date: Some(now),
                    body_preview: Some("Metadata sync marker created by external IMAP aggregator".to_string()),
                    raw_ref: None,
                    dedup_hash: Some(format!("sync-marker:{}:{}", account.id, folder.remote_name)),
                    deleted: false,
                    created_at: now,
                    updated_at: now,
                };
                self.coll_messages().insert_one(msg).await?;
                fetched += 1;
            }
        }

        self.coll_accounts()
            .update_one(
                doc! { "owner_user_id": owner_user_id, "id": &account.id },
                doc! { "$set": {
                    "last_sync_at": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                    "last_error": bson::Bson::Null,
                    "updated_at": bson::DateTime::from_millis(Utc::now().timestamp_millis())
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
