// imap_client_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

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
            Utc::now()
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
        let now = Utc::now();
        let mut fetched = 0u64;
        let folder_id = inbox_folder.as_ref().map(|f| f.id.clone());

        for h in fetched_headers {
            let msg_id_header = h.message_id.clone();
            let dedup = format!("uid:{}:{}", account.id, h.uid);
            let internal_dt = h.internal_date;
            let sent_dt = h.date;

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
                    "lastSyncAt": Utc::now(),
                    "lastError": bson::Bson::Null,
                    "updatedAt": Utc::now()
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
