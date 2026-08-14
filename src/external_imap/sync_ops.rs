// sync_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;

impl ExternalImapService {

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
                doc! { "ownerUserId": owner_user_id, "id": run_id },
                doc! {
                    "$set": {
                        "status": status,
                        "stats_fetched": i64::try_from(stats.fetched).unwrap_or(i64::MAX),
                        "stats_updated": i64::try_from(stats.updated).unwrap_or(i64::MAX),
                        "stats_deleted": i64::try_from(stats.deleted).unwrap_or(i64::MAX),
                        "endedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                        "error": error,
                    }
                },
            )
            .await?;

        self.coll_sync_runs()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": run_id })
            .await
    }

    pub async fn get_sync_run(&self, owner_user_id: &str, run_id: &str) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": run_id })
            .await
    }

    pub async fn get_sync_status(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalSyncRun>> {
        self.coll_sync_runs()
            .find(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .sort(doc! { "startedAt": -1 })
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
                doc! { "ownerUserId": owner_user_id, "id": account_id },
                doc! { "$set": { "status": status, "updatedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()) } },
            )
            .await?;
        let found = self
            .coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }
}
