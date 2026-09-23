//! Periodic background sync for external IMAP accounts.
//!
//! Feature: Multi-account aggregation (#598)
//! Spawns a tokio task that iterates all active external accounts and
//! triggers `run_sync_now` every 5 minutes. This keeps the unified inbox
//! fresh without requiring manual user action.

#![allow(unused_imports)]
use crate::external_imap::{
    ExternalImapAccount, ExternalImapService, StartSyncInput, SyncExecutionResult,
    UpdateExternalAccountInput,
};
use chrono::Utc;
use mongodb::error::Result;
use std::sync::Arc;
use std::time::Duration;

const SYNC_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Start the periodic external account sync background worker.
/// Runs every SYNC_INTERVAL_SECS, iterating all accounts across all users.
pub fn start_periodic_sync(svc: Arc<ExternalImapService>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(SYNC_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            if let Err(e) = run_once(&svc).await {
                eprintln!("periodic_sync: error: {e}");
            }
        }
    });
}

/// Single pass: fetch all active accounts and sync each.
async fn run_once(svc: &ExternalImapService) -> Result<()> {
    // We query all distinct owner_user_ids from the accounts collection,
    // then list + sync each account.
    let all_accounts = svc.list_all_accounts().await?;

    let mut synced = 0u64;
    let mut failed = 0u64;

    for (user_id, account) in all_accounts {
        if account.status != "active" {
            continue;
        }
        let input = StartSyncInput {
            mode: "incremental".into(),
            folders: vec![],
            since: None,
        };
        match svc.start_sync_run(&user_id, &account.id, &input).await {
            Ok(run) => match svc.run_sync_now(&user_id, &account, &run).await {
                Ok(stats) => {
                    let _ = svc
                        .complete_sync_run(&user_id, &run.id, "success", stats, None)
                        .await;
                    // Update last_sync_at timestamp
                    let _ = svc.update_account(
                        &user_id,
                        &account.id,
                        UpdateExternalAccountInput {
                            provider: None,
                            email: None,
                            auth_type: None,
                            status: None,
                            imap: None,
                            smtp: None,
                            credentials: None,
                            last_error: None,
                            last_sync_at: Some(Utc::now()),
                        },
                    ).await;
                    synced += 1;
                }
                Err(e) => {
                    let _ = svc
                        .complete_sync_run(
                            &user_id,
                            &run.id,
                            "failed",
                            SyncExecutionResult {
                                fetched: 0,
                                updated: 0,
                                deleted: 0,
                                discovered_folders: 0,
                            },
                            Some(e.to_string()),
                        )
                        .await;
                    failed += 1;
                }
            },
            Err(e) => {
                eprintln!(
                    "periodic_sync: start_sync_run failed for account {}: {e}",
                    account.id
                );
                failed += 1;
            }
        }
    }

    if synced > 0 || failed > 0 {
        println!(
            "periodic_sync: pass complete — synced={synced} failed={failed}"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_interval_is_five_minutes() {
        assert_eq!(SYNC_INTERVAL_SECS, 300);
    }
}
