// account_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

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
            .find(doc! { "ownerUserId": owner_user_id })
            .sort(doc! { "createdAt": -1 })
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
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn get_account_raw(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Option<ExternalImapAccount>> {
        self.coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await
    }

    pub async fn update_account(
        &self,
        owner_user_id: &str,
        account_id: &str,
        input: UpdateExternalAccountInput,
    ) -> Result<Option<ExternalImapAccount>> {
        let mut set_doc = doc! {
            "updatedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis())
        };

        if let Some(v) = input.provider { set_doc.insert("provider", v); }
        if let Some(v) = input.email { set_doc.insert("email", v); }
        if let Some(v) = input.auth_type { set_doc.insert("authType", v); }
        if let Some(v) = input.status { set_doc.insert("status", v); }
        if let Some(v) = input.last_error { set_doc.insert("lastError", v); }

        if let Some(imap) = input.imap {
            set_doc.insert("imapHost", imap.host);
            set_doc.insert("imapPort", i64::from(imap.port));
            set_doc.insert("imapTls", imap.tls);
        }

        if let Some(smtp) = input.smtp {
            set_doc.insert("smtpHost", smtp.host);
            set_doc.insert("smtpPort", smtp.port.map(i64::from));
            set_doc.insert("smtpTls", smtp.tls);
        }

        if let Some(creds) = input.credentials {
            set_doc.insert("secretRef", creds.secret_ref);
            set_doc.insert("secretValue", creds.secret_value);
        }

        self.coll_accounts()
            .update_one(
                doc! { "ownerUserId": owner_user_id, "id": account_id },
                doc! { "$set": set_doc },
            )
            .await?;

        let found = self
            .coll_accounts()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        Ok(found.map(redact_account))
    }

    pub async fn delete_account(&self, owner_user_id: &str, account_id: &str) -> Result<bool> {
        let deleted = self
            .coll_accounts()
            .delete_one(doc! { "ownerUserId": owner_user_id, "id": account_id })
            .await?;
        self.coll_folders()
            .delete_many(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .await?;
        self.coll_messages()
            .delete_many(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .await?;
        self.coll_sync_runs()
            .delete_many(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .await?;
        Ok(deleted.deleted_count > 0)
    }
}
