// folder_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;

impl ExternalImapService {

    pub async fn list_folders(
        &self,
        owner_user_id: &str,
        account_id: &str,
    ) -> Result<Vec<ExternalImapFolder>> {
        let cursor = self
            .coll_folders()
            .find(doc! { "ownerUserId": owner_user_id, "accountId": account_id })
            .sort(doc! { "remoteName": 1 })
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
                    "ownerUserId": owner_user_id,
                    "accountId": account_id,
                    "id": folder_id,
                },
                doc! {
                    "$set": {
                        "localRole": local_role,
                        "updatedAt": bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                    }
                },
            )
            .await?;

        self.coll_folders()
            .find_one(
                doc! {
                    "ownerUserId": owner_user_id,
                    "accountId": account_id,
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
                "ownerUserId": owner_user_id,
                "accountId": account_id,
                "remoteName": remote_name,
            })
            .await?;

        if let Some(mut folder) = existing {
            self.coll_folders()
                .update_one(
                    doc! { "id": &folder.id, "ownerUserId": owner_user_id, "accountId": account_id },
                    doc! { "$set": { "localRole": local_role, "updatedAt": now } },
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
}
