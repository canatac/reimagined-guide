// message_ops.rs.rs — split from external_imap/mod.rs (Sprint 14)
#![allow(unused_imports)]
use super::*;
use chrono::Utc;

impl ExternalImapService {

    pub async fn list_messages(
        &self,
        owner_user_id: &str,
        account_id: &str,
        folder: Option<&str>,
        page: u64,
        page_size: u64,
    ) -> Result<Vec<ExternalImapMessage>> {
        let mut filter = doc! {
            "ownerUserId": owner_user_id,
            "accountId": account_id,
            "deleted": false,
        };
        if let Some(folder_name) = folder {
            if let Some(folder_doc) = self
                .coll_folders()
                .find_one(doc! {
                    "ownerUserId": owner_user_id,
                    "accountId": account_id,
                    "$or": [
                        {"remoteName": folder_name},
                        {"localRole": folder_name},
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
            .sort(doc! { "internalDate": -1, "createdAt": -1 })
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
            .find_one(doc! { "ownerUserId": owner_user_id, "id": message_id })
            .await?;

        let Some(current) = found else {
            return Ok(None);
        };

        let now = bson::DateTime::from_millis(Utc::now().timestamp_millis());
        let mut set_doc = doc! { "updatedAt": now };
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
                doc! { "ownerUserId": owner_user_id, "id": message_id },
                doc! { "$set": set_doc },
            )
            .await?;

        self.coll_messages()
            .find_one(doc! { "ownerUserId": owner_user_id, "id": message_id })
            .await
    }
}
