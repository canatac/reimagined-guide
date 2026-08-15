// email_impl.rs — split from logic/mod.rs (Sprint 11)
// Extends impl Logic with a subset of methods.
#![allow(unused_imports)]
use super::*;

impl Logic {

    pub async fn get_emails(&self, username: &str, mailbox: &str) -> Result<Vec<Email>> {
        self.get_emails_page(username, mailbox, 200, 0).await
    }

    /// Sorted newest-first page; omits heavy headers projection at the driver level when possible.
    pub async fn get_emails_page(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>> {
        self.repo
            .get_emails_page(username, mailbox, limit, skip)
            .await
    }

    pub async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
        self.repo.fetch_email(username, email_id).await
    }

    pub async fn store_email_flag(&self, username: &str, email_id: &str, flag: &str) -> Result<()> {
        let _ = username;
        self.repo.update_email_flag(email_id, flag).await
    }

    pub async fn move_email_to_mailbox(
        &self,
        username: &str,
        email_id: &str,
        mailbox: &str,
    ) -> Result<bool> {
        self.repo
            .move_email_to_mailbox(username, email_id, &mailbox.to_ascii_lowercase())
            .await
    }

    pub async fn set_email_read(
        &self,
        username: &str,
        email_id: &str,
        is_read: bool,
    ) -> Result<bool> {
        self.repo
            .set_email_read(username, email_id, is_read)
            .await
    }

    pub async fn set_email_starred(
        &self,
        username: &str,
        email_id: &str,
        is_starred: bool,
    ) -> Result<bool> {
        self.repo
            .set_email_starred(username, email_id, is_starred)
            .await
    }

    pub async fn delete_email(&self, username: &str, email_id: &str) -> Result<()> {
        let _ = username;
        self.repo.delete_email(email_id).await
    }

    pub async fn archive_email(&self, username: &str, email_id: &str) -> Result<()> {
        let _ = username;
        self.repo.archive_email(email_id).await
    }
}
