// mailbox_impl.rs — split from logic/mod.rs (Sprint 11)
// Extends impl Logic with a subset of methods.
#![allow(unused_imports)]
use super::*;

impl Logic {

    pub async fn select_mailbox(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        self.repo.select_mailbox_for_user(username, mailbox).await
    }

    pub async fn search_messages(&self, username: &str, criteria: &str) -> Result<Vec<u32>> {
        self.repo.search_messages_for_user(username, criteria).await
    }

    pub async fn expunge_mailbox(&self, username: &str) -> Result<Vec<u32>> {
        self.repo.expunge_mailbox_for_user(username).await
    }

    pub async fn copy_messages(
        &self,
        username: &str,
        sequence_set: &str,
        _target_mailbox: &str,
    ) -> Result<()> {
        self.repo.copy_messages_for_user(username, sequence_set, _target_mailbox).await
    }

    pub async fn store_flags(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()> {
        self.repo.store_flags_for_user(username, sequence_set, flags, mode).await
    }

    pub async fn check_mailbox(&self) -> Result<()> {
        Ok(())
    }

    pub async fn close_mailbox(&self, username: &str) -> Result<()> {
        self.expunge_mailbox(username).await?;
        Ok(())
    }

    pub async fn noop(&self) -> Result<()> {
        Ok(())
    }

    pub async fn get_mailbox_status(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        self.select_mailbox(username, mailbox).await
    }

    pub async fn create_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        self.repo.create_mailbox_for_user(username, mailbox).await
    }

    pub async fn delete_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        self.repo.delete_mailbox_for_user(username, mailbox).await
    }

    pub async fn rename_mailbox(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        self.repo.rename_mailbox_for_user(username, old_name, new_name).await
    }

    pub async fn subscribe_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        self.repo.subscribe_mailbox_for_user(username, mailbox).await
    }

    pub async fn unsubscribe_mailbox(&self, username: &str, mailbox: &str) -> Result<()> {
        self.repo.unsubscribe_mailbox_for_user(username, mailbox).await
    }

    pub async fn list_subscribed_mailboxes(
        &self,
        username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        let _ = (_reference, _pattern);
        self.repo.list_subscribed_mailboxes_for_user(username).await
    }

    pub async fn get_mailbox_status_items(
        &self,
        username: &str,
        mailbox: &str,
        items: &str,
    ) -> Result<String> {
        let status = self.select_mailbox(username, mailbox).await?;
        let mut response = Vec::new();
        for item in items.split_whitespace() {
            match item.trim_matches(|c| c == '(' || c == ')') {
                "MESSAGES" => response.push(format!("MESSAGES {}", status.exists)),
                "RECENT" => response.push(format!("RECENT {}", status.recent)),
                "UNSEEN" => response.push(format!("UNSEEN {}", status.unseen)),
                "UIDNEXT" => response.push(format!("UIDNEXT {}", status.uid_next)),
                "UIDVALIDITY" => response.push(format!("UIDVALIDITY {}", status.uid_validity)),
                _ => continue,
            }
        }
        Ok(response.join(" "))
    }

    pub async fn store_email(&self, username: &str, mailbox: &str, email: &Email) -> Result<()> {
        self.repo.store_email(username, mailbox, email).await
    }

    pub async fn list_mailboxes(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>> {
        self.repo.list_mailboxes_for_user(username, reference, mailbox).await
    }

    // --- Calendar Event CRUD ---
}
