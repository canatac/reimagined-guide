// Auto-split from mongo_adapter.rs (refactor: découpage par domaine).
use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{Mailbox, User};
use futures_util::TryStreamExt;
use mongodb::bson::{self, doc};
use mongodb::error::Result;

#[allow(dead_code)]
impl MongoDatabaseAdapter {
    pub async fn select_mailbox_impl(&self, mailbox: &str) -> Result<Mailbox> {
        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        })
    }

    pub async fn search_messages_impl(&self, _criteria: &str) -> Result<Vec<u32>> {
        Ok(vec![])
    }

    pub async fn expunge_mailbox_impl(&self) -> Result<Vec<u32>> {
        Ok(vec![])
    }

    pub async fn copy_messages_impl(&self, _sequence_set: &str, _target_mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn store_flags_impl(
        &self,
        _sequence_set: &str,
        _flags: Vec<String>,
        _mode: &str,
    ) -> Result<()> {
        Ok(())
    }

    pub async fn find_mailbox_impl(&self, _name: &str) -> Result<Option<Mailbox>> {
        Ok(None)
    }

    pub async fn update_mailbox_impl(&self, _mailbox: &str, _update: Mailbox) -> Result<()> {
        Ok(())
    }

    pub async fn create_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn delete_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn rename_mailbox_impl(&self, _old_name: &str, _new_name: &str) -> Result<()> {
        Ok(())
    }

    pub async fn subscribe_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn unsubscribe_mailbox_impl(&self, _mailbox: &str) -> Result<()> {
        Ok(())
    }

    pub async fn list_subscribed_mailboxes_impl(
        &self,
        _username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }

    pub async fn get_mailbox_status_items_impl(
        &self,
        _username: &str,
        _mailbox: &str,
        _items: &str,
    ) -> Result<String> {
        Ok(String::new())
    }

    pub async fn get_mailbox_status_impl(&self, _username: &str, mailbox: &str) -> Result<Mailbox> {
        Ok(Mailbox {
            name: mailbox.to_string(),
            flags: vec![],
            exists: 0,
            recent: 0,
            unseen: 0,
            permanent_flags: vec![],
            uid_validity: 1,
            uid_next: 1,
            user_id: String::new(),
        })
    }

    pub async fn noop_impl(&self) -> Result<()> {
        Ok(())
    }

    pub async fn close_mailbox_impl(&self) -> Result<()> {
        Ok(())
    }

    pub async fn check_mailbox_impl(&self) -> Result<()> {
        Ok(())
    }

    pub async fn list_mailboxes_impl(
        &self,
        _username: &str,
        _reference: &str,
        _mailbox: &str,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }

}
