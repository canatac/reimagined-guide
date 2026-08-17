// mongo_adapter/trait_impl.rs — implémentation du trait `DatabaseInterface`
// pour `MongoDatabaseAdapter`. Chaque méthode délègue au `*_impl` inhérent défini
// dans les sous-modules par domaine. Séparé de `mod.rs` pour tenir sous 300 LOC.

use super::MongoDatabaseAdapter;
use crate::entities::{CalendarEvent, Email};
use crate::logic::{DatabaseInterface, Mailbox, User};
use async_trait::async_trait;
use mongodb::bson;
use mongodb::error::Result;

#[async_trait]
impl DatabaseInterface for MongoDatabaseAdapter {
    async fn insert_user(&self, user: User) -> Result<()> {
        self.insert_user_impl(user).await
    }
    async fn find_user(&self, username: &str, password: &str) -> Result<Option<User>> {
        self.find_user_impl(username, password).await
    }
    async fn create_user(
        &self,
        username: &str,
        password: &str,
        mailbox: &str,
    ) -> Result<()> {
        self.create_user_impl(username, password, mailbox).await
    }
    async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>> {
        self.authenticate_user_impl(username, password).await
    }
    async fn update_user_locale(&self, username: &str, locale: &str) -> Result<()> {
        self.update_user_locale_impl(username, locale).await
    }
    async fn find_or_create_oauth_user(
        &self,
        provider: &str,
        provider_user_id: &str,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<User> {
        self.find_or_create_oauth_user_impl(provider, provider_user_id, email, display_name).await
    }
    async fn create_alias(&self, alias: &str, target: &str) -> Result<()> {
        self.create_alias_impl(alias, target).await
    }
    async fn find_emails(&self, mailbox: &str) -> Result<Vec<Email>> {
        self.find_emails_impl(mailbox).await
    }
    async fn find_email(&self, email_id: &str) -> Result<Option<Email>> {
        self.find_email_impl(email_id).await
    }
    async fn update_email_flag(&self, email_id: &str, flag: &str) -> Result<()> {
        self.update_email_flag_impl(email_id, flag).await
    }
    async fn delete_email(&self, email_id: &str) -> Result<()> {
        self.delete_email_impl(email_id).await
    }
    async fn archive_email(&self, email_id: &str) -> Result<()> {
        self.archive_email_impl(email_id).await
    }
    async fn store_email(
        &self,
        username: &str,
        mailbox: &str,
        email: &Email,
    ) -> Result<()> {
        self.store_email_impl(username, mailbox, email).await
    }
    async fn get_emails_page(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>> {
        self.get_emails_page_impl(username, mailbox, limit, skip).await
    }
    async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>> {
        self.fetch_email_impl(username, email_id).await
    }
    async fn set_email_read(
        &self,
        username: &str,
        email_id: &str,
        read: bool,
    ) -> Result<bool> {
        self.set_email_read_impl(username, email_id, read).await
    }
    async fn set_email_starred(
        &self,
        username: &str,
        email_id: &str,
        starred: bool,
    ) -> Result<bool> {
        self.set_email_starred_impl(username, email_id, starred).await
    }
    async fn move_email_to_mailbox(
        &self,
        username: &str,
        email_id: &str,
        target_mailbox: &str,
    ) -> Result<bool> {
        self.move_email_to_mailbox_impl(username, email_id, target_mailbox).await
    }
    async fn deliver_to_inbox(&self, username: &str, email: &Email) -> Result<()> {
        self.deliver_to_inbox_impl(username, email).await
    }
    async fn log_mail_event(
        &self,
        kind: &str,
        user_id: &str,
        email_id: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        self.log_mail_event_impl(kind, user_id, email_id, subject, from, to).await
    }
    async fn select_mailbox(&self, mailbox: &str) -> Result<Mailbox> {
        self.select_mailbox_impl(mailbox).await
    }
    async fn search_messages(&self, _criteria: &str) -> Result<Vec<u32>> {
        self.search_messages_impl(_criteria).await
    }
    async fn expunge_mailbox(&self) -> Result<Vec<u32>> {
        self.expunge_mailbox_impl().await
    }
    async fn copy_messages(&self, _sequence_set: &str, _target_mailbox: &str) -> Result<()> {
        self.copy_messages_impl(_sequence_set, _target_mailbox).await
    }
    async fn store_flags(
        &self,
        _sequence_set: &str,
        _flags: Vec<String>,
        _mode: &str,
    ) -> Result<()> {
        self.store_flags_impl(_sequence_set, _flags, _mode).await
    }
    async fn find_mailbox(&self, _name: &str) -> Result<Option<Mailbox>> {
        self.find_mailbox_impl(_name).await
    }
    async fn update_mailbox(&self, _mailbox: &str, _update: Mailbox) -> Result<()> {
        self.update_mailbox_impl(_mailbox, _update).await
    }
    async fn create_mailbox(&self, _mailbox: &str) -> Result<()> {
        self.create_mailbox_impl(_mailbox).await
    }
    async fn delete_mailbox(&self, _mailbox: &str) -> Result<()> {
        self.delete_mailbox_impl(_mailbox).await
    }
    async fn rename_mailbox(&self, _old_name: &str, _new_name: &str) -> Result<()> {
        self.rename_mailbox_impl(_old_name, _new_name).await
    }
    async fn subscribe_mailbox(&self, _mailbox: &str) -> Result<()> {
        self.subscribe_mailbox_impl(_mailbox).await
    }
    async fn unsubscribe_mailbox(&self, _mailbox: &str) -> Result<()> {
        self.unsubscribe_mailbox_impl(_mailbox).await
    }
    async fn list_subscribed_mailboxes(
        &self,
        _username: &str,
        _reference: &str,
        _pattern: &str,
    ) -> Result<Vec<String>> {
        self.list_subscribed_mailboxes_impl(_username, _reference, _pattern).await
    }
    async fn get_mailbox_status_items(
        &self,
        _username: &str,
        _mailbox: &str,
        _items: &str,
    ) -> Result<String> {
        self.get_mailbox_status_items_impl(_username, _mailbox, _items).await
    }
    async fn get_mailbox_status(&self, _username: &str, mailbox: &str) -> Result<Mailbox> {
        self.get_mailbox_status_impl(_username, mailbox).await
    }
    async fn noop(&self) -> Result<()> {
        self.noop_impl().await
    }
    async fn close_mailbox(&self) -> Result<()> {
        self.close_mailbox_impl().await
    }
    async fn check_mailbox(&self) -> Result<()> {
        self.check_mailbox_impl().await
    }
    async fn list_mailboxes(
        &self,
        _username: &str,
        _reference: &str,
        _mailbox: &str,
    ) -> Result<Vec<String>> {
        self.list_mailboxes_impl(_username, _reference, _mailbox).await
    }
    async fn create_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
        self.create_mailbox_for_user_impl(username, mailbox).await
    }
    async fn delete_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
        self.delete_mailbox_for_user_impl(username, mailbox).await
    }
    async fn rename_mailbox_for_user(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()> {
        self.rename_mailbox_for_user_impl(username, old_name, new_name).await
    }
    async fn subscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
        self.subscribe_mailbox_for_user_impl(username, mailbox).await
    }
    async fn unsubscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()> {
        self.unsubscribe_mailbox_for_user_impl(username, mailbox).await
    }
    async fn select_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<Mailbox> {
        self.select_mailbox_for_user_impl(username, mailbox).await
    }
    async fn search_messages_for_user(&self, username: &str, criteria: &str) -> Result<Vec<u32>> {
        self.search_messages_for_user_impl(username, criteria).await
    }
    async fn expunge_mailbox_for_user(&self, username: &str) -> Result<Vec<u32>> {
        self.expunge_mailbox_for_user_impl(username).await
    }
    async fn copy_messages_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        _target_mailbox: &str,
    ) -> Result<()> {
        self.copy_messages_for_user_impl(username, sequence_set, _target_mailbox).await
    }
    async fn store_flags_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()> {
        self.store_flags_for_user_impl(username, sequence_set, flags, mode).await
    }
    async fn list_subscribed_mailboxes_for_user(
        &self,
        username: &str,
    ) -> Result<Vec<String>> {
        self.list_subscribed_mailboxes_for_user_impl(username).await
    }
    async fn list_mailboxes_for_user(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>> {
        self.list_mailboxes_for_user_impl(username, reference, mailbox).await
    }
    async fn create_calendar_event(&self, event: &CalendarEvent) -> Result<()> {
        self.create_calendar_event_impl(event).await
    }
    async fn get_calendar_events(
        &self,
        username: &str,
        start_after: Option<bson::DateTime>,
        start_before: Option<bson::DateTime>,
    ) -> Result<Vec<CalendarEvent>> {
        self.get_calendar_events_impl(username, start_after, start_before).await
    }
    async fn get_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> Result<Option<CalendarEvent>> {
        self.get_calendar_event_impl(username, event_id).await
    }
    async fn update_calendar_event(
        &self,
        username: &str,
        event_id: &str,
        update_doc: bson::Document,
    ) -> Result<Option<CalendarEvent>> {
        self.update_calendar_event_impl(username, event_id, update_doc).await
    }
    async fn delete_calendar_event(&self, username: &str, event_id: &str) -> Result<()> {
        self.delete_calendar_event_impl(username, event_id).await
    }
}
