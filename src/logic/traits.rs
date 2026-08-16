use super::{Logic, Mailbox, User};
use crate::entities::{CalendarEvent, Email};
use mongodb::bson;
use mongodb::error::Result;

#[cfg(test)]
use mockall::{automock, predicate::*};

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait DatabaseInterface: Send + Sync {
    async fn insert_user(&self, user: User) -> Result<()>;
    async fn find_user(&self, username: &str, password: &str) -> Result<Option<User>>;
    async fn find_emails(&self, mailbox: &str) -> Result<Vec<Email>>;
    async fn find_email(&self, email_id: &str) -> Result<Option<Email>>;
    async fn update_email_flag(&self, email_id: &str, flag: &str) -> Result<()>;
    async fn delete_email(&self, email_id: &str) -> Result<()>;
    async fn archive_email(&self, email_id: &str) -> Result<()>;
    async fn select_mailbox(&self, mailbox: &str) -> Result<Mailbox>;
    async fn search_messages(&self, criteria: &str) -> Result<Vec<u32>>;
    async fn expunge_mailbox(&self) -> Result<Vec<u32>>;
    async fn copy_messages(&self, sequence_set: &str, target_mailbox: &str) -> Result<()>;
    async fn store_flags(&self, sequence_set: &str, flags: Vec<String>, mode: &str) -> Result<()>;
    async fn find_mailbox(&self, name: &str) -> Result<Option<Mailbox>>;
    async fn update_mailbox(&self, mailbox: &str, update: Mailbox) -> Result<()>;
    async fn create_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn delete_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn rename_mailbox(&self, old_name: &str, new_name: &str) -> Result<()>;
    async fn subscribe_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn unsubscribe_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn list_subscribed_mailboxes(
        &self,
        username: &str,
        reference: &str,
        pattern: &str,
    ) -> Result<Vec<String>>;
    async fn get_mailbox_status_items(
        &self,
        username: &str,
        mailbox: &str,
        items: &str,
    ) -> Result<String>;
    async fn store_email(&self, username: &str, mailbox: &str, email: &Email) -> Result<()>;
    async fn get_mailbox_status(&self, username: &str, mailbox: &str) -> Result<Mailbox>;
    async fn noop(&self) -> Result<()>;
    async fn close_mailbox(&self) -> Result<()>;
    async fn check_mailbox(&self) -> Result<()>;
    async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()>;
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<User>>;
    async fn list_mailboxes(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>>;

    // Boucle 6 — extensions du port pour lecture/écriture email par user.
    async fn get_emails_page(
        &self,
        username: &str,
        mailbox: &str,
        limit: i64,
        skip: u64,
    ) -> Result<Vec<Email>>;
    async fn fetch_email(&self, username: &str, email_id: &str) -> Result<Option<Email>>;
    async fn set_email_read(
        &self,
        username: &str,
        email_id: &str,
        read: bool,
    ) -> Result<bool>;
    async fn set_email_starred(
        &self,
        username: &str,
        email_id: &str,
        starred: bool,
    ) -> Result<bool>;
    async fn move_email_to_mailbox(
        &self,
        username: &str,
        email_id: &str,
        target_mailbox: &str,
    ) -> Result<bool>;

    // Boucle 7 — extensions user-scopées pour l'administration des mailboxes.
    async fn create_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;
    async fn delete_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;
    async fn rename_mailbox_for_user(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<()>;
    async fn subscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;
    async fn unsubscribe_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<()>;

    // Boucle 8 — sélection mailbox user-scopée.
    async fn select_mailbox_for_user(&self, username: &str, mailbox: &str) -> Result<Mailbox>;

    // Boucle 9 — calendar via port.
    async fn create_calendar_event(&self, event: &CalendarEvent) -> Result<()>;
    async fn get_calendar_events(
        &self,
        username: &str,
        start_after: Option<bson::DateTime>,
        start_before: Option<bson::DateTime>,
    ) -> Result<Vec<CalendarEvent>>;
    async fn get_calendar_event(
        &self,
        username: &str,
        event_id: &str,
    ) -> Result<Option<CalendarEvent>>;
    async fn update_calendar_event(
        &self,
        username: &str,
        event_id: &str,
        update_doc: bson::Document,
    ) -> Result<Option<CalendarEvent>>;
    async fn delete_calendar_event(&self, username: &str, event_id: &str) -> Result<()>;

    // Boucle 10 — user admin + delivery + logging.
    async fn update_user_locale(&self, username: &str, locale: &str) -> Result<()>;
    async fn create_alias(&self, alias: &str, target: &str) -> Result<()>;
    async fn deliver_to_inbox(&self, username: &str, email: &Email) -> Result<()>;
    async fn log_mail_event(
        &self,
        kind: &str,
        user_id: &str,
        email_id: &str,
        subject: &str,
        from: &str,
        to: &str,
    ) -> Result<()>;

    // Boucle 11 — IMAP: search/expunge/copy/store_flags/list_subscribed/status_items/list.
    async fn search_messages_for_user(&self, username: &str, criteria: &str) -> Result<Vec<u32>>;
    async fn expunge_mailbox_for_user(&self, username: &str) -> Result<Vec<u32>>;
    async fn copy_messages_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        target_mailbox: &str,
    ) -> Result<()>;
    async fn store_flags_for_user(
        &self,
        username: &str,
        sequence_set: &str,
        flags: Vec<String>,
        mode: &str,
    ) -> Result<()>;
    async fn list_subscribed_mailboxes_for_user(
        &self,
        username: &str,
    ) -> Result<Vec<String>>;
    async fn list_mailboxes_for_user(
        &self,
        username: &str,
        reference: &str,
        mailbox: &str,
    ) -> Result<Vec<String>>;

    // Boucle 12 — OAuth (find or create).
    async fn find_or_create_oauth_user(
        &self,
        provider: &str,
        provider_user_id: &str,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<User>;
}

#[async_trait::async_trait]
pub trait LogicTrait: Send + Sync {
    async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()>;
}

#[async_trait::async_trait]
impl LogicTrait for Logic {
    async fn create_user(&self, username: &str, password: &str, mailbox: &str) -> Result<()> {
        self.create_user(username, password, mailbox).await
    }
}

// Cycle 22 hexagonal — ré-export du port migré vers `crates/domain`.
// Les nouveaux use-cases doivent dépendre de `simple_smtp_domain::ports::LogicPort`
// (exprimé en `DomainResult`) plutôt que du `LogicTrait` historique lié à mongodb.
pub use simple_smtp_domain::ports::LogicPort;

// Cycle 23 hexagonal — 2ème port migré : `MailboxSessionPort` couvre
// NOOP / CLOSE / CHECK, entièrement autonome (pas de dépendances mongodb).
pub use simple_smtp_domain::ports::MailboxSessionPort;

// Cycle 24 hexagonal — 3ème port migré : `MailboxSubscriptionPort`
// couvre IMAP SUBSCRIBE / UNSUBSCRIBE (signatures primitives, aucun
// type infrastructure).
pub use simple_smtp_domain::ports::MailboxSubscriptionPort;
